use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use rustls::sign::CertifiedKey;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::tunnel::attestation_result::AttestationResult;
use crate::tunnel::cert_verifier::TngCommonCertVerifier;
use crate::tunnel::provider::ProviderType;
use crate::tunnel::ra_context::{AttestContext, RaContext, VerifyContext};
use rats_cert::tee::AttesterPipeline;

use super::claims::EXPORTER_LEN;
use super::codec::{read_request, read_response, write_request, write_response};
use super::core::{
    ack_response, error_response, produce_background_check_evidence, produce_passport_token,
    produced_error_reason, ChallengeSource, EvidenceProducer, ExchangeState, ExchangeVerifier,
    PassportEvidenceCache, TokenProducer, VerifyMode,
};
use super::exporter::{export_from_client, export_from_server, spki_from_certified_key};
use super::pb::{request, response, Request, Response};

pub const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);

pub struct ExchangeResources<'a> {
    pub verify_mode: VerifyMode,
    pub verifier_converter: Option<&'a dyn ChallengeSource>,
    pub attest_converter: Option<&'a dyn ChallengeSource>,
    pub evidence_producer: Option<&'a dyn EvidenceProducer>,
    pub token_producer: Option<&'a dyn TokenProducer>,
    pub verifier: Option<&'a dyn ExchangeVerifier>,
    pub passport_cache: Option<&'a PassportEvidenceCache>,
    pub own_spki_der: Option<&'a [u8]>,
    pub peer_spki_der: Option<&'a [u8]>,
    pub exporter: [u8; EXPORTER_LEN],
    pub max_retries: usize,
}

fn resources_from_ra<'a>(
    ra: &'a RaContext,
    verifier: Option<&'a dyn ExchangeVerifier>,
    exporter: [u8; EXPORTER_LEN],
    own_spki_der: Option<&'a [u8]>,
    peer_spki_der: Option<&'a [u8]>,
    token_producer: Option<&'a dyn TokenProducer>,
) -> ExchangeResources<'a> {
    let verify_mode = match ra.verify_context() {
        Some(VerifyContext::BackgroundCheck { .. }) => VerifyMode::BackgroundCheck,
        Some(VerifyContext::Passport { .. }) => VerifyMode::Passport,
        None => VerifyMode::None,
    };
    let verifier_converter = match ra.verify_context() {
        Some(VerifyContext::BackgroundCheck { converter, .. }) => {
            Some(converter as &dyn ChallengeSource)
        }
        _ => None,
    };
    let (evidence_producer, attest_converter, passport_cache, max_retries) =
        match ra.attest_context() {
            Some(AttestContext::Passport {
                converter,
                passport_cache,
                max_retries,
                ..
            }) => (
                None,
                Some(converter as &dyn ChallengeSource),
                Some(passport_cache),
                *max_retries,
            ),
            Some(AttestContext::BackgroundCheck {
                attester,
                max_retries,
                ..
            }) => (
                Some(attester as &dyn EvidenceProducer),
                None,
                None,
                *max_retries,
            ),
            None => (None, None, None, 0),
        };

    ExchangeResources {
        verify_mode,
        verifier_converter,
        attest_converter,
        evidence_producer,
        token_producer,
        verifier,
        passport_cache,
        own_spki_der,
        peer_spki_der,
        exporter,
        max_retries,
    }
}

async fn run_on_stream<S>(
    stream: S,
    resources: ExchangeResources<'_>,
) -> Result<(S, Option<AttestationResult>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    run_on_stream_with_timeout(stream, resources, EXCHANGE_TIMEOUT).await
}

async fn run_on_stream_with_timeout<S>(
    stream: S,
    resources: ExchangeResources<'_>,
    timeout: Duration,
) -> Result<(S, Option<AttestationResult>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut rd, mut wr) = tokio::io::split(stream);
    match tokio::time::timeout(timeout, run_halves(&mut rd, &mut wr, resources)).await {
        Ok(Ok(result)) => Ok((rd.unsplit(wr), result)),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(anyhow!("attestation exchange timed out")),
    }
}

pub async fn finish_rats_tls_server<IO>(
    stream: tokio_rustls::server::TlsStream<IO>,
    ra: &RaContext,
    verifier: Option<&TngCommonCertVerifier>,
    attested_key: Option<&CertifiedKey>,
) -> Result<(
    tokio_rustls::server::TlsStream<IO>,
    Option<AttestationResult>,
)>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let exporter = export_from_server(&stream, Some(&[]))?;
    finish_rats_tls(stream, ra, verifier, attested_key, exporter).await
}

pub async fn finish_rats_tls_client<IO>(
    stream: tokio_rustls::client::TlsStream<IO>,
    ra: &RaContext,
    verifier: Option<&TngCommonCertVerifier>,
    attested_key: Option<&CertifiedKey>,
) -> Result<(
    tokio_rustls::client::TlsStream<IO>,
    Option<AttestationResult>,
)>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let exporter = export_from_client(&stream, Some(&[]))?;
    finish_rats_tls(stream, ra, verifier, attested_key, exporter).await
}

async fn finish_rats_tls<S>(
    stream: S,
    ra: &RaContext,
    verifier: Option<&TngCommonCertVerifier>,
    attested_key: Option<&CertifiedKey>,
    exporter: [u8; EXPORTER_LEN],
) -> Result<(S, Option<AttestationResult>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let own_spki = attested_key.map(spki_from_certified_key).transpose()?;
    let peer_spki = verifier.map(|v| v.peer_spki_der()).transpose()?;
    let passport_pipeline = match ra.attest_context() {
        Some(AttestContext::Passport {
            attester,
            converter,
            ..
        }) => Some(AttesterPipeline::new(attester, converter)),
        _ => None,
    };
    let resources = resources_from_ra(
        ra,
        verifier.map(|v| v as &dyn ExchangeVerifier),
        exporter,
        own_spki.as_deref(),
        peer_spki.as_deref(),
        passport_pipeline.as_ref().map(|p| p as &dyn TokenProducer),
    );
    run_on_stream(stream, resources).await
}

async fn run_halves<R, W>(
    rd: &mut R,
    wr: &mut W,
    resources: ExchangeResources<'_>,
) -> Result<Option<AttestationResult>>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut state = ExchangeState::new(resources.verify_mode);
    let my_req = state
        .prepare_request(resources.verifier_converter)
        .await
        .context("converter errors while fetching the nonce")?;

    let (_, peer_req) = tokio::try_join!(write_request(wr, &my_req), read_request(rd))?;

    let outgoing = produce_outgoing(&resources, &peer_req).await?;
    let failed_reason = produced_error_reason(&outgoing).map(str::to_string);

    let (_, incoming) = tokio::try_join!(write_response(wr, &outgoing), read_response(rd))?;

    if let Some(reason) = failed_reason {
        bail!("attestation failed after retries: {reason}");
    }

    verify_incoming(&state, &resources, incoming).await
}

async fn produce_outgoing(resources: &ExchangeResources<'_>, peer: &Request) -> Result<Response> {
    match peer.body.as_ref() {
        None => bail!("request message has empty body"),
        Some(request::Body::None(_)) => Ok(ack_response()),
        Some(request::Body::BackgroundCheck(bc)) => {
            let producer = match resources.evidence_producer {
                Some(p) => p,
                None => return Ok(error_response("not configured to attest")),
            };
            let own_spki = match resources.own_spki_der {
                Some(s) => s,
                None => {
                    return Ok(error_response(
                        "attesting side has no snapshotted certificate",
                    ))
                }
            };
            produce_background_check_evidence(
                producer,
                own_spki,
                &bc.nonce,
                &resources.exporter,
                resources.max_retries,
            )
            .await
        }
        Some(request::Body::Passport(_)) => {
            let producer = match resources.token_producer {
                Some(p) => p,
                None => return Ok(error_response("not configured to attest")),
            };
            let cache = match resources.passport_cache {
                Some(c) => c,
                None => return Ok(error_response("not configured to attest")),
            };
            let converter = match resources.attest_converter {
                Some(c) => c,
                None => return Ok(error_response("not configured to attest")),
            };
            let own_spki = match resources.own_spki_der {
                Some(s) => s,
                None => {
                    return Ok(error_response(
                        "attesting side has no snapshotted certificate",
                    ))
                }
            };
            produce_passport_token(producer, converter, own_spki, cache, resources.max_retries)
                .await
        }
    }
}

async fn verify_incoming(
    state: &ExchangeState,
    resources: &ExchangeResources<'_>,
    incoming: Response,
) -> Result<Option<AttestationResult>> {
    match (resources.verify_mode, incoming.body) {
        (VerifyMode::None, Some(response::Body::Ack(_))) => Ok(None),
        (VerifyMode::None, Some(response::Body::Evidence(_) | response::Body::Token(_))) => {
            bail!("unsolicited credentials")
        }
        (VerifyMode::None, Some(response::Body::Error(e))) => {
            bail!("peer sent an error: {}", e.reason)
        }
        (VerifyMode::BackgroundCheck, Some(response::Body::Evidence(ev))) => {
            ProviderType::from_required_wire_str(&ev.provider)?;
            let verifier = resources
                .verifier
                .context("verifying side has no verifier")?;
            let peer_spki = resources
                .peer_spki_der
                .context("verifying side has no peer certificate")?;
            let expected = state.expected_claims(peer_spki, &resources.exporter)?;
            let result = verifier
                .verify_evidence(&ev.provider, &ev.json, expected)
                .await
                .context("evidence conversion or verification failed")?;
            Ok(Some(result))
        }
        (VerifyMode::BackgroundCheck, Some(response::Body::Token(_))) => {
            bail!("verifier rejects token when it sent background_check")
        }
        (VerifyMode::BackgroundCheck, Some(response::Body::Ack(_))) => {
            bail!("peer did not attest")
        }
        (VerifyMode::BackgroundCheck, Some(response::Body::Error(e))) => {
            bail!("peer attestation failed: {}", e.reason)
        }
        (VerifyMode::Passport, Some(response::Body::Token(t))) => {
            ProviderType::from_required_wire_str(&t.provider)?;
            let verifier = resources
                .verifier
                .context("verifying side has no verifier")?;
            let peer_spki = resources
                .peer_spki_der
                .context("verifying side has no peer certificate")?;
            let expected = state.expected_claims(peer_spki, &resources.exporter)?;
            let result = verifier
                .verify_token(&t.provider, &t.jwt, expected)
                .await
                .context("evidence conversion or verification failed")?;
            Ok(Some(result))
        }
        (VerifyMode::Passport, Some(response::Body::Evidence(_))) => {
            bail!("verifier rejects evidence when it sent passport")
        }
        (VerifyMode::Passport, Some(response::Body::Ack(_))) => {
            bail!("peer did not attest")
        }
        (VerifyMode::Passport, Some(response::Body::Error(e))) => {
            bail!("peer attestation failed: {}", e.reason)
        }
        (_, None) => bail!("response message has empty body"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rats_cert::tee::claims::Claims;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::super::claims::expected_subset_of;
    use super::super::core::{
        ack_response, error_response, evidence_response, none_request, token_response,
    };
    use super::super::pb::{request, response, BackgroundCheck};
    use crate::tunnel::provider::{ProviderType, TngToken};

    const SPKI: &[u8] = b"spki-a";
    const EXP: [u8; EXPORTER_LEN] = [7u8; EXPORTER_LEN];

    fn dummy_result() -> AttestationResult {
        AttestationResult::from_token(
            TngToken::from_wire(ProviderType::Coco, "fake.jwt.token".into()).unwrap(),
        )
    }

    fn resources<'a>(verify_mode: VerifyMode) -> ExchangeResources<'a> {
        ExchangeResources {
            verify_mode,
            verifier_converter: None,
            attest_converter: None,
            evidence_producer: None,
            token_producer: None,
            verifier: None,
            passport_cache: None,
            own_spki_der: None,
            peer_spki_der: None,
            exporter: EXP,
            max_retries: 0,
        }
    }

    struct RecordingConverter {
        nonce: String,
    }

    #[async_trait::async_trait]
    impl ChallengeSource for RecordingConverter {
        async fn get_nonce(&self) -> Result<String> {
            Ok(self.nonce.clone())
        }
    }

    struct ClaimsEchoProducer;

    #[async_trait::async_trait]
    impl EvidenceProducer for ClaimsEchoProducer {
        async fn produce(&self, claims: Claims) -> Result<super::super::pb::Evidence> {
            Ok(super::super::pb::Evidence {
                provider: "coco".into(),
                json: serde_json::to_string(&claims)?,
            })
        }
    }

    struct SubsetVerifier;

    #[async_trait::async_trait]
    impl ExchangeVerifier for SubsetVerifier {
        async fn verify_evidence(
            &self,
            _provider: &str,
            json: &str,
            expected: Claims,
        ) -> Result<AttestationResult> {
            let actual: Claims = serde_json::from_str(json)
                .context("stub verifier expected claims JSON in evidence")?;
            if !expected_subset_of(&expected, &actual) {
                bail!("expected claims not subset of evidence");
            }
            Ok(dummy_result())
        }

        async fn verify_token(
            &self,
            _provider: &str,
            jwt: &str,
            _expected: Claims,
        ) -> Result<AttestationResult> {
            if jwt.is_empty() {
                bail!("empty token");
            }
            Ok(dummy_result())
        }
    }

    fn verify_only<'a>(
        converter: &'a dyn ChallengeSource,
        verifier: &'a dyn ExchangeVerifier,
    ) -> ExchangeResources<'a> {
        let mut r = resources(VerifyMode::BackgroundCheck);
        r.verifier_converter = Some(converter);
        r.verifier = Some(verifier);
        r.peer_spki_der = Some(SPKI);
        r
    }

    fn passport_verify_only<'a>(verifier: &'a dyn ExchangeVerifier) -> ExchangeResources<'a> {
        let mut r = resources(VerifyMode::Passport);
        r.verifier = Some(verifier);
        r.peer_spki_der = Some(SPKI);
        r
    }

    fn attest_only<'a>(producer: &'a dyn EvidenceProducer) -> ExchangeResources<'a> {
        let mut r = resources(VerifyMode::None);
        r.evidence_producer = Some(producer);
        r.own_spki_der = Some(SPKI);
        r
    }

    fn assert_err_contains<T: std::fmt::Debug>(res: Result<T>, needle: &str) {
        let err = res.unwrap_err();
        assert!(
            err.to_string().contains(needle),
            "unexpected error: {err:#}"
        );
    }

    async fn against_peer(
        resources: ExchangeResources<'_>,
        peer_req: Request,
        peer_resp: Response,
    ) -> (Result<Option<AttestationResult>>, Request) {
        let (mut peer, local) = tokio::io::duplex(4096);
        let local_fut = run_on_stream(local, resources);
        let peer_fut = async {
            write_request(&mut peer, &peer_req).await.unwrap();
            let got = read_request(&mut peer).await.unwrap();
            write_response(&mut peer, &peer_resp).await.unwrap();
            let _ = read_response(&mut peer).await.unwrap();
            got
        };
        let (local_res, got) = tokio::join!(local_fut, peer_fut);
        (local_res.map(|(_, result)| result), got)
    }

    #[tokio::test]
    async fn verifier_accepts_background_check_evidence() {
        let conv = RecordingConverter { nonce: "n".into() };
        let producer = ClaimsEchoProducer;
        let verifier = SubsetVerifier;
        let (client, server) = tokio::io::duplex(65536);
        let (rc, rs) = tokio::join!(
            run_on_stream(client, verify_only(&conv, &verifier)),
            run_on_stream(server, attest_only(&producer)),
        );
        assert!(rc.unwrap().1.is_some());
        assert!(rs.unwrap().1.is_none());
    }

    #[tokio::test]
    async fn none_none_then_application_data() {
        let (a, b) = tokio::io::duplex(1024);
        let (ra, rb) = tokio::join!(
            run_on_stream(a, resources(VerifyMode::None)),
            run_on_stream(b, resources(VerifyMode::None)),
        );
        let (mut a, res_a) = ra.unwrap();
        let (mut b, res_b) = rb.unwrap();
        assert!(res_a.is_none());
        assert!(res_b.is_none());
        a.write_all(b"hello").await.unwrap();
        a.flush().await.unwrap();
        let mut buf = [0u8; 5];
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
    }

    #[tokio::test]
    async fn verifier_fail_closes_on_peer_error_or_ack() {
        let conv = RecordingConverter { nonce: "n".into() };
        let verifier = SubsetVerifier;
        let (res, _) = against_peer(
            verify_only(&conv, &verifier),
            none_request(),
            error_response("changed my mind"),
        )
        .await;
        let err = res.unwrap_err().to_string();
        assert!(err.contains("changed my mind"), "{err}");
        assert!(!err.contains("timed out"), "{err}");

        let (res, _) = against_peer(
            verify_only(&conv, &verifier),
            none_request(),
            ack_response(),
        )
        .await;
        assert_err_contains(res, "peer did not attest");
    }

    #[tokio::test]
    async fn verifier_rejects_wrong_response_arm() {
        let conv = RecordingConverter { nonce: "n".into() };
        let verifier = SubsetVerifier;
        let (res, _) = against_peer(
            verify_only(&conv, &verifier),
            none_request(),
            token_response("coco", "fake.jwt.token"),
        )
        .await;
        assert_err_contains(res, "verifier rejects token when it sent background_check");

        let (res, got) = against_peer(
            passport_verify_only(&verifier),
            none_request(),
            evidence_response("coco", "{}"),
        )
        .await;
        assert!(matches!(got.body, Some(request::Body::Passport(_))));
        assert_err_contains(res, "verifier rejects evidence when it sent passport");
    }

    #[tokio::test]
    async fn bad_provider_fail_closes() {
        let conv = RecordingConverter { nonce: "n".into() };
        let verifier = SubsetVerifier;
        for provider in ["", "notaprovider"] {
            let (res, _) = against_peer(
                verify_only(&conv, &verifier),
                none_request(),
                evidence_response(provider, "{}"),
            )
            .await;
            let err = res.unwrap_err().to_string();
            assert!(
                err.contains("empty provider") || err.contains("unrecognized provider"),
                "provider={provider:?} err={err}"
            );
        }
    }

    #[tokio::test]
    async fn empty_nonce_fail_closes_as_missing_nonce() {
        let producer = ClaimsEchoProducer;
        let (mut peer, local) = tokio::io::duplex(1024);
        let local_fut = run_on_stream(local, attest_only(&producer));
        let peer_fut = async {
            write_request(
                &mut peer,
                &Request {
                    body: Some(request::Body::BackgroundCheck(BackgroundCheck {
                        nonce: vec![],
                    })),
                },
            )
            .await
            .unwrap();
            let _ = read_request(&mut peer).await.unwrap();
            let resp = read_response(&mut peer).await.unwrap();
            match resp.body {
                Some(response::Body::Error(e)) => {
                    assert!(e.reason.contains("missing nonce"), "{}", e.reason);
                }
                other => panic!("expected error, got {other:?}"),
            }
            write_response(&mut peer, &ack_response()).await.unwrap();
        };
        let (local_res, _) = tokio::join!(local_fut, peer_fut);
        assert_err_contains(local_res, "missing nonce");
    }

    #[tokio::test]
    async fn response_not_written_until_requests_exchanged() {
        let (mut peer, local) = tokio::io::duplex(1024);
        let local_fut = run_on_stream(local, resources(VerifyMode::None));
        let peer_fut = async {
            let req = read_request(&mut peer).await.unwrap();
            assert!(matches!(req.body, Some(request::Body::None(_))));
            let extra =
                tokio::time::timeout(Duration::from_millis(50), read_response(&mut peer)).await;
            assert!(
                extra.is_err(),
                "response written before peer request was sent"
            );
            write_request(&mut peer, &none_request()).await.unwrap();
            write_response(&mut peer, &ack_response()).await.unwrap();
            let resp = read_response(&mut peer).await.unwrap();
            assert!(matches!(resp.body, Some(response::Body::Ack(_))));
        };
        let (local_res, _) = tokio::join!(local_fut, peer_fut);
        assert!(local_res.unwrap().1.is_none());
    }
}
