use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use rustls::sign::CertifiedKey;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::tunnel::attest::{
    ack_response, check_response, error_response, pick_proposal, produce_attest_response,
    produced_error_reason, Answer, AttestClaims, AttestRequest, AttestResponse, AttestVerifier,
    EvidenceProducer, TokenProducer,
};
use crate::tunnel::attestation_metrics::AttestationAttempt;
use crate::tunnel::attestation_result::AttestationResult;
use crate::tunnel::cert_verifier::TngCommonCertVerifier;
use crate::tunnel::challenge::ChallengeSource;
use crate::tunnel::proposal::{AttestProposal, Model};
use crate::tunnel::provider::ProviderType;
use crate::tunnel::ra_context::{AttestContext, RaContext, VerifyContextSet};
use crate::tunnel::service_metrics::{
    AttestationMetrics, AttestationOperation, AttestationProtocol,
};
use rats_cert::tee::AttesterPipeline;

use super::claims::{
    background_check_claims, passport_attester_claims, BackgroundCheckExpectation,
    PassportExpectation, EXPORTER_LEN,
};
use super::codec::{self, read_request, read_response, write_request, write_response};
use super::core::{BoundPassportCache, PassportEvidenceCache};
use super::exporter::{export_from_client, export_from_server, spki_from_certified_key};

pub const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);

/// Builds this side's proposals, with fresh nonces, at the start of every exchange.
#[async_trait::async_trait]
pub trait ProposalMaker: Send + Sync {
    async fn fresh_proposals(&self) -> Result<Vec<AttestProposal>>;
}

#[async_trait::async_trait]
impl ProposalMaker for VerifyContextSet {
    async fn fresh_proposals(&self) -> Result<Vec<AttestProposal>> {
        let metrics = self.attestation_metrics();
        self.make_proposals(|| {
            Some(metrics.start(
                AttestationOperation::Challenge,
                AttestationProtocol::RatsTls,
            ))
        })
        .await
    }
}

pub struct ExchangeResources<'a> {
    /// `None` when this side does not verify its peer.
    pub proposal_maker: Option<&'a dyn ProposalMaker>,
    pub attest_key: Option<(Model, ProviderType)>,
    pub attest_converter: Option<&'a dyn ChallengeSource>,
    pub evidence_producer: Option<&'a dyn EvidenceProducer>,
    pub token_producer: Option<&'a dyn TokenProducer>,
    pub verifier: Option<&'a dyn AttestVerifier>,
    pub passport_cache: Option<&'a PassportEvidenceCache>,
    pub own_spki_der: Option<&'a [u8]>,
    pub peer_spki_der: Option<&'a [u8]>,
    pub exporter: [u8; EXPORTER_LEN],
    pub max_retries: usize,
    pub attestation_metrics: Option<&'a AttestationMetrics>,
}

impl ExchangeResources<'_> {
    fn start_if(
        &self,
        applies: bool,
        operation: AttestationOperation,
    ) -> Option<AttestationAttempt> {
        self.attestation_metrics
            .filter(|_| applies)
            .map(|metrics| metrics.start(operation, AttestationProtocol::RatsTls))
    }
}

fn mark_succeeded(attempt: Option<AttestationAttempt>) {
    if let Some(attempt) = attempt {
        attempt.mark_succeeded();
    }
}

fn resources_from_ra<'a>(
    ra: &'a RaContext,
    verifier: Option<&'a dyn AttestVerifier>,
    exporter: [u8; EXPORTER_LEN],
    own_spki_der: Option<&'a [u8]>,
    peer_spki_der: Option<&'a [u8]>,
    token_producer: Option<&'a dyn TokenProducer>,
) -> ExchangeResources<'a> {
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
        proposal_maker: ra.verify_set().map(|v| v as &dyn ProposalMaker),
        attest_key: ra.attest_context().map(AttestContext::proposal_key),
        attest_converter,
        evidence_producer,
        token_producer,
        verifier,
        passport_cache,
        own_spki_der,
        peer_spki_der,
        exporter,
        max_retries,
        attestation_metrics: ra.attestation_metrics(),
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
        verifier.map(|v| v as &dyn AttestVerifier),
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
    let my_req = AttestRequest {
        proposals: match resources.proposal_maker {
            Some(maker) => maker.fresh_proposals().await?,
            None => vec![],
        },
    };

    let (write_res, read_res) = tokio::join!(write_request(wr, &my_req), read_request(rd));
    write_res?;
    let peer_req = match read_res {
        Ok(req) => req,
        Err(e) if codec::is_malformed(&e) => {
            tracing::warn!(error = ?e, "peer sent a malformed attestation request");
            let outgoing = error_response("malformed attestation proposal");
            let _ = tokio::join!(write_response(wr, &outgoing), read_response(rd));
            bail!("failed to attest to peer: malformed attestation proposal");
        }
        Err(e) => return Err(e),
    };

    let generate = resources.start_if(
        !peer_req.proposals.is_empty(),
        AttestationOperation::Generate,
    );
    let outgoing = produce_outgoing(&resources, &peer_req).await;
    if matches!(outgoing, Ok(Some(_))) {
        mark_succeeded(generate);
    }
    let failed_reason = produced_error_reason(&outgoing).map(str::to_string);

    let (write_res, read_res) = tokio::join!(write_response(wr, &outgoing), read_response(rd));
    write_res?;
    let incoming = read_res?;

    if let Some(reason) = failed_reason {
        bail!("failed to attest to peer: {reason}");
    }

    let verify = resources.start_if(!my_req.proposals.is_empty(), AttestationOperation::Verify);
    let result = verify_incoming(&my_req, &resources, &incoming).await?;
    mark_succeeded(verify);
    Ok(result)
}

async fn produce_outgoing(
    resources: &ExchangeResources<'_>,
    peer: &AttestRequest,
) -> AttestResponse {
    let proposal = match pick_proposal(&peer.proposals, resources.attest_key) {
        Answer::Ack => return ack_response(),
        Answer::Reject(reason) => return error_response(reason),
        Answer::Matched(proposal) => proposal,
    };
    let Some(own_spki) = resources.own_spki_der else {
        return error_response("attesting side has no snapshotted certificate");
    };
    let bound = resources.passport_cache.map(|cache| BoundPassportCache {
        cache,
        spki: own_spki,
    });
    let claims = TlsClaims {
        own_spki,
        exporter: &resources.exporter,
        converter: resources.attest_converter,
    };
    produce_attest_response(
        proposal,
        &claims,
        resources.evidence_producer,
        resources.token_producer,
        bound.as_ref(),
        resources.max_retries,
    )
    .await
}

struct TlsClaims<'a> {
    own_spki: &'a [u8],
    exporter: &'a [u8],
    converter: Option<&'a dyn ChallengeSource>,
}

impl AttestClaims for TlsClaims<'_> {
    fn claims<'a>(
        &'a self,
        proposal: &'a AttestProposal,
    ) -> Pin<Box<dyn Future<Output = Result<rats_cert::tee::claims::Claims>> + Send + 'a>> {
        Box::pin(tls_claims(
            proposal,
            self.own_spki,
            self.exporter,
            self.converter,
        ))
    }
}

async fn tls_claims(
    proposal: &AttestProposal,
    own_spki: &[u8],
    exporter: &[u8],
    converter: Option<&dyn ChallengeSource>,
) -> Result<rats_cert::tee::claims::Claims> {
    match proposal {
        AttestProposal::BackgroundCheck {
            challenge_token, ..
        } => background_check_claims(own_spki, challenge_token, exporter),
        AttestProposal::Passport { .. } => {
            let converter = converter.context("not configured to attest")?;
            let nonce = converter.get_nonce().await?;
            passport_attester_claims(own_spki, &nonce)
        }
    }
}

async fn verify_incoming(
    sent: &AttestRequest,
    resources: &ExchangeResources<'_>,
    incoming: &AttestResponse,
) -> Result<Option<AttestationResult>> {
    check_response(sent, incoming, resources.verifier, |proposal| {
        let peer_spki = resources
            .peer_spki_der
            .context("verifying side has no peer certificate")?;
        match proposal {
            AttestProposal::BackgroundCheck {
                challenge_token, ..
            } => BackgroundCheckExpectation {
                peer_spki_der: peer_spki,
                issued_nonce: challenge_token,
                exporter: &resources.exporter,
            }
            .to_claims(),
            AttestProposal::Passport { .. } => PassportExpectation {
                peer_spki_der: peer_spki,
            }
            .to_claims(),
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use rats_cert::tee::claims::Claims;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::super::claims::expected_subset_of;
    use crate::tunnel::attest::Evidence;
    use crate::tunnel::attest::{evidence_response, token_response};
    use crate::tunnel::provider::TngToken;
    use crate::tunnel::select_proposal::NO_COMPATIBLE_PROPOSAL;

    const SPKI: &[u8] = b"spki-a";
    const EXP: [u8; EXPORTER_LEN] = [7u8; EXPORTER_LEN];

    fn dummy_result() -> AttestationResult {
        AttestationResult::from_token(
            Model::Passport,
            TngToken::from_wire(ProviderType::Coco, "fake.jwt.token".into()).unwrap(),
        )
    }

    fn resources<'a>() -> ExchangeResources<'a> {
        ExchangeResources {
            proposal_maker: None,
            attest_key: None,
            attest_converter: None,
            evidence_producer: None,
            token_producer: None,
            verifier: None,
            passport_cache: None,
            own_spki_der: None,
            peer_spki_der: None,
            exporter: EXP,
            max_retries: 0,
            attestation_metrics: None,
        }
    }

    struct FixedProposals(Vec<AttestProposal>);

    #[async_trait::async_trait]
    impl ProposalMaker for FixedProposals {
        async fn fresh_proposals(&self) -> Result<Vec<AttestProposal>> {
            Ok(self.0.clone())
        }
    }

    fn coco_bc(nonce: &str) -> AttestProposal {
        AttestProposal::BackgroundCheck {
            provider: ProviderType::Coco,
            challenge_token: nonce.into(),
        }
    }

    fn coco_bc_proposals() -> FixedProposals {
        FixedProposals(vec![coco_bc("n")])
    }

    struct ClaimsEchoProducer;

    #[async_trait::async_trait]
    impl EvidenceProducer for ClaimsEchoProducer {
        async fn produce(&self, claims: Claims) -> Result<Evidence> {
            Ok(Evidence {
                provider: ProviderType::Coco,
                evidence: serde_json::to_value(&claims)?,
            })
        }
    }

    struct SubsetVerifier;

    #[async_trait::async_trait]
    impl AttestVerifier for SubsetVerifier {
        async fn verify_evidence(
            &self,
            _provider: ProviderType,
            evidence: &serde_json::Value,
            expected: Claims,
        ) -> Result<AttestationResult> {
            let actual: Claims = serde_json::from_value(evidence.clone())
                .context("stub verifier expected claims JSON in evidence")?;
            if !expected_subset_of(&expected, &actual) {
                bail!("expected claims not subset of evidence");
            }
            Ok(dummy_result())
        }

        async fn verify_token(
            &self,
            _provider: ProviderType,
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
        proposals: &'a FixedProposals,
        verifier: &'a dyn AttestVerifier,
    ) -> ExchangeResources<'a> {
        let mut r = resources();
        r.proposal_maker = Some(proposals);
        r.verifier = Some(verifier);
        r.peer_spki_der = Some(SPKI);
        r
    }

    fn attest_only<'a>(producer: &'a dyn EvidenceProducer) -> ExchangeResources<'a> {
        let mut r = resources();
        r.attest_key = Some((Model::BackgroundCheck, ProviderType::Coco));
        r.evidence_producer = Some(producer);
        r.own_spki_der = Some(SPKI);
        r
    }

    fn assert_err_contains<T: std::fmt::Debug>(res: Result<T>, needle: &str) {
        let err = res.unwrap_err();
        assert!(
            format!("{err:#}").contains(needle),
            "unexpected error: {err:#}"
        );
    }

    async fn against_peer(
        resources: ExchangeResources<'_>,
        peer_req: AttestRequest,
        peer_resp: AttestResponse,
    ) -> (Result<Option<AttestationResult>>, AttestRequest) {
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

    /// Plays an attester-side peer that sends `peer_req` and returns the response it receives.
    async fn attester_answer(
        resources: ExchangeResources<'_>,
        peer_req: AttestRequest,
    ) -> (Result<Option<AttestationResult>>, AttestResponse) {
        let (mut peer, local) = tokio::io::duplex(4096);
        let local_fut = run_on_stream(local, resources);
        let peer_fut = async {
            write_request(&mut peer, &peer_req).await.unwrap();
            let _ = read_request(&mut peer).await.unwrap();
            let resp = read_response(&mut peer).await.unwrap();
            write_response(&mut peer, &ack_response()).await.unwrap();
            resp
        };
        let (local_res, resp) = tokio::join!(local_fut, peer_fut);
        (local_res.map(|(_, result)| result), resp)
    }

    fn proposing(proposals: &[AttestProposal]) -> AttestRequest {
        AttestRequest {
            proposals: proposals.to_vec(),
        }
    }

    fn error_reason(resp: AttestResponse) -> String {
        match resp {
            Err(reason) => reason,
            other => panic!("expected error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn verifier_accepts_background_check_evidence() {
        let proposals = coco_bc_proposals();
        let producer = ClaimsEchoProducer;
        let verifier = SubsetVerifier;
        let (client, server) = tokio::io::duplex(65536);
        let (rc, rs) = tokio::join!(
            run_on_stream(client, verify_only(&proposals, &verifier)),
            run_on_stream(server, attest_only(&producer)),
        );
        assert!(rc.unwrap().1.is_some());
        assert!(rs.unwrap().1.is_none());
    }

    #[tokio::test]
    async fn multi_proposal_verifier_accepts_either_matching_answer() {
        let proposals = FixedProposals(vec![
            coco_bc("n"),
            AttestProposal::Passport {
                provider: ProviderType::Ita,
            },
        ]);
        let producer = ClaimsEchoProducer;
        let verifier = SubsetVerifier;
        let two_proposals = || verify_only(&proposals, &verifier);

        let (client, server) = tokio::io::duplex(65536);
        let (rc, rs) = tokio::join!(
            run_on_stream(client, two_proposals()),
            run_on_stream(server, attest_only(&producer)),
        );
        assert!(rc.unwrap().1.is_some());
        assert!(rs.unwrap().1.is_none());

        let (res, got) = against_peer(
            two_proposals(),
            AttestRequest::default(),
            token_response(ProviderType::Ita, "fake.jwt.token"),
        )
        .await;
        assert!(res.unwrap().is_some());
        assert_eq!(got.proposals.len(), 2);

        // No nonce was issued for ita, so ita evidence cannot be checked against one.
        let (res, _) = against_peer(
            two_proposals(),
            AttestRequest::default(),
            evidence_response(ProviderType::Ita, serde_json::json!({})),
        )
        .await;
        assert_err_contains(res, "not proposed");
    }

    #[tokio::test]
    async fn none_none_then_application_data() {
        let (a, b) = tokio::io::duplex(1024);
        let (ra, rb) = tokio::join!(run_on_stream(a, resources()), run_on_stream(b, resources()),);
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
        let proposals = coco_bc_proposals();
        let verifier = SubsetVerifier;
        let (res, _) = against_peer(
            verify_only(&proposals, &verifier),
            AttestRequest::default(),
            error_response("changed my mind"),
        )
        .await;
        let err = res.unwrap_err().to_string();
        assert!(err.contains("changed my mind"), "{err}");
        assert!(!err.contains("timed out"), "{err}");

        let (res, _) = against_peer(
            verify_only(&proposals, &verifier),
            AttestRequest::default(),
            ack_response(),
        )
        .await;
        assert_err_contains(res, "peer did not attest");
    }

    #[tokio::test]
    async fn verifier_rejects_unasked_answer() {
        let bc_proposals = coco_bc_proposals();
        let passport_proposals = FixedProposals(vec![AttestProposal::Passport {
            provider: ProviderType::Coco,
        }]);
        let verifier = SubsetVerifier;
        let (res, _) = against_peer(
            verify_only(&bc_proposals, &verifier),
            AttestRequest::default(),
            token_response(ProviderType::Coco, "fake.jwt.token"),
        )
        .await;
        assert_err_contains(res, "not proposed");

        let (res, _) = against_peer(
            verify_only(&passport_proposals, &verifier),
            AttestRequest::default(),
            evidence_response(ProviderType::Coco, serde_json::json!({})),
        )
        .await;
        assert_err_contains(res, "not proposed");
    }

    #[tokio::test]
    async fn bad_provider_fail_closes() {
        let proposals = coco_bc_proposals();
        let verifier = SubsetVerifier;
        for provider in ["", "notaprovider"] {
            let body = format!(
                r#"{{"Ok":{{"background_check":{{"provider":{provider:?},"evidence":{{}}}}}}}}"#
            );
            let res = against_peer_raw(
                verify_only(&proposals, &verifier),
                AttestRequest::default(),
                body.as_bytes(),
            )
            .await;
            let err = format!("{:#}", res.unwrap_err());
            assert!(
                err.contains("unrecognized provider"),
                "provider={provider:?} err={err}"
            );
        }
    }

    async fn against_peer_raw(
        resources: ExchangeResources<'_>,
        peer_req: AttestRequest,
        peer_resp: &[u8],
    ) -> Result<Option<AttestationResult>> {
        let (mut peer, local) = tokio::io::duplex(4096);
        let local_fut = run_on_stream(local, resources);
        let peer_fut = async {
            write_request(&mut peer, &peer_req).await.unwrap();
            let _ = read_request(&mut peer).await.unwrap();
            peer.write_u32(peer_resp.len() as u32).await.unwrap();
            peer.write_all(peer_resp).await.unwrap();
            peer.flush().await.unwrap();
            let _ = read_response(&mut peer).await;
        };
        let (local_res, _) = tokio::join!(local_fut, peer_fut);
        local_res.map(|(_, result)| result)
    }

    #[tokio::test]
    async fn attester_fail_closes_on_unanswerable_proposals() {
        let producer = ClaimsEchoProducer;
        let cases = [
            (proposing(&[coco_bc("")]), "missing nonce"),
            (
                proposing(&[AttestProposal::Passport {
                    provider: ProviderType::Ita,
                }]),
                NO_COMPATIBLE_PROPOSAL,
            ),
            (proposing(&[coco_bc("a"), coco_bc("b")]), "duplicate"),
        ];
        for (req, needle) in cases {
            let (res, resp) = attester_answer(attest_only(&producer), req).await;
            let reason = error_reason(resp);
            assert!(reason.contains(needle), "{reason}");
            assert_err_contains(res, needle);
        }

        let (mut peer, local) = tokio::io::duplex(4096);
        let local_fut = run_on_stream(local, attest_only(&producer));
        let peer_fut = async {
            let body = br#"{"proposals":[{"model":"passport","provider":"bad_provider"}]}"#;
            peer.write_u32(body.len() as u32).await.unwrap();
            peer.write_all(body).await.unwrap();
            peer.flush().await.unwrap();
            let _ = read_request(&mut peer).await.unwrap();
            let resp = read_response(&mut peer).await.unwrap();
            write_response(&mut peer, &ack_response()).await.unwrap();
            resp
        };
        let (res, resp) = tokio::join!(local_fut, peer_fut);
        assert_eq!(error_reason(resp), "malformed attestation proposal");
        assert_err_contains(
            res.map(|(_, result)| result),
            "malformed attestation proposal",
        );
    }

    #[tokio::test]
    async fn response_not_written_until_requests_exchanged() {
        let (mut peer, local) = tokio::io::duplex(1024);
        let local_fut = run_on_stream(local, resources());
        let peer_fut = async {
            let req = read_request(&mut peer).await.unwrap();
            assert!(req.proposals.is_empty());
            let extra =
                tokio::time::timeout(Duration::from_millis(50), read_response(&mut peer)).await;
            assert!(
                extra.is_err(),
                "response written before peer request was sent"
            );
            write_request(&mut peer, &AttestRequest::default())
                .await
                .unwrap();
            write_response(&mut peer, &ack_response()).await.unwrap();
            let resp = read_response(&mut peer).await.unwrap();
            assert_eq!(resp, ack_response());
        };
        let (local_res, _) = tokio::join!(local_fut, peer_fut);
        assert!(local_res.unwrap().1.is_none());
    }
}
