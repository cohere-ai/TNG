use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::AttestError;
use crate::tunnel::attest::{
    check_response, make_proposals, respond, AttestRequest, AttestResponse, AttestVerifier,
    Attester, Prepared,
};
use crate::tunnel::attestation_metrics::AttestationAttempt;
use crate::tunnel::attestation_result::AttestationResult;
use crate::tunnel::cert_verifier::TngCommonCertVerifier;
use crate::tunnel::proposal::AttestProposal;
use crate::tunnel::ra_context::{AttestContext, RaContext, VerifyContextSet};
use crate::tunnel::service_metrics::{
    AttestationMetrics, AttestationOperation, AttestationProtocol,
};
use crate::tunnel::utils::cert_manager::AttestedKey;

use super::claims::{
    background_check_claims, BackgroundCheckExpectation, PassportExpectation, EXPORTER_LEN,
};
use super::codec::{self, read_request, read_response, write_request, write_response};
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
        make_proposals(self.proposers(), || {
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
    /// `None` when this side does not attest.
    pub attester: Option<Attester<'a>>,
    /// Prepared alongside `own_spki_der`'s certificate.
    pub prepared: Prepared,
    pub verifier: Option<&'a dyn AttestVerifier>,
    pub own_spki_der: Option<&'a [u8]>,
    pub peer_spki_der: Option<&'a [u8]>,
    pub exporter: [u8; EXPORTER_LEN],
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
    prepared: Prepared,
) -> ExchangeResources<'a> {
    ExchangeResources {
        proposal_maker: ra.verify_set().map(|v| v as &dyn ProposalMaker),
        attester: ra.attest_context().map(AttestContext::attester),
        prepared,
        verifier,
        own_spki_der,
        peer_spki_der,
        exporter,
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
    attested_key: Option<&AttestedKey>,
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
    attested_key: Option<&AttestedKey>,
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
    attested_key: Option<&AttestedKey>,
    exporter: [u8; EXPORTER_LEN],
) -> Result<(S, Option<AttestationResult>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let own_spki = attested_key
        .map(|key| spki_from_certified_key(&key.cert))
        .transpose()?;
    let peer_spki = verifier.map(|v| v.peer_spki_der()).transpose()?;
    let resources = resources_from_ra(
        ra,
        verifier.map(|v| v.verify_set() as &dyn AttestVerifier),
        exporter,
        own_spki.as_deref(),
        peer_spki.as_deref(),
        attested_key
            .map(|key| key.prepared.clone())
            .unwrap_or_default(),
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
            let outgoing = Err(AttestError::Malformed);
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
    let failed = outgoing.as_ref().err().cloned();

    let (write_res, read_res) = tokio::join!(write_response(wr, &outgoing), read_response(rd));
    write_res?;
    let incoming = read_res?;

    if let Some(error) = failed {
        bail!("failed to attest to peer: {error}");
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
    respond(peer, resources.attester, &resources.prepared, |nonce| {
        let own_spki = resources
            .own_spki_der
            .context("attesting side has no snapshotted certificate")?;
        background_check_claims(own_spki, nonce, &resources.exporter)
    })
    .await
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
    use crate::tunnel::attest::{evidence_response, token_response, Evidence, EvidenceProducer};
    use crate::tunnel::proposal::Model;
    use crate::tunnel::provider::{ProviderType, TngToken};

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
            attester: None,
            prepared: Prepared::default(),
            verifier: None,
            own_spki_der: None,
            peer_spki_der: None,
            exporter: EXP,
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
        r.attester = Some(Attester::BackgroundCheck {
            provider: ProviderType::Coco,
            producer,
            max_retries: 0,
        });
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
            write_response(&mut peer, &Ok(None)).await.unwrap();
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

    fn error_of(resp: AttestResponse) -> AttestError {
        match resp {
            Err(error) => error,
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
            Err(AttestError::NotConfigured),
        )
        .await;
        let err = res.unwrap_err().to_string();
        assert!(err.contains("not configured to attest"), "{err}");
        assert!(!err.contains("timed out"), "{err}");

        let (res, _) = against_peer(
            verify_only(&proposals, &verifier),
            AttestRequest::default(),
            Ok(None),
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
            (proposing(&[coco_bc("")]), AttestError::MissingNonce),
            (
                proposing(&[AttestProposal::Passport {
                    provider: ProviderType::Ita,
                }]),
                AttestError::NoCompatibleProposal,
            ),
            (
                proposing(&[coco_bc("a"), coco_bc("b")]),
                AttestError::DuplicateProposal {
                    model: Model::BackgroundCheck,
                    provider: ProviderType::Coco,
                },
            ),
        ];
        for (req, expected) in cases {
            let (res, resp) = attester_answer(attest_only(&producer), req).await;
            let error = error_of(resp);
            assert_eq!(error, expected);
            assert_err_contains(res, &error.to_string());
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
            write_response(&mut peer, &Ok(None)).await.unwrap();
            resp
        };
        let (res, resp) = tokio::join!(local_fut, peer_fut);
        assert_eq!(error_of(resp), AttestError::Malformed);
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
            write_response(&mut peer, &Ok(None)).await.unwrap();
            let resp = read_response(&mut peer).await.unwrap();
            assert_eq!(resp, Ok(None));
        };
        let (local_res, _) = tokio::join!(local_fut, peer_fut);
        assert!(local_res.unwrap().1.is_none());
    }
}
