use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use rustls::sign::CertifiedKey;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::tunnel::attestation_metrics::AttestationAttempt;
use crate::tunnel::attestation_result::AttestationResult;
use crate::tunnel::cert_verifier::TngCommonCertVerifier;
use crate::tunnel::challenge::ChallengeSource;
use crate::tunnel::proposal::{AttestProposal, Model};
use crate::tunnel::provider::ProviderType;
use crate::tunnel::ra_context::{AttestContext, RaContext, VerifyContextSet};
use crate::tunnel::select_proposal::{find_proposal, pick_proposal};
use crate::tunnel::service_metrics::{
    AttestationMetrics, AttestationOperation, AttestationProtocol,
};
use rats_cert::tee::AttesterPipeline;

use super::claims::{BackgroundCheckExpectation, PassportExpectation, EXPORTER_LEN};
use super::codec::{read_request, read_response, write_request, write_response};
use super::core::{
    ack_response, error_response, produce_background_check_evidence, produce_passport_token,
    produced_error_reason, EvidenceProducer, ExchangeVerifier, PassportEvidenceCache,
    TokenProducer,
};
use super::exporter::{export_from_client, export_from_server, spki_from_certified_key};
use super::pb::{self, response, Request, Response};

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
    pub verifier: Option<&'a dyn ExchangeVerifier>,
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
    verifier: Option<&'a dyn ExchangeVerifier>,
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
    let my_proposals = match resources.proposal_maker {
        Some(maker) => maker.fresh_proposals().await?,
        None => vec![],
    };
    let my_req = Request {
        proposals: my_proposals.iter().map(proposal_to_pb).collect(),
    };

    let (_, peer_req) = tokio::try_join!(write_request(wr, &my_req), read_request(rd))?;

    let generate = resources.start_if(
        !peer_req.proposals.is_empty(),
        AttestationOperation::Generate,
    );
    let outgoing = produce_outgoing(&resources, &peer_req).await?;
    if matches!(
        outgoing.body,
        Some(response::Body::Evidence(_) | response::Body::Token(_))
    ) {
        mark_succeeded(generate);
    }
    let failed_reason = produced_error_reason(&outgoing).map(str::to_string);

    let (_, incoming) = tokio::try_join!(write_response(wr, &outgoing), read_response(rd))?;

    if let Some(reason) = failed_reason {
        bail!("failed to attest to peer: {reason}");
    }

    let verify = resources.start_if(!my_proposals.is_empty(), AttestationOperation::Verify);
    let result = verify_incoming(&my_proposals, &resources, incoming).await?;
    mark_succeeded(verify);
    Ok(result)
}

fn proposal_to_pb(proposal: &AttestProposal) -> pb::AttestProposal {
    let kind = match proposal {
        AttestProposal::BackgroundCheck {
            provider,
            challenge_token,
        } => pb::attest_proposal::Kind::BackgroundCheck(pb::BackgroundCheck {
            provider: provider.as_str().to_owned(),
            challenge_token: challenge_token.clone(),
        }),
        AttestProposal::Passport { provider } => {
            pb::attest_proposal::Kind::Passport(pb::Passport {
                provider: provider.as_str().to_owned(),
            })
        }
    };
    pb::AttestProposal { kind: Some(kind) }
}

fn proposal_from_pb(proposal: &pb::AttestProposal) -> Result<AttestProposal> {
    match proposal.kind.as_ref().context("proposal has no kind")? {
        pb::attest_proposal::Kind::BackgroundCheck(bc) => Ok(AttestProposal::BackgroundCheck {
            provider: ProviderType::from_required_wire_str(&bc.provider)?,
            challenge_token: bc.challenge_token.clone(),
        }),
        pb::attest_proposal::Kind::Passport(p) => Ok(AttestProposal::Passport {
            provider: ProviderType::from_required_wire_str(&p.provider)?,
        }),
    }
}

async fn produce_outgoing(resources: &ExchangeResources<'_>, peer: &Request) -> Result<Response> {
    if peer.proposals.is_empty() {
        return Ok(ack_response());
    }
    let proposals = match peer
        .proposals
        .iter()
        .map(proposal_from_pb)
        .collect::<Result<Vec<_>>>()
    {
        Ok(proposals) => proposals,
        Err(e) => {
            tracing::warn!(error = ?e, "peer sent a malformed attestation proposal");
            return Ok(error_response("malformed attestation proposal"));
        }
    };
    let Some(own_key) = resources.attest_key else {
        return Ok(error_response("not configured to attest"));
    };
    let proposal = match pick_proposal(own_key, &proposals) {
        Ok(proposal) => proposal,
        Err(e) => return Ok(error_response(e.to_string())),
    };
    let Some(own_spki) = resources.own_spki_der else {
        return Ok(error_response(
            "attesting side has no snapshotted certificate",
        ));
    };
    match proposal {
        AttestProposal::BackgroundCheck {
            challenge_token, ..
        } => {
            let Some(producer) = resources.evidence_producer else {
                return Ok(error_response("not configured to attest"));
            };
            produce_background_check_evidence(
                producer,
                own_spki,
                challenge_token,
                &resources.exporter,
                resources.max_retries,
            )
            .await
        }
        AttestProposal::Passport { .. } => {
            let (Some(producer), Some(cache), Some(converter)) = (
                resources.token_producer,
                resources.passport_cache,
                resources.attest_converter,
            ) else {
                return Ok(error_response("not configured to attest"));
            };
            produce_passport_token(producer, converter, own_spki, cache, resources.max_retries)
                .await
        }
    }
}

async fn verify_incoming(
    my_proposals: &[AttestProposal],
    resources: &ExchangeResources<'_>,
    incoming: Response,
) -> Result<Option<AttestationResult>> {
    let body = incoming.body.context("response message has empty body")?;
    if my_proposals.is_empty() {
        return match body {
            response::Body::Ack(_) => Ok(None),
            response::Body::Evidence(_) | response::Body::Token(_) => {
                bail!("unsolicited credentials")
            }
            response::Body::Error(e) => bail!("peer sent an error: {}", e.reason),
        };
    }

    let verifier = || resources.verifier.context("verifying side has no verifier");
    let peer_spki = || {
        resources
            .peer_spki_der
            .context("verifying side has no peer certificate")
    };
    let result = match body {
        response::Body::Evidence(ev) => {
            let provider = ProviderType::from_required_wire_str(&ev.provider)?;
            let issued_nonce = find_proposal(my_proposals, Model::BackgroundCheck, provider)?
                .challenge_token()
                .context("background-check proposal carries no nonce")?;
            let expected = BackgroundCheckExpectation {
                peer_spki_der: peer_spki()?,
                issued_nonce,
                exporter: &resources.exporter,
            }
            .to_claims()?;
            verifier()?
                .verify_evidence(provider, &ev.json, expected)
                .await
        }
        response::Body::Token(t) => {
            let provider = ProviderType::from_required_wire_str(&t.provider)?;
            find_proposal(my_proposals, Model::Passport, provider)?;
            let expected = PassportExpectation {
                peer_spki_der: peer_spki()?,
            }
            .to_claims()?;
            verifier()?.verify_token(provider, &t.jwt, expected).await
        }
        response::Body::Ack(_) => bail!("peer did not attest"),
        response::Body::Error(e) => bail!("peer attestation failed: {}", e.reason),
    }
    .context("evidence conversion or verification failed")?;
    Ok(Some(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rats_cert::tee::claims::Claims;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::super::claims::expected_subset_of;
    use super::super::core::{evidence_response, token_response};
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
        async fn produce(&self, claims: Claims) -> Result<pb::Evidence> {
            Ok(pb::Evidence {
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
            _provider: ProviderType,
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
        verifier: &'a dyn ExchangeVerifier,
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

    /// Plays an attester-side peer that sends `peer_req` and returns the response it receives.
    async fn attester_answer(
        resources: ExchangeResources<'_>,
        peer_req: Request,
    ) -> (Result<Option<AttestationResult>>, Response) {
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

    fn proposing(proposals: &[AttestProposal]) -> Request {
        Request {
            proposals: proposals.iter().map(proposal_to_pb).collect(),
        }
    }

    fn error_reason(resp: Response) -> String {
        match resp.body {
            Some(response::Body::Error(e)) => e.reason,
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
            Request::default(),
            token_response("ita", "fake.jwt.token"),
        )
        .await;
        assert!(res.unwrap().is_some());
        assert_eq!(got.proposals.len(), 2);

        // No nonce was issued for ita, so ita evidence cannot be checked against one.
        let (res, _) = against_peer(
            two_proposals(),
            Request::default(),
            evidence_response("ita", "{}"),
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
            Request::default(),
            error_response("changed my mind"),
        )
        .await;
        let err = res.unwrap_err().to_string();
        assert!(err.contains("changed my mind"), "{err}");
        assert!(!err.contains("timed out"), "{err}");

        let (res, _) = against_peer(
            verify_only(&proposals, &verifier),
            Request::default(),
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
            Request::default(),
            token_response("coco", "fake.jwt.token"),
        )
        .await;
        assert_err_contains(res, "not proposed");

        let (res, _) = against_peer(
            verify_only(&passport_proposals, &verifier),
            Request::default(),
            evidence_response("coco", "{}"),
        )
        .await;
        assert_err_contains(res, "not proposed");
    }

    #[tokio::test]
    async fn bad_provider_fail_closes() {
        let proposals = coco_bc_proposals();
        let verifier = SubsetVerifier;
        for provider in ["", "notaprovider"] {
            let (res, _) = against_peer(
                verify_only(&proposals, &verifier),
                Request::default(),
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

        let unknown_provider = Request {
            proposals: vec![pb::AttestProposal {
                kind: Some(pb::attest_proposal::Kind::Passport(pb::Passport {
                    provider: "bad_provider".into(),
                })),
            }],
        };
        let (res, resp) = attester_answer(attest_only(&producer), unknown_provider).await;
        assert_eq!(error_reason(resp), "malformed attestation proposal");
        assert_err_contains(res, "malformed attestation proposal");
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
            write_request(&mut peer, &Request::default()).await.unwrap();
            write_response(&mut peer, &ack_response()).await.unwrap();
            let resp = read_response(&mut peer).await.unwrap();
            assert!(matches!(resp.body, Some(response::Body::Ack(_))));
        };
        let (local_res, _) = tokio::join!(local_fut, peer_fut);
        assert!(local_res.unwrap().1.is_none());
    }
}
