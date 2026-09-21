use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::tunnel::attestation_result::AttestationResult;
use crate::tunnel::ra_context::{AttestContext, RaContext, VerifyContext};
use rats_cert::tee::AttesterPipeline;

use super::claims::EXPORTER_LEN;
use super::codec::{read_declaration, read_evidence, write_declaration, write_evidence};
use super::core::{
    evidence_action, inspect_evidence, peer_challenge_token, produce_background_check_evidence,
    produce_passport_evidence, refusal_evidence, verify_action, ChallengeSource, EvidenceAction,
    EvidenceProducer, ExchangeState, InspectedEvidence, LocalRole, PassportEvidenceCache,
    RawEvidenceVerifier, VerifyAction, VerifyMode,
};
use super::pb::{Declaration, Evidence};

pub const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);

pub struct ExchangeResources<'a> {
    pub local: LocalRole,
    pub verify_mode: VerifyMode,
    pub verifier_converter: Option<&'a dyn ChallengeSource>,
    pub attest_converter: Option<&'a dyn ChallengeSource>,
    pub producer: Option<&'a dyn EvidenceProducer>,
    pub verifier: Option<&'a dyn RawEvidenceVerifier>,
    pub passport_cache: Option<&'a PassportEvidenceCache>,
    pub own_spki_der: Option<&'a [u8]>,
    pub peer_spki_der: Option<&'a [u8]>,
    pub exporter: [u8; EXPORTER_LEN],
    pub max_retries: usize,
}

fn resources_from_ra<'a>(
    ra: &'a RaContext,
    verifier: Option<&'a dyn RawEvidenceVerifier>,
    exporter: [u8; EXPORTER_LEN],
    own_spki_der: Option<&'a [u8]>,
    peer_spki_der: Option<&'a [u8]>,
    passport_producer: Option<&'a dyn EvidenceProducer>,
) -> ExchangeResources<'a> {
    let local = LocalRole {
        will_attest: ra.attest_context().is_some(),
        wants_evidence: ra.verify_context().is_some(),
    };
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
    let (producer, attest_converter, passport_cache, max_retries) = match ra.attest_context() {
        Some(AttestContext::Passport {
            converter,
            passport_cache,
            max_retries,
            ..
        }) => (
            passport_producer,
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
        local,
        verify_mode,
        verifier_converter,
        attest_converter,
        producer,
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

pub async fn finish_rats_tls<S>(
    stream: S,
    ra: &RaContext,
    verifier: Option<&dyn RawEvidenceVerifier>,
    exporter: [u8; EXPORTER_LEN],
    own_spki: Option<Vec<u8>>,
    peer_spki: Option<Vec<u8>>,
) -> Result<(S, Option<AttestationResult>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
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
        verifier,
        exporter,
        own_spki.as_deref(),
        peer_spki.as_deref(),
        passport_pipeline
            .as_ref()
            .map(|p| p as &dyn EvidenceProducer),
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
    let mut state = ExchangeState::new(resources.local, resources.verify_mode);
    let my_decl = state
        .prepare_declaration(resources.verifier_converter)
        .await
        .context("converter errors while fetching the nonce")?;

    let (_, peer_decl) = tokio::try_join!(write_declaration(wr, &my_decl), read_declaration(rd))?;

    let vf_action = verify_action(resources.local, &peer_decl);
    if matches!(vf_action, VerifyAction::ClosePeerWillNotAttest) {
        bail!("peer declared it will not attest");
    }

    let outgoing = match evidence_action(resources.local, &peer_decl) {
        EvidenceAction::Produce => Some(produce_outgoing(&resources, &peer_decl).await?),
        EvidenceAction::Refuse => Some(refusal_evidence("not configured to attest")),
        EvidenceAction::Skip => None,
    };

    let failed_reason = match outgoing.as_ref() {
        Some(ev) => match inspect_evidence(ev)? {
            InspectedEvidence::AttestationFailed(r) => Some(r.to_string()),
            _ => None,
        },
        None => None,
    };

    let write_fut = async {
        if let Some(ev) = &outgoing {
            write_evidence(wr, ev).await?;
        }
        Ok::<_, anyhow::Error>(())
    };
    let read_fut = async {
        match vf_action {
            VerifyAction::RequireEvidence => Ok(Some(read_evidence(rd).await?)),
            VerifyAction::Skip | VerifyAction::ClosePeerWillNotAttest => Ok(None),
        }
    };
    let (_, incoming) = tokio::try_join!(write_fut, read_fut)?;

    if let Some(reason) = failed_reason {
        bail!("attestation failed after retries: {reason}");
    }

    match vf_action {
        VerifyAction::Skip | VerifyAction::ClosePeerWillNotAttest => Ok(None),
        VerifyAction::RequireEvidence => {
            let incoming = incoming.context("missing peer evidence")?;
            match inspect_evidence(&incoming)? {
                InspectedEvidence::Refusal(r) => {
                    bail!("peer sent an explicit refusal: {r}")
                }
                InspectedEvidence::AttestationFailed(r) => {
                    bail!("peer attestation failed: {r}")
                }
                InspectedEvidence::Raw(raw) => {
                    let verifier = resources
                        .verifier
                        .context("verifying side has no verifier")?;
                    let peer_spki = resources
                        .peer_spki_der
                        .context("verifying side has no peer certificate")?;
                    let expected = state.expected_claims(peer_spki, &resources.exporter)?;
                    let result = verifier
                        .verify(raw.cbor_tag, raw.raw.clone(), expected)
                        .await
                        .context("evidence conversion or verification failed")?;
                    Ok(Some(result))
                }
            }
        }
    }
}

async fn produce_outgoing(
    resources: &ExchangeResources<'_>,
    peer: &Declaration,
) -> Result<Evidence> {
    let producer = resources
        .producer
        .context("attesting side has no attester")?;
    let own_spki = resources
        .own_spki_der
        .context("attesting side has no snapshotted certificate")?;
    match peer_challenge_token(peer) {
        Some(token) => {
            produce_background_check_evidence(
                producer,
                own_spki,
                token,
                &resources.exporter,
                resources.max_retries,
            )
            .await
        }
        None => {
            let cache = resources
                .passport_cache
                .context("passport evidence requested but this end has no passport cache")?;
            let converter = resources
                .attest_converter
                .context("passport evidence requested but this end has no passport converter")?;
            produce_passport_evidence(producer, converter, own_spki, cache, resources.max_retries)
                .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use rats_cert::tee::claims::Claims;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::super::claims::expected_subset_of;
    use super::super::core::{build_declaration, raw_evidence, refusal_evidence};
    use crate::tunnel::provider::{ProviderType, TngToken};

    fn dummy_result() -> AttestationResult {
        AttestationResult::from_token(
            TngToken::from_wire(ProviderType::Coco, "fake.jwt.token".into()).unwrap(),
        )
    }

    fn nora_resources<'a>() -> ExchangeResources<'a> {
        ExchangeResources {
            local: LocalRole::no_ra(),
            verify_mode: VerifyMode::None,
            verifier_converter: None,
            attest_converter: None,
            producer: None,
            verifier: None,
            passport_cache: None,
            own_spki_der: None,
            peer_spki_der: None,
            exporter: [7u8; EXPORTER_LEN],
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

    struct FailingConverter;

    #[async_trait::async_trait]
    impl ChallengeSource for FailingConverter {
        async fn get_nonce(&self) -> Result<String> {
            bail!("as down");
        }
    }

    struct ClaimsEchoProducer;

    #[async_trait::async_trait]
    impl EvidenceProducer for ClaimsEchoProducer {
        async fn produce(&self, claims: Claims) -> Result<(u64, Vec<u8>)> {
            Ok((1, serde_json::to_vec(&claims)?))
        }
    }

    struct FailingProducer {
        count: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl EvidenceProducer for FailingProducer {
        async fn produce(&self, _claims: Claims) -> Result<(u64, Vec<u8>)> {
            self.count.fetch_add(1, Ordering::SeqCst);
            bail!("attester down");
        }
    }

    struct SubsetVerifier;

    #[async_trait::async_trait]
    impl RawEvidenceVerifier for SubsetVerifier {
        async fn verify(
            &self,
            _cbor_tag: u64,
            raw: Vec<u8>,
            expected: Claims,
        ) -> Result<AttestationResult> {
            let actual: Claims = serde_json::from_slice(&raw)
                .context("stub verifier expected claims JSON in raw evidence")?;
            if !expected_subset_of(&expected, &actual) {
                bail!("expected claims not subset of evidence");
            }
            Ok(dummy_result())
        }
    }

    struct FailingVerifier;

    #[async_trait::async_trait]
    impl RawEvidenceVerifier for FailingVerifier {
        async fn verify(
            &self,
            _cbor_tag: u64,
            _raw: Vec<u8>,
            _expected: Claims,
        ) -> Result<AttestationResult> {
            bail!("trustee unreachable");
        }
    }

    fn verify_only<'a>(
        converter: &'a dyn ChallengeSource,
        verifier: &'a dyn RawEvidenceVerifier,
        peer_spki: &'a [u8],
        exporter: [u8; EXPORTER_LEN],
    ) -> ExchangeResources<'a> {
        ExchangeResources {
            local: LocalRole {
                will_attest: false,
                wants_evidence: true,
            },
            verify_mode: VerifyMode::BackgroundCheck,
            verifier_converter: Some(converter),
            attest_converter: None,
            producer: None,
            verifier: Some(verifier),
            passport_cache: None,
            own_spki_der: None,
            peer_spki_der: Some(peer_spki),
            exporter,
            max_retries: 0,
        }
    }

    fn attest_only<'a>(
        producer: &'a dyn EvidenceProducer,
        own_spki: &'a [u8],
        exporter: [u8; EXPORTER_LEN],
    ) -> ExchangeResources<'a> {
        ExchangeResources {
            local: LocalRole {
                will_attest: true,
                wants_evidence: false,
            },
            verify_mode: VerifyMode::None,
            verifier_converter: None,
            attest_converter: None,
            producer: Some(producer),
            verifier: None,
            passport_cache: None,
            own_spki_der: Some(own_spki),
            peer_spki_der: None,
            exporter,
            max_retries: 0,
        }
    }

    fn mutual<'a>(
        converter: &'a dyn ChallengeSource,
        producer: &'a dyn EvidenceProducer,
        verifier: &'a dyn RawEvidenceVerifier,
        own_spki: &'a [u8],
        peer_spki: &'a [u8],
        exporter: [u8; EXPORTER_LEN],
    ) -> ExchangeResources<'a> {
        ExchangeResources {
            local: LocalRole {
                will_attest: true,
                wants_evidence: true,
            },
            verify_mode: VerifyMode::BackgroundCheck,
            verifier_converter: Some(converter),
            attest_converter: None,
            producer: Some(producer),
            verifier: Some(verifier),
            passport_cache: None,
            own_spki_der: Some(own_spki),
            peer_spki_der: Some(peer_spki),
            exporter,
            max_retries: 0,
        }
    }

    const SPKI_A: &[u8] = b"spki-a";
    const SPKI_B: &[u8] = b"spki-b";
    const EXP: [u8; EXPORTER_LEN] = [7u8; EXPORTER_LEN];

    #[tokio::test]
    async fn mutual_background_check_yields_result_on_both_ends() {
        let conv_a = RecordingConverter {
            nonce: "nonce-a".into(),
        };
        let conv_b = RecordingConverter {
            nonce: "nonce-b".into(),
        };
        let producer = ClaimsEchoProducer;
        let verifier = SubsetVerifier;
        let (a, b) = tokio::io::duplex(65536);
        let (ra, rb) = tokio::join!(
            run_on_stream(
                a,
                mutual(&conv_a, &producer, &verifier, SPKI_A, SPKI_B, EXP)
            ),
            run_on_stream(
                b,
                mutual(&conv_b, &producer, &verifier, SPKI_B, SPKI_A, EXP)
            ),
        );
        let (_, res_a) = ra.unwrap();
        let (_, res_b) = rb.unwrap();
        assert!(res_a.is_some());
        assert!(res_b.is_some());
    }

    #[tokio::test]
    async fn server_attests_client_verifies() {
        let conv = RecordingConverter {
            nonce: "nonce-c".into(),
        };
        let producer = ClaimsEchoProducer;
        let verifier = SubsetVerifier;
        let (client, server) = tokio::io::duplex(65536);
        let (rc, rs) = tokio::join!(
            run_on_stream(client, verify_only(&conv, &verifier, SPKI_A, EXP)),
            run_on_stream(server, attest_only(&producer, SPKI_A, EXP)),
        );
        assert!(rc.unwrap().1.is_some());
        assert!(rs.unwrap().1.is_none());
    }

    #[tokio::test]
    async fn client_attests_server_verifies() {
        let conv = RecordingConverter {
            nonce: "nonce-s".into(),
        };
        let producer = ClaimsEchoProducer;
        let verifier = SubsetVerifier;
        let (client, server) = tokio::io::duplex(65536);
        let (rc, rs) = tokio::join!(
            run_on_stream(client, attest_only(&producer, SPKI_B, EXP)),
            run_on_stream(server, verify_only(&conv, &verifier, SPKI_B, EXP)),
        );
        assert!(rc.unwrap().1.is_none());
        assert!(rs.unwrap().1.is_some());
    }

    #[tokio::test]
    async fn nora_exchanges_declarations_then_application_data() {
        let (a, b) = tokio::io::duplex(1024);
        let (ra, rb) = tokio::join!(
            run_on_stream(a, nora_resources()),
            run_on_stream(b, nora_resources()),
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
    async fn nora_paired_with_attester_completes() {
        let producer = ClaimsEchoProducer;
        let (a, b) = tokio::io::duplex(65536);
        let (ra, rb) = tokio::join!(
            run_on_stream(a, nora_resources()),
            run_on_stream(b, attest_only(&producer, SPKI_A, EXP)),
        );
        let (mut a, res_a) = ra.unwrap();
        let (mut b, res_b) = rb.unwrap();
        assert!(res_a.is_none());
        assert!(res_b.is_none());
        a.write_all(b"app").await.unwrap();
        a.flush().await.unwrap();
        let mut buf = [0u8; 3];
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"app");
    }

    #[tokio::test]
    async fn application_bytes_before_evidence_are_not_forwarded() {
        let conv = RecordingConverter { nonce: "n".into() };
        let verifier = SubsetVerifier;
        let (mut peer, local) = tokio::io::duplex(1024);
        let local_fut = run_on_stream(local, verify_only(&conv, &verifier, SPKI_A, EXP));
        let peer_fut = async {
            let decl = build_declaration(
                LocalRole {
                    will_attest: true,
                    wants_evidence: false,
                },
                None,
            );
            write_declaration(&mut peer, &decl).await.unwrap();
            let _ = read_declaration(&mut peer).await.unwrap();
            peer.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
                .await
                .unwrap();
            peer.flush().await.unwrap();
            // Keep the stream open until the local side errors.
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        let (local_res, _) = tokio::join!(local_fut, peer_fut);
        assert!(local_res.is_err());
    }

    #[tokio::test]
    async fn peer_that_sends_nothing_times_out() {
        let conv = RecordingConverter { nonce: "n".into() };
        let verifier = SubsetVerifier;
        let (peer, local) = tokio::io::duplex(1024);
        let err = run_on_stream_with_timeout(
            local,
            verify_only(&conv, &verifier, SPKI_A, EXP),
            Duration::from_millis(50),
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("timed out"),
            "unexpected error: {err:#}"
        );
        drop(peer);
    }

    #[tokio::test]
    async fn verifier_closes_when_peer_will_not_attest() {
        let conv = RecordingConverter { nonce: "n".into() };
        let verifier = SubsetVerifier;
        let (a, b) = tokio::io::duplex(1024);
        let (ra, rb) = tokio::join!(
            run_on_stream(a, verify_only(&conv, &verifier, SPKI_A, EXP)),
            run_on_stream(b, nora_resources()),
        );
        let err = ra.unwrap_err();
        assert!(
            err.to_string().contains("peer declared it will not attest"),
            "unexpected error: {err:#}"
        );
        let _ = rb;
    }

    #[tokio::test]
    async fn truncated_declaration_is_distinct_from_timeout() {
        let conv = RecordingConverter { nonce: "n".into() };
        let verifier = SubsetVerifier;
        let (mut peer, local) = tokio::io::duplex(1024);
        let local_fut = run_on_stream(local, verify_only(&conv, &verifier, SPKI_A, EXP));
        let peer_fut = async {
            peer.write_all(&8u32.to_be_bytes()).await.unwrap();
            peer.write_all(&[1, 2, 3]).await.unwrap();
            peer.flush().await.unwrap();
            drop(peer);
        };
        let (local_res, _) = tokio::join!(local_fut, peer_fut);
        let err = local_res.unwrap_err();
        assert!(
            err.to_string().contains("truncated"),
            "unexpected error: {err:#}"
        );
        assert!(!err.to_string().contains("timed out"));
    }

    #[tokio::test]
    async fn background_check_evidence_omitting_binder_fails() {
        let conv = RecordingConverter { nonce: "n".into() };
        let verifier = SubsetVerifier;
        let (mut peer, local) = tokio::io::duplex(65536);
        let local_fut = run_on_stream(local, verify_only(&conv, &verifier, SPKI_A, EXP));
        let peer_fut = async {
            let decl = build_declaration(
                LocalRole {
                    will_attest: true,
                    wants_evidence: false,
                },
                None,
            );
            write_declaration(&mut peer, &decl).await.unwrap();
            let _ = read_declaration(&mut peer).await.unwrap();
            let empty = Claims::new();
            write_evidence(
                &mut peer,
                &raw_evidence(1, serde_json::to_vec(&empty).unwrap()),
            )
            .await
            .unwrap();
        };
        let (local_res, _) = tokio::join!(local_fut, peer_fut);
        let err = local_res.unwrap_err();
        assert!(
            err.to_string().contains("expected claims not subset")
                || err.to_string().contains("verification failed"),
            "unexpected error: {err:#}"
        );
    }

    #[tokio::test]
    async fn declared_attest_then_refusal_closes() {
        let conv = RecordingConverter { nonce: "n".into() };
        let verifier = SubsetVerifier;
        let (mut peer, local) = tokio::io::duplex(1024);
        let local_fut = run_on_stream(local, verify_only(&conv, &verifier, SPKI_A, EXP));
        let peer_fut = async {
            let decl = build_declaration(
                LocalRole {
                    will_attest: true,
                    wants_evidence: false,
                },
                None,
            );
            write_declaration(&mut peer, &decl).await.unwrap();
            let _ = read_declaration(&mut peer).await.unwrap();
            write_evidence(&mut peer, &refusal_evidence("changed my mind"))
                .await
                .unwrap();
        };
        let (local_res, _) = tokio::join!(local_fut, peer_fut);
        let err = local_res.unwrap_err();
        assert!(
            err.to_string().contains("explicit refusal"),
            "unexpected error: {err:#}"
        );
    }

    #[tokio::test]
    async fn attester_exhaustion_returns_attestation_failed_and_closes() {
        let conv = RecordingConverter { nonce: "n".into() };
        let producer = FailingProducer {
            count: AtomicUsize::new(0),
        };
        let verifier = SubsetVerifier;
        let (client, server) = tokio::io::duplex(65536);
        let (rc, rs) = tokio::join!(
            run_on_stream(client, verify_only(&conv, &verifier, SPKI_A, EXP)),
            run_on_stream(server, attest_only(&producer, SPKI_A, EXP)),
        );
        let server_err = rs.unwrap_err();
        assert!(
            server_err
                .to_string()
                .contains("attestation failed after retries"),
            "unexpected server error: {server_err:#}"
        );
        let client_err = rc.unwrap_err();
        assert!(
            client_err.to_string().contains("peer attestation failed"),
            "unexpected client error: {client_err:#}"
        );
    }

    #[tokio::test]
    async fn converter_nonce_error_writes_no_declaration() {
        let conv = FailingConverter;
        let verifier = SubsetVerifier;
        let (mut peer, local) = tokio::io::duplex(1024);
        let err = run_on_stream(local, verify_only(&conv, &verifier, SPKI_A, EXP))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("nonce"),
            "unexpected error: {err:#}"
        );
        let mut buf = [0u8; 4];
        let read = tokio::time::timeout(Duration::from_millis(30), peer.read(&mut buf)).await;
        match read {
            Err(_) => {}
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => panic!("declaration was written ({n} bytes)"),
            Ok(Err(e)) => panic!("unexpected io error: {e}"),
        }
    }

    #[tokio::test]
    async fn trustee_unreachable_during_conversion_closes() {
        let conv = RecordingConverter { nonce: "n".into() };
        let producer = ClaimsEchoProducer;
        let verifier = FailingVerifier;
        let (client, server) = tokio::io::duplex(65536);
        let (rc, rs) = tokio::join!(
            run_on_stream(client, verify_only(&conv, &verifier, SPKI_A, EXP)),
            run_on_stream(server, attest_only(&producer, SPKI_A, EXP)),
        );
        let err = rc.unwrap_err();
        assert!(
            err.to_string().contains("trustee unreachable")
                || err.to_string().contains("verification failed"),
            "unexpected error: {err:#}"
        );
        let _ = rs;
    }
}
