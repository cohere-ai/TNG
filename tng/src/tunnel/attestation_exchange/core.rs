use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use again::RetryPolicy;
use anyhow::{anyhow, bail, Context, Result};
use rats_cert::tee::claims::Claims;
use rats_cert::tee::{DiceParseEvidenceOutput, GenericAttester, GenericEvidence};

use crate::tunnel::attestation_result::AttestationResult;
use crate::tunnel::provider::TngToken;
use crate::tunnel::utils::maybe_cached::Expire;

use super::claims::{
    background_check_claims, passport_attester_claims, BackgroundCheckExpectation,
    PassportExpectation,
};
use super::pb::{
    evidence::Payload, AttestationFailed, Declaration, Evidence, RawEvidence, Refusal,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalRole {
    pub will_attest: bool,
    pub wants_evidence: bool,
}

impl LocalRole {
    #[cfg(test)]
    pub fn no_ra() -> Self {
        Self {
            will_attest: false,
            wants_evidence: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyMode {
    BackgroundCheck,
    Passport,
    None,
}

#[derive(Debug, PartialEq, Eq)]
pub enum EvidenceAction {
    Produce,
    Refuse,
    Skip,
}

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyAction {
    RequireEvidence,
    ClosePeerWillNotAttest,
    Skip,
}

pub fn evidence_action(local: LocalRole, peer: &Declaration) -> EvidenceAction {
    if !peer.wants_evidence {
        EvidenceAction::Skip
    } else if local.will_attest {
        EvidenceAction::Produce
    } else {
        EvidenceAction::Refuse
    }
}

pub fn verify_action(local: LocalRole, peer: &Declaration) -> VerifyAction {
    if !local.wants_evidence {
        VerifyAction::Skip
    } else if peer.will_attest {
        VerifyAction::RequireEvidence
    } else {
        VerifyAction::ClosePeerWillNotAttest
    }
}

pub fn build_declaration(local: LocalRole, challenge_token: Option<&[u8]>) -> Declaration {
    Declaration {
        will_attest: local.will_attest,
        wants_evidence: local.wants_evidence,
        challenge_token: challenge_token.unwrap_or(&[]).to_vec(),
        certificate_request_context: vec![],
    }
}

/// Per-connection state: the nonce issued for this connection, if any, is retained until convert.
pub struct ExchangeState {
    local: LocalRole,
    verify_mode: VerifyMode,
    issued_nonce: Option<String>,
}

impl ExchangeState {
    pub fn new(local: LocalRole, verify_mode: VerifyMode) -> Self {
        Self {
            local,
            verify_mode,
            issued_nonce: None,
        }
    }

    pub async fn prepare_declaration<C>(&mut self, converter: Option<&C>) -> Result<Declaration>
    where
        C: ChallengeSource + ?Sized,
    {
        if self.verify_mode == VerifyMode::BackgroundCheck {
            let converter = converter.context("background-check verifier has no converter")?;
            self.issued_nonce = Some(converter.get_nonce().await?);
        }
        Ok(build_declaration(
            self.local,
            self.issued_nonce.as_deref().map(str::as_bytes),
        ))
    }

    #[cfg(test)]
    pub fn issued_nonce(&self) -> Option<&str> {
        self.issued_nonce.as_deref()
    }

    pub fn expected_claims(
        &self,
        peer_spki_der: &[u8],
        exporter: &[u8],
    ) -> Result<rats_cert::tee::claims::Claims> {
        match self.verify_mode {
            VerifyMode::BackgroundCheck => {
                let nonce = self
                    .issued_nonce
                    .as_deref()
                    .context("background-check verifier has no issued nonce")?;
                BackgroundCheckExpectation {
                    peer_spki_der,
                    issued_nonce: nonce,
                    exporter,
                }
                .to_claims()
            }
            VerifyMode::Passport => PassportExpectation { peer_spki_der }.to_claims(),
            VerifyMode::None => bail!("not verifying; no expected claims"),
        }
    }
}

#[async_trait::async_trait]
pub trait ChallengeSource: Send + Sync {
    async fn get_nonce(&self) -> Result<String>;
}

#[async_trait::async_trait]
pub trait EvidenceProducer: Send + Sync {
    async fn produce(&self, claims: Claims) -> Result<(u64, Vec<u8>)>;
}

#[async_trait::async_trait]
pub trait RawEvidenceVerifier: Send + Sync {
    async fn verify(
        &self,
        cbor_tag: u64,
        raw: Vec<u8>,
        expected: Claims,
    ) -> Result<AttestationResult>;
}

pub fn peer_challenge_token(peer: &Declaration) -> Option<&[u8]> {
    if peer.challenge_token.is_empty() {
        None
    } else {
        Some(peer.challenge_token.as_slice())
    }
}

pub fn refusal_evidence(reason: impl Into<String>) -> Evidence {
    Evidence {
        payload: Some(Payload::Refusal(Refusal {
            reason: reason.into(),
        })),
    }
}

pub fn attestation_failed_evidence(reason: impl Into<String>) -> Evidence {
    Evidence {
        payload: Some(Payload::AttestationFailed(AttestationFailed {
            reason: reason.into(),
        })),
    }
}

pub fn raw_evidence(cbor_tag: u64, raw: Vec<u8>) -> Evidence {
    Evidence {
        payload: Some(Payload::Evidence(RawEvidence { cbor_tag, raw })),
    }
}

pub async fn produce_background_check_evidence<P: EvidenceProducer + ?Sized>(
    producer: &P,
    own_spki_der: &[u8],
    challenge_token: &[u8],
    exporter: &[u8],
    max_retries: usize,
) -> Result<Evidence> {
    let token =
        std::str::from_utf8(challenge_token).context("challenge_token is not valid UTF-8")?;
    let claims = background_check_claims(own_spki_der, token, exporter)?;
    match produce_with_retry(producer, claims, max_retries).await {
        Ok((cbor_tag, raw)) => Ok(raw_evidence(cbor_tag, raw)),
        Err(e) => Ok(attestation_failed_evidence(format!("{e:#}"))),
    }
}

pub async fn produce_passport_evidence<
    P: EvidenceProducer + ?Sized,
    C: ChallengeSource + ?Sized,
>(
    producer: &P,
    converter: &C,
    own_spki_der: &[u8],
    cache: &PassportEvidenceCache,
    max_retries: usize,
) -> Result<Evidence> {
    match cache
        .get_or_mint(own_spki_der, || async {
            let nonce = converter.get_nonce().await?;
            let claims = passport_attester_claims(own_spki_der, &nonce)?;
            produce_with_retry(producer, claims, max_retries).await
        })
        .await
    {
        Ok((cbor_tag, raw)) => Ok(raw_evidence(cbor_tag, raw)),
        Err(e) => Ok(attestation_failed_evidence(format!("{e:#}"))),
    }
}

async fn produce_with_retry<P: EvidenceProducer + ?Sized>(
    producer: &P,
    claims: Claims,
    max_retries: usize,
) -> Result<(u64, Vec<u8>)> {
    let policy = RetryPolicy::fixed(Duration::from_secs(1)).with_max_retries(max_retries);
    policy
        .retry(|| {
            let claims = claims.clone();
            async move {
                producer
                    .produce(claims)
                    .await
                    .context("Failed to generate attestation evidence")
            }
        })
        .await
}

/// Cache a passport token until its `exp` (or until the attested SPKI rotates).
#[derive(Default)]
pub struct PassportEvidenceCache {
    inner: Mutex<Option<CachedPassport>>,
}

#[derive(Clone)]
struct CachedPassport {
    spki: Vec<u8>,
    tag: u64,
    raw: Vec<u8>,
    expire: Expire,
}

impl PassportEvidenceCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn get_or_mint<F, Fut>(&self, spki: &[u8], mint: F) -> Result<(u64, Vec<u8>)>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<(u64, Vec<u8>)>>,
    {
        {
            let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(cached) = guard.as_ref() {
                if cached.spki == spki && expire_is_fresh(cached.expire) {
                    return Ok((cached.tag, cached.raw.clone()));
                }
            }
        }
        let (tag, raw) = mint().await?;
        *self.inner.lock().unwrap_or_else(|e| e.into_inner()) = Some(CachedPassport {
            spki: spki.to_vec(),
            tag,
            raw: raw.clone(),
            expire: expire_of_token(tag, &raw),
        });
        Ok((tag, raw))
    }

    #[cfg(test)]
    fn insert_for_test(&self, spki: &[u8], tag: u64, raw: Vec<u8>, expire: Expire) {
        *self.inner.lock().unwrap_or_else(|e| e.into_inner()) = Some(CachedPassport {
            spki: spki.to_vec(),
            tag,
            raw,
            expire,
        });
    }
}

fn expire_is_fresh(expire: Expire) -> bool {
    match expire {
        Expire::NoExpire => true,
        Expire::ExpireAt(t) => t > SystemTime::now(),
    }
}

fn expire_of_token(tag: u64, raw: &[u8]) -> Expire {
    match TngToken::create_evidence_from_dice(tag, raw) {
        DiceParseEvidenceOutput::Ok(token) => token
            .exp()
            .ok()
            .and_then(|exp| Expire::from_timestamp(exp).ok())
            .unwrap_or(Expire::NoExpire),
        _ => Expire::NoExpire,
    }
}

pub fn inspect_evidence(evidence: &Evidence) -> Result<InspectedEvidence<'_>> {
    match evidence.payload.as_ref() {
        Some(Payload::Evidence(raw)) => Ok(InspectedEvidence::Raw(raw)),
        Some(Payload::Refusal(r)) => Ok(InspectedEvidence::Refusal(&r.reason)),
        Some(Payload::AttestationFailed(r)) => Ok(InspectedEvidence::AttestationFailed(&r.reason)),
        None => Err(anyhow!("evidence message has empty payload")),
    }
}

#[derive(Debug)]
pub enum InspectedEvidence<'a> {
    Raw(&'a RawEvidence),
    Refusal(&'a str),
    AttestationFailed(&'a str),
}

#[async_trait::async_trait]
impl<A> EvidenceProducer for A
where
    A: GenericAttester + Send + Sync,
{
    async fn produce(&self, claims: Claims) -> Result<(u64, Vec<u8>)> {
        let evidence = self
            .get_evidence(&rats_cert::tee::ReportData::Claims(claims))
            .await
            .map_err(|e| anyhow!("attester failed: {e}"))?;
        let tag = rats_cert::tee::GenericEvidence::get_dice_cbor_tag(&evidence);
        let raw = rats_cert::tee::GenericEvidence::get_dice_raw_evidence(&evidence)
            .map_err(|e| anyhow!("serialize evidence: {e}"))?;
        Ok((tag, raw))
    }
}

#[cfg(test)]
mod tests {
    use super::super::claims::{expected_subset_of, CLAIM_CHALLENGE_TOKEN, CLAIM_TLS_BINDER};
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn decl(will_attest: bool, wants_evidence: bool) -> Declaration {
        Declaration {
            will_attest,
            wants_evidence,
            challenge_token: if wants_evidence {
                b"nonce".to_vec()
            } else {
                vec![]
            },
            certificate_request_context: vec![],
        }
    }

    #[test]
    fn verify_peer_will_not_attest_closes() {
        let local = LocalRole {
            will_attest: false,
            wants_evidence: true,
        };
        assert_eq!(
            verify_action(local, &decl(false, false)),
            VerifyAction::ClosePeerWillNotAttest
        );
    }

    #[test]
    fn non_attesting_side_refuses_challenge() {
        let local = LocalRole {
            will_attest: false,
            wants_evidence: false,
        };
        assert_eq!(
            evidence_action(local, &decl(true, true)),
            EvidenceAction::Refuse
        );
    }

    #[test]
    fn non_verifying_side_skips_challenge() {
        let local = LocalRole {
            will_attest: true,
            wants_evidence: false,
        };
        assert_eq!(verify_action(local, &decl(true, true)), VerifyAction::Skip);
        assert_eq!(
            evidence_action(local, &decl(false, false)),
            EvidenceAction::Skip
        );
    }

    #[test]
    fn refusal_is_distinct_from_attestation_failed() {
        let refusal_msg = refusal_evidence("not configured");
        let failed_msg = attestation_failed_evidence("attester exhausted retries");
        let refusal = inspect_evidence(&refusal_msg).unwrap();
        let failed = inspect_evidence(&failed_msg).unwrap();
        match (refusal, failed) {
            (InspectedEvidence::Refusal(a), InspectedEvidence::AttestationFailed(b)) => {
                assert_ne!(a, b);
            }
            other => panic!("expected distinct variants, got mismatch: {other:?}"),
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

    #[tokio::test]
    async fn issued_nonce_is_the_value_handed_to_convert() {
        let conv = RecordingConverter {
            nonce: "as-nonce-1".into(),
        };
        let mut state = ExchangeState::new(
            LocalRole {
                will_attest: false,
                wants_evidence: true,
            },
            VerifyMode::BackgroundCheck,
        );
        let decl = state.prepare_declaration(Some(&conv)).await.unwrap();
        assert_eq!(decl.challenge_token, b"as-nonce-1");
        assert_eq!(state.issued_nonce(), Some("as-nonce-1"));
    }

    #[tokio::test]
    async fn dummy_nonce_still_builds_matching_expectation() {
        let conv = RecordingConverter {
            nonce: "dummy nonce".into(),
        };
        let mut state = ExchangeState::new(
            LocalRole {
                will_attest: true,
                wants_evidence: true,
            },
            VerifyMode::BackgroundCheck,
        );
        let _ = state.prepare_declaration(Some(&conv)).await.unwrap();
        let expected = state
            .expected_claims(b"spki", b"0123456789abcdef0123456789abcdef")
            .unwrap();
        let actual =
            background_check_claims(b"spki", "dummy nonce", b"0123456789abcdef0123456789abcdef")
                .unwrap();
        assert!(expected_subset_of(&expected, &actual));
    }

    struct CountingProducer {
        count: AtomicUsize,
        fail_times: usize,
        claims: Mutex<Option<Claims>>,
    }

    #[async_trait::async_trait]
    impl EvidenceProducer for CountingProducer {
        async fn produce(&self, claims: Claims) -> Result<(u64, Vec<u8>)> {
            let n = self.count.fetch_add(1, Ordering::SeqCst);
            if n < self.fail_times {
                bail!("attester down");
            }
            *self.claims.lock().unwrap() = Some(claims);
            Ok((99, b"evidence".to_vec()))
        }
    }

    fn counting_producer(fail_times: usize) -> CountingProducer {
        CountingProducer {
            count: AtomicUsize::new(0),
            fail_times,
            claims: Mutex::new(None),
        }
    }

    #[tokio::test]
    async fn passport_cache_reuses_token_until_spki_or_expiry_change() {
        let producer = counting_producer(0);
        let conv = RecordingConverter {
            nonce: "passport-as-nonce".into(),
        };
        let cache = PassportEvidenceCache::new();
        let first = produce_passport_evidence(&producer, &conv, b"spki", &cache, 0)
            .await
            .unwrap();
        let second = produce_passport_evidence(&producer, &conv, b"spki", &cache, 0)
            .await
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(producer.count.load(Ordering::SeqCst), 1);
        let stored = producer.claims.lock().unwrap().clone().unwrap();
        assert!(!stored.contains_key(CLAIM_TLS_BINDER));
        assert_eq!(
            stored.get(CLAIM_CHALLENGE_TOKEN).unwrap().as_str(),
            Some("passport-as-nonce")
        );

        produce_passport_evidence(&producer, &conv, b"other-spki", &cache, 0)
            .await
            .unwrap();
        assert_eq!(producer.count.load(Ordering::SeqCst), 2);

        cache.insert_for_test(
            b"spki",
            99,
            b"stale".to_vec(),
            Expire::ExpireAt(SystemTime::UNIX_EPOCH),
        );
        produce_passport_evidence(&producer, &conv, b"spki", &cache, 0)
            .await
            .unwrap();
        assert_eq!(producer.count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn attester_exhaustion_returns_attestation_failed_not_refusal() {
        let producer = counting_producer(usize::MAX);
        let evidence = produce_background_check_evidence(
            &producer,
            b"spki",
            b"nonce",
            b"0123456789abcdef0123456789abcdef",
            0,
        )
        .await
        .unwrap();
        match inspect_evidence(&evidence).unwrap() {
            InspectedEvidence::AttestationFailed(_) => {}
            InspectedEvidence::Refusal(_) => panic!("AA outage must not look like a refusal"),
            InspectedEvidence::Raw(_) => panic!("expected attestation-failed"),
        }

        let conv = RecordingConverter {
            nonce: "passport-as-nonce".into(),
        };
        let passport =
            produce_passport_evidence(&producer, &conv, b"spki", &PassportEvidenceCache::new(), 0)
                .await
                .unwrap();
        match inspect_evidence(&passport).unwrap() {
            InspectedEvidence::AttestationFailed(_) => {}
            InspectedEvidence::Refusal(_) => {
                panic!("passport AA outage must not look like a refusal")
            }
            InspectedEvidence::Raw(_) => panic!("expected attestation-failed"),
        }
    }

    #[tokio::test]
    async fn prepare_declaration_on_passport_sends_no_token() {
        let mut state = ExchangeState::new(
            LocalRole {
                will_attest: false,
                wants_evidence: true,
            },
            VerifyMode::Passport,
        );
        let decl = state
            .prepare_declaration(None::<&RecordingConverter>)
            .await
            .unwrap();
        assert!(decl.wants_evidence);
        assert!(decl.challenge_token.is_empty());
        assert!(state.issued_nonce().is_none());
    }
}
