use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use again::RetryPolicy;
use anyhow::{anyhow, bail, Context, Result};
use rats_cert::tee::claims::Claims;
use rats_cert::tee::{GenericAttester, GenericConverter, ReportData};

use crate::tunnel::attestation_result::AttestationResult;
use crate::tunnel::provider::{ProviderType, TngEvidence, TngToken};
use crate::tunnel::utils::maybe_cached::Expire;

use super::claims::{
    background_check_claims, passport_attester_claims, BackgroundCheckExpectation,
    PassportExpectation,
};
use super::pb::{request, response, BackgroundCheck, Evidence, Passport, Request, Response, Token};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyMode {
    BackgroundCheck,
    Passport,
    None,
}

/// Per-connection state: the nonce issued for this connection, if any, is retained until convert.
pub struct ExchangeState {
    verify_mode: VerifyMode,
    issued_nonce: Option<String>,
}

impl ExchangeState {
    pub fn new(verify_mode: VerifyMode) -> Self {
        Self {
            verify_mode,
            issued_nonce: None,
        }
    }

    pub async fn prepare_request<C>(&mut self, converter: Option<&C>) -> Result<Request>
    where
        C: ChallengeSource + ?Sized,
    {
        match self.verify_mode {
            VerifyMode::BackgroundCheck => {
                let converter = converter.context("background-check verifier has no converter")?;
                let nonce = converter.get_nonce().await?;
                if nonce.is_empty() {
                    bail!("background-check converter returned empty nonce");
                }
                let req = Request {
                    body: Some(request::Body::BackgroundCheck(BackgroundCheck {
                        nonce: nonce.as_bytes().to_vec(),
                    })),
                };
                self.issued_nonce = Some(nonce);
                Ok(req)
            }
            VerifyMode::Passport => Ok(Request {
                body: Some(request::Body::Passport(Passport {})),
            }),
            VerifyMode::None => Ok(none_request()),
        }
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
    async fn produce(&self, claims: Claims) -> Result<Evidence>;
}

#[async_trait::async_trait]
pub trait TokenProducer: Send + Sync {
    async fn produce(&self, claims: Claims) -> Result<TngToken>;
}

#[async_trait::async_trait]
pub trait ExchangeVerifier: Send + Sync {
    async fn verify_evidence(
        &self,
        provider: &str,
        json: &str,
        expected: Claims,
    ) -> Result<AttestationResult>;

    async fn verify_token(
        &self,
        provider: &str,
        jwt: &str,
        expected: Claims,
    ) -> Result<AttestationResult>;
}

pub fn none_request() -> Request {
    Request {
        body: Some(request::Body::None(super::pb::None {})),
    }
}

pub fn ack_response() -> Response {
    Response {
        body: Some(response::Body::Ack(super::pb::None {})),
    }
}

pub fn error_response(reason: impl Into<String>) -> Response {
    Response {
        body: Some(response::Body::Error(super::pb::Error {
            reason: reason.into(),
        })),
    }
}

pub fn evidence_response(provider: impl Into<String>, json: impl Into<String>) -> Response {
    Response {
        body: Some(response::Body::Evidence(Evidence {
            provider: provider.into(),
            json: json.into(),
        })),
    }
}

pub fn token_response(provider: impl Into<String>, jwt: impl Into<String>) -> Response {
    Response {
        body: Some(response::Body::Token(Token {
            provider: provider.into(),
            jwt: jwt.into(),
        })),
    }
}

pub async fn produce_background_check_evidence<P: EvidenceProducer + ?Sized>(
    producer: &P,
    own_spki_der: &[u8],
    nonce: &[u8],
    exporter: &[u8],
    max_retries: usize,
) -> Result<Response> {
    if nonce.is_empty() {
        return Ok(error_response("missing nonce"));
    }
    let token = match std::str::from_utf8(nonce) {
        Ok(t) => t,
        Err(_) => return Ok(error_response("challenge_token is not valid UTF-8")),
    };
    let claims = background_check_claims(own_spki_der, token, exporter)?;
    match produce_evidence_with_retry(producer, claims, max_retries).await {
        Ok(evidence) => Ok(evidence_response(evidence.provider, evidence.json)),
        Err(e) => Ok(error_response(format!("{e:#}"))),
    }
}

pub async fn produce_passport_token<P: TokenProducer + ?Sized, C: ChallengeSource + ?Sized>(
    producer: &P,
    converter: &C,
    own_spki_der: &[u8],
    cache: &PassportEvidenceCache,
    max_retries: usize,
) -> Result<Response> {
    match cache
        .get_or_mint(own_spki_der, || async {
            let nonce = converter.get_nonce().await?;
            let claims = passport_attester_claims(own_spki_der, &nonce)?;
            produce_token_with_retry(producer, claims, max_retries).await
        })
        .await
    {
        Ok(token) => Ok(token_response(
            token.provider_type().as_str(),
            token.as_str(),
        )),
        Err(e) => Ok(error_response(format!("{e:#}"))),
    }
}

async fn produce_evidence_with_retry<P: EvidenceProducer + ?Sized>(
    producer: &P,
    claims: Claims,
    max_retries: usize,
) -> Result<Evidence> {
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

async fn produce_token_with_retry<P: TokenProducer + ?Sized>(
    producer: &P,
    claims: Claims,
    max_retries: usize,
) -> Result<TngToken> {
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

struct CachedPassport {
    spki: Vec<u8>,
    provider: ProviderType,
    jwt: String,
    expire: Expire,
}

impl PassportEvidenceCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn get_or_mint<F, Fut>(&self, spki: &[u8], mint: F) -> Result<TngToken>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<TngToken>>,
    {
        {
            let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(cached) = guard.as_ref() {
                if cached.spki == spki && is_unexpired(cached.expire) {
                    return TngToken::from_wire(cached.provider, cached.jwt.clone());
                }
            }
        }
        let token = mint().await?;
        *self.inner.lock().unwrap_or_else(|e| e.into_inner()) = Some(CachedPassport {
            spki: spki.to_vec(),
            provider: token.provider_type(),
            jwt: token.as_str().to_string(),
            expire: token_expire(&token),
        });
        Ok(token)
    }

    #[cfg(test)]
    fn insert_for_test(&self, spki: &[u8], provider: ProviderType, jwt: String, expire: Expire) {
        *self.inner.lock().unwrap_or_else(|e| e.into_inner()) = Some(CachedPassport {
            spki: spki.to_vec(),
            provider,
            jwt,
            expire,
        });
    }
}

fn is_unexpired(expire: Expire) -> bool {
    match expire {
        Expire::NoExpire => true,
        Expire::ExpireAt(t) => t > SystemTime::now(),
    }
}

fn token_expire(token: &TngToken) -> Expire {
    token
        .exp()
        .ok()
        .and_then(|exp| Expire::from_timestamp(exp).ok())
        .unwrap_or(Expire::NoExpire)
}

pub fn produced_error_reason(response: &Response) -> Option<&str> {
    match response.body.as_ref() {
        Some(response::Body::Error(e)) => Some(e.reason.as_str()),
        _ => None,
    }
}

#[async_trait::async_trait]
impl<C> ChallengeSource for C
where
    C: GenericConverter<Nonce = String> + Send + Sync,
{
    async fn get_nonce(&self) -> Result<String> {
        GenericConverter::get_nonce(self)
            .await
            .map_err(|e| anyhow!("converter errors while fetching the nonce: {e}"))
    }
}

#[async_trait::async_trait]
impl<A> EvidenceProducer for A
where
    A: GenericAttester<Evidence = TngEvidence> + Send + Sync,
{
    async fn produce(&self, claims: Claims) -> Result<Evidence> {
        let evidence = self
            .get_evidence(&ReportData::Claims(claims))
            .await
            .map_err(|e| anyhow!("attester failed: {e}"))?;
        let json = serde_json::to_string(&evidence.serialize_to_json()?)
            .context("serialize evidence JSON")?;
        Ok(Evidence {
            provider: evidence.provider_type().as_str().to_string(),
            json,
        })
    }
}

#[async_trait::async_trait]
impl<A> TokenProducer for A
where
    A: GenericAttester<Evidence = TngToken> + Send + Sync,
{
    async fn produce(&self, claims: Claims) -> Result<TngToken> {
        self.get_evidence(&ReportData::Claims(claims))
            .await
            .map_err(|e| anyhow!("attester failed: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::super::claims::{expected_subset_of, CLAIM_CHALLENGE_TOKEN, CLAIM_TLS_BINDER};
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

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
        let mut state = ExchangeState::new(VerifyMode::BackgroundCheck);
        let req = state.prepare_request(Some(&conv)).await.unwrap();
        match req.body {
            Some(request::Body::BackgroundCheck(bc)) => {
                assert_eq!(bc.nonce, b"as-nonce-1");
            }
            other => panic!("expected background_check, got {other:?}"),
        }
        assert_eq!(state.issued_nonce(), Some("as-nonce-1"));
        let expected = state
            .expected_claims(b"spki", b"0123456789abcdef0123456789abcdef")
            .unwrap();
        let actual =
            background_check_claims(b"spki", "as-nonce-1", b"0123456789abcdef0123456789abcdef")
                .unwrap();
        assert!(expected_subset_of(&expected, &actual));
    }

    struct CountingEvidenceProducer {
        count: AtomicUsize,
        fail_times: usize,
        claims: Mutex<Option<Claims>>,
    }

    #[async_trait::async_trait]
    impl EvidenceProducer for CountingEvidenceProducer {
        async fn produce(&self, claims: Claims) -> Result<Evidence> {
            let n = self.count.fetch_add(1, Ordering::SeqCst);
            if n < self.fail_times {
                bail!("attester down");
            }
            *self.claims.lock().unwrap() = Some(claims.clone());
            Ok(Evidence {
                provider: "coco".into(),
                json: serde_json::to_string(&claims)?,
            })
        }
    }

    struct CountingTokenProducer {
        count: AtomicUsize,
        fail_times: usize,
        claims: Mutex<Option<Claims>>,
    }

    fn test_jwt() -> String {
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
            .to_string()
    }

    #[async_trait::async_trait]
    impl TokenProducer for CountingTokenProducer {
        async fn produce(&self, claims: Claims) -> Result<TngToken> {
            let n = self.count.fetch_add(1, Ordering::SeqCst);
            if n < self.fail_times {
                bail!("attester down");
            }
            *self.claims.lock().unwrap() = Some(claims);
            TngToken::from_wire(ProviderType::Coco, test_jwt())
        }
    }

    fn counting_evidence(fail_times: usize) -> CountingEvidenceProducer {
        CountingEvidenceProducer {
            count: AtomicUsize::new(0),
            fail_times,
            claims: Mutex::new(None),
        }
    }

    fn counting_token(fail_times: usize) -> CountingTokenProducer {
        CountingTokenProducer {
            count: AtomicUsize::new(0),
            fail_times,
            claims: Mutex::new(None),
        }
    }

    #[tokio::test]
    async fn passport_cache_reuses_token_until_spki_or_expiry_change() {
        let producer = counting_token(0);
        let conv = RecordingConverter {
            nonce: "passport-as-nonce".into(),
        };
        let cache = PassportEvidenceCache::new();
        let first = produce_passport_token(&producer, &conv, b"spki", &cache, 0)
            .await
            .unwrap();
        let second = produce_passport_token(&producer, &conv, b"spki", &cache, 0)
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

        produce_passport_token(&producer, &conv, b"other-spki", &cache, 0)
            .await
            .unwrap();
        assert_eq!(producer.count.load(Ordering::SeqCst), 2);

        cache.insert_for_test(
            b"spki",
            ProviderType::Coco,
            test_jwt(),
            Expire::ExpireAt(SystemTime::UNIX_EPOCH),
        );
        produce_passport_token(&producer, &conv, b"spki", &cache, 0)
            .await
            .unwrap();
        assert_eq!(producer.count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn attester_exhaustion_returns_error_not_credentials() {
        let producer = counting_evidence(usize::MAX);
        let evidence = produce_background_check_evidence(
            &producer,
            b"spki",
            b"nonce",
            b"0123456789abcdef0123456789abcdef",
            0,
        )
        .await
        .unwrap();
        assert!(produced_error_reason(&evidence).is_some());

        let conv = RecordingConverter {
            nonce: "passport-as-nonce".into(),
        };
        let token_producer = counting_token(usize::MAX);
        let passport = produce_passport_token(
            &token_producer,
            &conv,
            b"spki",
            &PassportEvidenceCache::new(),
            0,
        )
        .await
        .unwrap();
        assert!(produced_error_reason(&passport).is_some());
    }

    #[tokio::test]
    async fn prepare_request_on_passport_sends_no_nonce() {
        let mut state = ExchangeState::new(VerifyMode::Passport);
        let req = state
            .prepare_request(None::<&RecordingConverter>)
            .await
            .unwrap();
        match req.body {
            Some(request::Body::Passport(_)) => {}
            other => panic!("expected passport, got {other:?}"),
        }
        assert!(state.issued_nonce().is_none());
    }
}
