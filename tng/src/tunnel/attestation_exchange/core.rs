//! RA-TLS passport token cache.
//!
//! The exchange itself lives in [`super::session`] (who speaks when) and [`super::codec`]
//! (length-prefixed JSON on the TLS stream). This module only stores the token that
//! [`crate::tunnel::attest::produce_attest_response`] mints in passport mode.
//!
//! [`PassportEvidenceCache`] holds one token. [`BoundPassportCache`] pins that cache to the
//! attested certificate's SPKI for a single exchange and implements
//! [`crate::tunnel::attest::PassportTokenCache`]. A hit requires the same SPKI and an unexpired
//! `exp`. A miss runs the mint closure `produce_attest_response` supplies. OHTTP has its own
//! cache, bound to the HPKE key config, and does not use this type.

use std::sync::Mutex;
use std::time::SystemTime;

use std::future::Future;
use std::pin::Pin;

use anyhow::Result;

use crate::tunnel::attest::PassportTokenCache;
use crate::tunnel::provider::{ProviderType, TngToken};
use crate::tunnel::utils::maybe_cached::Expire;

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
        let expire = token_expire(&token)?;
        *self.inner.lock().unwrap_or_else(|e| e.into_inner()) = Some(CachedPassport {
            spki: spki.to_vec(),
            provider: token.provider_type(),
            jwt: token.as_str().to_string(),
            expire,
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

/// [`PassportEvidenceCache`] bound to the certificate public key for this exchange.
pub struct BoundPassportCache<'a> {
    pub cache: &'a PassportEvidenceCache,
    pub spki: &'a [u8],
}

impl PassportTokenCache for BoundPassportCache<'_> {
    fn get_or_mint<'a>(
        &'a self,
        mint: Box<
            dyn FnOnce() -> Pin<Box<dyn Future<Output = Result<TngToken>> + Send + 'a>> + Send + 'a,
        >,
    ) -> Pin<Box<dyn Future<Output = Result<TngToken>> + Send + 'a>> {
        Box::pin(self.cache.get_or_mint(self.spki, move || mint()))
    }
}

fn is_unexpired(expire: Expire) -> bool {
    match expire {
        Expire::NoExpire => true,
        Expire::ExpireAt(t) => t > SystemTime::now(),
    }
}

fn token_expire(token: &TngToken) -> Result<Expire> {
    Expire::from_timestamp(token.exp()?)
}

#[cfg(test)]
mod tests {
    use super::super::claims::{passport_attester_claims, CLAIM_CHALLENGE_TOKEN, CLAIM_TLS_BINDER};
    use super::*;
    use std::future::Future;
    use std::pin::Pin;

    use crate::tunnel::attest::{
        produce_attest_response, produced_error_reason, AttestClaims, Evidence, EvidenceProducer,
        TokenProducer, ATTESTATION_UNAVAILABLE,
    };
    use crate::tunnel::challenge::ChallengeSource;
    use crate::tunnel::proposal::AttestProposal;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use rats_cert::tee::claims::Claims;
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
                anyhow::bail!("attester down");
            }
            *self.claims.lock().unwrap() = Some(claims.clone());
            Ok(Evidence {
                provider: ProviderType::Coco,
                evidence: serde_json::to_value(&claims)?,
            })
        }
    }

    struct CountingTokenProducer {
        count: AtomicUsize,
        fail_times: usize,
        claims: Mutex<Option<Claims>>,
        jwt: String,
    }

    fn make_jwt(claims: &serde_json::Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256"}"#);
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
        let sig = URL_SAFE_NO_PAD.encode(b"fake-sig");
        format!("{header}.{payload}.{sig}")
    }

    fn test_jwt() -> String {
        let exp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        make_jwt(&serde_json::json!({"sub": "1234567890", "exp": exp}))
    }

    #[async_trait::async_trait]
    impl TokenProducer for CountingTokenProducer {
        async fn produce(&self, claims: Claims) -> Result<TngToken> {
            let n = self.count.fetch_add(1, Ordering::SeqCst);
            if n < self.fail_times {
                anyhow::bail!("attester down");
            }
            *self.claims.lock().unwrap() = Some(claims);
            TngToken::from_wire(ProviderType::Coco, self.jwt.clone())
        }
    }

    fn counting_evidence(fail_times: usize) -> CountingEvidenceProducer {
        CountingEvidenceProducer {
            count: AtomicUsize::new(0),
            fail_times,
            claims: Mutex::new(None),
        }
    }

    async fn cached_passport(
        producer: &CountingTokenProducer,
        conv: &RecordingConverter,
        spki: &[u8],
        cache: &PassportEvidenceCache,
    ) -> crate::tunnel::attest::AttestResponse {
        let proposal = AttestProposal::Passport {
            provider: ProviderType::Coco,
        };
        let bound = BoundPassportCache { cache, spki };
        let claims = PassportTestClaims { conv, spki };
        produce_attest_response(&proposal, &claims, None, Some(producer), Some(&bound), 0).await
    }

    struct PassportTestClaims<'a> {
        conv: &'a RecordingConverter,
        spki: &'a [u8],
    }

    impl AttestClaims for PassportTestClaims<'_> {
        fn claims<'a>(
            &'a self,
            _proposal: &'a AttestProposal,
        ) -> Pin<Box<dyn Future<Output = Result<Claims>> + Send + 'a>> {
            Box::pin(async move {
                let nonce = self.conv.get_nonce().await?;
                passport_attester_claims(self.spki, &nonce)
            })
        }
    }

    struct EmptyClaims;

    impl AttestClaims for EmptyClaims {
        fn claims<'a>(
            &'a self,
            _proposal: &'a AttestProposal,
        ) -> Pin<Box<dyn Future<Output = Result<Claims>> + Send + 'a>> {
            Box::pin(async { Ok(Claims::new()) })
        }
    }

    fn counting_token(fail_times: usize) -> CountingTokenProducer {
        CountingTokenProducer {
            count: AtomicUsize::new(0),
            fail_times,
            claims: Mutex::new(None),
            jwt: test_jwt(),
        }
    }

    #[tokio::test]
    async fn passport_cache_reuses_token_until_spki_or_expiry_change() {
        let producer = counting_token(0);
        let conv = RecordingConverter {
            nonce: "passport-as-nonce".into(),
        };
        let cache = PassportEvidenceCache::new();
        let first = cached_passport(&producer, &conv, b"spki", &cache).await;
        let second = cached_passport(&producer, &conv, b"spki", &cache).await;
        assert_eq!(first, second);
        assert_eq!(producer.count.load(Ordering::SeqCst), 1);
        let stored = producer.claims.lock().unwrap().clone().unwrap();
        assert!(!stored.contains_key(CLAIM_TLS_BINDER));
        assert_eq!(
            stored.get(CLAIM_CHALLENGE_TOKEN).unwrap().as_str(),
            Some("passport-as-nonce")
        );

        assert!(cached_passport(&producer, &conv, b"other-spki", &cache)
            .await
            .is_ok());
        assert_eq!(producer.count.load(Ordering::SeqCst), 2);

        cache.insert_for_test(
            b"spki",
            ProviderType::Coco,
            test_jwt(),
            Expire::ExpireAt(SystemTime::UNIX_EPOCH),
        );
        assert!(cached_passport(&producer, &conv, b"spki", &cache)
            .await
            .is_ok());
        assert_eq!(producer.count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn passport_cache_does_not_store_token_without_exp() {
        let producer = CountingTokenProducer {
            count: AtomicUsize::new(0),
            fail_times: 0,
            claims: Mutex::new(None),
            jwt: make_jwt(&serde_json::json!({"sub": "1234567890"})),
        };
        let conv = RecordingConverter {
            nonce: "passport-as-nonce".into(),
        };
        let cache = PassportEvidenceCache::new();
        let first = cached_passport(&producer, &conv, b"spki", &cache).await;
        let second = cached_passport(&producer, &conv, b"spki", &cache).await;
        assert_eq!(produced_error_reason(&first), Some(ATTESTATION_UNAVAILABLE));
        assert_eq!(
            produced_error_reason(&second),
            Some(ATTESTATION_UNAVAILABLE)
        );
        assert_eq!(producer.count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn attester_exhaustion_returns_error_not_credentials() {
        let producer = counting_evidence(usize::MAX);
        let proposal = AttestProposal::BackgroundCheck {
            provider: ProviderType::Coco,
            challenge_token: "nonce".into(),
        };
        let evidence = produce_attest_response(
            &proposal,
            &EmptyClaims,
            Some(&producer),
            None,
            None::<&BoundPassportCache>,
            0,
        )
        .await;
        assert_eq!(
            produced_error_reason(&evidence),
            Some(ATTESTATION_UNAVAILABLE)
        );

        let conv = RecordingConverter {
            nonce: "passport-as-nonce".into(),
        };
        let token_producer = counting_token(usize::MAX);
        let passport = cached_passport(
            &token_producer,
            &conv,
            b"spki",
            &PassportEvidenceCache::new(),
        )
        .await;
        assert_eq!(
            produced_error_reason(&passport),
            Some(ATTESTATION_UNAVAILABLE)
        );
    }
}
