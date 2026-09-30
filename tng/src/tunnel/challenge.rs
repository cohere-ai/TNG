//! A source of fresh nonces, shared by whoever builds a background-check proposal or mints a
//! passport token.

use anyhow::{anyhow, Result};
use rats_cert::tee::GenericConverter;

#[async_trait::async_trait]
pub trait ChallengeSource: Send + Sync {
    async fn get_nonce(&self) -> Result<String>;
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

/// A nonce fetch in progress; dropping it without [`Self::succeeded`] records a failure, so a
/// fetch cut short by a timeout still counts.
pub trait ChallengeAttempt {
    fn succeeded(self);
}

impl ChallengeAttempt for () {
    fn succeeded(self) {}
}

#[cfg(unix)]
impl ChallengeAttempt for Option<super::attestation_metrics::AttestationAttempt> {
    fn succeeded(self) {
        if let Some(attempt) = self {
            attempt.mark_succeeded();
        }
    }
}
