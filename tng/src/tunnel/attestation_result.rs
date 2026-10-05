use std::sync::Arc;

use serde::Serialize;

use super::attest::Model;
use super::provider::{ProviderType, TngToken};

/// The result of remote attestation.
///
/// This struct is cheap to clone.
#[derive(Clone)]
pub struct AttestationResult {
    model: Model,
    /// Use Arc to avoid cloning the claims to save memory.
    token: Arc<TngToken>,
}

impl Serialize for AttestationResult {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self.token.as_str())
    }
}

impl std::fmt::Debug for AttestationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttestationResult")
            .field("token", &self.token.as_str())
            .finish()
    }
}

impl AttestationResult {
    pub fn from_token(model: Model, token: TngToken) -> Self {
        Self {
            model,
            token: Arc::new(token),
        }
    }

    /// The `(model, provider)` of the verifier entry that accepted this result.
    pub fn key(&self) -> (Model, ProviderType) {
        (self.model, self.token.provider_type())
    }

    pub fn exp(&self) -> anyhow::Result<u64> {
        self.token.exp()
    }
}
