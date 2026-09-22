use rats_cert::errors::*;
#[cfg(feature = "__coco-builtin-as")]
use rats_cert::tee::coco::converter::builtin::CocoBuiltinConverter;
use rats_cert::tee::coco::converter::{CoCoNonce, CocoConverter};
use rats_cert::tee::ita::ItaConverter;
use rats_cert::tee::GenericConverter;

use super::evidence::TngEvidence;
use super::token::TngToken;

/// Provider-polymorphic converter. Converts evidence into an AS token.
/// Uses `try_into()` on evidence to enable cross-provider compatibility.
///
/// The variants mirror the `as_provider` values in configuration. `CocoBuiltin` is its own variant
/// rather than a case of `Coco` because it runs the attestation service in this process instead of
/// reaching one over the network, which is a different thing from the gRPC and REST interfaces
/// `Coco` chooses between.
pub enum TngConverter {
    Coco(CocoConverter),
    #[cfg(feature = "__coco-builtin-as")]
    CocoBuiltin(CocoBuiltinConverter),
    Ita(ItaConverter),
}

impl TngConverter {
    /// Both CoCo variants report the same provider: they differ in where the service runs, while
    /// this names the token format that goes over the wire, which is a CoCo AS token either way.
    pub fn provider_type(&self) -> super::provider_type::ProviderType {
        match self {
            Self::Coco(_) => super::provider_type::ProviderType::Coco,
            #[cfg(feature = "__coco-builtin-as")]
            Self::CocoBuiltin(_) => super::provider_type::ProviderType::Coco,
            Self::Ita(_) => super::provider_type::ProviderType::Ita,
        }
    }
}

#[async_trait::async_trait]
impl GenericConverter for TngConverter {
    type InEvidence = TngEvidence;
    type OutEvidence = TngToken;
    type Nonce = String;

    async fn convert(&self, in_evidence: &TngEvidence) -> Result<TngToken> {
        match self {
            Self::Coco(c) => {
                let native_evidence = in_evidence.try_into()?;
                Ok(c.convert(&native_evidence).await?.into())
            }
            #[cfg(feature = "__coco-builtin-as")]
            Self::CocoBuiltin(c) => {
                let native_evidence = in_evidence.try_into()?;
                Ok(c.convert(&native_evidence).await?.into())
            }
            Self::Ita(c) => {
                let native_evidence = in_evidence.try_into()?;
                Ok(c.convert(&native_evidence).await?.into())
            }
        }
    }

    async fn get_nonce(&self) -> Result<String> {
        match self {
            Self::Coco(c) => {
                let CoCoNonce::Jwt(token) = c.get_nonce().await?;
                Ok(token)
            }
            #[cfg(feature = "__coco-builtin-as")]
            Self::CocoBuiltin(c) => {
                let CoCoNonce::Jwt(token) = c.get_nonce().await?;
                Ok(token)
            }
            Self::Ita(c) => c.get_nonce().await,
        }
    }
}
