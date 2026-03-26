use anyhow::{anyhow, Result};
use rats_cert::tee::coco::evidence::CocoEvidence;
use rats_cert::tee::ita::ItaEvidence;

use super::evidence::TngEvidence;

/// Trait for translating a TNG enum type to a provider-specific inner type.
///
/// The set of `TranslateTo` impls defines the cross-provider compatibility matrix.
/// - Identity conversions (same provider) always succeed.
/// - Cross-provider conversions either perform a real translation or fail with a
///   descriptive error.
/// - Missing impls cause a compile error, enforcing exhaustive coverage.
///
/// Note: only used for evidence, not tokens. Token compatibility is always
/// identity-only (same provider or fail), handled via direct match in verifiers.
pub trait TranslateTo<T> {
    fn translate(&self) -> Result<T>;
}

impl TranslateTo<CocoEvidence> for TngEvidence {
    fn translate(&self) -> Result<CocoEvidence> {
        match self {
            Self::Coco(e) => Ok(e.clone()),
            other => Err(anyhow!(
                "{} evidence cannot be translated to CocoEvidence",
                other.provider_type()
            )),
        }
    }
}

impl TranslateTo<ItaEvidence> for TngEvidence {
    fn translate(&self) -> Result<ItaEvidence> {
        match self {
            Self::Ita(e) => Ok(e.clone()),
            other => Err(anyhow!(
                "{} evidence cannot be translated to ItaEvidence",
                other.provider_type()
            )),
        }
    }
}
