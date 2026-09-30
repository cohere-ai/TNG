//! Polymorphic provider layer for attestation components.
//!
//! This module abstracts over concrete attestation providers (currently CoCo,
//! designed for future ITA/others) by defining `Tng*` wrapper enums that
//! implement the `Generic*` traits from `rats-cert`. Factory functions
//! (`create_attester`, `create_converter`, `create_verifier`) instantiate
//! the correct underlying provider based on config enums.
//!
//! **Wire format:** Which provider applies to a given evidence object or AS token
//! is signaled by a required `provider` field next to the payload, not by nesting
//! a provider tag inside the evidence JSON or JWT. Call sites pass [`ProviderType`]
//! into [`TngEvidence`] / [`TngToken`] deserialization.

#[cfg(unix)]
pub mod attester;
pub mod converter;
pub mod evidence;
pub mod factory;
pub mod provider_type;
pub mod token;
pub mod verifier;

#[cfg(unix)]
pub use attester::TngAttester;
pub use converter::TngConverter;
pub use evidence::TngEvidence;
pub use factory::*;
#[allow(unused_imports)]
pub use provider_type::ProviderType;
pub use token::TngToken;
pub use verifier::TngVerifier;
