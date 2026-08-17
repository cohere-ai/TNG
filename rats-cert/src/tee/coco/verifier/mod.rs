//! Verification of a CoCo attestation service token.
//!
//! Unlike the converter, this needs no enum over the service's interfaces: a token is verified
//! against trust material, and how it was obtained does not change that. So one verifier covers
//! both the gRPC and REST services, and [`coco_builtin::CocoBuiltinVerifier`] stands beside it for
//! the in-process case, which differs in its trust material rather than its transport.

#[cfg(feature = "__coco-builtin-as")]
pub mod coco_builtin;
mod common;
pub mod remote;
pub mod token;
