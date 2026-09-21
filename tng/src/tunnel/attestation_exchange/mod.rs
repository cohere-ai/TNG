mod claims;
mod codec;
mod core;
pub mod exporter;
mod session;

pub mod pb {
    include!(concat!(
        env!("OUT_DIR"),
        "/tng.rats_tls.attestation_exchange.rs"
    ));
}

pub use core::{ChallengeSource, PassportEvidenceCache, RawEvidenceVerifier};
pub use session::{resources_from_ra, run_on_stream};
