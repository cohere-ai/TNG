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
pub use session::finish_rats_tls;
