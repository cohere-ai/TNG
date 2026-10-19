#![allow(incomplete_features)]
// To suppress warning messages appearing in recent nightly rust. See https://github.com/rust-lang/rust/issues/121315
#![allow(unused_imports)]

pub mod cert;
pub mod crypto;
pub mod errors;
#[cfg(feature = "__coco-builtin-as")]
pub mod policy_source;
pub mod tee;

/// Must run before any jsonwebtoken call; constructors of every type that uses it call this.
/// The builtin AS enables jsonwebtoken's `aws_lc_rs` backend next to our `rust_crypto`, and with
/// both compiled in jsonwebtoken panics on first use unless a provider was installed.
pub(crate) fn install_jwt_crypto_provider() {
    // Errors only when a provider is already installed, which is fine.
    let _ = jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER.install_default();
}

#[cfg(test)]
mod tests {

    #[cfg(test)]
    #[ctor::ctor]
    fn init() {
        use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "debug".into());
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
    }
}
