mod client;
mod response;

use pyo3::prelude::*;

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Initialize tracing with a reasonable default filter.
    // Users can override via RUST_LOG env var.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn,tng=info")),
        )
        .try_init();

    // Install the default rustls crypto provider (ring).
    let _ = rustls::crypto::ring::default_provider().install_default();

    m.add_class::<client::TngClient>()?;
    m.add_class::<response::TngResponse>()?;
    Ok(())
}
