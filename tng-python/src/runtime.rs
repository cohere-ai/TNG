use std::thread;

use anyhow::{Context, Result};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};

use tng::config::TngConfig;
use tng::runtime::{TngRuntime, TracingReloadHandle};

pub struct TngHandle {
    port: u16,
    canceller: CancellationToken,
    _thread: thread::JoinHandle<()>,
}

struct StartResult {
    port: u16,
    canceller: CancellationToken,
}

impl TngHandle {
    /// Start TNG on a background thread with its own tokio runtime.
    ///
    /// `config_json` should be either:
    /// - A full TngConfig JSON (with `add_ingress` array), or
    /// - A single AddIngressArgs JSON (will be wrapped into a TngConfig)
    pub fn start(config_json: String) -> Result<Self> {
        let (result_tx, result_rx) = oneshot::channel::<Result<StartResult>>();

        let thread_handle = thread::Builder::new()
            .name("tng-runtime".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .thread_name("tng-worker")
                    .build()
                    .expect("Failed to build tokio runtime");

                rt.block_on(start_tng(&config_json, result_tx));
            })
            .context("Failed to spawn TNG runtime thread")?;

        let start_result = result_rx
            .blocking_recv()
            .context("TNG runtime thread dropped before sending result")??;

        Ok(Self {
            port: start_result.port,
            canceller: start_result.canceller,
            _thread: thread_handle,
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn shutdown(&self) {
        self.canceller.cancel();
    }
}

async fn start_tng(config_json: &str, result_tx: oneshot::Sender<Result<StartResult>>) {
    // Initialize rustls crypto provider (idempotent)
    let _ = rustls::crypto::ring::default_provider().install_default();

    let reload_handle = setup_tracing();

    // Build the TNG config — determine port
    let (tng_config, port) = match build_config(config_json) {
        Ok(v) => v,
        Err(e) => {
            let _ = result_tx.send(Err(e));
            return;
        }
    };

    let tng_runtime =
        match TngRuntime::from_config_with_reload_handle(tng_config, &reload_handle).await {
            Ok(rt) => rt,
            Err(e) => {
                let _ = result_tx.send(Err(e));
                return;
            }
        };

    let canceller = tng_runtime.canceller();
    let (ready_tx, ready_rx) = oneshot::channel::<()>();

    // Spawn serve — it runs until cancellation and handles its own shutdown
    let serve_handle = tokio::spawn(async move {
        if let Err(e) = tng_runtime.serve_with_ready(ready_tx).await {
            tracing::error!(error = ?e, "TNG serve exited with error");
        }
    });

    // Wait for TNG to be ready before returning to Python
    let _ = ready_rx.await;

    // Now send the result back — TNG is listening and ready
    let _ = result_tx.send(Ok(StartResult {
        port,
        canceller: canceller.clone(),
    }));

    // Wait for the serve task to complete (triggered by canceller.cancel())
    let _ = serve_handle.await;
}

/// Build a TngConfig from JSON. Returns the config and the port that the ingress will listen on.
///
/// If port is 0 in the config, we pick an unused port via portpicker and substitute it in.
fn build_config(config_json: &str) -> Result<(TngConfig, u16)> {
    // Try parsing as full TngConfig first
    if let Ok(mut config) = serde_json::from_str::<TngConfig>(config_json) {
        let port = resolve_ingress_port(&mut config)?;
        return Ok((config, port));
    }

    // Otherwise, try parsing as a single AddIngressArgs and wrap it
    let ingress_args: serde_json::Value = serde_json::from_str(config_json)
        .context("Config is neither valid TngConfig nor valid AddIngressArgs JSON")?;

    let full_config = serde_json::json!({
        "add_ingress": [ingress_args]
    });

    let mut config: TngConfig = serde_json::from_value(full_config)
        .context("Failed to construct TngConfig from ingress args")?;
    let port = resolve_ingress_port(&mut config)?;
    Ok((config, port))
}

/// If the first ingress mapping has port 0, pick an unused port and set it.
/// Returns the port the ingress will listen on.
fn resolve_ingress_port(config: &mut TngConfig) -> Result<u16> {
    use tng::config::ingress::IngressMode;

    let ingress = config
        .add_ingress
        .first_mut()
        .context("No ingress configured")?;

    match &mut ingress.ingress_mode {
        IngressMode::Mapping(ref mut args) => {
            if args.r#in.port == 0 {
                let port =
                    portpicker::pick_unused_port().context("Failed to pick an unused port")?;
                args.r#in.port = port;
                Ok(port)
            } else {
                Ok(args.r#in.port)
            }
        }
        IngressMode::HttpProxy(ref mut args) => {
            if args.proxy_listen.port == 0 {
                let port =
                    portpicker::pick_unused_port().context("Failed to pick an unused port")?;
                args.proxy_listen.port = port;
                Ok(port)
            } else {
                Ok(args.proxy_listen.port)
            }
        }
        IngressMode::Socks5(ref mut args) => {
            if args.proxy_listen.port == 0 {
                let port =
                    portpicker::pick_unused_port().context("Failed to pick an unused port")?;
                args.proxy_listen.port = port;
                Ok(port)
            } else {
                Ok(args.proxy_listen.port)
            }
        }
        IngressMode::Netfilter(_) => {
            anyhow::bail!("Netfilter ingress mode is not supported in the Python SDK")
        }
    }
}

fn setup_tracing() -> TracingReloadHandle {
    let pending_layers: Vec<
        Box<dyn tracing_subscriber::Layer<tracing_subscriber::Registry> + Send + Sync>,
    > = vec![];
    let (pending_layers, reload_handle) = tracing_subscriber::reload::Layer::new(pending_layers);

    // Only initialize if no subscriber is set yet (avoid double-init in tests)
    let _ = tracing_subscriber::registry()
        .with(
            pending_layers.with_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "warn,tng=info".into()),
            ),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "warn,tng=info".into()),
                ),
        )
        .try_init();

    reload_handle
}
