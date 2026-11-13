#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
// The builtin-AS release future's layout exceeds rustc's default query depth.
#![recursion_limit = "256"]

use std::{
    fs::File,
    io::{BufReader, IsTerminal},
};

use anyhow::{bail, Context};
use clap::Parser as _;
use cli::{Cli, GlobalSubcommand};
use tng::runtime::TngRuntime;
use tracing::{
    field::{Field, Visit},
    Event, Metadata, Subscriber,
};
use tracing_subscriber::layer::{Context as LayerContext, Filter};
use tracing_subscriber::Layer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use tng::build;
use tng::config::TngConfig;

mod cli;

struct MemberlistCloseNoise;

impl<S: Subscriber> Filter<S> for MemberlistCloseNoise {
    fn enabled(&self, _: &Metadata<'_>, _: &LayerContext<'_, S>) -> bool {
        true
    }

    fn event_enabled(&self, event: &Event<'_>, _: &LayerContext<'_, S>) -> bool {
        if event.metadata().target() != "memberlist_core::state"
            || event.metadata().level() != &tracing::Level::ERROR
        {
            return true;
        }
        let mut fields = CloseNoiseFields::default();
        event.record(&mut fields);
        !(fields.message && fields.error)
    }
}

#[derive(Default)]
struct CloseNoiseFields {
    message: bool,
    error: bool,
}

impl Visit for CloseNoiseFields {
    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            "message" => self.message = value == "memberlist: failed to close connection",
            "err" => self.error = value == "error writing a body to connection",
            _ => {}
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if matches!(field.name(), "message" | "err") {
            self.record_str(field, &format!("{value:?}"));
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize rustls crypto provider
    #[allow(clippy::expect_used)]
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Initialize log tracing
    let pending_tracing_layers = vec![];
    let (pending_tracing_layers, reload_handle) =
        tracing_subscriber::reload::Layer::new(pending_tracing_layers);
    let subscriber_init = tracing_subscriber::registry()
        // Here we add two layer each has it's own filter (per-layer filter), and the first layer is
        // a vector which can be updated dynamically later(e.g. to append a layer like otlp exporter).
        .with(
            pending_tracing_layers.with_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info,tokio_graceful=off,rats_cert=trace,tng=trace".into()),
            ),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(std::io::stdout().is_terminal())
                .with_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                        "info,tokio_graceful=off,rats_cert=info,tng=info".into()
                    }),
                )
                .with_filter(MemberlistCloseNoise),
        );
    if cli.tokio_console {
        // Initialize tokio console
        subscriber_init.with(console_subscriber::spawn()).init();
    } else {
        subscriber_init.init();
    }

    tracing::info!(
        r#"
  _______   ________
 /_  __/ | / / ____/
  / / /  |/ / / __  
 / / / /|  / /_/ /  Welcome to the Trusted Network Gateway!
/_/ /_/ |_/\____/   version: v{}  commit: {}  buildtime: {}"#,
        build::PKG_VERSION,
        build::COMMIT_HASH,
        build::BUILD_TIME
    );

    tracing::info!("Current process PID: {}", std::process::id());

    let fut = async {
        match cli.command {
            GlobalSubcommand::Launch(options) => {
                // Load config
                let config: TngConfig = async {
                    Ok::<_, anyhow::Error>(match (options.config_file, options.config_content) {
                        (Some(_), Some(_)) => {
                            bail!("Cannot set both --config-file and --config-content at the same time")
                        }
                        (None, None) => {
                            bail!("Either --config-file or --config-content should be set")
                        }
                        (None, Some(s)) => serde_json::from_str(&s)?,
                        (Some(path), None) => {
                            tracing::info!("Loading config from: {path:?}");
                            let file = File::open(path)?;
                            let reader = BufReader::new(file);
                            serde_json::from_reader(reader)?
                        }
                    })
                }
                .await
                .context("Failed to load config")?;

                tracing::debug!("TNG config: {config:#?}");

                tracing::info!("Starting tng instance now");
                TngRuntime::from_config_with_reload_handle(config, &reload_handle)
                    .await?
                    .serve()
                    .await?;

                tracing::info!("Exited gracefully");
            }
        }

        Ok::<_, anyhow::Error>(())
    };

    if let Err(error) = fut.await {
        tracing::error!(error = format!("{error:#}"));
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    struct Counter(Arc<AtomicUsize>);

    impl<S: Subscriber> Layer<S> for Counter {
        fn on_event(&self, _: &Event<'_>, _: LayerContext<'_, S>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn suppresses_only_expected_memberlist_close_noise() {
        let printed = Arc::new(AtomicUsize::new(0));
        let all = Arc::new(AtomicUsize::new(0));
        let subscriber = tracing_subscriber::registry()
            .with(
                Counter(printed.clone())
                    .with_filter(tracing_subscriber::EnvFilter::new("info"))
                    .with_filter(MemberlistCloseNoise),
            )
            .with(Counter(all.clone()));
        tracing::subscriber::with_default(subscriber, || {
            tracing::error!(target: "memberlist_core::state", err = %"error writing a body to connection", "memberlist: failed to close connection");
            assert_eq!(printed.load(Ordering::Relaxed), 0);
            assert_eq!(all.load(Ordering::Relaxed), 1);
            tracing::error!(target: "memberlist_core::state", err = "error writing a body to connection", message = "memberlist: failed to close connection");
            assert_eq!(printed.load(Ordering::Relaxed), 0);
            tracing::error!(target: "memberlist_core::state", err = %"permission denied", "memberlist: failed to close connection");
            assert_eq!(printed.load(Ordering::Relaxed), 1);
            tracing::error!(target: "memberlist_core::state", err = %"error writing a body to connection", "memberlist: push/pull sync failed");
            assert_eq!(printed.load(Ordering::Relaxed), 2);
            tracing::warn!(target: "memberlist_core::state", "memberlist.state: was able to connect to target over reliable connection but unreliable probes failed, network may be misconfigured");
            assert_eq!(printed.load(Ordering::Relaxed), 3);
            tracing::error!(target: "other_component", err = %"error writing a body to connection", "memberlist: failed to close connection");
            assert_eq!(printed.load(Ordering::Relaxed), 4);
            tracing::warn!(target: "memberlist_core::state", err = %"error writing a body to connection", "memberlist: failed to close connection");
            assert_eq!(printed.load(Ordering::Relaxed), 5);
            assert_eq!(all.load(Ordering::Relaxed), 7);
        });
    }
}
