pub mod netns;
pub mod task;

use std::{
    collections::HashMap,
    io::Write,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use anyhow::{bail, Context, Result};
use futures::StreamExt as _;
use netns::BridgeNetwork;
use serde_json::Value;
use task::Task;
use tokio::sync::OnceCell;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::{fmt::MakeWriter, layer::SubscriberExt, util::SubscriberInitExt, Layer};

static BIN_TEST_LOG_RELOAD_HANDLE: OnceCell<
    tracing_subscriber::reload::Handle<
        Vec<Box<dyn tracing_subscriber::Layer<tracing_subscriber::Registry> + Send + Sync>>,
        tracing_subscriber::Registry,
    >,
> = OnceCell::const_new();

type CaptureBuffer = Arc<Mutex<Vec<u8>>>;

static STRUCTURED_LOG_CAPTURE: OnceLock<Mutex<Option<CaptureBuffer>>> = OnceLock::new();

fn structured_log_capture() -> &'static Mutex<Option<CaptureBuffer>> {
    STRUCTURED_LOG_CAPTURE.get_or_init(|| Mutex::new(None))
}

struct StructuredCaptureMakeWriter;

struct StructuredCaptureWriter {
    buffer: Option<CaptureBuffer>,
    event: Vec<u8>,
}

impl Write for StructuredCaptureWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.event.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for StructuredCaptureWriter {
    fn drop(&mut self) {
        if self.event.is_empty() {
            return;
        }
        if let Some(buffer) = &self.buffer {
            match buffer.lock() {
                Ok(mut buffer) => buffer.extend_from_slice(&self.event),
                Err(error) => {
                    eprintln!("failed to append structured log event: {error}");
                }
            }
        }
    }
}

impl<'a> MakeWriter<'a> for StructuredCaptureMakeWriter {
    type Writer = StructuredCaptureWriter;

    fn make_writer(&'a self) -> Self::Writer {
        StructuredCaptureWriter {
            buffer: structured_log_capture()
                .lock()
                .expect("structured log capture lock poisoned")
                .clone(),
            event: Vec::new(),
        }
    }
}

pub struct StructuredLogCapture {
    buffer: CaptureBuffer,
    active: bool,
}

pub fn capture_structured_logs() -> Result<StructuredLogCapture> {
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let mut active_capture = structured_log_capture()
        .lock()
        .map_err(|error| anyhow::anyhow!("structured log capture lock poisoned: {error}"))?;
    if active_capture.is_some() {
        bail!("a structured log capture is already active");
    }
    *active_capture = Some(Arc::clone(&buffer));
    Ok(StructuredLogCapture {
        buffer,
        active: true,
    })
}

impl StructuredLogCapture {
    pub fn finish(mut self) -> Result<Vec<Value>> {
        self.stop()?;
        let buffer = self
            .buffer
            .lock()
            .map_err(|error| anyhow::anyhow!("structured log buffer lock poisoned: {error}"))?;
        buffer
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| {
                serde_json::from_slice(line)
                    .context("failed to parse captured structured log event")
            })
            .collect()
    }

    fn stop(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }
        let mut active_capture = structured_log_capture()
            .lock()
            .map_err(|error| anyhow::anyhow!("structured log capture lock poisoned: {error}"))?;
        let is_current_capture = active_capture
            .as_ref()
            .is_some_and(|buffer| Arc::ptr_eq(buffer, &self.buffer));
        if !is_current_capture {
            bail!("active structured log capture changed unexpectedly");
        }
        *active_capture = None;
        self.active = false;
        Ok(())
    }
}

impl Drop for StructuredLogCapture {
    fn drop(&mut self) {
        if let Err(error) = self.stop() {
            eprintln!("failed to stop structured log capture: {error:#}");
        }
    }
}

/// This is a common function to run bin tests. For each test, it will create many virtual nodes under
/// a bridge network (192.168.1.0/24), at least there will be one node act as the server side, the other act as
/// the client side. And the attestation service will be at `http://192.168.1.254:8080`.
/// And all the test will be run in those two virtual nodes one by one.
pub async fn run_test(tasks: Vec<Box<dyn Task>>) -> Result<()> {
    let token = CancellationToken::new();

    let test_future = async {
        BIN_TEST_LOG_RELOAD_HANDLE
            .get_or_init(|| async {
                // Initialize rustls crypto provider
                rustls::crypto::ring::default_provider()
                    .install_default()
                    .expect("Failed to install rustls crypto provider");

                // Initialize log tracing
                let pending_tracing_layers = vec![];
                let (pending_tracing_layers, reload_handle) =
                    tracing_subscriber::reload::Layer::new(pending_tracing_layers);
                tracing_subscriber::registry()
                    .with(pending_tracing_layers.with_filter(
                        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(
                            |_| "info,tokio_graceful=off,rats_cert=trace,tng=trace".into(),
                        ),
                    ))
                    .with(
                        tracing_subscriber::fmt::layer()
                            .with_ansi(atty::is(atty::Stream::Stdout))
                            .with_filter(
                                tracing_subscriber::EnvFilter::try_from_default_env()
                                    .unwrap_or_else(|_| {
                                        format!(
                                    "info,tokio_graceful=off,rats_cert=debug,tng=debug,{}=debug",
                                    std::module_path!().split("::").next().unwrap()
                                )
                                        .into()
                                    }),
                            ),
                    )
                    .with(
                        tracing_subscriber::fmt::layer()
                            .json()
                            .with_ansi(false)
                            .with_writer(StructuredCaptureMakeWriter)
                            .with_filter(tracing_subscriber::EnvFilter::new(
                                "tng::attestation=info",
                            )),
                    )
                    // .with(console_subscriber::spawn()) // Initialize tokio console
                    .init();

                reload_handle
            })
            .await;

        // Create a virtual network with two nodes connected to a bridge
        let network = BridgeNetwork::new("192.168.1.254", 24).await?;

        // Create required Node for each task
        let mut ip_to_nodes = HashMap::new();
        let mut tasks_with_nodes = vec![];
        for task in tasks {
            let ip = task.node_type().ip();
            if !ip_to_nodes.contains_key(&ip) {
                let new_node = Arc::new(network.new_node(&ip).await?);
                ip_to_nodes.insert(ip.clone(), Arc::clone(&new_node));
            }
            let node = ip_to_nodes.get(&ip).unwrap();

            tasks_with_nodes.push((task, Arc::clone(node)));
        }

        // Launch all tasks in order and get the join handles
        let mut sub_tasks = futures::stream::FuturesUnordered::new();
        for (task, node) in tasks_with_nodes {
            sub_tasks.push({
                let task_name = task.name();

                let task_result = {
                    let task_name = task_name.clone();

                    let token = token.clone();
                    node.run(async move {
                        // Timeout is 1 minute.
                        let timeout = tokio::time::sleep(Duration::from_secs(60));

                        tokio::select! {
                            _ = timeout => {
                                bail!("Timeout waiting for task {task_name} to be ready");
                            },
                            res = task.launch(token) => res
                        }
                    })
                    .await
                    .and_then(|r| r)?
                };

                async {
                    (
                        task_name,
                        task_result
                            .await
                            .map_err(anyhow::Error::from)
                            .and_then(|r| r),
                    )
                }
            });
        }

        let mut first_error = None;

        loop {
            match sub_tasks.next().await {
                Some((task_name, res)) => {
                    if let Err(e) = res.with_context(|| format!("Error in the {task_name} task")) {
                        tracing::error!(error=?e, "Got error in task");
                        if first_error.is_none() {
                            first_error = Some(e);
                        }
                    }
                }
                None => {
                    break;
                }
            }
        }

        if let Some(e) = first_error {
            return Err(e);
        }

        Ok::<_, anyhow::Error>(())
    };

    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    tokio::select! {
        _ = sigint.recv() => {
            token.cancel();
            bail!("We got SIGINT, cancel now");
        }
        _ = sigterm.recv() => {
            token.cancel();
            bail!("We got SIGTERM, cancel now");
        }
        res = test_future => {
            res?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod structured_log_capture_tests {
    use std::collections::HashSet;

    use tracing_subscriber::layer::SubscriberExt as _;

    use super::*;

    #[serial_test::serial]
    #[test]
    fn captures_typed_json_event_fields_and_releases_capture() {
        let capture = capture_structured_logs().unwrap();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_ansi(false)
                .with_writer(StructuredCaptureMakeWriter),
        );

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(
                target: "tng::attestation",
                event = "passport_cache_lookup",
                cache_hit = true,
            );
        });

        let logs = capture.finish().unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0]["fields"]["event"], "passport_cache_lookup");
        assert_eq!(logs[0]["fields"]["cache_hit"], true);

        drop(capture_structured_logs().unwrap());
    }

    #[serial_test::serial]
    #[test]
    fn event_writer_publishes_only_when_dropped() {
        let capture = capture_structured_logs().unwrap();
        let mut writer = StructuredCaptureMakeWriter.make_writer();
        writer.write_all(br#"{"fields":{"event":"atomic""#).unwrap();
        assert!(capture.buffer.lock().unwrap().is_empty());
        writer.write_all(b"}}\n").unwrap();
        drop(writer);

        let logs = capture.finish().unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0]["fields"]["event"], "atomic");
    }

    #[serial_test::serial]
    #[test]
    fn concurrent_events_are_complete_and_not_interleaved() {
        const THREADS: usize = 8;
        const EVENTS_PER_THREAD: usize = 100;

        let capture = capture_structured_logs().unwrap();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_ansi(false)
                .with_writer(StructuredCaptureMakeWriter),
        );
        let dispatch = tracing::Dispatch::new(subscriber);

        std::thread::scope(|scope| {
            for worker in 0..THREADS {
                let dispatch = dispatch.clone();
                scope.spawn(move || {
                    tracing::dispatcher::with_default(&dispatch, || {
                        for sequence in 0..EVENTS_PER_THREAD {
                            tracing::info!(
                                target: "tng::attestation",
                                event = "concurrent_capture_test",
                                worker,
                                sequence,
                            );
                        }
                    });
                });
            }
        });

        let logs = capture.finish().unwrap();
        assert_eq!(logs.len(), THREADS * EVENTS_PER_THREAD);
        let event_ids = logs
            .iter()
            .map(|log| {
                assert_eq!(log["fields"]["event"], "concurrent_capture_test");
                (
                    log["fields"]["worker"].as_u64().unwrap(),
                    log["fields"]["sequence"].as_u64().unwrap(),
                )
            })
            .collect::<HashSet<_>>();
        assert_eq!(event_ids.len(), THREADS * EVENTS_PER_THREAD);
    }
}
