use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use indexmap::IndexMap;
use opentelemetry::{
    metrics::{Counter, Meter, MeterProvider},
    KeyValue,
};

use crate::observability::metric::simple_exporter::noop::NoopMeterProvider;

#[derive(Debug, Clone, Copy)]
pub enum AttestationOperation {
    Generate,
    Verify,
    Challenge,
}

impl AttestationOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Generate => "generate",
            Self::Verify => "verify",
            Self::Challenge => "challenge",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum AttestationModel {
    Passport,
    BackgroundCheck,
}

impl AttestationModel {
    fn as_str(self) -> &'static str {
        match self {
            Self::Passport => "passport",
            Self::BackgroundCheck => "background_check",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum AttestationProtocol {
    Ohttp,
    RatsTls,
}

impl AttestationProtocol {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ohttp => "ohttp",
            Self::RatsTls => "rats_tls",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AttestationMetrics {
    total: Counter<u64>,
    failed: Counter<u64>,
    attributes: Arc<IndexMap<String, String>>,
    evidence_in_flight: Arc<AtomicU64>,
    next_evidence_attempt_id: Arc<AtomicU64>,
}

impl AttestationMetrics {
    pub(crate) fn noop() -> Self {
        let provider = NoopMeterProvider::new();
        Self::new(&provider.meter("tng"), Arc::new(IndexMap::new()))
    }

    pub(crate) fn new(meter: &Meter, attributes: Arc<IndexMap<String, String>>) -> Self {
        Self {
            total: meter
                .u64_counter("attestation_total")
                .with_description("Total number of remote attestation operations")
                .build(),
            failed: meter
                .u64_counter("attestation_failed")
                .with_description("Total number of failed remote attestation operations")
                .build(),
            attributes,
            evidence_in_flight: Arc::new(AtomicU64::new(0)),
            next_evidence_attempt_id: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn start_evidence(
        &self,
        model: AttestationModel,
        protocol: AttestationProtocol,
    ) -> EvidenceAttempt {
        let in_flight_at_start = self.evidence_in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        let attempt_id = self.next_evidence_attempt_id.fetch_add(1, Ordering::SeqCst) + 1;
        EvidenceAttempt {
            metrics: self.clone(),
            model,
            protocol,
            attempt_id,
            in_flight_at_start,
            started_at: Instant::now(),
            succeeded: false,
        }
    }

    pub fn start(
        &self,
        operation: AttestationOperation,
        protocol: AttestationProtocol,
    ) -> AttestationAttempt {
        AttestationAttempt {
            metrics: self.clone(),
            operation,
            protocol,
            succeeded: false,
        }
    }

    pub fn record(
        &self,
        operation: AttestationOperation,
        protocol: AttestationProtocol,
        success: bool,
    ) {
        let mut attributes = self
            .attributes
            .iter()
            .map(|(key, value)| KeyValue::new(key.clone(), value.clone()))
            .collect::<Vec<_>>();
        attributes.push(KeyValue::new("operation", operation.as_str()));
        attributes.push(KeyValue::new("protocol", protocol.as_str()));

        self.total.add(1, &attributes);
        if !success {
            self.failed.add(1, &attributes);
        }
    }
}

pub struct AttestationAttempt {
    metrics: AttestationMetrics,
    operation: AttestationOperation,
    protocol: AttestationProtocol,
    succeeded: bool,
}

impl AttestationAttempt {
    pub fn mark_succeeded(mut self) {
        self.succeeded = true;
    }
}

impl Drop for AttestationAttempt {
    fn drop(&mut self) {
        self.metrics
            .record(self.operation, self.protocol, self.succeeded);
    }
}

pub struct EvidenceAttempt {
    metrics: AttestationMetrics,
    model: AttestationModel,
    protocol: AttestationProtocol,
    attempt_id: u64,
    in_flight_at_start: u64,
    started_at: Instant,
    succeeded: bool,
}

impl EvidenceAttempt {
    pub fn mark_succeeded(mut self) {
        self.succeeded = true;
    }
}

impl Drop for EvidenceAttempt {
    fn drop(&mut self) {
        let remaining = self
            .metrics
            .evidence_in_flight
            .fetch_sub(1, Ordering::SeqCst)
            - 1;
        tracing::info!(
            target: "tng::attestation",
            event = "attestation_evidence_completed",
            attempt_id = self.attempt_id,
            attestation_model = self.model.as_str(),
            protocol = self.protocol.as_str(),
            success = self.succeeded,
            duration_ms = self.started_at.elapsed().as_secs_f64() * 1000.0,
            in_flight_at_start = self.in_flight_at_start,
            in_flight_after = remaining,
        );
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::observability::metric::{
        instance::MetricExporterInstance,
        simple_exporter::{SimpleMetric, SimpleMetricExporter},
    };
    use serde_json::Value;
    use tracing_subscriber::{fmt::MakeWriter, layer::SubscriberExt, EnvFilter, Layer};

    struct BufferWriter {
        buf: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for BufferWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.buf.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct BufferMakeWriter(Arc<Mutex<Vec<u8>>>);

    impl<'a> MakeWriter<'a> for BufferMakeWriter {
        type Writer = BufferWriter;

        fn make_writer(&'a self) -> Self::Writer {
            BufferWriter {
                buf: Arc::clone(&self.0),
            }
        }
    }

    fn parse_attestation_evidence_events(buffer: &[u8]) -> Vec<Value> {
        buffer
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
            .filter(|event| {
                event.pointer("/fields/event").and_then(Value::as_str)
                    == Some("attestation_evidence_completed")
            })
            .collect()
    }

    #[test]
    fn evidence_attempt_emits_structured_completion_events() {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(BufferMakeWriter(Arc::clone(&buffer)))
                .with_filter(EnvFilter::new("info")),
        );

        tracing::subscriber::with_default(subscriber, || {
            let metrics = AttestationMetrics::noop();
            let attempt1 = metrics.start_evidence(
                AttestationModel::BackgroundCheck,
                AttestationProtocol::Ohttp,
            );
            let attempt2 =
                metrics.start_evidence(AttestationModel::Passport, AttestationProtocol::Ohttp);
            attempt1.mark_succeeded();
            drop(attempt2);
        });

        let events = parse_attestation_evidence_events(&buffer.lock().unwrap());
        assert_eq!(events.len(), 2);

        let attempt_id0 = events[0]["fields"]["attempt_id"].as_u64().unwrap();
        let attempt_id1 = events[1]["fields"]["attempt_id"].as_u64().unwrap();

        assert_eq!(
            events[0]["fields"]["event"],
            "attestation_evidence_completed"
        );
        assert_eq!(events[0]["fields"]["attestation_model"], "background_check");
        assert_eq!(events[0]["fields"]["protocol"], "ohttp");
        assert_eq!(events[0]["fields"]["success"], true);
        assert!(events[0]["fields"]["duration_ms"].as_f64().unwrap() >= 0.0);
        assert_eq!(events[0]["fields"]["in_flight_at_start"], 1);
        assert_eq!(events[0]["fields"]["in_flight_after"], 1);

        assert_eq!(events[1]["fields"]["attestation_model"], "passport");
        assert_eq!(events[1]["fields"]["success"], false);
        assert_eq!(events[1]["fields"]["in_flight_at_start"], 2);
        assert_eq!(events[1]["fields"]["in_flight_after"], 0);

        assert!(attempt_id1 > attempt_id0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn exports_failed_attestation_with_bounded_attributes() {
        let (sender, receiver) = std::sync::mpsc::channel();
        let exporter: Arc<dyn SimpleMetricExporter + Send + Sync> =
            Arc::new(move |metrics: &[SimpleMetric]| {
                for metric in metrics {
                    if metric.name == "attestation_failed" {
                        let _ = sender.send((metric.value.as_u64(), metric.attributes.clone()));
                    }
                }
                Ok(())
            });
        let provider = MetricExporterInstance::Simple(1, exporter).into_sdk_meter_provider();
        let metrics = AttestationMetrics::new(
            &provider.meter("tng"),
            Arc::new(IndexMap::from([(
                "egress_id".to_owned(),
                "model-a".to_owned(),
            )])),
        );

        drop(metrics.start(AttestationOperation::Verify, AttestationProtocol::Ohttp));

        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        let (value, attributes) = receiver
            .try_iter()
            .next()
            .expect("failed attestation metric was not exported");
        assert_eq!(value, Some(1));
        assert_eq!(attributes.get("egress_id"), Some(&"model-a".to_owned()));
        assert_eq!(attributes.get("operation"), Some(&"verify".to_owned()));
        assert_eq!(attributes.get("protocol"), Some(&"ohttp".to_owned()));
        provider.shutdown().unwrap();
    }
}
