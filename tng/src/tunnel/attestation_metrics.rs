use std::sync::Arc;

use indexmap::IndexMap;
use opentelemetry::{
    metrics::{Counter, Gauge, Meter, MeterProvider},
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
    startup_failed: Gauge<u64>,
    attributes: Arc<IndexMap<String, String>>,
}

impl AttestationMetrics {
    pub(crate) fn noop() -> Self {
        let provider = NoopMeterProvider::new();
        Self::new(&provider.meter("tng"), Arc::new(IndexMap::new()))
    }

    pub(crate) fn new(meter: &Meter, attributes: Arc<IndexMap<String, String>>) -> Self {
        Self {
            total: meter
                .u64_counter("tng_attestation_total")
                .with_description("Total number of remote attestation operations")
                .build(),
            failed: meter
                .u64_counter("tng_attestation_failed")
                .with_description("Total number of failed remote attestation operations")
                .build(),
            startup_failed: meter
                .u64_gauge("tng_startup_attestation_failed")
                .with_description("Startup attestation self-check failed (1) or passed (0)")
                .build(),
            attributes,
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

    /// Record only a completed self-check, so a restart does not clear an earlier failure.
    pub fn record_startup_result(&self, success: bool) {
        let attributes = self
            .attributes
            .iter()
            .map(|(key, value)| KeyValue::new(key.clone(), value.clone()))
            .collect::<Vec<_>>();
        self.startup_failed.record(u64::from(!success), &attributes);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability::metric::{
        instance::MetricExporterInstance,
        simple_exporter::{SimpleMetric, SimpleMetricExporter, ValueType},
    };

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn exports_failed_attestation_with_bounded_attributes() {
        let (sender, receiver) = std::sync::mpsc::channel();
        let exporter: Arc<dyn SimpleMetricExporter + Send + Sync> =
            Arc::new(move |metrics: &[SimpleMetric]| {
                for metric in metrics {
                    if metric.name == "tng_attestation_failed" {
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn exports_startup_attestation_result_on_shutdown() {
        for success in [false, false, true] {
            let (sender, receiver) = std::sync::mpsc::channel();
            let exporter: Arc<dyn SimpleMetricExporter + Send + Sync> =
                Arc::new(move |metrics: &[SimpleMetric]| {
                    for metric in metrics {
                        if metric.name == "tng_startup_attestation_failed" {
                            let _ = sender.send((
                                metric.value.as_u64(),
                                metric.value_type,
                                metric.attributes.clone(),
                            ));
                        }
                    }
                    Ok(())
                });
            // Export only on shutdown, without an earlier zero sample.
            let provider = MetricExporterInstance::Simple(3600, exporter).into_sdk_meter_provider();
            let metrics = AttestationMetrics::new(
                &provider.meter("tng"),
                Arc::new(IndexMap::from([("egress_id".to_owned(), "0".to_owned())])),
            );
            metrics.record_startup_result(success);
            drop(metrics);
            drop(provider);

            let (value, value_type, attributes) =
                receiver.try_recv().expect("startup gauge was not exported");
            assert_eq!(value, Some(u64::from(!success)));
            assert_eq!(value_type, ValueType::Gauge);
            assert_eq!(attributes.get("egress_id"), Some(&"0".to_owned()));
            assert!(!attributes.contains_key("operation"));
            assert!(!attributes.contains_key("protocol"));
        }
    }
}
