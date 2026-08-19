use std::sync::Arc;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability::metric::{
        instance::MetricExporterInstance,
        simple_exporter::{SimpleMetric, SimpleMetricExporter},
    };

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
