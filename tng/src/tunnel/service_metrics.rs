use std::sync::Arc;

use indexmap::IndexMap;
use opentelemetry::metrics::{Counter, MeterProvider, UpDownCounter};
use opentelemetry::KeyValue;

use crate::observability::metric::{
    counter::{AttributedCounter, WithAttributes},
    stream::StreamWithCounter,
};

pub struct ServiceMetricsCreator(Arc<dyn MeterProvider + Send + Sync>);

impl ServiceMetricsCreator {
    pub fn new_creator(
        meter_provider: Arc<dyn MeterProvider + Send + Sync>,
    ) -> ServiceMetricsCreator {
        ServiceMetricsCreator(meter_provider)
    }

    pub fn new_service_metrics(
        &self,
        attributes: impl Into<IndexMap<String, String>>,
    ) -> ServiceMetrics {
        ServiceMetrics::new(self.0.clone(), attributes)
    }
}

/// ServiceMetrics is a set of metrics for a service.
///
/// This struct is free be cloned and used anywhere.
#[derive(Debug, Clone)]
pub struct ServiceMetrics {
    cx_total: AttributedCounter<Counter<u64>, u64>,
    cx_active: AttributedCounter<UpDownCounter<i64>, i64>,
    cx_failed: AttributedCounter<Counter<u64>, u64>,
    tx_bytes_total: AttributedCounter<Counter<u64>, u64>,
    rx_bytes_total: AttributedCounter<Counter<u64>, u64>,
    attestation: AttestationMetrics,
}

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

impl ServiceMetrics {
    pub(self) fn new(
        meter_provider: Arc<dyn MeterProvider + Send + Sync>,
        attributes: impl Into<IndexMap<String, String>>,
    ) -> Self {
        let attributes = Arc::new(attributes.into());

        let meter = meter_provider.meter("tng");
        let cx_total = meter
            .u64_counter("cx_total")
            .with_description("Total number of connections handled since the instance started")
            .build()
            .with_attributes(attributes.clone());
        cx_total.add(0);

        let cx_active = meter
            .i64_up_down_counter("cx_active")
            .with_description("The number of active connections")
            .build()
            .with_attributes(attributes.clone());
        cx_active.add(0);

        let cx_failed = meter
            .u64_counter("cx_failed")
            .with_description("Total number of failed connections since the instance started")
            .build()
            .with_attributes(attributes.clone());
        cx_failed.add(0);

        let tx_bytes_total = meter
            .u64_counter("tx_bytes_total")
            .with_unit("bytes")
            .with_description("The total number of bytes sent")
            .build()
            .with_attributes(attributes.clone());
        tx_bytes_total.add(0);

        let rx_bytes_total = meter
            .u64_counter("rx_bytes_total")
            .with_unit("bytes")
            .with_description("The total number of bytes received")
            .build()
            .with_attributes(attributes.clone());
        rx_bytes_total.add(0);

        let attestation = AttestationMetrics {
            total: meter
                .u64_counter("attestation_total")
                .with_description("Total number of remote attestation operations")
                .build(),
            failed: meter
                .u64_counter("attestation_failed")
                .with_description("Total number of failed remote attestation operations")
                .build(),
            attributes,
        };

        Self {
            cx_total,
            cx_active,
            cx_failed,
            tx_bytes_total,
            rx_bytes_total,
            attestation,
        }
    }

    pub fn new_cx(&self) -> ActiveConnectionCounter {
        ActiveConnectionCounter::new(
            self.cx_total.clone(),
            self.cx_active.clone(),
            self.cx_failed.clone(),
        )
    }

    pub fn new_wrapped_stream<
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + std::marker::Unpin,
    >(
        &self,
        stream: T,
    ) -> StreamWithCounter<T> {
        StreamWithCounter {
            inner: stream,
            tx_bytes_total: self.tx_bytes_total.clone(),
            rx_bytes_total: self.rx_bytes_total.clone(),
        }
    }

    pub fn attestation(&self) -> AttestationMetrics {
        self.attestation.clone()
    }
}

pub struct ActiveConnectionCounter {
    cx_active: AttributedCounter<UpDownCounter<i64>, i64>,
    cx_failed: AttributedCounter<Counter<u64>, u64>,
    finished_successfully: bool,
}

impl ActiveConnectionCounter {
    pub fn new(
        cx_total: AttributedCounter<Counter<u64>, u64>,
        cx_active: AttributedCounter<UpDownCounter<i64>, i64>,
        cx_failed: AttributedCounter<Counter<u64>, u64>,
    ) -> Self {
        cx_total.add(1);
        cx_active.add(1);

        Self {
            cx_active,
            cx_failed,
            finished_successfully: false,
        }
    }

    /// Call this function when the stream is finished successfully, or it will report an failed connection when it is droppeds.
    pub fn mark_finished_successfully(mut self) {
        self.finished_successfully = true;
    }
}

impl Drop for ActiveConnectionCounter {
    fn drop(&mut self) {
        if !self.finished_successfully {
            self.cx_failed.add(1);
        }
        self.cx_active.add(-1);
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
        let metrics =
            ServiceMetricsCreator::new_creator(Arc::new(provider.clone())).new_service_metrics(
                IndexMap::from([("egress_id".to_owned(), "model-a".to_owned())]),
            );

        drop(
            metrics
                .attestation()
                .start(AttestationOperation::Verify, AttestationProtocol::Ohttp),
        );

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
