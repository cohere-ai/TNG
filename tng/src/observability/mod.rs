#[cfg(feature = "metric")]
pub mod metric;

pub mod trace;

#[cfg(any(feature = "metric", feature = "trace"))]
pub fn otlp_resource() -> opentelemetry_sdk::Resource {
    // `Resource::builder()` already runs EnvResourceDetector (`OTEL_RESOURCE_ATTRIBUTES`),
    // so identity such as k8s.pod.name / model_name is on the resource, not metric labels.
    // Stamp service.name/version after that so they win over a generic env service.name.
    opentelemetry_sdk::Resource::builder()
        .with_service_name("tng")
        .with_attribute(
            // https://opentelemetry.io/docs/specs/semconv/attributes-registry/service/
            opentelemetry::KeyValue::new("service.version", crate::build::PKG_VERSION),
        )
        .build()
}

#[cfg(all(test, any(feature = "metric", feature = "trace")))]
mod tests {
    use super::otlp_resource;
    use opentelemetry::{Key, Value};

    #[test]
    fn otlp_resource_keeps_env_attributes() {
        let prev = std::env::var("OTEL_RESOURCE_ATTRIBUTES").ok();
        std::env::set_var(
            "OTEL_RESOURCE_ATTRIBUTES",
            "k8s.pod.name=cat2508rws-l-cc-0,model_name=command-a-translate-08-2025",
        );
        let resource = otlp_resource();
        match prev {
            Some(value) => std::env::set_var("OTEL_RESOURCE_ATTRIBUTES", value),
            None => std::env::remove_var("OTEL_RESOURCE_ATTRIBUTES"),
        }

        assert_eq!(
            resource.get(&Key::from_static_str("k8s.pod.name")),
            Some(Value::from("cat2508rws-l-cc-0"))
        );
        assert_eq!(
            resource.get(&Key::from_static_str("model_name")),
            Some(Value::from("command-a-translate-08-2025"))
        );
        assert_eq!(
            resource.get(&Key::from_static_str("service.name")),
            Some(Value::from("tng"))
        );
    }
}
