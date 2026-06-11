use std::sync::Arc;

use anyhow::Context;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use tng::{
    config::ingress::CommonArgs,
    tunnel::{endpoint::TngEndpoint, ingress::protocol::ohttp::security::OHttpSecurityLayer},
    RaContext, TokioRuntime,
};
use url::Url;

use crate::response::TngResponse;

/// The Rust-side OHTTP client that `Transport` and `AsyncTransport` delegate to.
///
/// Holds the OHTTP security layer, tokio runtime, and shutdown guard.
/// Not typically instantiated directly by Python users; the transport
/// classes in `tng.transport` are the public API.
#[pyclass]
pub struct TngClient {
    security_layer: Arc<OHttpSecurityLayer>,
    rt: Arc<tokio::runtime::Runtime>,
    _shutdown: tokio_graceful::Shutdown,
}

#[pymethods]
impl TngClient {
    #[new]
    fn new(config: &Bound<'_, PyAny>) -> PyResult<Self> {
        let json_str: String = Python::with_gil(|py| {
            let json_mod = py.import("json")?;
            let s = json_mod.call_method1("dumps", (config,))?;
            s.extract::<String>()
        })?;

        let common_args: CommonArgs =
            serde_json::from_str(&json_str).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

        let ohttp_args = common_args.ohttp.unwrap_or_default();
        let ra_args = common_args
            .ra_args
            .into_checked()
            .map_err(|e| PyRuntimeError::new_err(format!("{e:?}")))?;

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

        let (security_layer, shutdown) = rt.block_on(async {
            let shutdown = tokio_graceful::Shutdown::builder()
                .with_signal(std::future::pending::<()>())
                .build();
            let tng_runtime = TokioRuntime::current(shutdown.guard().clone())
                .context("failed to get current tokio runtime")
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

            let ra_context = Arc::new(
                RaContext::from_ra_args(&ra_args)
                    .await
                    .map_err(|e| PyRuntimeError::new_err(format!("{e:?}")))?,
            );

            let security_layer = OHttpSecurityLayer::new(
                #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                None,
                &ohttp_args,
                ra_context,
                tng_runtime,
            )
            .await
            .map_err(|e| PyRuntimeError::new_err(format!("{e:?}")))?;

            Ok::<_, PyErr>((security_layer, shutdown))
        })?;

        let rt = Arc::new(rt);

        Ok(Self {
            security_layer: Arc::new(security_layer),
            rt,
            _shutdown: shutdown,
        })
    }

    /// Send a request synchronously. Returns a `TngResponse`.
    ///
    /// The body is consumed by a background task on the tokio runtime,
    /// call `read_all()` on the response to get the full body bytes.
    #[pyo3(signature = (method, url, headers, body=None))]
    fn send(
        &self,
        py: Python<'_>,
        method: &str,
        url: &str,
        headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
    ) -> PyResult<TngResponse> {
        let (request, endpoint) = build_request(method, url, &headers, body)?;

        let security_layer = self.security_layer.clone();
        let rt = self.rt.clone();

        let (response, attestation_result) = py.allow_threads(|| {
            rt.block_on(async move {
                security_layer
                    .forward_http_request(&endpoint, request)
                    .await
                    .map_err(|e| PyRuntimeError::new_err(format!("{e:?}")))
            })
        })?;

        Ok(TngResponse::from_http_response(
            response,
            attestation_result,
            self.rt.clone(),
        ))
    }

    /// Send a request asynchronously. Returns a Python awaitable that
    /// resolves to a `TngResponse`.
    #[pyo3(signature = (method, url, headers, body=None))]
    fn send_async<'py>(
        &self,
        py: Python<'py>,
        method: &str,
        url: &str,
        headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let (request, endpoint) = build_request(method, url, &headers, body)?;

        let security_layer = self.security_layer.clone();
        let rt = self.rt.clone();

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let (response, attestation_result) = security_layer
                .forward_http_request(&endpoint, request)
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("{e:?}")))?;

            Ok(TngResponse::from_http_response(
                response,
                attestation_result,
                rt,
            ))
        })
    }
}

fn build_request(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<Vec<u8>>,
) -> PyResult<(axum::extract::Request, TngEndpoint)> {
    let parsed_url =
        Url::parse(url).map_err(|e| PyRuntimeError::new_err(format!("Invalid URL: {e}")))?;

    let host = parsed_url
        .host_str()
        .ok_or_else(|| PyRuntimeError::new_err("URL has no host"))?
        .to_string();

    let default_port = match parsed_url.scheme() {
        "https" => 443,
        _ => 80,
    };
    let port = parsed_url.port().unwrap_or(default_port);
    let scheme = parsed_url.scheme().to_string();

    let endpoint = TngEndpoint::new(host, port).with_scheme(scheme);

    let body_data = body.unwrap_or_default();
    let axum_body = if body_data.is_empty() {
        axum::body::Body::empty()
    } else {
        axum::body::Body::from(body_data)
    };

    let mut builder = http::Request::builder()
        .method(method)
        .uri(url)
        .version(http::Version::HTTP_11);

    for (k, v) in headers {
        builder = builder.header(k.as_str(), v.as_str());
    }

    let request = builder
        .body(axum_body)
        .map_err(|e| PyRuntimeError::new_err(format!("Failed to build request: {e}")))?;

    Ok((request, endpoint))
}
