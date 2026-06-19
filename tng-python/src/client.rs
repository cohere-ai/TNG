use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use tng::{
    config::ingress::CommonArgs,
    tunnel::{endpoint::TngEndpoint, ingress::protocol::ohttp::security::OHttpSecurityLayer},
    AttestationResult, RaContext, TokioRuntime,
};
use tokio::task::JoinHandle;
use tokio_util::io::ReaderStream;
use url::Url;

use crate::response::TngResponse;

pyo3::create_exception!(tng._native, TngTimeoutError, pyo3::exceptions::PyException);

/// Run a future with an optional timeout; raises `TngTimeoutError` on expiry.
async fn maybe_timeout<F, T>(fut: F, timeout_secs: Option<f64>, msg: &'static str) -> PyResult<T>
where
    F: std::future::Future<Output = PyResult<T>>,
{
    match timeout_secs {
        Some(secs) => tokio::time::timeout(Duration::from_secs_f64(secs), fut)
            .await
            .map_err(|_| TngTimeoutError::new_err(msg))?,
        None => fut.await,
    }
}

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

    /// Begin a streaming request. Returns a `RequestSender` that accepts
    /// body chunks via `write()`, then call `finish()` to complete the
    /// request and get the response.
    fn start_request(
        &self,
        method: &str,
        url: &str,
        headers: Vec<(String, String)>,
    ) -> PyResult<RequestSender> {
        let (request, endpoint, body_writer) = build_streaming_request(method, url, &headers)?;

        let security_layer = self.security_layer.clone();
        let rt = self.rt.clone();

        let handle = rt.spawn(async move {
            security_layer
                .forward_http_request(&endpoint, request)
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("{e:?}")))
        });

        Ok(RequestSender {
            body_writer: Arc::new(tokio::sync::Mutex::new(Some(body_writer))),
            handle: Some(handle),
            rt,
        })
    }
}

type ResponseResult = PyResult<(axum::response::Response, Option<AttestationResult>)>;

/// Handle for writing streaming request body chunks and completing the request.
///
/// Returned by `TngClient.start_request()`. Call `write()` for each body
/// chunk, then `finish()` to close the body stream and await the response.
#[pyclass]
pub struct RequestSender {
    body_writer: Arc<tokio::sync::Mutex<Option<tokio::io::DuplexStream>>>,
    handle: Option<JoinHandle<ResponseResult>>,
    rt: Arc<tokio::runtime::Runtime>,
}

#[pymethods]
impl RequestSender {
    /// Write a chunk of request body data. Blocks until the chunk is accepted.
    #[pyo3(signature = (data, timeout_secs=None))]
    fn write(&self, py: Python<'_>, data: Vec<u8>, timeout_secs: Option<f64>) -> PyResult<()> {
        let writer = self.body_writer.clone();
        let rt = self.rt.clone();

        py.allow_threads(move || {
            rt.block_on(async move {
                use tokio::io::AsyncWriteExt;
                maybe_timeout(
                    async {
                        let mut guard = writer.lock().await;
                        let w = guard.as_mut().ok_or_else(|| {
                            PyRuntimeError::new_err("request body already closed")
                        })?;
                        w.write_all(&data)
                            .await
                            .map_err(|e| PyRuntimeError::new_err(format!("write failed: {e}")))
                    },
                    timeout_secs,
                    "timed out writing request body",
                )
                .await
            })
        })
    }

    /// Write a chunk of request body data (async version).
    #[pyo3(signature = (data, timeout_secs=None))]
    fn write_async<'py>(
        &self,
        py: Python<'py>,
        data: Vec<u8>,
        timeout_secs: Option<f64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let writer = self.body_writer.clone();

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            use tokio::io::AsyncWriteExt;
            maybe_timeout(
                async {
                    let mut guard = writer.lock().await;
                    let w = guard
                        .as_mut()
                        .ok_or_else(|| PyRuntimeError::new_err("request body already closed"))?;
                    w.write_all(&data)
                        .await
                        .map_err(|e| PyRuntimeError::new_err(format!("write failed: {e}")))?;
                    Ok(())
                },
                timeout_secs,
                "timed out writing request body",
            )
            .await
        })
    }

    /// Close the body stream and await the response. Returns a `TngResponse`.
    #[pyo3(signature = (timeout_secs=None))]
    fn finish(&mut self, py: Python<'_>, timeout_secs: Option<f64>) -> PyResult<TngResponse> {
        let writer = self.body_writer.clone();
        let handle = self
            .handle
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("request already finished"))?;
        let rt = self.rt.clone();

        let (response, attestation_result) = py.allow_threads(|| {
            rt.block_on(async {
                drop(writer.lock().await.take());
                maybe_timeout(
                    async {
                        handle.await.map_err(|e| {
                            PyRuntimeError::new_err(format!("request task failed: {e}"))
                        })?
                    },
                    timeout_secs,
                    "timed out waiting for response",
                )
                .await
            })
        })?;

        Ok(TngResponse::from_http_response(
            response,
            attestation_result,
            rt,
        ))
    }

    /// Close the body stream and await the response (async version).
    #[pyo3(signature = (timeout_secs=None))]
    fn finish_async<'py>(
        &mut self,
        py: Python<'py>,
        timeout_secs: Option<f64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let writer = self.body_writer.clone();
        let handle = self
            .handle
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("request already finished"))?;
        let rt = self.rt.clone();

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            drop(writer.lock().await.take());
            let (response, attestation_result) = maybe_timeout(
                async {
                    handle.await.map_err(|e| {
                        PyRuntimeError::new_err(format!("request task failed: {e}"))
                    })?
                },
                timeout_secs,
                "timed out waiting for response",
            )
            .await?;
            Ok(TngResponse::from_http_response(
                response,
                attestation_result,
                rt,
            ))
        })
    }
}

fn build_streaming_request(
    method: &str,
    url: &str,
    headers: &[(String, String)],
) -> PyResult<(axum::extract::Request, TngEndpoint, tokio::io::DuplexStream)> {
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

    let (read_half, write_half) = tokio::io::duplex(65536);
    let body = axum::body::Body::from_stream(ReaderStream::new(read_half));

    let mut builder = http::Request::builder()
        .method(method)
        .uri(url)
        .version(http::Version::HTTP_11);

    for (k, v) in headers {
        builder = builder.header(k.as_str(), v.as_str());
    }

    let request = builder
        .body(body)
        .map_err(|e| PyRuntimeError::new_err(format!("Failed to build request: {e}")))?;

    Ok((request, endpoint, write_half))
}
