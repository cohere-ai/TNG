use std::sync::Arc;
use std::time::Duration;

use http_body_util::BodyExt;
use pyo3::exceptions::{PyRuntimeError, PyStopAsyncIteration};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::client::TngTimeoutError;

type BodyReceiver = Arc<tokio::sync::Mutex<mpsc::Receiver<Result<Vec<u8>, String>>>>;

/// An HTTP response returned by `RequestSender.finish()` / `finish_async()`.
///
/// The response body is streamed via a background tokio task that drains
/// the axum body into an mpsc channel. Consumers can either iterate
/// chunk-by-chunk (`__iter__`/`__aiter__`) or read everything at once
/// (`read_all()`).
#[pyclass]
pub struct TngResponse {
    status: u16,
    headers: Vec<(String, String)>,
    attestation_token: Option<String>,
    body_rx: BodyReceiver,
    drain_handle: Arc<tokio::sync::Mutex<Option<JoinHandle<()>>>>,
    rt: Arc<tokio::runtime::Runtime>,
    read_timeout_secs: std::sync::Mutex<Option<f64>>,
}

impl TngResponse {
    pub fn from_http_response(
        response: axum::response::Response,
        attestation_result: Option<tng::AttestationResult>,
        rt: Arc<tokio::runtime::Runtime>,
    ) -> Self {
        let (parts, body) = response.into_parts();

        let status = parts.status.as_u16();
        let headers = parts
            .headers
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        let attestation_token = attestation_result.and_then(|ar| {
            serde_json::to_value(&ar)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
        });

        let (tx, rx) = mpsc::channel(32);

        let handle = rt.spawn(async move {
            let mut body = body;
            loop {
                match body.frame().await {
                    Some(Ok(frame)) => {
                        if let Some(data) = frame.data_ref() {
                            if tx.send(Ok(data.to_vec())).await.is_err() {
                                break;
                            }
                        }
                    }
                    Some(Err(e)) => {
                        let _ = tx.send(Err(e.to_string())).await;
                        break;
                    }
                    None => break,
                }
            }
        });

        Self {
            status,
            headers,
            attestation_token,
            body_rx: Arc::new(tokio::sync::Mutex::new(rx)),
            drain_handle: Arc::new(tokio::sync::Mutex::new(Some(handle))),
            rt,
            read_timeout_secs: std::sync::Mutex::new(None),
        }
    }
}

impl TngResponse {
    fn read_timeout(&self) -> Option<Duration> {
        self.read_timeout_secs
            .lock()
            .unwrap()
            .map(Duration::from_secs_f64)
    }
}

/// Receive a single chunk with an optional per-chunk timeout.
/// Returns `Ok(None)` at end-of-stream, `Ok(Some(...))` for a chunk,
/// or `Err(TngTimeoutError)` on timeout.
async fn recv_with_timeout(
    rx: &BodyReceiver,
    timeout: Option<Duration>,
) -> PyResult<Option<Result<Vec<u8>, String>>> {
    let mut guard = rx.lock().await;
    if let Some(dur) = timeout {
        tokio::time::timeout(dur, guard.recv())
            .await
            .map_err(|_| TngTimeoutError::new_err("timed out reading response body"))
    } else {
        Ok(guard.recv().await)
    }
}

#[pymethods]
impl TngResponse {
    #[getter]
    fn status(&self) -> u16 {
        self.status
    }

    #[getter]
    fn headers(&self) -> Vec<(String, String)> {
        self.headers.clone()
    }

    #[getter]
    fn attestation_token(&self) -> Option<String> {
        self.attestation_token.clone()
    }

    /// Set the per-chunk read timeout for body streaming operations.
    ///
    /// When set, `__next__`, `__anext__`, and `read_all` will raise
    /// `TngTimeoutError` if a chunk takes longer than this to arrive.
    #[pyo3(signature = (timeout_secs=None))]
    fn set_read_timeout(&self, timeout_secs: Option<f64>) {
        *self.read_timeout_secs.lock().unwrap() = timeout_secs;
    }

    /// Read the entire remaining body and return it as a single `bytes` object.
    fn read_all<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let rx = self.body_rx.clone();
        let rt = self.rt.clone();
        let timeout = self.read_timeout();

        let data = py.allow_threads(|| {
            rt.block_on(async {
                let mut buf = Vec::new();
                while let Some(chunk) = recv_with_timeout(&rx, timeout).await? {
                    match chunk {
                        Ok(data) => buf.extend_from_slice(&data),
                        Err(e) => return Err(PyRuntimeError::new_err(e)),
                    }
                }
                Ok(buf)
            })
        })?;

        Ok(PyBytes::new(py, &data))
    }

    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    /// Yield the next chunk of body bytes (sync iteration).
    /// Blocks the calling thread (releasing the GIL) until data arrives.
    fn __next__<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyBytes>>> {
        let rx = self.body_rx.clone();
        let rt = self.rt.clone();
        let timeout = self.read_timeout();

        let result = py.allow_threads(|| rt.block_on(recv_with_timeout(&rx, timeout)))?;

        match result {
            Some(Ok(data)) => Ok(Some(PyBytes::new(py, &data))),
            Some(Err(e)) => Err(PyRuntimeError::new_err(e)),
            None => Ok(None),
        }
    }

    fn __aiter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    /// Yield the next chunk of body bytes (async iteration).
    fn __anext__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let rx = self.body_rx.clone();
        let timeout = self.read_timeout();

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            match recv_with_timeout(&rx, timeout).await? {
                Some(Ok(data)) => Ok(data),
                Some(Err(e)) => Err(PyRuntimeError::new_err(e)),
                None => Err(PyStopAsyncIteration::new_err(())),
            }
        })
    }

    /// Cancel the background body-drain task and close the receiver.
    ///
    /// Safe to call multiple times. After close(), iteration will yield no
    /// further chunks.
    fn close(&self, py: Python<'_>) {
        let handle = self.drain_handle.clone();
        let rx = self.body_rx.clone();
        let rt = self.rt.clone();

        py.allow_threads(|| {
            rt.block_on(async {
                if let Some(h) = handle.lock().await.take() {
                    h.abort();
                }
                rx.lock().await.close();
            });
        });
    }

    /// Async version of close().
    fn close_async<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let handle = self.drain_handle.clone();
        let rx = self.body_rx.clone();

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            if let Some(h) = handle.lock().await.take() {
                h.abort();
            }
            rx.lock().await.close();
            Ok(())
        })
    }
}
