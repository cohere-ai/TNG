use std::sync::Arc;

use http_body_util::BodyExt;
use pyo3::exceptions::{PyRuntimeError, PyStopAsyncIteration, PyStopIteration};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use tokio::sync::mpsc;

type BodyReceiver = Arc<tokio::sync::Mutex<mpsc::Receiver<Result<Vec<u8>, String>>>>;

/// An HTTP response returned by `TngClient.send()` / `send_async()`.
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
    rt: Arc<tokio::runtime::Runtime>,
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

        rt.spawn(async move {
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
            rt,
        }
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

    /// Read the entire remaining body and return it as a single `bytes` object.
    fn read_all<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let rx = self.body_rx.clone();
        let rt = self.rt.clone();

        let result = py.allow_threads(|| {
            rt.block_on(async {
                let mut guard = rx.lock().await;
                let mut buf = Vec::new();
                while let Some(chunk) = guard.recv().await {
                    match chunk {
                        Ok(data) => buf.extend_from_slice(&data),
                        Err(e) => return Err(e),
                    }
                }
                Ok(buf)
            })
        });

        match result {
            Ok(data) => Ok(PyBytes::new(py, &data)),
            Err(e) => Err(PyRuntimeError::new_err(e)),
        }
    }

    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    /// Yield the next chunk of body bytes (sync iteration).
    /// Blocks the calling thread (releasing the GIL) until data arrives.
    fn __next__<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyBytes>>> {
        let rx = self.body_rx.clone();
        let rt = self.rt.clone();

        let result = py.allow_threads(|| rt.block_on(async { rx.lock().await.recv().await }));

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

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let chunk = rx.lock().await.recv().await;
            match chunk {
                Some(Ok(data)) => Ok(data),
                Some(Err(e)) => Err(PyRuntimeError::new_err(e)),
                None => Err(PyStopAsyncIteration::new_err(())),
            }
        })
    }
}
