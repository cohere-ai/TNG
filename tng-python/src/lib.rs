use std::sync::Arc;

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;

mod runtime;

use runtime::TngHandle;

/// A running TNG ingress instance embedded in the Python process.
///
/// This starts TNG's ingress on a background tokio runtime, listening on an
/// ephemeral localhost port. Requests routed to this port are encrypted via
/// OHTTP and forwarded to the configured egress.
#[pyclass]
struct TngInstance {
    handle: Arc<TngHandle>,
}

#[pymethods]
impl TngInstance {
    /// Create and start a TNG ingress from a config dict.
    ///
    /// The config dict should contain the fields of a single `add_ingress` entry
    /// (mapping, ohttp, verify, etc.) or a full TngConfig.
    #[new]
    #[pyo3(signature = (config))]
    fn new(config: &Bound<'_, pyo3::types::PyAny>) -> PyResult<Self> {
        let config_str = pythondict_to_json(config)?;
        let handle = TngHandle::start(config_str)
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to start TNG: {e}")))?;
        Ok(Self {
            handle: Arc::new(handle),
        })
    }

    /// The localhost port TNG ingress is listening on.
    fn port(&self) -> u16 {
        self.handle.port()
    }

    /// Gracefully shut down the TNG ingress.
    fn close(&self) {
        self.handle.shutdown();
    }
}

impl Drop for TngInstance {
    fn drop(&mut self) {
        self.handle.shutdown();
    }
}

fn pythondict_to_json(obj: &Bound<'_, pyo3::types::PyAny>) -> PyResult<String> {
    let json_module = obj.py().import("json")?;
    let json_str = json_module.call_method1("dumps", (obj,))?;
    json_str.extract::<String>()
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<TngInstance>()?;
    Ok(())
}
