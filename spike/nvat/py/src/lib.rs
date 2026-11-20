use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;

/// `verify(mode, report_path, certs_path, nonce_hex)`: nvat-spike-verify's JSON output.
#[pyfunction]
fn verify(mode: &str, report: &str, certs: &str, nonce: &str) -> PyResult<String> {
    let out = nvat_spike_verify::run(mode, report, certs, nonce)
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    Ok(serde_json::to_string_pretty(&out).unwrap())
}

#[pymodule]
fn nvat_spike(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(verify, m)?)
}
