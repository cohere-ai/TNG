use anyhow::{anyhow, Result};
use rustls::sign::CertifiedKey;

use super::claims::{EXPORTER_LABEL, EXPORTER_LEN};

pub fn spki_from_certified_key(key: &CertifiedKey) -> Result<Vec<u8>> {
    let cert = key
        .cert
        .first()
        .ok_or_else(|| anyhow!("certified key has no certificate"))?;
    rats_cert::cert::spki_der_from_x509_der(cert.as_ref())
        .map_err(|e| anyhow!("failed to extract SPKI from attested certificate: {e:?}"))
}

pub fn export_from_server<IO>(
    stream: &tokio_rustls::server::TlsStream<IO>,
    context: Option<&[u8]>,
) -> Result<[u8; EXPORTER_LEN]> {
    let mut out = [0u8; EXPORTER_LEN];
    stream
        .get_ref()
        .1
        .export_keying_material(&mut out[..], EXPORTER_LABEL, context)
        .map_err(|e| anyhow!("TLS exporter failed: {e}"))?;
    Ok(out)
}

pub fn export_from_client<IO>(
    stream: &tokio_rustls::client::TlsStream<IO>,
    context: Option<&[u8]>,
) -> Result<[u8; EXPORTER_LEN]> {
    let mut out = [0u8; EXPORTER_LEN];
    stream
        .get_ref()
        .1
        .export_keying_material(&mut out[..], EXPORTER_LABEL, context)
        .map_err(|e| anyhow!("TLS exporter failed: {e}"))?;
    Ok(out)
}
