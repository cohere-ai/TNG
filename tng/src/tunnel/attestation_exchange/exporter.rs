use anyhow::{anyhow, Result};
use rustls::sign::CertifiedKey;
use rustls::ConnectionCommon;

use super::claims::{EXPORTER_LABEL, EXPORTER_LEN};

pub fn spki_from_certified_key(key: &CertifiedKey) -> Result<Vec<u8>> {
    let cert = key
        .cert
        .first()
        .ok_or_else(|| anyhow!("certified key has no certificate"))?;
    rats_cert::cert::verify::spki_der_from_x509_der(cert.as_ref())
        .map_err(|e| anyhow!("failed to extract SPKI from attested certificate: {e:?}"))
}

pub fn export_from_conn<Data>(
    conn: &ConnectionCommon<Data>,
    context: Option<&[u8]>,
) -> Result<[u8; EXPORTER_LEN]> {
    let mut out = [0u8; EXPORTER_LEN];
    conn.export_keying_material(&mut out[..], EXPORTER_LABEL, context)
        .map_err(|e| anyhow!("TLS exporter failed: {e}"))?;
    Ok(out)
}

pub fn export_from_server<IO>(
    stream: &tokio_rustls::server::TlsStream<IO>,
    context: Option<&[u8]>,
) -> Result<[u8; EXPORTER_LEN]> {
    export_from_conn(stream.get_ref().1, context)
}

pub fn export_from_client<IO>(
    stream: &tokio_rustls::client::TlsStream<IO>,
    context: Option<&[u8]>,
) -> Result<[u8; EXPORTER_LEN]> {
    export_from_conn(stream.get_ref().1, context)
}
