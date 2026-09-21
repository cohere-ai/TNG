use std::sync::Arc;

use crate::tunnel::utils::rustls_config::{RustlsDummyCert, TlsConfigGenerator};
use anyhow::Result;
use rustls::ServerConfig;

use super::cert_verifier::TngClientCertVerifier;

impl TlsConfigGenerator {
    pub async fn get_one_time_rustls_server_config(&self) -> Result<OnetimeTlsServerConfig> {
        let mut config = match self {
            TlsConfigGenerator::NoRa => {
                let tls_server_config =
                    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                        .with_no_client_auth()
                        .with_cert_resolver(RustlsDummyCert::new_rustls_cert()?);
                OnetimeTlsServerConfig {
                    config: tls_server_config,
                    verifier: None,
                    attested_key: None,
                }
            }
            TlsConfigGenerator::Verify(verify_ctx) => {
                let verifier = Arc::new(TngClientCertVerifier::new(verify_ctx.clone())?);
                let tls_server_config: ServerConfig =
                    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                        .with_client_cert_verifier(verifier.clone())
                        .with_cert_resolver(RustlsDummyCert::new_rustls_cert()?);
                OnetimeTlsServerConfig {
                    config: tls_server_config,
                    verifier: Some(verifier),
                    attested_key: None,
                }
            }
            TlsConfigGenerator::Attest(cert_manager) => {
                let key = cert_manager.get_latest_cert().await?;
                let tls_server_config: ServerConfig =
                    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                        .with_no_client_auth()
                        .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(
                            key.as_ref().clone(),
                        )));
                OnetimeTlsServerConfig {
                    config: tls_server_config,
                    verifier: None,
                    attested_key: Some(key),
                }
            }
            TlsConfigGenerator::AttestAndVerify(cert_manager, verify_ctx) => {
                let verifier = Arc::new(TngClientCertVerifier::new(verify_ctx.clone())?);
                let key = cert_manager.get_latest_cert().await?;
                let tls_server_config: ServerConfig =
                    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                        .with_client_cert_verifier(verifier.clone())
                        .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(
                            key.as_ref().clone(),
                        )));
                OnetimeTlsServerConfig {
                    config: tls_server_config,
                    verifier: Some(verifier),
                    attested_key: Some(key),
                }
            }
        };
        config.config.alpn_protocols = vec![b"h2".to_vec()];
        config.config.send_tls13_tickets = 0;

        Ok(config)
    }
}

pub struct OnetimeTlsServerConfig {
    pub config: rustls::ServerConfig,
    pub verifier: Option<Arc<TngClientCertVerifier>>,
    pub attested_key: Option<Arc<rustls::sign::CertifiedKey>>,
}
