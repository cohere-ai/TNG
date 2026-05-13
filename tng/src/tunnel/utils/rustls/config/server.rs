use std::sync::Arc;

use anyhow::Result;
use rustls::ServerConfig;

use crate::tunnel::utils::rustls::{
    config::{alpn::Alpn, TlsConfigGenerator},
    dummy::RustlsDummyCert,
    ra::client_cert_verifier::LazyClientCertVerifier,
};

impl TlsConfigGenerator {
    pub async fn get_lazy_one_time_rustls_server_config(
        &self,
        alpn: Alpn,
    ) -> Result<LazyOnetimeTlsServerConfig> {
        let mut config = match self {
            TlsConfigGenerator::NoRa => {
                let tls_server_config =
                    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                        .with_no_client_auth()
                        .with_cert_resolver(RustlsDummyCert::new_rustls_cert()?);
                LazyOnetimeTlsServerConfig(tls_server_config, None)
            }
            TlsConfigGenerator::Verify(_runtime, verify_ctx) => {
                let verifier = Arc::new(LazyClientCertVerifier::new(verify_ctx.clone())?);
                let tls_server_config: ServerConfig =
                    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                        .with_client_cert_verifier(verifier.clone())
                        .with_cert_resolver(RustlsDummyCert::new_rustls_cert()?);
                LazyOnetimeTlsServerConfig(tls_server_config, Some(verifier))
            }
            TlsConfigGenerator::Attest(_runtime, cert_manager) => {
                let tls_server_config: ServerConfig =
                    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                        .with_no_client_auth()
                        .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(
                            cert_manager.get_latest_cert().await?.as_ref().clone(),
                        )));
                LazyOnetimeTlsServerConfig(tls_server_config, None)
            }
            TlsConfigGenerator::AttestAndVerify(_runtime, cert_manager, verify_ctx) => {
                let verifier = Arc::new(LazyClientCertVerifier::new(verify_ctx.clone())?);
                let tls_server_config: ServerConfig =
                    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                        .with_client_cert_verifier(verifier.clone())
                        .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(
                            cert_manager.get_latest_cert().await?.as_ref().clone(),
                        )));
                LazyOnetimeTlsServerConfig(tls_server_config, Some(verifier))
            }
        };
        config.0.alpn_protocols = vec![alpn.as_bytes().to_vec()];

        Ok(config)
    }
}

pub struct LazyOnetimeTlsServerConfig(
    pub rustls::ServerConfig,
    pub Option<Arc<LazyClientCertVerifier>>,
);

#[cfg(not(wasm))]
impl TlsConfigGenerator {
    pub async fn get_blocking_one_time_rustls_server_config(
        &self,
        alpn: Alpn,
    ) -> Result<BlockingOnetimeTlsServerConfig> {
        use crate::tunnel::utils::rustls::ra::client_cert_verifier::BlockingClientCertVerifier;

        let mut config = match self {
            TlsConfigGenerator::NoRa => {
                let tls_server_config =
                    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                        .with_no_client_auth()
                        .with_cert_resolver(RustlsDummyCert::new_rustls_cert()?);
                BlockingOnetimeTlsServerConfig(tls_server_config)
            }
            TlsConfigGenerator::Verify(runtime, verify_ctx) => {
                let verifier = Arc::new(BlockingClientCertVerifier::new(
                    runtime.clone(),
                    verify_ctx.clone(),
                )?);
                let tls_server_config: ServerConfig =
                    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                        .with_client_cert_verifier(verifier)
                        .with_cert_resolver(RustlsDummyCert::new_rustls_cert()?);
                BlockingOnetimeTlsServerConfig(tls_server_config)
            }
            TlsConfigGenerator::Attest(_runtime, cert_manager) => {
                let tls_server_config: ServerConfig =
                    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                        .with_no_client_auth()
                        .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(
                            cert_manager.get_latest_cert().await?.as_ref().clone(),
                        )));
                BlockingOnetimeTlsServerConfig(tls_server_config)
            }
            TlsConfigGenerator::AttestAndVerify(runtime, cert_manager, verify_ctx) => {
                let verifier = Arc::new(BlockingClientCertVerifier::new(
                    runtime.clone(),
                    verify_ctx.clone(),
                )?);
                let tls_server_config: ServerConfig =
                    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                        .with_client_cert_verifier(verifier)
                        .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(
                            cert_manager.get_latest_cert().await?.as_ref().clone(),
                        )));
                BlockingOnetimeTlsServerConfig(tls_server_config)
            }
        };
        config.0.alpn_protocols = vec![alpn.as_bytes().to_vec()];

        Ok(config)
    }
}

#[cfg(not(wasm))]
pub struct BlockingOnetimeTlsServerConfig(pub rustls::ServerConfig);
