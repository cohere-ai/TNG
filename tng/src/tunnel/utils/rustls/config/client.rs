use std::sync::Arc;

use anyhow::Result;
use rustls::RootCertStore;

use crate::tunnel::utils::rustls::{
    config::{alpn::Alpn, TlsConfigGenerator},
    dummy::verifier::DummyServerCertVerifier,
    ra::server_cert_verifier::LazyServerCertVerifier,
};

impl TlsConfigGenerator {
    pub async fn get_lazy_one_time_rustls_client_config(
        &self,
        alpn: Alpn,
    ) -> Result<LazyOnetimeTlsClientConfig> {
        let mut config =
            match self {
                TlsConfigGenerator::NoRa => {
                    let mut tls_client_config =
                        rustls::ClientConfig::builder_with_protocol_versions(&[
                            &rustls::version::TLS13,
                        ])
                        .with_root_certificates(RootCertStore::empty())
                        .with_no_client_auth();

                    tls_client_config
                        .dangerous()
                        .set_certificate_verifier(Arc::new(DummyServerCertVerifier::new()?));

                    LazyOnetimeTlsClientConfig(tls_client_config, None)
                }
                TlsConfigGenerator::Verify(_runtime, verify_ctx) => {
                    let mut tls_client_config =
                        rustls::ClientConfig::builder_with_protocol_versions(&[
                            &rustls::version::TLS13,
                        ])
                        .with_root_certificates(RootCertStore::empty())
                        .with_no_client_auth();

                    let verifier: Arc<LazyServerCertVerifier> =
                        Arc::new(LazyServerCertVerifier::new(verify_ctx.clone())?);
                    tls_client_config
                        .dangerous()
                        .set_certificate_verifier(verifier.clone());

                    LazyOnetimeTlsClientConfig(tls_client_config, Some(verifier))
                }
                #[cfg(unix)]
                TlsConfigGenerator::Attest(_runtime, cert_manager) => {
                    let mut tls_client_config =
                        rustls::ClientConfig::builder_with_protocol_versions(&[
                            &rustls::version::TLS13,
                        ])
                        .with_root_certificates(RootCertStore::empty())
                        .with_client_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(
                            cert_manager.get_latest_cert().await?.as_ref().clone(),
                        )));
                    tls_client_config
                        .dangerous()
                        .set_certificate_verifier(Arc::new(DummyServerCertVerifier::new()?));

                    LazyOnetimeTlsClientConfig(tls_client_config, None)
                }
                #[cfg(unix)]
                TlsConfigGenerator::AttestAndVerify(_runtime, cert_manager, verify_ctx) => {
                    let mut tls_client_config =
                        rustls::ClientConfig::builder_with_protocol_versions(&[
                            &rustls::version::TLS13,
                        ])
                        .with_root_certificates(RootCertStore::empty())
                        .with_client_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(
                            cert_manager.get_latest_cert().await?.as_ref().clone(),
                        )));

                    let verifier: Arc<LazyServerCertVerifier> =
                        Arc::new(LazyServerCertVerifier::new(verify_ctx.clone())?);
                    tls_client_config
                        .dangerous()
                        .set_certificate_verifier(verifier.clone());

                    LazyOnetimeTlsClientConfig(tls_client_config, Some(verifier))
                }
            };

        config.0.alpn_protocols = vec![alpn.as_bytes().to_vec()];

        Ok(config)
    }
}

pub struct LazyOnetimeTlsClientConfig(
    pub rustls::ClientConfig,
    pub Option<Arc<LazyServerCertVerifier>>,
);

#[cfg(not(wasm))]
impl TlsConfigGenerator {
    pub async fn get_blocking_one_time_rustls_client_config(
        &self,
        alpn: Alpn,
    ) -> Result<BlockingOnetimeTlsClientConfig> {
        use crate::tunnel::utils::rustls::ra::server_cert_verifier::BlockingServerCertVerifier;

        let mut config =
            match self {
                TlsConfigGenerator::NoRa => {
                    let mut tls_client_config =
                        rustls::ClientConfig::builder_with_protocol_versions(&[
                            &rustls::version::TLS13,
                        ])
                        .with_root_certificates(RootCertStore::empty())
                        .with_no_client_auth();

                    tls_client_config
                        .dangerous()
                        .set_certificate_verifier(Arc::new(DummyServerCertVerifier::new()?));

                    BlockingOnetimeTlsClientConfig(tls_client_config)
                }
                TlsConfigGenerator::Verify(runtime, verify_ctx) => {
                    let mut tls_client_config =
                        rustls::ClientConfig::builder_with_protocol_versions(&[
                            &rustls::version::TLS13,
                        ])
                        .with_root_certificates(RootCertStore::empty())
                        .with_no_client_auth();

                    let verifier: Arc<BlockingServerCertVerifier> = Arc::new(
                        BlockingServerCertVerifier::new(runtime.clone(), verify_ctx.clone())?,
                    );
                    tls_client_config
                        .dangerous()
                        .set_certificate_verifier(verifier.clone());

                    BlockingOnetimeTlsClientConfig(tls_client_config)
                }
                #[cfg(unix)]
                TlsConfigGenerator::Attest(_runtime, cert_manager) => {
                    let mut tls_client_config =
                        rustls::ClientConfig::builder_with_protocol_versions(&[
                            &rustls::version::TLS13,
                        ])
                        .with_root_certificates(RootCertStore::empty())
                        .with_client_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(
                            cert_manager.get_latest_cert().await?.as_ref().clone(),
                        )));
                    tls_client_config
                        .dangerous()
                        .set_certificate_verifier(Arc::new(DummyServerCertVerifier::new()?));

                    BlockingOnetimeTlsClientConfig(tls_client_config)
                }
                #[cfg(unix)]
                TlsConfigGenerator::AttestAndVerify(runtime, cert_manager, verify_ctx) => {
                    let mut tls_client_config =
                        rustls::ClientConfig::builder_with_protocol_versions(&[
                            &rustls::version::TLS13,
                        ])
                        .with_root_certificates(RootCertStore::empty())
                        .with_client_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(
                            cert_manager.get_latest_cert().await?.as_ref().clone(),
                        )));

                    let verifier: Arc<BlockingServerCertVerifier> = Arc::new(
                        BlockingServerCertVerifier::new(runtime.clone(), verify_ctx.clone())?,
                    );
                    tls_client_config
                        .dangerous()
                        .set_certificate_verifier(verifier.clone());

                    BlockingOnetimeTlsClientConfig(tls_client_config)
                }
            };

        config.0.alpn_protocols = vec![alpn.as_bytes().to_vec()];

        Ok(config)
    }
}

#[cfg(not(wasm))]
pub struct BlockingOnetimeTlsClientConfig(pub rustls::ClientConfig);
