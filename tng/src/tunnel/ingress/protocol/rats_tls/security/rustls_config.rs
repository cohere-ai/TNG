use std::sync::Arc;

use crate::tunnel::utils::rustls_config::TlsConfigGenerator;
use anyhow::Result;
use rustls::RootCertStore;

use super::cert_verifier::{dummy::DummyServerCertVerifier, ra::TngServerCertVerifier};

impl TlsConfigGenerator {
    pub async fn get_one_time_rustls_client_config(&self) -> Result<OnetimeTlsClientConfig> {
        let mut config = match self {
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

                OnetimeTlsClientConfig {
                    config: tls_client_config,
                    verifier: None,
                    attested_key: None,
                }
            }
            TlsConfigGenerator::Verify(verify_ctx) => {
                let mut tls_client_config =
                    rustls::ClientConfig::builder_with_protocol_versions(&[
                        &rustls::version::TLS13,
                    ])
                    .with_root_certificates(RootCertStore::empty())
                    .with_no_client_auth();

                let verifier: Arc<TngServerCertVerifier> =
                    Arc::new(TngServerCertVerifier::new(verify_ctx.clone())?);
                tls_client_config
                    .dangerous()
                    .set_certificate_verifier(verifier.clone());

                OnetimeTlsClientConfig {
                    config: tls_client_config,
                    verifier: Some(verifier),
                    attested_key: None,
                }
            }
            #[cfg(unix)]
            TlsConfigGenerator::Attest(cert_manager) => {
                let key = cert_manager.get_latest_cert().await?;
                let mut tls_client_config =
                    rustls::ClientConfig::builder_with_protocol_versions(&[
                        &rustls::version::TLS13,
                    ])
                    .with_root_certificates(RootCertStore::empty())
                    .with_client_cert_resolver(Arc::new(
                        rustls::sign::SingleCertAndKey::from(key.as_ref().clone()),
                    ));
                tls_client_config
                    .dangerous()
                    .set_certificate_verifier(Arc::new(DummyServerCertVerifier::new()?));

                OnetimeTlsClientConfig {
                    config: tls_client_config,
                    verifier: None,
                    attested_key: Some(key),
                }
            }
            #[cfg(unix)]
            TlsConfigGenerator::AttestAndVerify(cert_manager, verify_ctx) => {
                let key = cert_manager.get_latest_cert().await?;
                let mut tls_client_config =
                    rustls::ClientConfig::builder_with_protocol_versions(&[
                        &rustls::version::TLS13,
                    ])
                    .with_root_certificates(RootCertStore::empty())
                    .with_client_cert_resolver(Arc::new(
                        rustls::sign::SingleCertAndKey::from(key.as_ref().clone()),
                    ));

                let verifier: Arc<TngServerCertVerifier> =
                    Arc::new(TngServerCertVerifier::new(verify_ctx.clone())?);
                tls_client_config
                    .dangerous()
                    .set_certificate_verifier(verifier.clone());

                OnetimeTlsClientConfig {
                    config: tls_client_config,
                    verifier: Some(verifier),
                    attested_key: Some(key),
                }
            }
        };

        config.config.alpn_protocols = vec![b"h2".to_vec()];
        config.config.resumption = rustls::client::Resumption::disabled();

        Ok(config)
    }
}

pub struct OnetimeTlsClientConfig {
    pub config: rustls::ClientConfig,
    pub verifier: Option<Arc<TngServerCertVerifier>>,
    pub attested_key: Option<Arc<rustls::sign::CertifiedKey>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::ServerName;
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    use crate::tunnel::attestation_exchange::exporter::{export_from_client, export_from_server};
    use crate::tunnel::utils::rustls_config::RustlsDummyCert;

    async fn handshake() -> (
        tokio_rustls::client::TlsStream<tokio::io::DuplexStream>,
        tokio_rustls::server::TlsStream<tokio::io::DuplexStream>,
    ) {
        let (client_io, server_io) = tokio::io::duplex(8192);

        let mut server_config =
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_cert_resolver(RustlsDummyCert::new_rustls_cert().unwrap());
        server_config.send_tls13_tickets = 0;

        let mut client_config =
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth();
        client_config
            .dangerous()
            .set_certificate_verifier(Arc::new(DummyServerCertVerifier::new().unwrap()));
        client_config.resumption = rustls::client::Resumption::disabled();

        let server = TlsAcceptor::from(Arc::new(server_config)).accept(server_io);
        let client = TlsConnector::from(Arc::new(client_config))
            .connect(ServerName::try_from("localhost").unwrap(), client_io);
        let (client, server) = tokio::join!(client, server);
        (client.unwrap(), server.unwrap())
    }

    #[tokio::test]
    async fn exporters_match_on_both_ends() {
        let (client, server) = handshake().await;
        let ctx = Some(&b""[..]);
        let c = export_from_client(&client, ctx).unwrap();
        let s = export_from_server(&server, ctx).unwrap();
        assert_eq!(c, s);
    }

    #[tokio::test]
    async fn sequential_connections_derive_different_exporters() {
        let (c1, _) = handshake().await;
        let (c2, _) = handshake().await;
        let ctx = Some(&b""[..]);
        assert_ne!(
            export_from_client(&c1, ctx).unwrap(),
            export_from_client(&c2, ctx).unwrap()
        );
    }

    #[tokio::test]
    async fn nora_configs_disable_resumption_and_have_no_attested_key() {
        let server = TlsConfigGenerator::NoRa
            .get_one_time_rustls_server_config()
            .await
            .unwrap();
        assert_eq!(server.config.send_tls13_tickets, 0);
        assert!(server.attested_key.is_none());

        let client = TlsConfigGenerator::NoRa
            .get_one_time_rustls_client_config()
            .await
            .unwrap();
        assert!(client.attested_key.is_none());
    }
}
