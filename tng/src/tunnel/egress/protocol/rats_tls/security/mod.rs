mod cert_verifier;
mod rustls_config;

use std::sync::Arc;

use crate::tunnel::{
    attestation_exchange::finish_rats_tls_server,
    attestation_result::AttestationResult,
    ra_context::RaContext,
    stream::CommonStreamTrait,
    utils::{runtime::TokioRuntime, rustls_config::TlsConfigGenerator},
};
use anyhow::{Context as _, Result};
use rustls_config::OnetimeTlsServerConfig;
use tokio_rustls::TlsAcceptor;
use tracing::Instrument;

pub(super) struct RatsTlsSecurityLayer {
    ra_context: Arc<RaContext>,
    tls_config_generator: TlsConfigGenerator,
}

impl RatsTlsSecurityLayer {
    pub async fn new(ra_context: Arc<RaContext>, runtime: TokioRuntime) -> Result<Self> {
        let tls_config_generator = TlsConfigGenerator::new(ra_context.clone(), runtime).await?;

        Ok(Self {
            ra_context,
            tls_config_generator,
        })
    }

    pub async fn handshake<T: CommonStreamTrait + std::marker::Sync>(
        &self,
        stream: T,
    ) -> Result<(
        tokio_rustls::server::TlsStream<T>,
        Option<AttestationResult>,
    )> {
        async {
            // Prepare TLS config
            let OnetimeTlsServerConfig {
                config: tls_server_config,
                verifier,
                attested_key,
            } = self
                .tls_config_generator
                .get_one_time_rustls_server_config()
                .await?;

            let tls_acceptor = TlsAcceptor::from(Arc::new(tls_server_config));
            tracing::debug!("Start to estabilish rats-tls connection");

            async {
                let security_layer_stream = tls_acceptor.accept(stream).await?;

                let (security_layer_stream, attestation_result) = finish_rats_tls_server(
                    security_layer_stream,
                    self.ra_context.as_ref(),
                    verifier.as_ref().map(|v| &v.common),
                    attested_key.as_deref(),
                )
                .await?;

                tracing::debug!("New rats-tls connection established");
                Ok::<_, anyhow::Error>((security_layer_stream, attestation_result))
            }
            .await
            .context("Failed to accept rats-tls connection from downstream")
        }
        .instrument(tracing::info_span!("security"))
        .await
    }
}
