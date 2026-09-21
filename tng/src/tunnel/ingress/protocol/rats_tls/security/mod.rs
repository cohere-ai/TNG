mod cert_verifier;
pub mod pool;
mod rustls_config;

use std::{
    collections::HashMap,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    task::Poll,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result};
use http::Uri;
use hyper_util::client::legacy::Client;
use pin_project::pin_project;
use pool::{ClientPool, HyperClientType, PoolKey};
use rustls::pki_types::ServerName;
use rustls_config::OnetimeTlsClientConfig;
use tokio::sync::RwLock;
use tokio_rustls::TlsConnector;
use tracing::{Instrument, Span};

use crate::{
    tunnel::{
        attestation_exchange::{
            exporter::{export_from_client, spki_from_certified_key},
            finish_rats_tls, RawEvidenceVerifier,
        },
        attestation_result::AttestationResult,
        endpoint::TngEndpoint,
        ingress::protocol::rats_tls::wrapping::RatsTlsWrappingLayer,
        ra_context::RaContext,
        utils::{runtime::TokioRuntime, rustls_config::TlsConfigGenerator, tokio::TokioIo},
    },
    CommonStreamTrait,
};

use super::transport::{RatsTlsTransportLayerConnector, RatsTlsTransportLayerCreator};

#[derive(Clone)]
pub struct RatsTlsClient {
    pub id: u64,
    pub hyper: HyperClientType,
    created_at: Instant,
}

pub struct RatsTlsSecurityLayer {
    next_id: AtomicU64,
    pool: RwLock<ClientPool>,
    transport_layer_creator: RatsTlsTransportLayerCreator,
    tls_config_generator: Arc<TlsConfigGenerator>,
    ra_context: Arc<RaContext>,
    runtime: TokioRuntime,
    pool_ttl: Duration,
}

impl RatsTlsSecurityLayer {
    pub async fn new(
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        transport_so_mark: Option<u32>,
        ra_context: Arc<RaContext>,
        runtime: TokioRuntime,
        pool_ttl: Duration,
    ) -> Result<Self> {
        let transport_layer_creator = RatsTlsTransportLayerCreator::new(
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            transport_so_mark,
        );
        let tls_config_generator =
            Arc::new(TlsConfigGenerator::new(ra_context.clone(), runtime.clone()).await?);

        Ok(Self {
            next_id: AtomicU64::new(0),
            pool: RwLock::new(HashMap::new()),
            transport_layer_creator,
            tls_config_generator,
            ra_context,
            runtime,
            pool_ttl,
        })
    }

    async fn create_security_connector(
        &self,
        pool_key: &PoolKey,
        parent_span: Span,
    ) -> Result<SecurityConnector> {
        let transport_layer_connector =
            self.transport_layer_creator.create(pool_key, parent_span)?;

        Ok(SecurityConnector {
            tls_config_generator: self.tls_config_generator.clone(),
            ra_context: self.ra_context.clone(),
            transport_layer_connector,
            security_layer_span: Span::current(),
        })
    }

    pub(crate) async fn get_client(&self, pool_key: &PoolKey) -> Result<RatsTlsClient> {
        self.get_client_with_span(pool_key, Span::current())
            .instrument(tracing::info_span!(
                "security",
                session_id = tracing::field::Empty
            ))
            .await
    }

    async fn get_client_with_span(
        &self,
        pool_key: &PoolKey,
        parent_span: Span,
    ) -> Result<RatsTlsClient> {
        let client = {
            let read = self.pool.read().await;
            read.get(pool_key).cloned()
        };

        if let Some(c) = client {
            if c.created_at.elapsed() < self.pool_ttl {
                Span::current().record("session_id", c.id);
                tracing::debug!(session_id = c.id, "Reuse existed rats-tls session");
                return Ok(c);
            }
        }

        let mut write = self.pool.write().await;
        if let Some(c) = write.get(pool_key) {
            if c.created_at.elapsed() < self.pool_ttl {
                Span::current().record("session_id", c.id);
                tracing::debug!(session_id = c.id, "Reuse existed rats-tls session");
                return Ok(c.clone());
            }
            // Evict without closing: in-flight clones of the hyper client drain naturally.
            write.remove(pool_key);
        }

        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        Span::current().record("session_id", id);
        tracing::debug!(
            session_id = id,
            "No rats-tls session found, create a new one"
        );

        let connector = self
            .create_security_connector(pool_key, parent_span)
            .await?;
        let client = RatsTlsClient {
            id,
            hyper: Client::builder(self.runtime.clone()).build(connector),
            created_at: Instant::now(),
        };
        write.insert(pool_key.to_owned(), client.clone());
        Ok(client)
    }

    pub async fn allocate_secured_stream(
        &self,
        endpoint: TngEndpoint,
    ) -> Result<(
        impl CommonStreamTrait + Sync,
        /* local_addr */ SocketAddr,
        Option<AttestationResult>,
    )> {
        let pool_key = PoolKey::new(endpoint);

        let client = self.get_client(&pool_key).await?;
        RatsTlsWrappingLayer::create_stream_from_hyper(&client)
            .instrument(tracing::info_span!("wrapping"))
            .await
    }

    #[cfg(test)]
    pub(crate) async fn force_expire(&self, pool_key: &PoolKey) {
        if let Some(c) = self.pool.write().await.get_mut(pool_key) {
            c.created_at = Instant::now() - Duration::from_secs(10);
        }
    }
}

#[derive(Clone)]
pub struct SecurityConnector {
    tls_config_generator: Arc<TlsConfigGenerator>,
    ra_context: Arc<RaContext>,
    transport_layer_connector: RatsTlsTransportLayerConnector,
    security_layer_span: Span,
}

impl SecurityConnector {}

impl tower::Service<Uri> for SecurityConnector {
    type Response = RatsTlsConnection;

    type Error = anyhow::Error;

    type Future =
        Pin<Box<dyn Future<Output = std::result::Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri /* Not use this as destination endpoint */) -> Self::Future {
        let tls_config_generator = self.tls_config_generator.clone();
        let ra_context = self.ra_context.clone();
        let mut transport_layer_connector = self.transport_layer_connector.clone();
        Box::pin(
            async move {
                let OnetimeTlsClientConfig {
                    config: tls_client_config,
                    verifier,
                    attested_key,
                } = tls_config_generator
                    .get_one_time_rustls_client_config()
                    .await?;

                let transport_layer_stream = transport_layer_connector.call(uri.clone()).await?;

                tracing::debug!("Creating rats-tls connection");
                async {
                    let security_layer_stream = TlsConnector::from(Arc::new(tls_client_config))
                        .connect(
                            ServerName::try_from(uri.host().context("Host is empty")?)?.to_owned(),
                            transport_layer_stream.into_inner(),
                        )
                        .await?;

                    let exporter = export_from_client(&security_layer_stream, Some(&[]))?;
                    let own_spki = attested_key
                        .as_ref()
                        .map(|key| spki_from_certified_key(key))
                        .transpose()?;
                    let peer_spki = verifier
                        .as_ref()
                        .map(|v| v.common.peer_spki_der())
                        .transpose()?;
                    let (security_layer_stream, attestation_result) = finish_rats_tls(
                        security_layer_stream,
                        ra_context.as_ref(),
                        verifier
                            .as_ref()
                            .map(|v| &v.common as &dyn RawEvidenceVerifier),
                        exporter,
                        own_spki,
                        peer_spki,
                    )
                    .await?;

                    tracing::debug!("New rats-tls connection established");
                    Ok::<_, anyhow::Error>(
                        StreamWithAttestationResult::wrap_with_attestation_result(
                            TokioIo::new(security_layer_stream),
                            attestation_result,
                        ),
                    )
                }
                .await
                .context("Failed to establish rats-tls connection as client")
            }
            .instrument(self.security_layer_span.clone()),
        )
    }
}

pub type RatsTlsConnection =
    StreamWithAttestationResult<TokioIo<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>>;

#[pin_project]
pub struct StreamWithAttestationResult<T> {
    #[pin]
    inner: T,
    attestation_result: Option<AttestationResult>,
}

impl<T> StreamWithAttestationResult<T> {
    pub fn wrap_with_attestation_result(
        inner: T,
        attestation_result: Option<AttestationResult>,
    ) -> Self {
        Self {
            inner,
            attestation_result,
        }
    }
}

impl hyper_util::client::legacy::connect::Connection for RatsTlsConnection {
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        let (tcp, tls) = self.inner.inner().get_ref();
        let connected = if tls.alpn_protocol() == Some(b"h2") {
            tcp.connected().negotiated_h2()
        } else {
            tcp.connected()
        };
        connected.extra(self.attestation_result.clone())
    }
}

impl<T: hyper::rt::Read + hyper::rt::Write + Unpin> hyper::rt::Read
    for StreamWithAttestationResult<T>
{
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        self.project().inner.poll_read(cx, buf)
    }
}

impl<T: hyper::rt::Write + hyper::rt::Read + Unpin> hyper::rt::Write
    for StreamWithAttestationResult<T>
{
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        self.project().inner.poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        self.project().inner.poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        self.project().inner.poll_shutdown(cx)
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        self.project().inner.poll_write_vectored(cx, bufs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ra::{RaArgsUnchecked, DEFAULT_RATS_TLS_POOL_TTL_SECS};
    use crate::tests::run_test_with_tokio_runtime;

    async fn layer(runtime: TokioRuntime, ttl: Duration) -> RatsTlsSecurityLayer {
        RatsTlsSecurityLayer::new(
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            None,
            Arc::new(RaContext::NoRa),
            runtime,
            ttl,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn reuses_entry_younger_than_ttl() -> Result<()> {
        run_test_with_tokio_runtime(|runtime| async move {
            let layer = layer(runtime, Duration::from_secs(60)).await;
            let key = PoolKey::new(TngEndpoint::new("127.0.0.1", 1));
            let first = layer.get_client(&key).await?;
            let second = layer.get_client(&key).await?;
            assert_eq!(first.id, second.id);
            Ok(())
        })
        .await
    }

    #[tokio::test]
    async fn expired_entry_is_replaced_without_dropping_inflight_clone() -> Result<()> {
        run_test_with_tokio_runtime(|runtime| async move {
            let layer = layer(runtime, Duration::from_millis(1)).await;
            let key = PoolKey::new(TngEndpoint::new("127.0.0.1", 2));
            let first = layer.get_client(&key).await?;
            layer.force_expire(&key).await;
            let inflight = first.clone();
            let second = layer.get_client(&key).await?;
            assert_ne!(first.id, second.id);
            assert_eq!(inflight.id, first.id);
            Ok(())
        })
        .await
    }

    #[tokio::test]
    async fn concurrent_gets_after_expiry_create_one_replacement() -> Result<()> {
        run_test_with_tokio_runtime(|runtime| async move {
            let layer = Arc::new(layer(runtime, Duration::from_millis(1)).await);
            let key = PoolKey::new(TngEndpoint::new("127.0.0.1", 3));
            let _ = layer.get_client(&key).await?;
            layer.force_expire(&key).await;
            let a = layer.clone();
            let b = layer.clone();
            let key_a = key.clone();
            let key_b = key.clone();
            let (ca, cb) = tokio::join!(a.get_client(&key_a), b.get_client(&key_b));
            assert_eq!(ca?.id, cb?.id);
            Ok(())
        })
        .await
    }

    #[test]
    fn verify_only_config_gets_default_pool_ttl() {
        let json = serde_json::json!({
            "verify": {
                "as_addr": "http://127.0.0.1:8080",
                "policy_ids": ["default"]
            }
        });
        let ra: RaArgsUnchecked = serde_json::from_value(json).unwrap();
        assert!(ra.attest.is_none());
        assert_eq!(
            ra.rats_tls_pool_ttl().as_secs(),
            DEFAULT_RATS_TLS_POOL_TTL_SECS
        );
    }

    #[test]
    fn refresh_interval_zero_does_not_change_pool_ttl() {
        let json = serde_json::json!({
            "attest": {
                "aa_addr": "unix:///tmp/tng-no-aa.sock",
                "refresh_interval": 0
            }
        });
        let ra: RaArgsUnchecked = serde_json::from_value(json).unwrap();
        assert_eq!(
            ra.attest.as_ref().and_then(|a| match a {
                crate::config::ra::AttestArgs::BackgroundCheck {
                    refresh_interval, ..
                } => *refresh_interval,
                crate::config::ra::AttestArgs::Passport {
                    refresh_interval, ..
                } => *refresh_interval,
            }),
            Some(0)
        );
        assert_eq!(
            ra.rats_tls_pool_ttl().as_secs(),
            DEFAULT_RATS_TLS_POOL_TTL_SECS
        );
    }
}
