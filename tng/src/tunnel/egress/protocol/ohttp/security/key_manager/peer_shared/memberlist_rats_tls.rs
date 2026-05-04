use std::{
    collections::HashMap, io, marker::PhantomData, net::SocketAddr, sync::Arc, time::SystemTime,
};

use anyhow::Context;
use async_stream::stream;
use futures::{AsyncReadExt, AsyncWriteExt, StreamExt as _};
use peekable::future::AsyncPeekable;
use prost::Message;
use serf::{
    agnostic::{
        net::{Net, TcpListener as _, TcpStream as _},
        Runtime,
    },
    net::stream_layer::{Listener, PromisedStream, StreamLayer},
};
use tokio::io::{AsyncReadExt as TokioAsyncReadExt, AsyncWriteExt as TokioAsyncWriteExt};
use tokio_util::compat::TokioAsyncReadCompatExt as _;
use tokio_util::compat::TokioAsyncWriteCompatExt as _;

use crate::{
    tunnel::{
        egress::{
            protocol::{
                ohttp::security::key_manager::{
                    callback_manager::KeyChangeEvent, peer_shared::key_update, KeyInfo,
                },
                rats_tls::RatsTlsStreamDecoder,
            },
            stream_manager::trusted::ProtocolStreamDecoder as _,
        },
        endpoint::TngEndpoint,
        ingress::protocol::rats_tls::RatsTlsStreamForwarder,
        ohttp::key_config::{KeyConfigExtend, PublicKeyData},
        ra_context::RaContext,
    },
    CommonStreamTrait, TokioRuntime,
};

/// Shared key state used by the stream layer for key exchange on TCP connections.
pub struct KeyExchangeStore {
    own_keys: tokio::sync::RwLock<HashMap<PublicKeyData, KeyInfo>>,
    peer_keys: tokio::sync::RwLock<HashMap<PublicKeyData, KeyInfo>>,
}

impl KeyExchangeStore {
    pub fn new() -> Self {
        Self {
            own_keys: tokio::sync::RwLock::new(HashMap::new()),
            peer_keys: tokio::sync::RwLock::new(HashMap::new()),
        }
    }

    pub async fn handle_own_key_event(&self, event: &KeyChangeEvent<'_>) {
        let mut own = self.own_keys.write().await;
        match event {
            KeyChangeEvent::Created { key_info }
            | KeyChangeEvent::StatusChanged { key_info, .. } => {
                if let Ok(pkd) = key_info.key_config.public_key_data() {
                    own.insert(pkd, key_info.as_ref().clone());
                }
            }
            KeyChangeEvent::Removed { key_info } => {
                if let Ok(pkd) = key_info.key_config.public_key_data() {
                    own.remove(&pkd);
                }
            }
        }
    }

    pub async fn get_all_keys_for_exchange(&self) -> Vec<KeyInfo> {
        let own = self.own_keys.read().await;
        let peer = self.peer_keys.read().await;
        let now = SystemTime::now();
        own.values()
            .chain(peer.values())
            .filter(|ki| now < ki.expire_at)
            .cloned()
            .collect()
    }

    pub async fn merge_received_keys(&self, keys: Vec<KeyInfo>) {
        let now = SystemTime::now();
        let mut peer = self.peer_keys.write().await;
        for key_info in keys {
            if now < key_info.expire_at {
                if let Ok(pkd) = key_info.key_config.public_key_data() {
                    peer.insert(pkd, key_info);
                }
            }
        }
        peer.retain(|_, ki| now < ki.expire_at);
    }

    pub async fn read_peer_keys(
        &self,
    ) -> tokio::sync::RwLockReadGuard<'_, HashMap<PublicKeyData, KeyInfo>> {
        self.peer_keys.read().await
    }
}

const KEY_EXCHANGE_MAX_SIZE: u32 = 10 * 1024 * 1024; // 10 MB

async fn send_keyset(
    stream: &mut (impl tokio::io::AsyncWrite + Unpin),
    keys: &[KeyInfo],
) -> io::Result<()> {
    let pb_keys: Vec<key_update::pb::KeyInfo> = keys
        .iter()
        .filter_map(|ki| key_update::pb::KeyInfo::try_from(ki.clone()).ok())
        .collect();
    let exchange = key_update::pb::KeySetExchange { keys: pb_keys };
    let buf = exchange.encode_to_vec();
    let len = buf.len() as u32;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&buf).await?;
    stream.flush().await?;
    Ok(())
}

async fn recv_keyset(stream: &mut (impl tokio::io::AsyncRead + Unpin)) -> io::Result<Vec<KeyInfo>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len > KEY_EXCHANGE_MAX_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("key exchange payload too large: {len} bytes"),
        ));
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;
    let exchange = key_update::pb::KeySetExchange::decode(buf.as_slice())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let keys: Vec<KeyInfo> = exchange
        .keys
        .into_iter()
        .filter_map(|pb_ki| {
            KeyInfo::try_from(pb_ki)
                .map_err(|e| tracing::warn!(?e, "failed to decode key from peer during exchange"))
                .ok()
        })
        .collect();
    Ok(keys)
}

/// Rats-TLS stream layer.
pub struct RatsTls<R> {
    forwarder: Arc<RatsTlsStreamForwarder>,
    decoder: Arc<RatsTlsStreamDecoder>,
    key_exchange_store: Arc<KeyExchangeStore>,
    phantom: PhantomData<R>,
}

impl<R: Runtime> StreamLayer for RatsTls<R> {
    type Runtime = R;
    type Listener = RatsTlsListener<R>;
    type Stream = RatsTlsStream<R>;
    type Options = (Arc<RaContext>, TokioRuntime, Arc<KeyExchangeStore>);

    #[inline]
    async fn new((ra_context, runtime, key_exchange_store): Self::Options) -> io::Result<Self> {
        Ok(Self {
            forwarder: Arc::new(
                RatsTlsStreamForwarder::new(
                    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                    None,
                    ra_context.clone(),
                    runtime.clone(),
                )
                .await
                .context("Failed to create rats-tls stream forwarder")
                .map_err(io::Error::other)?,
            ),
            decoder: Arc::new(
                RatsTlsStreamDecoder::new(ra_context, runtime)
                    .await
                    .context("Failed to create rats-tls stream decoder")
                    .map_err(io::Error::other)?,
            ),
            key_exchange_store,
            phantom: Default::default(),
        })
    }

    async fn connect(&self, addr: SocketAddr) -> io::Result<Self::Stream> {
        let (stream, local_addr, _attestation_result) = self
            .forwarder
            .connect(TngEndpoint::new(addr.ip().to_string(), addr.port()))
            .await
            .with_context(|| format!("Failed to connect to {addr:?}"))
            .map_err(io::Error::other)?;

        let mut stream = Box::new(stream) as Box<dyn CommonStreamTrait + Sync>;

        // Client side: send our keyset first, then receive peer's
        let all_keys = self.key_exchange_store.get_all_keys_for_exchange().await;
        send_keyset(&mut stream, &all_keys).await?;
        let peer_keys = recv_keyset(&mut stream).await?;
        let received_count = peer_keys.len();
        self.key_exchange_store.merge_received_keys(peer_keys).await;
        tracing::debug!(
            peer = %addr,
            sent = all_keys.len(),
            received = received_count,
            "key exchange completed (client)"
        );

        let (reader, writer) = tokio::io::split(stream);

        Ok(RatsTlsStream {
            local_addr,
            peer_addr: addr,
            reader: AsyncPeekable::new(reader.compat()),
            writer: writer.compat_write(),
            phantom: Default::default(),
        })
    }

    async fn bind(&self, addr: SocketAddr) -> io::Result<Self::Listener> {
        <<R::Net as Net>::TcpListener as serf::agnostic::net::TcpListener>::bind(addr)
            .await
            .and_then(|ln| {
                ln.local_addr().map(|local_addr| {
                    RatsTlsListener::new(
                        ln,
                        local_addr,
                        Arc::clone(&self.decoder),
                        Arc::clone(&self.key_exchange_store),
                    )
                })
            })
    }

    fn is_secure() -> bool {
        false
    }
}

/// [`Listener`] of the TCP stream layer
pub struct RatsTlsListener<R: Runtime> {
    local_addr: SocketAddr,
    #[allow(clippy::type_complexity)]
    incoming: tokio::sync::Mutex<
        std::pin::Pin<
            Box<
                dyn futures::Stream<Item = io::Result<(<Self as Listener>::Stream, SocketAddr)>>
                    + Send,
            >,
        >,
    >,
}
// impl Stream<Item = Result<<... as TcpListener>::Stream, ...>> + Send
impl<R: Runtime> RatsTlsListener<R> {
    fn new(
        ln: <R::Net as Net>::TcpListener,
        local_addr: SocketAddr,
        decoder: Arc<RatsTlsStreamDecoder>,
        key_exchange_store: Arc<KeyExchangeStore>,
    ) -> Self {
        let incoming = ln.into_incoming().flat_map_unordered(None, move |next| {
            let decoder = decoder.clone();
            let key_exchange_store = key_exchange_store.clone();
            Box::pin(stream! {
                match next {
                    Ok(conn) => {
                        let peer_addr = match conn.peer_addr() {
                            Ok(peer_addr) => peer_addr,
                            Err(err) => {yield Err(err); return;},
                        };

                        let pending = decoder
                            .decode_stream(Box::new(conn))
                            .await
                            .context("Failed to decode rats-tls serf stream")
                            .map_err(io::Error::other);

                        match pending {
                            Ok(mut pending) => {
                                while let Some(result) = pending.next().await {
                                    match result {
                                        Ok((mut stream, _att)) => {
                                            // Server side: receive peer's keyset first, then send ours
                                            let exchange_result: io::Result<()> = async {
                                                let peer_keys = recv_keyset(&mut stream).await?;
                                                let all_keys = key_exchange_store.get_all_keys_for_exchange().await;
                                                send_keyset(&mut stream, &all_keys).await?;
                                                let received_count = peer_keys.len();
                                                key_exchange_store.merge_received_keys(peer_keys).await;
                                                tracing::debug!(
                                                    peer = %peer_addr,
                                                    sent = all_keys.len(),
                                                    received = received_count,
                                                    "key exchange completed (server)"
                                                );
                                                Ok(())
                                            }.await;

                                            match exchange_result {
                                                Ok(()) => {
                                                    let (reader, writer) = tokio::io::split(stream);
                                                    yield Ok((
                                                        RatsTlsStream::<R> {
                                                            writer: writer.compat_write(),
                                                            reader: AsyncPeekable::new(reader.compat()),
                                                            local_addr,
                                                            peer_addr,
                                                            phantom: Default::default(),
                                                        },
                                                        peer_addr,
                                                    ));
                                                },
                                                Err(err) => {
                                                    tracing::warn!(
                                                        peer = %peer_addr,
                                                        ?err,
                                                        "key exchange failed on server side"
                                                    );
                                                    yield Err(err);
                                                }
                                            }
                                        },
                                        Err(err) => {
                                            yield Err(io::Error::other(
                                                format!("Failed to get next rats-tls serf stream: {err:?}"),
                                            ));
                                        }
                                    }
                                }
                            },
                            Err(err) => {
                                yield Err(err)
                            }
                        }
                    },
                    Err(err) => {
                        yield Err(err)
                    }
                }
            })
        });

        Self {
            local_addr,
            incoming: tokio::sync::Mutex::new(Box::pin(incoming)),
        }
    }
}

impl<R: Runtime> Listener for RatsTlsListener<R> {
    type Stream = RatsTlsStream<R>;

    async fn accept(&self) -> io::Result<(Self::Stream, SocketAddr)> {
        self.incoming
            .lock()
            .await
            .next()
            .await
            .context("Failed to get next rats-tls serf stream")
            .map_err(io::Error::other)?
    }

    async fn shutdown(&self) -> io::Result<()> {
        Ok(())
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

/// [`PromisedStream`] of the TCP stream layer
#[pin_project::pin_project]
pub struct RatsTlsStream<R: Runtime> {
    #[pin]
    writer: tokio_util::compat::Compat<tokio::io::WriteHalf<Box<dyn CommonStreamTrait + Sync>>>,
    #[pin]
    reader: AsyncPeekable<
        tokio_util::compat::Compat<tokio::io::ReadHalf<Box<dyn CommonStreamTrait + Sync>>>,
    >,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    phantom: PhantomData<R>,
}

impl<R: Runtime> serf::net::Connection for RatsTlsStream<R> {
    type Reader = AsyncPeekable<
        tokio_util::compat::Compat<tokio::io::ReadHalf<Box<dyn CommonStreamTrait + Sync>>>,
    >;

    type Writer =
        tokio_util::compat::Compat<tokio::io::WriteHalf<Box<dyn CommonStreamTrait + Sync>>>;

    #[inline]
    fn split(self) -> (Self::Reader, Self::Writer) {
        (self.reader, self.writer)
    }

    async fn close(&mut self) -> std::io::Result<()> {
        AsyncWriteExt::close(&mut self.writer).await
    }

    async fn write_all(&mut self, payload: &[u8]) -> std::io::Result<()> {
        AsyncWriteExt::write_all(&mut self.writer, payload).await
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        AsyncWriteExt::flush(&mut self.writer).await
    }

    async fn peek(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reader.peek(buf).await
    }

    async fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        AsyncReadExt::read_exact(&mut self.reader, buf).await
    }

    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        AsyncReadExt::read(&mut self.reader, buf).await
    }

    async fn peek_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        self.reader.peek_exact(buf).await
    }

    fn consume_peek(&mut self) {
        self.reader.consume();
    }
}

impl<R: Runtime> PromisedStream for RatsTlsStream<R> {
    type Instant = R::Instant;

    #[inline]
    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    #[inline]
    fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
}
