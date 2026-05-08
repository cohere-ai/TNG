use std::{collections::HashSet, io, net::SocketAddr, sync::Arc, time::SystemTime};

use prost::Message;
use serf::net::stream_layer::{Listener, StreamLayer};

use crate::tunnel::{
    egress::protocol::ohttp::security::key_manager::{
        peer_shared::key_update, KeyInfo, KeyManager,
    },
    ohttp::key_config::{KeyConfigExtend, PublicKeyData},
};

use super::serf::PeerSharedKeyManagerInner;

// ── Key exchange helpers (use Connection trait) ─────────────────────────────

async fn send_keyset(conn: &mut impl serf::net::Connection, keys: &[KeyInfo]) -> io::Result<()> {
    let pb_keys: Vec<key_update::pb::KeyInfo> = keys
        .iter()
        .filter_map(|ki| key_update::pb::KeyInfo::try_from(ki.clone()).ok())
        .collect();
    let exchange = key_update::pb::KeySetExchange { keys: pb_keys };
    let buf = exchange.encode_to_vec();
    let len = buf.len() as u32;
    conn.write_all(&len.to_be_bytes()).await?;
    conn.write_all(&buf).await?;
    conn.flush().await?;
    Ok(())
}

async fn recv_keyset(conn: &mut impl serf::net::Connection) -> io::Result<Vec<KeyInfo>> {
    let mut len_buf = [0u8; 4];
    conn.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    let mut buf = vec![0u8; len as usize];
    conn.read_exact(&mut buf).await?;
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

/// Collects all non-expired keys (own + peer) for sending during exchange.
async fn get_all_keys_for_exchange(inner: &PeerSharedKeyManagerInner) -> Vec<KeyInfo> {
    let now = SystemTime::now();
    let own_keys = inner
        .inner_key_manager
        .get_client_visible_keys()
        .await
        .unwrap_or_default();
    let peer_keys = inner.keys_from_peers.read().await;
    own_keys
        .into_iter()
        .chain(peer_keys.values().cloned())
        .filter(|ki| now < ki.expire_at)
        .collect()
}

/// Merges received keys into the peer key store, skipping own keys and expired keys.
async fn merge_received_keys(
    inner: &PeerSharedKeyManagerInner,
    keys: Vec<KeyInfo>,
    peer: &SocketAddr,
) {
    let now = SystemTime::now();
    let own_pkds: HashSet<PublicKeyData> = inner
        .inner_key_manager
        .get_client_visible_keys()
        .await
        .unwrap_or_default()
        .iter()
        .filter_map(|ki| ki.key_config.public_key_data().ok())
        .collect();

    let mut peer_keys = inner.keys_from_peers.write().await;
    let mut new_key_count = 0u32;
    for key_info in keys {
        if now < key_info.expire_at {
            if let Ok(pkd) = key_info.key_config.public_key_data() {
                if !own_pkds.contains(&pkd) && !peer_keys.contains_key(&pkd) {
                    let has_private_key = key_info.key_config.dangerous_sk().is_some();
                    tracing::debug!(?pkd, has_private_key, "new peer key");
                    new_key_count += 1;
                }
                if !own_pkds.contains(&pkd) {
                    peer_keys.insert(pkd, key_info);
                }
            }
        }
    }
    peer_keys.retain(|pkd, ki| now < ki.expire_at && !own_pkds.contains(pkd));
    if new_key_count > 0 {
        tracing::info!(%peer, new_key_count, "received new keys via key exchange");
    }
}

// ── KeyExchangeLayer (wraps any StreamLayer) ────────────────────────────────

/// A `StreamLayer` wrapper that piggybacks OHTTP key exchange on every TCP
/// connection, keeping it on the already-authenticated inner transport (e.g.
/// RA-TLS) rather than using UDP gossip.
pub struct KeyExchangeLayer<S: StreamLayer> {
    inner: S,
    key_manager_inner: Arc<PeerSharedKeyManagerInner>,
}

impl<S: StreamLayer> StreamLayer for KeyExchangeLayer<S> {
    type Runtime = S::Runtime;
    type Listener = KeyExchangeListener<S>;
    type Stream = S::Stream;
    type Options = (S::Options, Arc<PeerSharedKeyManagerInner>);

    #[inline]
    async fn new((inner_opts, key_manager_inner): Self::Options) -> io::Result<Self> {
        Ok(Self {
            inner: S::new(inner_opts).await?,
            key_manager_inner,
        })
    }

    async fn connect(&self, addr: SocketAddr) -> io::Result<Self::Stream> {
        let mut stream = self.inner.connect(addr).await?;

        // Client side: send our keyset first, then receive peer's
        let all_keys = get_all_keys_for_exchange(&self.key_manager_inner).await;
        send_keyset(&mut stream, &all_keys).await?;
        let peer_keys = recv_keyset(&mut stream).await?;
        merge_received_keys(&self.key_manager_inner, peer_keys, &addr).await;

        Ok(stream)
    }

    async fn bind(&self, addr: SocketAddr) -> io::Result<Self::Listener> {
        let inner_listener = self.inner.bind(addr).await?;
        Ok(KeyExchangeListener {
            inner: inner_listener,
            key_manager_inner: Arc::clone(&self.key_manager_inner),
        })
    }

    fn is_secure() -> bool {
        S::is_secure()
    }
}

pub struct KeyExchangeListener<S: StreamLayer> {
    inner: S::Listener,
    key_manager_inner: Arc<PeerSharedKeyManagerInner>,
}

impl<S: StreamLayer> Listener for KeyExchangeListener<S> {
    type Stream = S::Stream;

    async fn accept(&self) -> io::Result<(Self::Stream, SocketAddr)> {
        let (mut stream, addr) = self.inner.accept().await?;

        // Server side: receive peer's keyset first, then send ours
        let exchange_result: io::Result<()> = async {
            let peer_keys = recv_keyset(&mut stream).await?;
            let all_keys = get_all_keys_for_exchange(&self.key_manager_inner).await;
            send_keyset(&mut stream, &all_keys).await?;
            merge_received_keys(&self.key_manager_inner, peer_keys, &addr).await;
            Ok(())
        }
        .await;

        match exchange_result {
            Ok(()) => Ok((stream, addr)),
            Err(err) => {
                tracing::warn!(
                    peer = %addr,
                    ?err,
                    "key exchange failed on server side"
                );
                Err(err)
            }
        }
    }

    async fn shutdown(&self) -> io::Result<()> {
        self.inner.shutdown().await
    }

    fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr()
    }
}
