use std::{
    collections::{HashMap, HashSet},
    io,
    net::SocketAddr,
    sync::Arc,
    time::SystemTime,
};

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

/// Core merge logic: inserts non-expired, non-own keys into `peer_keys`, then
/// prunes expired / own entries. Returns the number of newly added keys.
fn merge_keys_into(
    peer_keys: &mut HashMap<PublicKeyData, KeyInfo>,
    incoming: Vec<KeyInfo>,
    own_pkds: &HashSet<PublicKeyData>,
) -> u32 {
    let now = SystemTime::now();
    let mut new_key_count = 0u32;
    for key_info in incoming {
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
    new_key_count
}

/// Merges received keys into the peer key store, skipping own keys and expired keys.
async fn merge_received_keys(
    inner: &PeerSharedKeyManagerInner,
    keys: Vec<KeyInfo>,
    peer: &SocketAddr,
) {
    let own_pkds: HashSet<PublicKeyData> = inner
        .inner_key_manager
        .get_client_visible_keys()
        .await
        .unwrap_or_default()
        .iter()
        .filter_map(|ki| ki.key_config.public_key_data().ok())
        .collect();

    let mut peer_keys = inner.keys_from_peers.write().await;
    let new_key_count = merge_keys_into(&mut peer_keys, keys, &own_pkds);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::egress::protocol::ohttp::security::key_manager::{KeyInfo, KeyStatus};
    use std::collections::{HashMap, HashSet};
    use std::time::{Duration, SystemTime};

    use futures::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio_util::compat::{Compat, TokioAsyncReadCompatExt as _};

    /// Minimal `Connection` over an in-memory duplex for testing send/recv.
    struct MockConn {
        stream: Compat<tokio::io::DuplexStream>,
    }

    impl MockConn {
        fn pair() -> (Self, Self) {
            let (a, b) = tokio::io::duplex(8192);
            (Self { stream: a.compat() }, Self { stream: b.compat() })
        }
    }

    impl serf::net::Connection for MockConn {
        type Reader = peekable::future::AsyncPeekable<Compat<tokio::io::DuplexStream>>;
        type Writer = Compat<tokio::io::DuplexStream>;
        fn split(self) -> (Self::Reader, Self::Writer) {
            unimplemented!()
        }
        async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.stream.read(buf).await
        }
        async fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
            self.stream.read_exact(buf).await.map(|_| ())
        }
        async fn peek(&mut self, _: &mut [u8]) -> io::Result<usize> {
            unimplemented!()
        }
        async fn peek_exact(&mut self, _: &mut [u8]) -> io::Result<()> {
            unimplemented!()
        }
        fn consume_peek(&mut self) {
            unimplemented!()
        }
        async fn write_all(&mut self, payload: &[u8]) -> io::Result<()> {
            self.stream.write_all(payload).await
        }
        async fn flush(&mut self) -> io::Result<()> {
            self.stream.flush().await
        }
        async fn close(&mut self) -> io::Result<()> {
            self.stream.close().await
        }
    }

    fn make_test_key_info(key_id: u8) -> KeyInfo {
        let key_config = ohttp::KeyConfig::new(
            key_id,
            ohttp::hpke::Kem::X25519Sha256,
            vec![ohttp::SymmetricSuite::new(
                ohttp::hpke::Kdf::HkdfSha256,
                ohttp::hpke::Aead::Aes128Gcm,
            )],
        )
        .expect("failed to create test key config");
        let now = SystemTime::now();
        KeyInfo {
            key_config,
            status: KeyStatus::Active,
            created_at: now,
            stale_at: now + Duration::from_secs(3600),
            expire_at: now + Duration::from_secs(7200),
        }
    }

    #[tokio::test]
    async fn test_send_recv_keyset_roundtrip() {
        let (mut sender, mut receiver) = MockConn::pair();

        let original_keys = vec![make_test_key_info(1), make_test_key_info(2)];
        let expect: Vec<_> = original_keys
            .iter()
            .map(|ki| {
                let pkd = ki.key_config.public_key_data().unwrap();
                let pem = ki
                    .key_config
                    .dangerous_sk()
                    .unwrap()
                    .serialize_to_pkcs8_pem()
                    .unwrap();
                (pkd, pem)
            })
            .collect();

        let (send_result, received) = tokio::join!(
            send_keyset(&mut sender, &original_keys),
            recv_keyset(&mut receiver),
        );
        send_result.unwrap();
        let received = received.unwrap();

        let got: Vec<_> = received
            .iter()
            .map(|ki| {
                let pkd = ki.key_config.public_key_data().unwrap();
                let pem = ki
                    .key_config
                    .dangerous_sk()
                    .unwrap()
                    .serialize_to_pkcs8_pem()
                    .unwrap();
                (pkd, pem)
            })
            .collect();
        assert_eq!(expect, got);
    }

    #[test]
    fn test_merge_stores_correct_keys() {
        let mut store = HashMap::new();
        let keys = vec![make_test_key_info(1), make_test_key_info(2)];
        let expected_pkds: HashSet<_> = keys
            .iter()
            .map(|k| k.key_config.public_key_data().unwrap())
            .collect();

        let added = merge_keys_into(&mut store, keys, &HashSet::new());

        assert_eq!(added, 2);
        assert_eq!(store.len(), 2);
        let stored_pkds: HashSet<_> = store.keys().cloned().collect();
        assert_eq!(expected_pkds, stored_pkds);
    }

    #[test]
    fn test_merge_rejects_expired_keys() {
        let mut store = HashMap::new();
        let mut expired = make_test_key_info(1);
        expired.expire_at = SystemTime::now() - Duration::from_secs(1);

        let added = merge_keys_into(&mut store, vec![expired], &HashSet::new());

        assert_eq!(added, 0);
        assert!(store.is_empty());
    }

    #[test]
    fn test_merge_skips_own_keys() {
        let mut store = HashMap::new();
        let own_key = make_test_key_info(1);
        let own_pkds: HashSet<_> = [own_key.key_config.public_key_data().unwrap()].into();

        let added = merge_keys_into(&mut store, vec![own_key], &own_pkds);

        assert_eq!(added, 0);
        assert!(store.is_empty());
    }

    #[test]
    fn test_merge_deduplicates() {
        let mut store = HashMap::new();
        let key = make_test_key_info(1);
        let key_pkd = key.key_config.public_key_data().unwrap();

        merge_keys_into(&mut store, vec![key.clone()], &HashSet::new());
        let added = merge_keys_into(&mut store, vec![key], &HashSet::new());

        assert_eq!(added, 0);
        assert_eq!(store.len(), 1);
        assert!(store.contains_key(&key_pkd));
    }
}
