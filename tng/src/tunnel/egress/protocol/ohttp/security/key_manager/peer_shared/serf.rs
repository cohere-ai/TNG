use crate::config::egress::PeerSharedArgs;
use crate::error::TngError;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::peer_shared::key_exchange_layer::KeyExchangeLayer;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::peer_shared::memberlist_rats_tls::RatsTls;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::peer_shared::runtime::InstrumentedRuntime;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::self_generated::SelfGeneratedKeyManager;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::KeyInfo;
use crate::tunnel::ohttp::key_config::PublicKeyData;
use crate::tunnel::utils::runtime::TokioRuntime;
use crate::tunnel::utils::runtime::supervised_task::SupervisedTaskResult;
use tokio::task::JoinHandle;

use anyhow::{anyhow, Context};
use futures::StreamExt;
use serf::delegate::CompositeDelegate;
use serf::net::hostaddr::Host;
use serf::net::resolver::socket_addr::SocketAddrResolver;
use serf::net::{HostAddr, NetTransport, NetTransportOptions, Node, NodeId};
use serf::types::MaybeResolvedAddress;
use serf::{MemberlistOptions, Options};
use uuid::Uuid;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use crate::tunnel::ra_context::RaContext;
use crate::tunnel::utils::file_watcher::FileWatcher;
use std::path::Path;

pub struct PeerSharedKeyManager {
    pub(super) inner: Arc<PeerSharedKeyManagerInner>,
    serf: Arc<SerfGracefulShutdown>,
    #[allow(unused)]
    peers_file_watch_task: Option<JoinHandle<SupervisedTaskResult<()>>>,
}

type InstrumentedTokioRuntime = InstrumentedRuntime<serf::agnostic::tokio::TokioRuntime>;

type SerfTransport = NetTransport<
    NodeId,
    SocketAddrResolver<InstrumentedTokioRuntime>,
    KeyExchangeLayer<RatsTls<InstrumentedTokioRuntime>>,
    InstrumentedTokioRuntime,
>;

type SerfDelegate = CompositeDelegate<NodeId, SocketAddr>;

type Serf = serf::Serf<SerfTransport, SerfDelegate>;

pub struct PeerSharedKeyManagerInner {
    pub(super) inner_key_manager: SelfGeneratedKeyManager,
    pub(super) keys_from_peers: RwLock<HashMap<PublicKeyData, KeyInfo>>,
}

impl PeerSharedKeyManager {
    pub async fn new(runtime: TokioRuntime, peer_shared: PeerSharedArgs) -> Result<Self, TngError> {
        // Step 1: Initialize internal key state
        let inner = Arc::new(PeerSharedKeyManagerInner {
            inner_key_manager: SelfGeneratedKeyManager::new_with_auto_refresh(
                runtime.clone(),
                peer_shared.rotation_interval,
                peer_shared.activation_delay,
            )?,
            keys_from_peers: Default::default(),
        });

        // Step 2: Initialize Serf node and network transport.
        // The exchange layer holds a reference to `inner` so it can read own keys
        // and merge peer keys directly during TCP push-pull connections.
        let (serf, _node_id_str) = Self::setup_serf(&runtime, &peer_shared, inner.clone()).await?;

        // Step 3: Join cluster via static peers and optional file
        let peers_file_watch_task =
            Self::spawn_cluster_join_tasks(&runtime, &serf, &peer_shared).await?;

        Ok(Self {
            inner,
            serf,
            peers_file_watch_task,
        })
    }

    /// Sets up the Serf instance with proper options and networking.
    async fn setup_serf(
        runtime: &TokioRuntime,
        peer_shared: &PeerSharedArgs,
        inner: Arc<PeerSharedKeyManagerInner>,
    ) -> Result<(Arc<SerfGracefulShutdown>, String), TngError> {
        let memberlist_opts =
            MemberlistOptions::lan().with_push_pull_interval(Duration::from_secs(5));
        let opts = Options::new().with_memberlist_options(memberlist_opts);
        let node_id_str = Uuid::new_v4().to_string();
        let node_id = NodeId::<255>::new(&node_id_str)
            .with_context(|| format!("invalid node id {node_id_str}"))
            .map_err(TngError::InvalidParameter)?;
        tracing::info!(
            ?node_id,
            "Launching peer shared key manager with serf protocol"
        );
        let ra_args = peer_shared.ra_args.clone().into_checked()?;
        let ra_context = Arc::new(
            RaContext::from_ra_args(&ra_args)
                .await
                .map_err(TngError::InvalidParameter)?,
        );
        let net_opts =
            NetTransportOptions::<_, SocketAddrResolver<InstrumentedTokioRuntime>, _>::with_stream_layer_options(
                node_id,
                ((ra_context, runtime.clone()), inner),
            )
            .with_bind_addresses(
                [{
                    let addr = format!("{}:{}", peer_shared.host, peer_shared.port);
                    std::net::SocketAddr::from_str(&addr)
                        .with_context(|| format!("invalid address {addr}"))
                        .map_err(TngError::InvalidParameter)?
                }]
                .into_iter()
                .collect(),
            );

        let serf = Serf::new(net_opts, opts)
            .await
            .map_err(|error| TngError::SerfCrateError(anyhow!(error)))?;

        let graceful_serf = Arc::new(SerfGracefulShutdown::new(serf, runtime.clone()));

        Ok((graceful_serf, node_id_str))
    }

    /// Handles joining the Serf cluster using both static peers and file-based dynamic peers.
    async fn spawn_cluster_join_tasks(
        runtime: &TokioRuntime,
        serf: &Arc<SerfGracefulShutdown>,
        peer_shared: &PeerSharedArgs,
    ) -> Result<Option<JoinHandle<SupervisedTaskResult<()>>>, TngError> {
        // First, join using static peers
        if !peer_shared.peers.is_empty() {
            if let Err(e) = join_serf_cluster(serf.as_ref(), &peer_shared.peers).await {
                tracing::warn!(error = ?e, "Failed to join some static peers");
            }
        }

        // If peers_file is configured, start monitoring it for changes
        if let Some(peers_file) = &peer_shared.peers_file {
            let peers_file_path = peers_file.clone();

            // Load initial peers from file and join if any
            if let Ok(file_peers) = load_peers_from_file(&peers_file_path).await {
                // Join using peers from file
                if let Err(e) = join_serf_cluster(serf, &file_peers).await {
                    tracing::warn!(error = ?e, "Some peers from file failed to join, continuing...");
                }
            }

            // Start file watcher to monitor peers file changes
            let serf_weak_for_watcher = Arc::downgrade(serf);

            let peers_file_path_for_watcher = Path::new(&peers_file_path).to_path_buf();

            let mut file_watcher = FileWatcher::new(peers_file_path_for_watcher.clone())
                .map_err(|e| TngError::WatchFileFailed(peers_file_path_for_watcher.clone(), e))?;

            let watch_task = runtime.spawn_supervised_task_current_span(async move {
                    while let Some(result) = file_watcher.recv().await {
                        match result {
                            Ok(()) => {
                                tracing::info!(peers_file = ?peers_file_path_for_watcher, "Peers file changed, reloading and joining new peers");

                                match load_peers_from_file(&peers_file_path_for_watcher.to_string_lossy()).await {
                                    Ok(new_peers) => {
                                        tracing::info!(peers_count = new_peers.len(), "Loaded peers from file");

                                        // Join using newly loaded peers
                                        let Some(serf_clone) = serf_weak_for_watcher.upgrade() else {
                                            tracing::debug!(
                                                "stop watching peers file since serf has been dropped"
                                            );
                                            break;
                                        };

                                        if let Err(e) = join_serf_cluster(&serf_clone, &new_peers).await {
                                            tracing::warn!(error = ?e, "Some peers from file failed to join, continuing...");
                                        }
                                    }
                                    Err(error) => {
                                        tracing::error!(
                                            peers_file = ?peers_file_path_for_watcher,
                                            ?error,
                                            "Failed to load peers from updated file"
                                        );
                                    }
                                }
                            }
                            Err(error) => {
                                tracing::error!(
                                    peers_file = ?peers_file_path_for_watcher,
                                    ?error,
                                    "Internal error in peers file watcher"
                                );
                            }
                        }
                    }

                    tracing::info!(peers_file = ?peers_file_path_for_watcher, "Peers file watcher stopped");
                });
            Ok(Some(watch_task))
        } else {
            Ok(None)
        }
    }
}

async fn resolve_peer_addresses(addr: &String) -> Result<Vec<SocketAddr>, TngError> {
    let host_addr = HostAddr::from_str(addr)
        .with_context(|| format!("Invalid peer address: {addr}"))
        .map_err(TngError::InvalidParameter)?;
    let port = host_addr
        .port()
        .context("Missing port in peer address")
        .map_err(TngError::InvalidParameter)?;
    let host = host_addr.host();
    let socket_addrs = match host {
        Host::Ip(ip) => vec![SocketAddr::new(*ip, port)],
        Host::Domain(name) => {
            // Finally, try to find the socket addr locally
            serf::agnostic::net::ToSocketAddrs::<serf::agnostic::tokio::TokioRuntime>::to_socket_addrs(&(
                name.as_str(),
                port,
            ))
            .await.with_context(||format!("failed to resolve {}", name)).map_err(TngError::InvalidParameter)?.collect()
        }
    };
    Ok(socket_addrs)
}

/// Joins the Serf cluster via a list of peer addresses.
async fn join_serf_cluster(serf: &Serf, peers: &[String]) -> Result<(), TngError> {
    for (i, peer) in peers.iter().enumerate() {
        tracing::info!(peer, "Attempting to join Serf cluster");

        let socket_addrs = resolve_peer_addresses(peer).await?;

        // Attempt to join the cluster using every resolved socket address for this host.
        // Since a hostname (e.g., via DNS) may resolve to multiple IPs (A/AAAA records),
        // we try each one to maximize the chance of successful connectivity.
        // It's sufficient to successfully join via at least one address.
        let count_success = futures::stream::iter(socket_addrs.into_iter()).filter_map(|socket_addr| async move {
            tracing::debug!(
                ?peer,
                resolved_address = %socket_addr,
                "Attempting to join serf cluster using resolved socket address"
            );

            let node = Node::new(
                #[allow(clippy::unwrap_used)]
                NodeId::<255>::new(format!("unresolved_peer_{}", i)).unwrap(),
                MaybeResolvedAddress::resolved(socket_addr),
            );

            match serf.join(node, false).await {
                Ok(_) => {
                    tracing::info!(
                        ?peer,
                        via = %socket_addr,
                        "Successfully joined serf cluster via resolved address"
                    );
                    Some(())
                }
                Err(error) => {
                    tracing::warn!(
                        ?peer,
                        failed_address = %socket_addr,
                        ?error,
                        "Failed to join serf cluster via this address, will try next if available"
                    );
                    None
                }
            }
        }).count().await;

        if count_success > 0 {
            continue;
        } else {
            return Err(TngError::SerfCrateError(anyhow!(
                "Failed to join any address of peer: {peer}"
            )));
        }
    }

    Ok(())
}

/// Loads peer list from JSON file.
async fn load_peers_from_file(path: &str) -> Result<Vec<String>, anyhow::Error> {
    let content = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("Failed to read peers file: {path}"))?;
    serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse peers file as JSON: {path}"))
}

struct SerfGracefulShutdown {
    serf: Option<Serf>,
    runtime: TokioRuntime,
}

impl SerfGracefulShutdown {
    fn new(serf: Serf, runtime: TokioRuntime) -> Self {
        Self {
            serf: Some(serf),
            runtime,
        }
    }
}

impl Deref for SerfGracefulShutdown {
    type Target = Serf;

    fn deref(&self) -> &Self::Target {
        #[allow(clippy::unwrap_used)]
        self.serf.as_ref().unwrap()
    }
}

impl Drop for SerfGracefulShutdown {
    fn drop(&mut self) {
        if let Some(serf) = self.serf.take() {
            tracing::info!("Start leaving the serf cluster");

            self.runtime
                .spawn_unsupervised_task_current_span(async move {
                    match serf.leave().await {
                        Ok(()) => {
                            let _ = serf.shutdown().await;
                            tracing::info!("Left the serf cluster gracefully");
                        }
                        Err(error) => {
                            tracing::error!(?error, "Failed to leave the serf cluster gracefully");
                            let _ = serf.shutdown().await;
                        }
                    }
                });
        }
    }
}

impl Drop for PeerSharedKeyManager {
    fn drop(&mut self) {
        if let Some(task) = self.peers_file_watch_task.take() {
            task.abort();
        }
    }
}
