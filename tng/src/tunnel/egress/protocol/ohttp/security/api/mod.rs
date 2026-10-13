pub mod key_config;
pub mod tunnel;

use std::sync::Arc;

use anyhow::Result;
use tokio::sync::OnceCell;

use crate::config::egress::KeyArgs;
use crate::error::TngError;
use crate::tunnel::attest::Prepared;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::file::FileBasedKeyManager;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::peer_shared::PeerSharedKeyManager;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::{
    callback_manager::KeyChangeEvent, self_generated::SelfGeneratedKeyManager, KeyManager,
    KeyStatus,
};
use crate::tunnel::ohttp::protocol::HpkeKeyConfig;
use crate::tunnel::ra_context::RaContext;
use crate::tunnel::utils::maybe_cached::MaybeCached;
use crate::TokioRuntime;

/// The client-visible key config and the attestation prepared for it.
type KeyConfigSnapshot = (HpkeKeyConfig, Prepared);

/// OHTTP API handler for processing TNG server interfaces
///
/// This struct implements the server-side APIs required for TNG OHTTP functionality,
/// including key configuration management, encrypted request processing, and attestation
/// handling in different modes (passport or background check).
///
/// The handler manages cryptographic keys, remote attestation data, and provides
/// caching mechanisms to optimize performance for repeated operations.
pub struct OhttpServerApi {
    /// Pre-instantiated Remote Attestation context
    ra_context: Arc<RaContext>,
    /// Key manager for OHTTP key configurations
    pub(crate) key_manager: Arc<dyn KeyManager>,
    /// Cache for storing the key configuration and the attestation prepared for it
    ///
    /// In passport mode, the server generates an attestation (passport) that is cached
    /// and reused for subsequent client requests to avoid expensive re-attestation.
    /// The cache automatically refreshes based on configured refresh strategy.
    passport_cache: Arc<OnceCell<MaybeCached<KeyConfigSnapshot, TngError>>>,
}

impl OhttpServerApi {
    /// Create a new OHttp Server API handler
    ///
    /// This function creates an OHTTP server API with a default random key manager.
    pub async fn new(
        ra_context: Arc<RaContext>,
        key: KeyArgs,
        runtime: TokioRuntime,
    ) -> Result<Self, TngError> {
        // Create key manager based on configuration
        let key_manager: Arc<dyn KeyManager> = match key {
            KeyArgs::SelfGenerated { rotation_interval } => Arc::new(
                SelfGeneratedKeyManager::new_with_auto_refresh(
                    runtime.clone(),
                    rotation_interval,
                    0,
                )
                .await?,
            ),
            KeyArgs::File { path } => {
                Arc::new(FileBasedKeyManager::new(runtime.clone(), path.into()).await?)
            }
            KeyArgs::PeerShared(peer_shared_args) => {
                let metrics = ra_context
                    .attestation_metrics()
                    .cloned()
                    .unwrap_or_else(crate::tunnel::attestation_metrics::AttestationMetrics::noop);
                Arc::new(
                    PeerSharedKeyManager::new(runtime.clone(), peer_shared_args, metrics).await?,
                )
            }
        };

        let passport_cache: Arc<OnceCell<MaybeCached<_, TngError>>> = Default::default();

        // Register a callback to refresh the passport cache when the advertised keys change
        {
            let passport_cache_cloned = passport_cache.clone();
            key_manager
                .register_callback(Arc::new(move |event| {
                    let passport_cache_cloned = passport_cache_cloned.clone();
                    let refresh = changes_advertised_keys(event);
                    Box::pin(async move {
                        // Only signal: key managers may fire this while holding their key lock
                        if let Some(cache) = passport_cache_cloned.get() {
                            if refresh {
                                cache.invalidate();
                            }
                        }
                    })
                }))
                .await;
        }

        // Built after the callback is registered so no key activation is missed
        if let Some(attest_ctx) = ra_context.attest_context() {
            let cache = Self::new_snapshot_cache(
                ra_context.clone(),
                key_manager.clone(),
                attest_ctx.refresh_strategy(),
                runtime,
            )
            .await?;
            let _ = passport_cache.set(cache);
        }

        Ok(OhttpServerApi {
            ra_context,
            key_manager,
            passport_cache,
        })
    }
}

/// Clients are only offered `Active` keys (or `Stale` ones until a new key activates), so a key
/// becoming `Active` is the only change they can see.
fn changes_advertised_keys(event: &KeyChangeEvent<'_>) -> bool {
    match event {
        KeyChangeEvent::Created { key_info } => matches!(key_info.status, KeyStatus::Active),
        KeyChangeEvent::StatusChanged { new_status, .. } => matches!(new_status, KeyStatus::Active),
        KeyChangeEvent::Removed { .. } => false,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use anyhow::Context as _;

    use super::*;
    use crate::config::ra::{
        AttestArgs, AttesterArgs, CocoAttesterArgs, CocoConverterArgs, ConverterArgs, RaArgs,
    };
    use crate::tests::run_test_with_tokio_runtime;
    use crate::tunnel::attest::{AttestProposal, AttestRequest};
    use crate::tunnel::egress::protocol::ohttp::security::context::TngStreamContext;
    use crate::tunnel::ohttp::protocol::KeyConfigRequest;
    use crate::tunnel::provider::ProviderType;
    use crate::tunnel::utils::cert_manager::tests::dummy_aa;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn failed_passport_mint_still_serves_the_key_config() -> Result<()> {
        run_test_with_tokio_runtime(|runtime| async move {
            let (aa_addr, _listener) = dummy_aa();
            let ra_context = RaContext::from_ra_args(&RaArgs::AttestOnly(AttestArgs::Passport {
                attester: AttesterArgs::Coco(CocoAttesterArgs::Uds { aa_addr }),
                converter: ConverterArgs::Coco(CocoConverterArgs::Restful {
                    as_addr: "http://127.0.0.1:1".into(),
                    policy_ids: vec![],
                    as_headers: Default::default(),
                    as_ca_certs: vec![],
                }),
                refresh_interval: None,
                max_retries: Some(0),
            }))
            .await?;
            let api = OhttpServerApi::new(
                Arc::new(ra_context),
                KeyArgs::SelfGenerated {
                    rotation_interval: 3600,
                },
                runtime.clone(),
            )
            .await?;
            let (sender, _receiver) = tokio::sync::mpsc::unbounded_channel();
            let context = TngStreamContext { runtime, sender };

            let response = api.get_hpke_configuration(None, context.clone()).await?;
            assert_eq!(response.status(), axum::http::StatusCode::OK);

            let proposals = vec![AttestProposal::Passport {
                provider: ProviderType::Coco,
            }];
            let request = KeyConfigRequest {
                attest_request: AttestRequest { proposals },
            };
            let response = api
                .get_hpke_configuration(Some(axum::Json(request)), context)
                .await;
            assert!(matches!(response, Err(TngError::AttestationUnavailable(_))));
            Ok(())
        })
        .await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn key_rotation_refreshes_snapshot_without_a_request() -> Result<()> {
        run_test_with_tokio_runtime(|runtime| async move {
            let (aa_addr, _listener) = dummy_aa();
            let ra_context =
                RaContext::from_ra_args(&RaArgs::AttestOnly(AttestArgs::BackgroundCheck {
                    attester: AttesterArgs::Coco(CocoAttesterArgs::Uds { aa_addr }),
                    refresh_interval: Some(3600),
                    max_retries: None,
                }))
                .await?;
            let api = OhttpServerApi::new(
                Arc::new(ra_context),
                KeyArgs::SelfGenerated {
                    rotation_interval: 2,
                },
                runtime,
            )
            .await?;

            let cache = api.passport_cache.get().context("snapshot not built")?;
            let first = cache.get_latest().await?;
            for _ in 0..100 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                if cache.get_latest().await?.0 != first.0 {
                    return Ok(());
                }
            }
            anyhow::bail!("snapshot was not refreshed after the key rotated")
        })
        .await
    }
}
