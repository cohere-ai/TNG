use crate::error::TngError;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::callback_manager::{
    CallbackManager, KeyChangeCallback, KeyChangeEvent,
};
use crate::tunnel::egress::protocol::ohttp::security::key_manager::{
    KeyInfo, KeyManager, KeyStatus,
};
use crate::tunnel::ohttp::key_config::{KeyConfigExtend, PublicKeyData};
use crate::tunnel::utils::runtime::supervised_task::SupervisedTaskResult;
use crate::tunnel::utils::runtime::TokioRuntime;

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::Result;
use async_trait::async_trait;

/// Implementation of KeyManager that generates random keys with automatic rotation
pub struct SelfGeneratedKeyManager {
    /// Map of key IDs to key information
    inner: Arc<RandomKeyManagerInner>,
    /// Handle to cancel the refresh task when RandomKeyManager is dropped
    #[allow(unused)]
    refresh_task: tokio::task::JoinHandle<SupervisedTaskResult<()>>,
}

pub struct RandomKeyManagerInner {
    /// Map of key IDs to key information
    keys: tokio::sync::RwLock<HashMap<PublicKeyData, KeyInfo>>,
    /// List of registered callbacks triggered when a key is updated or created
    callback_manager: CallbackManager,

    rotation_interval: u64,
    activation_delay: u64,
}

impl SelfGeneratedKeyManager {
    /// Create a new RandomKeyManager with auto-refresh task
    ///
    /// Initializes the key manager with an empty key set and starts a background
    /// task that automatically refreshes keys based on their expiration schedule
    pub fn new_with_auto_refresh(
        runtime: TokioRuntime,
        rotation_interval: u64,
        activation_delay: u64,
    ) -> Result<Self, TngError> {
        if activation_delay >= rotation_interval {
            return Err(TngError::InvalidParameter(anyhow::anyhow!(
                "activation_delay ({activation_delay}s) must be less than rotation_interval ({rotation_interval}s)"
            )));
        }

        let inner = Arc::new(RandomKeyManagerInner {
            keys: tokio::sync::RwLock::new(HashMap::new()),
            callback_manager: CallbackManager::new(),
            rotation_interval,
            activation_delay,
        });

        let inner_clone = inner.clone();

        // Spawn the refresh task using the provided runtime
        let refresh_task = runtime.spawn_supervised_task_current_span(async move {
            loop {
                // Perform the refresh
                if let Err(e) = inner_clone.refresh_keys().await {
                    tracing::error!("Failed to refresh OHTTP keys: {:?}", e);
                }

                // Calculate the next refresh time
                let next_refresh = inner_clone.calculate_next_refresh_time().await;

                // Sleep until the next refresh
                tokio::time::sleep(next_refresh).await;
            }
        });

        Ok(Self {
            inner,
            refresh_task,
        })
    }
}

impl RandomKeyManagerInner {
    /// Calculate when the next key refresh should happen
    ///
    /// Returns the duration until the next refresh is needed
    async fn calculate_next_refresh_time(&self) -> std::time::Duration {
        let now = SystemTime::now();
        let mut earliest_time = now + Duration::from_secs(self.rotation_interval);

        let keys = self.keys.read().await;

        for key_info in keys.values() {
            match key_info.status {
                KeyStatus::Propagating => {
                    earliest_time = std::cmp::min(earliest_time, key_info.active_at);
                }
                KeyStatus::Active => {
                    earliest_time = std::cmp::min(earliest_time, key_info.stale_at);
                }
                KeyStatus::Stale => {}
            }

            // Compare with the expiration time (when key should be removed)
            earliest_time = std::cmp::min(earliest_time, key_info.expire_at);
        }

        // Calculate time until earliest event
        if let Ok(duration) = earliest_time.duration_since(now) {
            // Make sure we return at least 1 second to prevent busy loops
            if duration.as_secs() > 0 {
                return duration;
            }
        }
        Duration::from_secs(1) // at least 1 second
    }

    /// Generate a new key with the specified ID
    fn generate_key_config(&self, key_id: u8) -> Result<ohttp::KeyConfig, TngError> {
        // Create key config with X25519Sha256 KEM and multiple symmetric algorithms
        let config = ohttp::KeyConfig::new(
            key_id,
            ohttp::hpke::Kem::X25519Sha256,
            vec![
                ohttp::SymmetricSuite::new(
                    ohttp::hpke::Kdf::HkdfSha256,
                    ohttp::hpke::Aead::ChaCha20Poly1305,
                ),
                ohttp::SymmetricSuite::new(
                    ohttp::hpke::Kdf::HkdfSha256,
                    ohttp::hpke::Aead::Aes256Gcm,
                ),
                ohttp::SymmetricSuite::new(
                    ohttp::hpke::Kdf::HkdfSha256,
                    ohttp::hpke::Aead::Aes128Gcm,
                ),
            ],
        )
        .map_err(TngError::from)?;

        Ok(config)
    }

    /// Refresh keys based on their expiration times
    ///
    /// This method should be called periodically to manage key lifecycle:
    /// - Keys older than half their lifetime are marked as stale
    /// - Expired keys are removed
    /// - A new key is generated if no active key exists, with a lifetime of 2 * `rotation_interval`.
    async fn refresh_keys(&self) -> Result<(), TngError> {
        let now = SystemTime::now();
        let mut keys = self.keys.write().await;

        // Remove expired keys
        for (_, key_info) in keys.iter_mut() {
            // first, nofity the callbacks
            if key_info.expire_at <= now {
                self.callback_manager
                    .trigger(&KeyChangeEvent::Removed {
                        key_info: Cow::Borrowed(key_info),
                    })
                    .await;
            }
        }
        keys.retain(|_, key_info| key_info.expire_at > now);

        // Activate propagating keys whose activation delay has elapsed
        for (_, key_info) in keys.iter_mut() {
            if matches!(key_info.status, KeyStatus::Propagating) && now >= key_info.active_at {
                self.callback_manager
                    .trigger(&KeyChangeEvent::StatusChanged {
                        key_info: Cow::Borrowed(key_info),
                        old_status: KeyStatus::Propagating,
                        new_status: KeyStatus::Active,
                    })
                    .await;
                key_info.status = KeyStatus::Active;
            }
        }

        // Mark stale keys
        for (_, key_info) in keys.iter_mut() {
            if key_info.stale_at <= now && matches!(key_info.status, KeyStatus::Active) {
                self.callback_manager
                    .trigger(&KeyChangeEvent::StatusChanged {
                        key_info: Cow::Borrowed(key_info),
                        old_status: KeyStatus::Active,
                        new_status: KeyStatus::Stale,
                    })
                    .await;
                key_info.status = KeyStatus::Stale;
            }
        }

        // Add new key if needed (no Active or Propagating key exists)
        let need_new_key = !keys
            .values()
            .any(|key_info| matches!(key_info.status, KeyStatus::Active | KeyStatus::Propagating));

        if need_new_key {
            tracing::debug!("Generating new OHTTP key");
            let new_key_id = (0..u8::MAX)
                .find(|id| {
                    !keys
                        .values()
                        .any(|key_info| key_info.key_config.key_id() == *id)
                })
                .unwrap_or_else(|| {
                    tracing::warn!("No unused key ID found, generating key with ID 0 instead");
                    0
                });

            let key_config = self.generate_key_config(new_key_id)?;
            let created_at = now;

            // Cold start: no existing keys at all, activate immediately.
            // Rotation: delay activation to give peers time to receive the key via gossip.
            let is_cold_start = keys.is_empty();
            let active_at = if is_cold_start {
                created_at
            } else {
                created_at + Duration::from_secs(self.activation_delay)
            };

            let stale_at = created_at + Duration::from_secs(self.rotation_interval);
            let expire_at = created_at + Duration::from_secs(self.rotation_interval * 2);

            let status = if is_cold_start || self.activation_delay == 0 {
                KeyStatus::Active
            } else {
                KeyStatus::Propagating
            };

            let key_info = KeyInfo {
                key_config,
                status,
                created_at,
                active_at,
                stale_at,
                expire_at,
            };
            tracing::info!(?key_info, "New OHTTP key generated");
            self.callback_manager
                .trigger(&KeyChangeEvent::Created {
                    key_info: Cow::Borrowed(&key_info),
                })
                .await;
            keys.insert(key_info.key_config.public_key_data()?, key_info);
        }

        Ok(())
    }
}

#[async_trait]
impl KeyManager for SelfGeneratedKeyManager {
    async fn get_fist_key_by_key_id(&self, key_id: u8) -> Result<KeyInfo, TngError> {
        let keys = self.inner.keys.read().await;
        keys.values()
            .find(|key_info| key_info.key_config.key_id() == key_id)
            .cloned()
            .ok_or(TngError::ServerKeyConfigNotFound(either::Either::Left(
                key_id,
            )))
    }

    async fn get_key_by_public_key_data(
        &self,
        public_key_data: &PublicKeyData,
    ) -> Result<KeyInfo, TngError> {
        let keys = self.inner.keys.read().await;
        keys.get(public_key_data)
            .cloned()
            .ok_or(TngError::ServerKeyConfigNotFound(either::Either::Right(
                public_key_data.clone(),
            )))
    }

    async fn get_client_visible_keys(&self) -> Result<Vec<KeyInfo>, TngError> {
        let keys = self.inner.keys.read().await;

        let active: Vec<KeyInfo> = keys
            .values()
            .filter(|key_info| matches!(key_info.status, KeyStatus::Active))
            .cloned()
            .collect();

        if !active.is_empty() {
            return Ok(active);
        }

        // Fallback: while the new active key is waiting for activation,
        // continue advertising stale keys so clients can still encrypt.
        Ok(keys
            .values()
            .filter(|key_info| matches!(key_info.status, KeyStatus::Stale))
            .cloned()
            .collect())
    }

    /// Returns all keys regardless of activation delay or status.
    async fn get_all_keys(&self) -> Result<Vec<KeyInfo>, TngError> {
        Ok(self.inner.keys.read().await.values().cloned().collect())
    }

    async fn register_callback(&self, callback: KeyChangeCallback) {
        self.inner
            .callback_manager
            .register_callback(callback)
            .await;
    }
}

impl Drop for SelfGeneratedKeyManager {
    fn drop(&mut self) {
        self.refresh_task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::run_test_with_tokio_runtime;

    #[tokio::test]
    async fn activation_delay_rejects_invalid_config() {
        run_test_with_tokio_runtime(|rt| async move {
            let err = SelfGeneratedKeyManager::new_with_auto_refresh(rt.clone(), 10, 10);
            assert!(err.is_err());

            let err = SelfGeneratedKeyManager::new_with_auto_refresh(rt.clone(), 10, 15);
            assert!(err.is_err());

            let ok = SelfGeneratedKeyManager::new_with_auto_refresh(rt, 10, 0);
            assert!(ok.is_ok());

            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn cold_start_key_is_immediately_visible() {
        run_test_with_tokio_runtime(|rt| async move {
            let manager = SelfGeneratedKeyManager::new_with_auto_refresh(rt, 300, 30).unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;

            let k1 = &manager.get_client_visible_keys().await.unwrap()[0];
            assert!(k1.active_at <= SystemTime::now(), "key is already active");
            assert_eq!(k1.active_at, k1.created_at, "cold-start key has no delay");

            Ok(())
        })
        .await
        .unwrap();
    }

    /// Helper: sleep until `target` plus a small buffer.
    async fn sleep_until(target: SystemTime) {
        let wait = target.duration_since(SystemTime::now()).unwrap_or_default()
            + Duration::from_millis(200);
        tokio::time::sleep(wait).await;
    }

    #[tokio::test]
    async fn stale_key_serves_as_fallback_during_activation_delay() {
        run_test_with_tokio_runtime(|rt| async move {
            let manager = SelfGeneratedKeyManager::new_with_auto_refresh(rt, 2, 1).unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;

            let k1 = &manager.get_client_visible_keys().await.unwrap()[0];
            let k1_id = k1.key_config.key_id();
            assert_eq!(k1.active_at, k1.created_at, "cold-start key has no delay");

            // Wait for K1 to go stale -> K2 created but not yet active
            sleep_until(k1.stale_at).await;
            let fb = manager.get_client_visible_keys().await.unwrap();
            assert_eq!(fb[0].key_config.key_id(), k1_id, "stale K1 is the fallback");

            // Verify K2 timing, then wait for it to activate
            let k2 = manager.get_fist_key_by_key_id(k1_id + 1).await.unwrap();
            let k2_id = k2.key_config.key_id();
            assert_eq!(k2.active_at, k2.created_at + Duration::from_secs(1));
            sleep_until(k2.active_at).await;

            let keys = manager.get_client_visible_keys().await.unwrap();
            assert_ne!(keys[0].key_config.key_id(), k1_id, "K2 now visible");
            assert_eq!(keys[0].key_config.key_id(), k2_id, "K2 is the active key");

            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn get_all_keys_includes_non_active_keys_during_activation_delay() {
        run_test_with_tokio_runtime(|rt| async move {
            let manager = SelfGeneratedKeyManager::new_with_auto_refresh(rt, 2, 1).unwrap();
            // wait for first key to be generated and go stale, second key to be generated but not yet active
            tokio::time::sleep(Duration::from_millis(2500)).await;

            // get_all_keys must include both K1 (stale) and K2 (pending)
            let all = manager.get_all_keys().await.unwrap();
            assert_eq!(all.len(), 2, "both stale and pending keys are returned");
            let now = SystemTime::now();
            let (stale, not_stale): (Vec<_>, Vec<_>) = all.iter().partition(|k| now >= k.stale_at);
            assert_eq!(stale.len(), 1, "one key should be stale");
            assert_eq!(not_stale.len(), 1, "one key should not be stale");

            Ok(())
        })
        .await
        .unwrap();
    }
}
