use std::pin::Pin;
use std::sync::Arc;

use anyhow::Result;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::prelude::BASE64_STANDARD;
use base64::Engine as _;
use itertools::Itertools;
use ohttp::KeyConfig;
use rats_cert::tee::claims::Claims;

use crate::error::{AttestError, TngError};
use crate::tunnel::attest::{respond, Attester, Prepared};
use crate::tunnel::egress::protocol::ohttp::security::api::OhttpServerApi;
use crate::tunnel::egress::protocol::ohttp::security::context::TngStreamContext;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::KeyManager;
use crate::tunnel::ohttp::protocol::userdata::ServerUserData;
use crate::tunnel::ohttp::protocol::{HpkeKeyConfig, KeyConfigRequest, KeyConfigResponse};
use crate::tunnel::ra_context::RaContext;
use crate::tunnel::service_metrics::{AttestationOperation, AttestationProtocol};
use crate::tunnel::utils::maybe_cached::{Expire, MaybeCached};

impl OhttpServerApi {
    /// Interface 1: Get HPKE Configuration
    /// x-tng-ohttp-api: /tng/key-config
    ///
    /// This endpoint is used by TNG Clients to obtain the public key configuration needed
    /// to establish an encrypted channel and verify the server's identity.
    ///
    /// The client accesses this path before connecting to the TNG Server to obtain the
    /// server's public key and Evidence or Attestation Result (if needed).
    ///
    /// This endpoint only needs to be accessed once. Before hpke_key_config.expire_timestamp or
    /// attestation_result expiration, the configuration needs to be refreshed in the background.
    pub async fn get_hpke_configuration(
        &self,
        payload: Option<Json<KeyConfigRequest>>,
        context: TngStreamContext,
    ) -> Result<Response, TngError> {
        let attest_ctx = self.ra_context.attest_context();
        let snapshot = match attest_ctx {
            // If the server is set to be a attester, we cache the key config with the attestation prepared for it
            Some(attest_ctx) => {
                self.passport_cache
                    .read()
                    .await
                    .get_or_try_init(|| async {
                        let ra_context = self.ra_context.clone();
                        let key_manager = Arc::clone(&self.key_manager);

                        let refresh_strategy = attest_ctx.refresh_strategy();

                        MaybeCached::new(context.runtime.clone(), refresh_strategy, move || {
                            Box::pin({
                                tracing::info!("Regenerating key config snapshot");

                                let ra_context = ra_context.clone();
                                let key_manager = key_manager.clone();

                                async move {
                                    Self::get_hpke_configuration_internal(
                                        &ra_context,
                                        key_manager.as_ref(),
                                    )
                                    .await
                                }
                            }) as Pin<Box<_>>
                        })
                        .await
                    })
                    .await?
                    .get_latest()
                    .await?
            }
            // Otherwise, we generate a new key config
            None => Arc::new(
                Self::get_hpke_configuration_internal(&self.ra_context, self.key_manager.as_ref())
                    .await?
                    .0,
            ),
        };
        let (hpke_key_config, prepared) = snapshot.as_ref();

        let attest_request = payload
            .map(|Json(payload)| payload.attest_request)
            .unwrap_or_default();
        let attest_resp = respond(
            &attest_request,
            attest_ctx.map(|a| a as &dyn Attester),
            prepared,
            |nonce| ohttp_claims(hpke_key_config, nonce),
        )
        .await;

        if !attest_request.proposals.is_empty() {
            if let Some(metrics) = self.ra_context.attestation_metrics() {
                metrics.record(
                    AttestationOperation::Generate,
                    AttestationProtocol::Ohttp,
                    matches!(attest_resp, Ok(Some(_))),
                );
            }
        }

        Ok(IntoResponse::into_response(Json(KeyConfigResponse {
            hpke_key_config: hpke_key_config.clone(),
            attest_response: Ok(attest_resp.map_err(TngError::from)?),
        })))
    }

    async fn get_hpke_configuration_internal(
        ra_context: &RaContext,
        key_manager: &dyn KeyManager,
    ) -> Result<((HpkeKeyConfig, Prepared), Expire), TngError> {
        // Collect all client visible keys, and create encoded_key_config_list
        let all_keys = key_manager.get_client_visible_keys().await?;
        let keys_expire_time = all_keys
            .iter()
            .map(|key_info| key_info.expire_at)
            .min()
            .ok_or_else(|| TngError::NoActiveKey)?;

        let key_config_list = all_keys
            .into_iter()
            .sorted_by_key(|key_info| key_info.key_config.key_id())
            .map(|key_info| key_info.key_config)
            .collect_vec();

        let encoded_key_config_list = BASE64_STANDARD
            .encode(KeyConfig::encode_list(&key_config_list).map_err(TngError::from)?);

        let keys_expire_timestamp = keys_expire_time
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(TngError::from)?
            .as_secs();

        // Generate final HpkeKeyConfig
        let hpke_key_config = HpkeKeyConfig {
            expire_timestamp: keys_expire_timestamp,
            encoded_key_config_list,
        };

        let (prepared, expire) = match ra_context.attest_context() {
            Some(attest_ctx) => async {
                let prepared = attest_ctx
                    .prepare(|nonce| ohttp_claims(&hpke_key_config, nonce))
                    .await?;
                let expire = prepared.expire()?;
                anyhow::Ok((prepared, expire))
            }
            .await
            .map_err(|error| {
                tracing::error!(?error, "Failed to prepare attestation for the key config");
                TngError::from(AttestError::Unavailable)
            })?,
            None => (Prepared::default(), Expire::NoExpire),
        };

        Ok(((hpke_key_config, prepared), expire))
    }
}

fn ohttp_claims(hpke_key_config: &HpkeKeyConfig, nonce: &str) -> Result<Claims> {
    ServerUserData {
        challenge_token: Some(nonce.to_string()),
        hpke_key_config: hpke_key_config.clone(),
    }
    .to_claims()
}
