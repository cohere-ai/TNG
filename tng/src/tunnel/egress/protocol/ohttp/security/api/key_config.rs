use std::pin::Pin;
use std::sync::Arc;

use anyhow::{bail, Result};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::prelude::BASE64_STANDARD;
use base64::Engine as _;
use itertools::Itertools;
use ohttp::KeyConfig;
use rats_cert::tee::{AttesterPipeline, GenericAttester as _, GenericConverter as _, ReportData};

use crate::error::TngError;
use crate::tunnel::egress::protocol::ohttp::security::api::OhttpServerApi;
use crate::tunnel::egress::protocol::ohttp::security::context::TngStreamContext;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::KeyManager;
use crate::tunnel::ohttp::protocol::userdata::ServerUserData;
use crate::tunnel::ohttp::protocol::{
    HpkeKeyConfig, KeyConfigRequest, KeyConfigResponse, ServerAttestationInfo,
};
use crate::tunnel::proposal::AttestProposal;
use crate::tunnel::ra_context::{AttestContext, RaContext};
use crate::tunnel::select_proposal::pick_proposal;
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
        // Check if hit the cache
        let proposal_matches = |attest_ctx: &AttestContext| {
            payload.as_ref().is_some_and(|Json(req)| {
                pick_proposal(attest_ctx.proposal_key(), &req.proposals).is_ok()
            })
        };
        match self.ra_context.attest_context() {
            // A passport response never depends on which proposal matched, so every client
            // proposing this attester's passport shares one cached response
            Some(attest_ctx @ AttestContext::Passport { .. }) if proposal_matches(attest_ctx) => {
                self.passport_cache
                    .read()
                    .await
                    .get_or_try_init(|| async {
                        let ra_context = self.ra_context.clone();
                        let key_manager = Arc::clone(&self.key_manager);
                        let payload = Arc::new(payload);

                        let refresh_strategy = attest_ctx.refresh_strategy();

                        MaybeCached::new(context.runtime.clone(), refresh_strategy, move || {
                            Box::pin({
                                tracing::info!("Regenerating passport response");

                                let ra_context = ra_context.clone();
                                let key_manager = key_manager.clone();
                                let payload = payload.clone();

                                async move {
                                    let response = Self::get_hpke_configuration_internal(
                                        &ra_context,
                                        key_manager.as_ref(),
                                        payload.as_ref().clone(),
                                    )
                                    .await?;

                                    Ok((response, Expire::NoExpire))
                                }
                            }) as Pin<Box<_>>
                        })
                        .await
                    })
                    .await?
                    .get_latest()
                    .await
                    .map(|response: Arc<KeyConfigResponse>| {
                        IntoResponse::into_response(Json(response))
                    })
            }
            // Otherwise, we generate a new response
            _ => Self::get_hpke_configuration_internal(
                &self.ra_context,
                self.key_manager.as_ref(),
                payload,
            )
            .await
            .map(|response: KeyConfigResponse| IntoResponse::into_response(Json(response))),
        }
    }

    async fn get_hpke_configuration_internal(
        ra_context: &RaContext,
        key_manager: &dyn KeyManager,
        payload: Option<Json<KeyConfigRequest>>,
    ) -> Result<KeyConfigResponse, TngError> {
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

        let proposals = payload
            .map(|Json(payload)| payload.proposals)
            .unwrap_or_default();
        let attestation_requested = !proposals.is_empty();

        let response = async {
            Ok(match ra_context.attest_context() {
                // Just return the key config when the client sends no proposals. This can happen when the server is 'attest' while client is 'no_ra'
                Some(_) if proposals.is_empty() => KeyConfigResponse {
                    hpke_key_config,
                    attestation_info: None,
                },
                Some(attest_ctx) => match (
                    pick_proposal(attest_ctx.proposal_key(), &proposals)?,
                    attest_ctx,
                ) {
                    (
                        AttestProposal::Passport { .. },
                        AttestContext::Passport {
                            attester,
                            converter,
                            ..
                        },
                    ) => {
                        // fetch a challenge token from attestation service
                        let challenge_token = converter.get_nonce().await?;

                        let attester_pipeline = AttesterPipeline::new(attester, converter);

                        let userdata = ServerUserData {
                            challenge_token: Some(challenge_token),
                            hpke_key_config: hpke_key_config.clone(),
                        }
                        .to_claims()?;

                        let token = attester_pipeline
                            .get_evidence(&ReportData::Claims(userdata))
                            .await?;
                        let provider = token.provider_type();
                        KeyConfigResponse {
                            hpke_key_config,
                            attestation_info: Some(ServerAttestationInfo::Passport {
                                attestation_result: token.into_str(),
                                provider,
                            }),
                        }
                    }
                    (
                        AttestProposal::BackgroundCheck {
                            challenge_token, ..
                        },
                        AttestContext::BackgroundCheck { attester, .. },
                    ) => {
                        let userdata = ServerUserData {
                            challenge_token: Some(challenge_token.clone()),
                            hpke_key_config: hpke_key_config.clone(),
                        }
                        .to_claims()?;

                        let tng_evidence =
                            attester.get_evidence(&ReportData::Claims(userdata)).await?;
                        let provider = tng_evidence.provider_type();
                        let evidence = tng_evidence.serialize_to_json()?;

                        KeyConfigResponse {
                            hpke_key_config,
                            attestation_info: Some(ServerAttestationInfo::BackgroundCheck {
                                evidence,
                                provider,
                            }),
                        }
                    }
                    _ => bail!("picked proposal does not match the attester's model"),
                },
                None => {
                    // No attestation required (VerifyOnly or NoRa)
                    KeyConfigResponse {
                        hpke_key_config,
                        attestation_info: None,
                    }
                }
            })
        }
        .await;

        if attestation_requested {
            if let Some(metrics) = ra_context.attestation_metrics() {
                metrics.record(
                    AttestationOperation::Generate,
                    AttestationProtocol::Ohttp,
                    response
                        .as_ref()
                        .is_ok_and(|response| response.attestation_info.is_some()),
                );
            }
        }

        let response = response.map_err(TngError::GenServerHpkeConfigurationResponseFailed)?;

        Ok(response)
    }
}
