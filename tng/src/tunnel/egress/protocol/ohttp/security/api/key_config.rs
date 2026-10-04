use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use anyhow::{bail, Result};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::prelude::BASE64_STANDARD;
use base64::Engine as _;
use itertools::Itertools;
use ohttp::KeyConfig;
use rats_cert::tee::claims::Claims;
use rats_cert::tee::{AttesterPipeline, GenericConverter as _};

use crate::error::TngError;
use crate::tunnel::attest::{
    produce_attest_response, AttestClaims, AttestRequest, AttestResponse, EvidenceProducer,
    MintToken, PassportTokenCache, TokenProducer,
};
use crate::tunnel::egress::protocol::ohttp::security::api::OhttpServerApi;
use crate::tunnel::egress::protocol::ohttp::security::key_manager::KeyManager;
use crate::tunnel::ohttp::protocol::userdata::ServerUserData;
use crate::tunnel::ohttp::protocol::{HpkeKeyConfig, KeyConfigRequest, KeyConfigResponse};
use crate::tunnel::proposal::AttestProposal;
use crate::tunnel::provider::{ProviderType, TngToken};
use crate::tunnel::ra_context::{AttestContext, RaContext};
use crate::tunnel::service_metrics::{AttestationOperation, AttestationProtocol};
use crate::tunnel::utils::maybe_cached::{Expire, RefreshStrategy};

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
    ) -> Result<Response, TngError> {
        Self::get_hpke_configuration_internal(
            &self.ra_context,
            self.key_manager.as_ref(),
            &self.passport_cache,
            payload,
        )
        .await
        .map(|response: KeyConfigResponse| IntoResponse::into_response(Json(response)))
    }

    async fn get_hpke_configuration_internal(
        ra_context: &RaContext,
        key_manager: &dyn KeyManager,
        passport_cache: &OhttpPassportCache,
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

        let hpke_key_config = HpkeKeyConfig {
            expire_timestamp: keys_expire_timestamp,
            encoded_key_config_list,
        };

        let attest_request = payload
            .map(|Json(payload)| payload.attest_request)
            .unwrap_or_default();
        let attestation_requested = !attest_request.proposals.is_empty();
        let attest_resp = make_attest_response(
            ra_context,
            passport_cache,
            &attest_request,
            &hpke_key_config,
        )
        .await;

        if attestation_requested {
            if let Some(metrics) = ra_context.attestation_metrics() {
                metrics.record(
                    AttestationOperation::Generate,
                    AttestationProtocol::Ohttp,
                    matches!(attest_resp, Ok(Some(_))),
                );
            }
        }

        Ok(KeyConfigResponse {
            hpke_key_config,
            attest_response: Ok(attest_resp.map_err(TngError::from)?),
        })
    }
}

async fn make_attest_response(
    ra_context: &RaContext,
    passport_cache: &OhttpPassportCache,
    request: &AttestRequest,
    hpke_key_config: &HpkeKeyConfig,
) -> AttestResponse {
    let attest_ctx = ra_context.attest_context();
    let own_key = attest_ctx.map(AttestContext::proposal_key);
    let mut pipeline = None;
    let (evidence_producer, max_retries, refresh) = match attest_ctx {
        Some(AttestContext::BackgroundCheck {
            attester,
            max_retries,
            ..
        }) => (Some(attester as &dyn EvidenceProducer), *max_retries, None),
        Some(AttestContext::Passport {
            attester,
            converter,
            max_retries,
            refresh_strategy,
            ..
        }) => {
            pipeline = Some(AttesterPipeline::new(attester, converter));
            (None, *max_retries, Some(*refresh_strategy))
        }
        None => (None, 0, None),
    };
    let token_producer = pipeline
        .as_ref()
        .map(|pipeline| pipeline as &dyn TokenProducer);
    let bound_cache = refresh.map(|refresh| BoundOhttpPassportCache {
        cache: passport_cache,
        key_config: hpke_key_config,
        refresh,
    });
    let claims = OhttpClaims {
        hpke_key_config,
        attest_ctx,
    };
    produce_attest_response(
        request,
        own_key,
        &claims,
        evidence_producer,
        token_producer,
        bound_cache.as_ref(),
        max_retries,
    )
    .await
}

struct OhttpClaims<'a> {
    hpke_key_config: &'a HpkeKeyConfig,
    attest_ctx: Option<&'a AttestContext>,
}

impl AttestClaims for OhttpClaims<'_> {
    fn claims<'a>(
        &'a self,
        proposal: &'a AttestProposal,
    ) -> Pin<Box<dyn Future<Output = Result<Claims>> + Send + 'a>> {
        Box::pin(claims_for(proposal, self.hpke_key_config, self.attest_ctx))
    }
}

async fn claims_for(
    proposal: &AttestProposal,
    hpke_key_config: &HpkeKeyConfig,
    attest_ctx: Option<&AttestContext>,
) -> Result<Claims> {
    let Some(attest_ctx) = attest_ctx else {
        bail!("not configured to attest");
    };
    let challenge_token = match (proposal, attest_ctx) {
        (
            AttestProposal::BackgroundCheck {
                challenge_token, ..
            },
            AttestContext::BackgroundCheck { .. },
        ) => Some(challenge_token.clone()),
        (AttestProposal::Passport { .. }, AttestContext::Passport { converter, .. }) => {
            Some(converter.get_nonce().await?)
        }
        _ => bail!("picked proposal does not match the attester's model"),
    };
    ServerUserData {
        challenge_token,
        hpke_key_config: hpke_key_config.clone(),
    }
    .to_claims()
}

/// Passport tokens for the current HPKE key config. A hit requires the same key config, an
/// unexpired token, and a refresh interval that has not elapsed.
pub(super) struct OhttpPassportCache {
    inner: Mutex<Option<CachedOhttpPassport>>,
}

struct CachedOhttpPassport {
    key_config: HpkeKeyConfig,
    provider: ProviderType,
    jwt: String,
    expire: Expire,
    minted_at: SystemTime,
}

impl OhttpPassportCache {
    pub(super) fn new() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }

    pub(super) fn clear(&self) {
        *self.inner.lock().unwrap_or_else(|error| error.into_inner()) = None;
    }
}

struct BoundOhttpPassportCache<'a> {
    cache: &'a OhttpPassportCache,
    key_config: &'a HpkeKeyConfig,
    refresh: RefreshStrategy,
}

impl PassportTokenCache for BoundOhttpPassportCache<'_> {
    fn get_or_mint<'a>(
        &'a self,
        mint: MintToken<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<TngToken>> + Send + 'a>> {
        Box::pin(async move {
            {
                let guard = self
                    .cache
                    .inner
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                if let Some(cached) = guard.as_ref() {
                    if cached.key_config == *self.key_config
                        && is_unexpired(cached.expire)
                        && refresh_allows(cached.minted_at, self.refresh)
                    {
                        return TngToken::from_wire(cached.provider, cached.jwt.clone());
                    }
                }
            }
            let token = mint().await?;
            let expire = Expire::from_timestamp(token.exp()?)?;
            *self
                .cache
                .inner
                .lock()
                .unwrap_or_else(|error| error.into_inner()) = Some(CachedOhttpPassport {
                key_config: self.key_config.clone(),
                provider: token.provider_type(),
                jwt: token.as_str().to_string(),
                expire,
                minted_at: SystemTime::now(),
            });
            Ok(token)
        })
    }
}

fn is_unexpired(expire: Expire) -> bool {
    match expire {
        Expire::NoExpire => true,
        Expire::ExpireAt(time) => time > SystemTime::now(),
    }
}

fn refresh_allows(minted_at: SystemTime, refresh: RefreshStrategy) -> bool {
    match refresh {
        RefreshStrategy::Always => false,
        RefreshStrategy::Periodically { interval } => minted_at
            .elapsed()
            .map(|elapsed| elapsed < Duration::from_secs(interval))
            .unwrap_or(false),
    }
}
