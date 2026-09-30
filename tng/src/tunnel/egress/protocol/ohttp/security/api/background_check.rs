use anyhow::{bail, Context, Result};
use axum::extract::Query;
use axum::Json;
use rats_cert::tee::GenericConverter;

use crate::error::TngError;
use crate::tunnel::egress::protocol::ohttp::security::api::OhttpServerApi;
use crate::tunnel::ohttp::protocol::{
    AttestationChallengeQuery, AttestationChallengeResponse, AttestationVerifyRequest,
    AttestationVerifyResponse,
};
use crate::tunnel::proposal::Model;
use crate::tunnel::provider::{ProviderType, TngConverter, TngEvidence};
use crate::tunnel::ra_context::VerifyContext;
use crate::tunnel::service_metrics::{AttestationOperation, AttestationProtocol};

impl OhttpServerApi {
    /// The converter of the background-check verifier for `provider`, so the converter that
    /// minted a client's nonce is also the one that checks its evidence.
    fn background_check_converter(&self, provider: ProviderType) -> Result<&TngConverter> {
        let verify_set = self
            .ra_context
            .verify_set()
            .context("client attestation is not required")?;
        match verify_set.entry(Model::BackgroundCheck, provider)? {
            VerifyContext::BackgroundCheck { converter, .. } => Ok(converter),
            VerifyContext::Passport { .. } => bail!("background-check entry holds no converter"),
        }
    }

    /// Interface 3: Attestation Forward - Get Challenge
    /// x-tng-ohttp-api: /tng/background-check/challenge?provider=...
    ///
    /// This endpoint is a forwarder for the AS (Attestation Service) challenge endpoint.
    /// It is used specifically in the "Server verification Client + background check model" scenario.
    pub async fn get_attestation_challenge(
        &self,
        Query(query): Query<AttestationChallengeQuery>,
    ) -> Result<Json<AttestationChallengeResponse>, TngError> {
        let result = async {
            let challenge_token = self
                .background_check_converter(query.provider)?
                .get_nonce()
                .await?;
            Ok(Json(AttestationChallengeResponse { challenge_token }))
        }
        .await
        .map_err(TngError::ServerVerifyClientGetChallengeTokenFailed);
        if let Some(metrics) = self.ra_context.attestation_metrics() {
            metrics.record(
                AttestationOperation::Challenge,
                AttestationProtocol::Ohttp,
                result.is_ok(),
            );
        }
        result
    }

    /// Interface 3: Attestation Forward - Verify Evidence
    /// x-tng-ohttp-api: /tng/background-check/verify
    ///
    /// This endpoint is a forwarder for the AS (Attestation Service) verification endpoint.
    /// It is used specifically in the "Server verification Client + background check model" scenario.
    pub async fn verify_attestation(
        &self,
        Json(payload): Json<AttestationVerifyRequest>,
    ) -> Result<Json<AttestationVerifyResponse>, TngError> {
        let result = async {
            let converter = self.background_check_converter(payload.provider)?;
            let evidence = TngEvidence::deserialize_from_json(payload.provider, payload.evidence)?;
            let token = converter.convert(&evidence).await?;
            let provider = token.provider_type();
            Ok(Json(AttestationVerifyResponse {
                attestation_result: token.into_str(),
                provider,
            }))
        }
        .await
        .map_err(TngError::ServerVerifyClientEvidenceFailed);
        if let Some(metrics) = self.ra_context.attestation_metrics() {
            metrics.record(
                AttestationOperation::Verify,
                AttestationProtocol::Ohttp,
                result.is_ok(),
            );
        }
        result
    }
}
