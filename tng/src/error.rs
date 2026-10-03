use std::path::PathBuf;

use anyhow::Context as _;
use async_trait::async_trait;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use either::Either;
use serde::{Deserialize, Serialize};
use strum_macros::AsRefStr;
use thiserror::Error;

use crate::tunnel::ohttp::key_config::PublicKeyData;
use crate::tunnel::proposal::Model;
use crate::tunnel::provider::ProviderType;

/// Failure while answering an attestation request.
///
/// This is the `Err` arm of an [`crate::tunnel::attest::AttestResponse`], so a peer can match
/// the variant. [`Self::Unavailable`] is an attester or claims failure. Every other variant is
/// a request this side will not answer. Display text is for logs and HTTP bodies. It does not
/// include the local configuration or the local error chain. OHTTP maps [`Self::Unavailable`]
/// to HTTP 500 and the rest to HTTP 400.
#[derive(Debug, Error, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestError {
    #[error("not configured to attest")]
    NotConfigured,
    #[error("no compatible attestation proposal")]
    NoCompatibleProposal,
    #[error("duplicate proposal for ({model}, {provider})")]
    DuplicateProposal {
        model: Model,
        provider: ProviderType,
    },
    #[error("missing nonce")]
    MissingNonce,
    #[error("attestation unavailable")]
    Unavailable,
    #[error("malformed attestation proposal")]
    Malformed,
}

impl From<AttestError> for TngError {
    fn from(error: AttestError) -> Self {
        let message = error.to_string();
        match error {
            AttestError::Unavailable => TngError::AttestationUnavailable(message),
            _ => TngError::UnacceptableAttestRequest(message),
        }
    }
}

/// Custom error type
#[derive(Error, Debug, AsRefStr)]
pub enum TngError {
    #[error("System time error: {0}")]
    SystemTimeError(#[from] std::time::SystemTimeError),

    #[error("OHTTP error: {0}")]
    OhttpError(#[from] ohttp::Error),

    #[error("BHTTP error: {0}")]
    BhttpError(#[from] bhttp::Error),

    #[error("Base64 decode error: {0}")]
    Base64DecodeError(#[from] base64::DecodeError),

    #[error("Failed to read metadata")]
    MetadataReadError(#[source] std::io::Error),

    #[error("The metadata is too long")]
    MetadataTooLong,

    #[error("Failed to decode metadata")]
    MetadataDecodeError(#[source] prost::DecodeError),

    #[error("Failed to encode metadata")]
    MetadataEncodeError(#[source] prost::EncodeError),

    #[error("Failed to validate metadata")]
    MetadataValidateError(#[source] anyhow::Error),

    #[error("Not a valid http request")]
    InvalidHttpRequest,

    #[error("Not a valid http response")]
    InvalidHttpResponse,

    #[error("Http error during forwarding HTTP plain text to upstream")]
    HttpPlainTextForwardError(#[source] hyper::Error),

    #[error("Http error during forwarding HTTP cipher text to upstream")]
    HttpCipherTextForwardError(#[source] reqwest::Error),

    #[error("Got bad response during forwarding HTTP cipher text to upstream")]
    HttpCipherTextBadResponse(#[source] anyhow::Error),

    #[error("Failed to request key config from ohttp server")]
    RequestKeyConfigFailed(#[source] anyhow::Error),

    /// The key-config `attest_request` cannot be answered.
    #[error("{0}")]
    UnacceptableAttestRequest(String),

    /// The key-config request was acceptable and producing attestation failed.
    #[error("{0}")]
    AttestationUnavailable(String),

    #[error("Failed to connect to upstream")]
    ConnectUpstreamFailed,

    #[error("Failed to construct http response")]
    ConstructHttpResponseFailed(#[source] http::Error),

    #[error("Failed to select a hpke configuration")]
    ClientSelectHpkeConfigurationFailed(#[source] anyhow::Error),

    #[error("Failed to generate hpke configuration response")]
    GenServerHpkeConfigurationResponseFailed(#[source] anyhow::Error),

    #[error("Not a valid OHTTP request")]
    InvalidOHttpRequest(#[source] anyhow::Error),

    #[error("Not a valid OHTTP response")]
    InvalidOHttpResponse(#[source] anyhow::Error),

    #[error("Failed to create OHTTP client")]
    CreateOHttpClientFailed(#[source] anyhow::Error),

    #[error("Direct forward failed: {0}")]
    DirectForwardFailed(#[source] anyhow::Error),

    #[error("Failed to create RA context")]
    RaContextCreationFailed(#[source] anyhow::Error),

    #[error("Access to this service requires a TNG-secured connection. Ensure your client connects via TNG. To bypass, update the direct_forward rules in the TNG server side configuration.")]
    RejectNonTngRequest,

    #[error("Invalid request payload: {0}")]
    InvalidRequestPayload(#[from] axum::extract::rejection::JsonRejection),

    #[error("Invalid x-tng-ohttp-api value")]
    InvalidOhttpApiHeaderValue,

    #[error("The requested key does not exist: {}", match .0 {
        Either::Left(key_id) => format!("key_id: {}", key_id),
        Either::Right(public_key) => format!(
            "public_key: {:?}",
            public_key
        ),
    })]
    ServerKeyConfigNotFound(Either<u8 /* key_id */, PublicKeyData /* public_key_data */>),

    #[error("The server has no active key")]
    NoActiveKey,

    #[error("Failed to load private key {0}")]
    LoadPrivateKeyFailed(PathBuf, #[source] anyhow::Error),

    #[error("Invalid parameter")]
    InvalidParameter(#[source] anyhow::Error),

    #[cfg(feature = "__egress-common")]
    #[error("Error from serf crate")]
    SerfCrateError(#[source] anyhow::Error),

    #[error("Should request new KeyConfig from server")]
    ShouldRequestNewKeyConfigFromServerError(#[source] anyhow::Error),

    #[error("Failed to watch file {0}")]
    WatchFileFailed(PathBuf, #[source] anyhow::Error),
}

/// Error response structure
#[derive(Serialize, Deserialize, Debug)]
pub struct ErrorResponse {
    /// Machine-readable error code
    pub code: String,
    /// Human-readable error description
    pub message: String,
}

impl IntoResponse for TngError {
    fn into_response(self) -> Response {
        let status = match &self {
            // Client errors (4xx)
            TngError::InvalidRequestPayload(..) => StatusCode::BAD_REQUEST,
            TngError::RejectNonTngRequest => StatusCode::FORBIDDEN,
            TngError::InvalidOhttpApiHeaderValue => StatusCode::BAD_REQUEST,
            TngError::InvalidHttpRequest => StatusCode::BAD_REQUEST,
            TngError::InvalidHttpResponse => StatusCode::BAD_REQUEST,
            TngError::InvalidOHttpRequest(..) => StatusCode::BAD_REQUEST,
            TngError::InvalidOHttpResponse(..) => StatusCode::BAD_REQUEST,
            TngError::UnacceptableAttestRequest(..) => StatusCode::BAD_REQUEST,

            // Validation / Decode errors → 400 Bad Request
            TngError::Base64DecodeError(..) => StatusCode::BAD_REQUEST,
            TngError::MetadataDecodeError(..) => StatusCode::BAD_REQUEST,
            TngError::MetadataEncodeError(..) => StatusCode::INTERNAL_SERVER_ERROR,
            TngError::MetadataValidateError(..) => StatusCode::BAD_REQUEST,
            TngError::ConstructHttpResponseFailed(..) => StatusCode::INTERNAL_SERVER_ERROR,

            // Not Found / Upstream issues
            TngError::ConnectUpstreamFailed => StatusCode::BAD_GATEWAY,

            // Timeouts / Network failures
            TngError::HttpPlainTextForwardError(..) => StatusCode::BAD_GATEWAY,
            TngError::HttpCipherTextForwardError(e) => {
                #[cfg(unix)]
                let is_timeout = e.is_connect() || e.is_timeout();
                #[cfg(wasm)]
                let is_timeout = e.is_timeout();
                if is_timeout {
                    StatusCode::GATEWAY_TIMEOUT
                } else if e
                    .status()
                    .map(|s| s == StatusCode::TOO_MANY_REQUESTS)
                    .unwrap_or(false)
                {
                    StatusCode::TOO_MANY_REQUESTS
                } else {
                    StatusCode::BAD_GATEWAY
                }
            }
            TngError::HttpCipherTextBadResponse(..) => StatusCode::BAD_GATEWAY,
            TngError::DirectForwardFailed(..) => StatusCode::BAD_GATEWAY,

            // Metadata I/O errors
            TngError::MetadataReadError(..) => StatusCode::BAD_REQUEST,

            // Metadata size limit → 413 Payload Too Large
            TngError::MetadataTooLong => StatusCode::PAYLOAD_TOO_LARGE,

            // 500 for all other internal errors
            TngError::SystemTimeError(..)
            | TngError::OhttpError(..)
            | TngError::BhttpError(..)
            | TngError::RequestKeyConfigFailed(..)
            | TngError::AttestationUnavailable(..)
            | TngError::ClientSelectHpkeConfigurationFailed(..)
            | TngError::GenServerHpkeConfigurationResponseFailed(..)
            | TngError::CreateOHttpClientFailed(..)
            | TngError::RaContextCreationFailed(..)
            | TngError::LoadPrivateKeyFailed(..) => StatusCode::INTERNAL_SERVER_ERROR,
            TngError::InvalidParameter(..) => StatusCode::INTERNAL_SERVER_ERROR,
            TngError::WatchFileFailed(..) => StatusCode::INTERNAL_SERVER_ERROR,
            #[cfg(feature = "__egress-common")]
            TngError::SerfCrateError(..) => StatusCode::INTERNAL_SERVER_ERROR,
            // See the RFC 9458 section 6.4. Key Management
            // The client should request new KeyConfig from server when got UNPROCESSABLE_ENTITY from server.
            TngError::ServerKeyConfigNotFound { .. } => StatusCode::UNPROCESSABLE_ENTITY,
            TngError::NoActiveKey => StatusCode::UNPROCESSABLE_ENTITY,
            TngError::ShouldRequestNewKeyConfigFromServerError { .. } => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };

        (
            status,
            Json(ErrorResponse {
                code: self.as_ref().to_owned(),
                message: self.to_string(),
            }),
        )
            .into_response()
    }
}

#[cfg(unix)]
#[async_trait]
pub trait CheckErrorResponse: Sized {
    async fn check_error_response(self) -> Result<Self, anyhow::Error>;
}

#[cfg(unix)]
#[async_trait]
impl CheckErrorResponse for reqwest::Response {
    async fn check_error_response(self) -> Result<Self, anyhow::Error> {
        check_error_response(self).await
    }
}

#[cfg(wasm)]
#[async_trait(?Send)]
pub trait CheckErrorResponse: Sized {
    async fn check_error_response(self) -> Result<Self, anyhow::Error>;
}

#[cfg(wasm)]
#[async_trait(?Send)]
impl CheckErrorResponse for reqwest::Response {
    async fn check_error_response(self) -> Result<Self, anyhow::Error> {
        check_error_response(self).await
    }
}

async fn check_error_response(
    response: reqwest::Response,
) -> Result<reqwest::Response, anyhow::Error> {
    if let Err(error) = response.error_for_status_ref() {
        let text = response.text().await?;
        // Try to parse the error response as TNG error response
        if let Ok(ErrorResponse { code, message }) = serde_json::from_str(&text) {
            Err(error).context(format!("server error code: {code} message: {message}"))?
        } else {
            Err(error).context(format!("full response: {text}"))?
        }
    } else {
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    use super::*;

    #[test]
    fn key_config_attest_failures_use_http_status() {
        let unacceptable =
            TngError::UnacceptableAttestRequest("missing nonce".into()).into_response();
        assert_eq!(unacceptable.status(), StatusCode::BAD_REQUEST);

        let unavailable =
            TngError::AttestationUnavailable("attestation unavailable".into()).into_response();
        assert_eq!(unavailable.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
