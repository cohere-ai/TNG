use std::path::PathBuf;

use async_trait::async_trait;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use either::Either;
use serde::{Deserialize, Serialize};
use strum_macros::AsRefStr;
use thiserror::Error;

use crate::tunnel::attest::Model;
use crate::tunnel::ohttp::key_config::PublicKeyData;
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

    #[error("Not a valid http request")]
    InvalidHttpRequest,

    #[error("Not a valid http response")]
    InvalidHttpResponse,

    #[error("Http error during forwarding HTTP plain text to upstream")]
    HttpPlainTextForwardError(#[source] hyper_util::client::legacy::Error),

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
    /// The body of a non-TNG upstream (such as a gateway) that rejected a
    /// request forwarded on the client's behalf, truncated to
    /// `MAX_UPSTREAM_BODY_CHARS`. `default` keeps older peers' responses,
    /// which lack the field, parsing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_body: Option<String>,
}

/// Longest upstream body relayed in [`ErrorResponse::upstream_body`].
const MAX_UPSTREAM_BODY_CHARS: usize = 4096;

/// An error status returned by the upstream of a forwarded request, as
/// produced by `check_error_response`.
#[derive(Debug, Error)]
#[error("{detail}")]
pub struct UpstreamErrorResponse {
    /// The text logged for the error: the TNG peer's code and message, or the
    /// full upstream body.
    detail: String,
    /// The upstream body, truncated, when the upstream is not a TNG peer.
    /// `None` when the body is a TNG `ErrorResponse`.
    body: Option<String>,
    #[source]
    source: reqwest::Error,
}

impl UpstreamErrorResponse {
    /// The upstream status and body to relay to the client: a 4xx from an
    /// upstream that is not a TNG peer. A TNG peer's 4xx means the two TNGs
    /// disagree, which the client cannot fix. 422 asks TNG to fetch a new key
    /// config (RFC 9458 section 6.4) rather than being the client's error.
    fn client_error(&self) -> Option<(StatusCode, &str)> {
        let status = self.source.status()?;
        let body = self.body.as_deref()?;
        (status.is_client_error() && status != StatusCode::UNPROCESSABLE_ENTITY)
            .then_some((status, body))
    }
}

/// The relayable upstream client error in `error`'s chain, if any. Only the
/// `UpstreamErrorResponse` that `check_error_response` tags counts, so a
/// status from some other `reqwest::Error`, such as one in attestation
/// verification, is never relayed.
fn upstream_client_error(error: &anyhow::Error) -> Option<(StatusCode, &str)> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<UpstreamErrorResponse>())
        .and_then(UpstreamErrorResponse::client_error)
}

impl IntoResponse for TngError {
    fn into_response(self) -> Response {
        let mut upstream_body = None;
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
                } else {
                    StatusCode::BAD_GATEWAY
                }
            }

            // A request forwarded on the client's behalf that a non-TNG
            // upstream (such as a gateway) rejected with a 4xx keeps that
            // status and body. Anything else is TNG's own failure.
            TngError::HttpCipherTextBadResponse(e) => match upstream_client_error(e) {
                Some((status, body)) => {
                    upstream_body = Some(body.to_owned());
                    status
                }
                None => StatusCode::BAD_GATEWAY,
            },
            TngError::RequestKeyConfigFailed(e) | TngError::CreateOHttpClientFailed(e) => {
                match upstream_client_error(e) {
                    Some((status, body)) => {
                        upstream_body = Some(body.to_owned());
                        status
                    }
                    None => StatusCode::INTERNAL_SERVER_ERROR,
                }
            }
            TngError::DirectForwardFailed(..) => StatusCode::BAD_GATEWAY,

            // Metadata I/O errors
            TngError::MetadataReadError(..) => StatusCode::BAD_REQUEST,

            // Metadata size limit → 413 Payload Too Large
            TngError::MetadataTooLong => StatusCode::PAYLOAD_TOO_LARGE,

            // 500 for all other internal errors
            TngError::SystemTimeError(..)
            | TngError::OhttpError(..)
            | TngError::BhttpError(..)
            | TngError::AttestationUnavailable(..)
            | TngError::ClientSelectHpkeConfigurationFailed(..)
            | TngError::GenServerHpkeConfigurationResponseFailed(..)
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
                upstream_body,
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
    if let Err(source) = response.error_for_status_ref() {
        let text = response.text().await?;
        // Try to parse the error response as TNG error response
        let (detail, body) = match serde_json::from_str::<ErrorResponse>(&text) {
            Ok(ErrorResponse { code, message, .. }) => (
                format!("server error code: {code} message: {message}"),
                None,
            ),
            Err(_) => {
                let body = text.chars().take(MAX_UPSTREAM_BODY_CHARS).collect();
                (format!("full response: {text}"), Some(body))
            }
        };
        Err(UpstreamErrorResponse {
            detail,
            body,
            source,
        }
        .into())
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

    /// Run an upstream response with `status` and `body` through
    /// check_error_response, as the OHTTP client does, and return the error.
    async fn upstream_error(status: u16, body: &str) -> anyhow::Error {
        let response = http::Response::builder()
            .status(status)
            .body(body.to_owned())
            .unwrap();
        check_error_response(response.into()).await.unwrap_err()
    }

    /// The body of a TNG peer's error response.
    fn tng_peer_body(error: TngError) -> String {
        serde_json::to_string(&ErrorResponse {
            code: error.as_ref().to_owned(),
            message: error.to_string(),
            upstream_body: None,
        })
        .unwrap()
    }

    async fn response_parts(error: TngError) -> (u16, ErrorResponse) {
        let response = error.into_response();
        let status = response.status().as_u16();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn test_upstream_status_relay() {
        let peer_400 = tng_peer_body(TngError::UnacceptableAttestRequest(
            "no compatible attestation proposal".into(),
        ));
        let cases = [
            // Key-config fetch rejected by the gateway: relay the 4xx.
            (
                TngError::RequestKeyConfigFailed(upstream_error(404, "").await),
                404,
            ),
            (
                TngError::RequestKeyConfigFailed(upstream_error(429, "").await),
                429,
            ),
            // Encrypted request rejected by the gateway: relay the 4xx.
            (
                TngError::HttpCipherTextBadResponse(upstream_error(404, "").await),
                404,
            ),
            // A TNG peer's 4xx means the two TNGs disagree, which the client
            // cannot fix: keep TNG's own mapping.
            (
                TngError::RequestKeyConfigFailed(upstream_error(400, &peer_400).await),
                500,
            ),
            (
                TngError::HttpCipherTextBadResponse(upstream_error(400, &peer_400).await),
                502,
            ),
            // Upstream 5xx keeps TNG's own mapping.
            (
                TngError::RequestKeyConfigFailed(upstream_error(503, "").await),
                500,
            ),
            (
                TngError::HttpCipherTextBadResponse(upstream_error(503, "").await),
                502,
            ),
            // 422 means "refetch the key config", not a client error.
            (
                TngError::HttpCipherTextBadResponse(upstream_error(422, "").await),
                502,
            ),
            // No upstream response at all keeps the mapping.
            (
                TngError::CreateOHttpClientFailed(anyhow::anyhow!("bad url")),
                500,
            ),
        ];
        for (error, expected) in cases {
            let name = error.as_ref().to_owned();
            assert_eq!(error.into_response().status().as_u16(), expected, "{name}");
        }

        // get_or_create_ohttp_client wraps the key-config failure; the status
        // and body must survive that, which is the unknown-model case end to end.
        let wrapped = TngError::CreateOHttpClientFailed(anyhow::Error::new(
            TngError::RequestKeyConfigFailed(upstream_error(404, "not found").await),
        ));
        let (status, body) = response_parts(wrapped).await;
        assert_eq!(status, 404);
        assert_eq!(body.code, "CreateOHttpClientFailed");
        assert_eq!(body.upstream_body.as_deref(), Some("not found"));
    }

    #[tokio::test]
    async fn test_upstream_body_is_capped_and_omitted_when_not_relayed() {
        let long = "é".repeat(MAX_UPSTREAM_BODY_CHARS + 10);
        let (status, body) = response_parts(TngError::HttpCipherTextBadResponse(
            upstream_error(404, &long).await,
        ))
        .await;
        assert_eq!(status, 404);
        assert_eq!(
            body.upstream_body.map(|body| body.chars().count()),
            Some(MAX_UPSTREAM_BODY_CHARS)
        );

        // A status TNG does not relay carries no upstream body.
        let (status, body) = response_parts(TngError::HttpCipherTextBadResponse(
            upstream_error(503, "unavailable").await,
        ))
        .await;
        assert_eq!(status, 502);
        assert!(body.upstream_body.is_none());

        // A reqwest status that check_error_response did not tag is never
        // relayed, e.g. one from attestation verification.
        let untagged = http::Response::builder().status(404).body("").unwrap();
        let untagged = reqwest::Response::from(untagged)
            .error_for_status()
            .unwrap_err();
        let (status, _) = response_parts(TngError::CreateOHttpClientFailed(untagged.into())).await;
        assert_eq!(status, 500);
    }

    #[test]
    fn error_response_without_upstream_body_parses() {
        let body: ErrorResponse =
            serde_json::from_str(r#"{"code":"NoActiveKey","message":"no key"}"#).unwrap();
        assert!(body.upstream_body.is_none());
    }
}
