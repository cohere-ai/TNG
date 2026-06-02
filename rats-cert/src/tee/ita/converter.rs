use std::time::Duration;

use super::retry::RetryPolicy;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::errors::*;
use crate::tee::GenericConverter;

use super::evidence::{ItaEvidence, ItaNonce};
use super::token::ItaToken;

/// ITA delegates GPU evidence verification to NVIDIA's Remote Attestation Service
/// (NRAS), which may transiently fail. Intel recommends client-side retry logic for
/// GPU attestation requests.
/// See: https://docs.trustauthority.intel.com/main/articles/articles/ita/concept-gpu-attestation.html#:~:text=recommended%20to%20include-,retry%20logic,-in%20the%20client
const ITA_RETRY_INITIAL_DELAY: Duration = Duration::from_millis(500);
const ITA_RETRY_MAX_DELAY: Duration = Duration::from_secs(1);
const ITA_MAX_RETRIES: usize = 4;

const ITA_NONCE_PATH: &str = "/appraisal/v2/nonce";
const ITA_ATTEST_PATH: &str = "/appraisal/v2/attest";

// ---------------------------------------------------------------------------
// ITA API request/response types (private)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct ItaAttestRequest {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    policy_ids: Vec<String>,
    token_signing_alg: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    policy_must_match: bool,
    tdx: TdxEvidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    nvgpu: Option<NvgpuEvidence>,
}

#[derive(Serialize)]
struct TdxEvidence {
    quote: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    verifier_nonce: Option<ItaNonce>,
    #[serde(skip_serializing_if = "Option::is_none")]
    runtime_data: Option<String>,
}

#[derive(Serialize)]
struct NvgpuEvidence {
    evidence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    verifier_nonce: Option<ItaNonce>,
    gpu_nonce: String,
    certificate: String,
    arch: String,
}

#[derive(Deserialize)]
struct ItaAttestResponse {
    token: String,
}

// ---------------------------------------------------------------------------
// ItaConverter
// ---------------------------------------------------------------------------

pub struct ItaConverter {
    http: Client,
    api_key: String,
    base_url: String,
    policy_ids: Vec<String>,
    max_retries: usize,
    retry_initial_delay: Duration,
    retry_max_delay: Duration,
}

impl ItaConverter {
    pub fn new(api_key: &str, base_url: &str, policy_ids: &[String]) -> Result<Self> {
        Ok(Self {
            http: Client::new(),
            api_key: api_key.to_string(),
            base_url: base_url.trim_end_matches('/').to_string(),
            policy_ids: policy_ids.to_vec(),
            max_retries: ITA_MAX_RETRIES,
            retry_initial_delay: ITA_RETRY_INITIAL_DELAY,
            retry_max_delay: ITA_RETRY_MAX_DELAY,
        })
    }

    pub fn with_max_retries(mut self, max_retries: usize) -> Self {
        self.max_retries = max_retries;
        self
    }

    pub fn with_retry_initial_delay(mut self, delay: Duration) -> Self {
        self.retry_initial_delay = delay;
        self
    }

    pub fn with_retry_max_delay(mut self, delay: Duration) -> Self {
        self.retry_max_delay = delay;
        self
    }

    fn check_policy_matching(&self, token: &ItaToken) -> Result<()> {
        if self.policy_ids.is_empty() {
            return Ok(());
        }

        let claims = token.decode_payload()?;

        let matched = claims
            .get("policy_ids_matched")
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                Error::ItaError(
                    "ITA token missing policy_ids_matched, but policy_ids are configured"
                        .to_string(),
                )
            })?;

        let matched_ids: std::collections::HashSet<&str> = matched
            .iter()
            .filter_map(|v| v.get("id").and_then(|id| id.as_str()))
            .collect();

        for expected_id in &self.policy_ids {
            if !matched_ids.contains(expected_id.as_str()) {
                return Err(Error::ItaError(format!(
                    "Expected policy ID '{expected_id}' not found in policy_ids_matched"
                )));
            }
        }

        Ok(())
    }

    fn is_retryable_error(status: reqwest::StatusCode, body: &str) -> bool {
        status.is_server_error()
            || status == reqwest::StatusCode::TOO_MANY_REQUESTS
            || (status == reqwest::StatusCode::BAD_REQUEST
                && body.contains("Failed to verify GPU evidence"))
    }

    /// Send an HTTP request to ITA with retry logic, returning the response body
    /// on success.
    async fn ita_request(&self, request: reqwest::RequestBuilder, label: &str) -> Result<String> {
        let label = label.to_string();
        let max_retries = self.max_retries;
        let retry_initial_delay = self.retry_initial_delay;
        let retry_max_delay = self.retry_max_delay;

        let fut = async move {
            let policy = RetryPolicy::exponential(retry_initial_delay)
                .with_max_delay(retry_max_delay)
                .with_max_retries(max_retries);

            let (status, body) = policy
                .retry(|| async {
                    let resp = request
                        .try_clone()
                        .expect("request must be cloneable")
                        .send()
                        .await
                        .map_err(|e| Error::ItaHttpRequestFailed {
                            endpoint: label.clone(),
                            source: e,
                        })?;
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    if Self::is_retryable_error(status, &body) {
                        tracing::warn!(%status, body = %body, "{label} failed (retrying)");
                        return Err(Error::ItaHttpResponseError {
                            endpoint: label.clone(),
                            status_code: status.as_u16(),
                            response_body: body,
                        });
                    }
                    Ok((status, body))
                })
                .await?;

            if !status.is_success() {
                return Err(Error::ItaHttpResponseError {
                    endpoint: label,
                    status_code: status.as_u16(),
                    response_body: body,
                });
            }

            Ok(body)
        };

        #[cfg(all(
            target_arch = "wasm32",
            target_vendor = "unknown",
            target_os = "unknown"
        ))]
        let result = tokio_with_wasm::task::spawn(fut)
            .await
            .map_err(|e| Error::ItaError(format!("Failed to spawn ITA request task: {e}")))
            .and_then(|e| e);
        #[cfg(not(all(
            target_arch = "wasm32",
            target_vendor = "unknown",
            target_os = "unknown"
        )))]
        let result = fut.await;

        result
    }
}

#[async_trait::async_trait]
impl GenericConverter for ItaConverter {
    type InEvidence = ItaEvidence;
    type OutEvidence = ItaToken;
    type Nonce = String;

    async fn get_nonce(&self) -> Result<String> {
        let url = format!("{}{}", self.base_url, ITA_NONCE_PATH);
        tracing::debug!(url = %url, "Fetching ITA nonce");

        let req = self
            .http
            .get(&url)
            .header("x-api-key", &self.api_key)
            .header("Accept", "application/json");

        let resp_body = self.ita_request(req, &url).await?;

        let nonce: ItaNonce =
            serde_json::from_str(&resp_body).map_err(Error::ParseChallengeResponseFailed)?;
        let nonce_str = serde_json::to_string(&nonce).map_err(Error::SerializeJsonFailed)?;
        tracing::debug!(nonce = %nonce_str, "ITA nonce request succeeded");
        Ok(nonce_str)
    }

    async fn convert(&self, in_evidence: &ItaEvidence) -> Result<ItaToken> {
        let quote_b64 = BASE64.encode(&in_evidence.tdx_quote);
        let runtime_data_b64 = BASE64.encode(&in_evidence.runtime_data);

        let tdx = TdxEvidence {
            quote: quote_b64,
            verifier_nonce: in_evidence.nonce.clone(),
            runtime_data: Some(runtime_data_b64),
        };

        let nvgpu = in_evidence
            .nvgpu_evidence
            .as_ref()
            .map(|gpu| NvgpuEvidence {
                evidence: gpu.evidence.clone(),
                verifier_nonce: in_evidence.nonce.clone(),
                gpu_nonce: hex::encode(gpu.runtime_data_hash),
                certificate: gpu.certificate.clone(),
                arch: gpu.arch.clone(),
            });

        let body = ItaAttestRequest {
            policy_ids: self.policy_ids.clone(),
            token_signing_alg: "PS384".to_string(),
            policy_must_match: false,
            tdx,
            nvgpu,
        };

        let url = format!("{}{}", self.base_url, ITA_ATTEST_PATH);

        tracing::debug!(
            url = %url,
            body = %serde_json::to_string(&body).unwrap_or_default(),
            "Sending ITA attest request"
        );

        let req = self
            .http
            .post(&url)
            .header("x-api-key", &self.api_key)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&body);

        let resp_body = self.ita_request(req, &url).await?;
        let attest_resp: ItaAttestResponse = serde_json::from_str(&resp_body)
            .map_err(|e| Error::ItaError(format!("Failed to parse ITA attest response: {e}")))?;

        tracing::debug!(token = %attest_resp.token, "ITA attest request succeeded");
        let token = ItaToken::new(attest_resp.token)?;
        self.check_policy_matching(&token)?;
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // -- is_retryable_error --

    #[test]
    fn retryable_on_server_error() {
        assert!(ItaConverter::is_retryable_error(
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            ""
        ));
        assert!(ItaConverter::is_retryable_error(
            reqwest::StatusCode::BAD_GATEWAY,
            ""
        ));
    }

    #[test]
    fn retryable_on_too_many_requests() {
        assert!(ItaConverter::is_retryable_error(
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            ""
        ));
    }

    #[test]
    fn retryable_on_gpu_verification_failure() {
        assert!(ItaConverter::is_retryable_error(
            reqwest::StatusCode::BAD_REQUEST,
            "Failed to verify GPU evidence: transient NRAS error"
        ));
    }

    #[test]
    fn not_retryable_on_other_client_errors() {
        assert!(!ItaConverter::is_retryable_error(
            reqwest::StatusCode::BAD_REQUEST,
            "request body describing non-GPU evidence verification error"
        ));
        assert!(!ItaConverter::is_retryable_error(
            reqwest::StatusCode::NOT_FOUND,
            ""
        ));
        assert!(!ItaConverter::is_retryable_error(
            reqwest::StatusCode::OK,
            ""
        ));
    }

    // -- wiremock: get_nonce --

    #[tokio::test]
    async fn get_nonce_parses_response() {
        let server = MockServer::start().await;
        let expected_nonce = ItaNonce {
            val: "dGVzdC12YWw=".into(),
            iat: "dGVzdC1pYXQ=".into(),
            signature: "dGVzdC1zaWc=".into(),
        };

        Mock::given(method("GET"))
            .and(path(ITA_NONCE_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::to_value(&expected_nonce).unwrap()),
            )
            .expect(1)
            .mount(&server)
            .await;

        let converter = ItaConverter::new("test-key", &server.uri(), &[]).unwrap();
        let nonce_str = converter.get_nonce().await.unwrap();
        let nonce: ItaNonce = serde_json::from_str(&nonce_str).unwrap();
        assert_eq!(nonce.val, expected_nonce.val);
        assert_eq!(nonce.iat, expected_nonce.iat);
        assert_eq!(nonce.signature, expected_nonce.signature);
    }

    // -- wiremock: convert --

    #[tokio::test]
    async fn convert_returns_token() {
        let server = MockServer::start().await;
        let expected_jwt = "fake-jwt-token";

        Mock::given(method("POST"))
            .and(path(ITA_ATTEST_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"token": expected_jwt})),
            )
            .expect(1)
            .mount(&server)
            .await;

        let converter = ItaConverter::new("test-key", &server.uri(), &[]).unwrap();
        let evidence = ItaEvidence::new(b"fake-quote".to_vec(), None, b"{}".to_vec(), None);
        let token = converter.convert(&evidence).await.unwrap();
        assert_eq!(token.as_str(), expected_jwt);
    }

    // -- wiremock: retry paths --

    #[tokio::test]
    async fn convert_retries_on_server_error() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path(ITA_ATTEST_PATH))
            .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
            .expect((ITA_MAX_RETRIES + 1) as u64) // 1 initial + N retries
            .mount(&server)
            .await;

        let converter = ItaConverter::new("key", &server.uri(), &[]).unwrap();
        let evidence = ItaEvidence::new(b"fake-quote".to_vec(), None, b"{}".to_vec(), None);
        let err = converter.convert(&evidence).await.unwrap_err();
        assert!(matches!(
            err,
            Error::ItaHttpResponseError {
                status_code: 500,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn convert_no_retry_on_non_retryable_400() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path(ITA_ATTEST_PATH))
            .respond_with(ResponseTemplate::new(400).set_body_string("invalid request body"))
            .expect(1)
            .mount(&server)
            .await;

        let converter = ItaConverter::new("key", &server.uri(), &[]).unwrap();
        let evidence = ItaEvidence::new(b"fake-quote".to_vec(), None, b"{}".to_vec(), None);
        let err = converter.convert(&evidence).await.unwrap_err();
        assert!(matches!(
            err,
            Error::ItaHttpResponseError {
                status_code: 400,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn with_retry_config_respects_custom_max_retries() {
        let server = MockServer::start().await;
        let custom_retries: usize = 2;

        Mock::given(method("POST"))
            .and(path(ITA_ATTEST_PATH))
            .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
            .expect((custom_retries + 1) as u64)
            .mount(&server)
            .await;

        let converter = ItaConverter::new("key", &server.uri(), &[])
            .unwrap()
            .with_max_retries(custom_retries)
            .with_retry_initial_delay(Duration::from_millis(10))
            .with_retry_max_delay(Duration::from_millis(50));
        let evidence = ItaEvidence::new(b"fake-quote".to_vec(), None, b"{}".to_vec(), None);
        let err = converter.convert(&evidence).await.unwrap_err();
        assert!(matches!(
            err,
            Error::ItaHttpResponseError {
                status_code: 500,
                ..
            }
        ));
    }

    fn make_token(claims: &serde_json::Value) -> ItaToken {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"PS384"}"#);
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
        let sig = URL_SAFE_NO_PAD.encode(b"fake-sig");
        ItaToken::new(format!("{header}.{payload}.{sig}")).unwrap()
    }

    fn make_jwt(claims: &serde_json::Value) -> String {
        make_token(claims).into_str()
    }

    // -- check_policy_matching --

    #[test]
    fn policy_check_skipped_when_no_ids_configured() {
        let converter = ItaConverter::new("key", "https://example.com", &[]).unwrap();
        let token = ItaToken::new("not-even-a-jwt".into()).unwrap();
        converter.check_policy_matching(&token).unwrap();
    }

    #[test]
    fn policy_check_passes_when_all_ids_matched() {
        let ids = vec!["p1".into(), "p2".into()];
        let converter = ItaConverter::new("key", "https://example.com", &ids).unwrap();
        let token = make_token(&serde_json::json!({
            "policy_ids_matched": [{"id": "p1"}, {"id": "p2"}, {"id": "p3"}]
        }));
        converter.check_policy_matching(&token).unwrap();
    }

    #[test]
    fn policy_check_fails_when_expected_id_missing() {
        let ids = vec!["p1".into(), "p2".into()];
        let converter = ItaConverter::new("key", "https://example.com", &ids).unwrap();
        let token = make_token(&serde_json::json!({
            "policy_ids_matched": [{"id": "p1"}]
        }));
        let err = converter.check_policy_matching(&token).unwrap_err();
        assert!(
            matches!(&err, Error::ItaError(msg) if msg.contains("p2")),
            "expected error about missing p2, got: {err:?}"
        );
    }

    #[test]
    fn policy_check_fails_when_field_missing() {
        let ids = vec!["p1".into()];
        let converter = ItaConverter::new("key", "https://example.com", &ids).unwrap();
        let token = make_token(&serde_json::json!({"sub": "test"}));
        assert!(converter.check_policy_matching(&token).is_err());
    }

    #[tokio::test]
    async fn token_is_checked_in_convert_with_policies() {
        let server = MockServer::start().await;
        let policy_ids = vec!["p1".into()];

        let response_jwt = make_jwt(&serde_json::json!({
            "policy_ids_matched": [{"id": "p1"}]
        }));

        Mock::given(method("POST"))
            .and(path(ITA_ATTEST_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"token": response_jwt})),
            )
            .expect(1)
            .mount(&server)
            .await;

        let converter = ItaConverter::new("test-key", &server.uri(), &policy_ids).unwrap();
        let evidence = ItaEvidence::new(b"fake-quote".to_vec(), None, b"{}".to_vec(), None);
        converter.convert(&evidence).await.unwrap();
    }

    #[tokio::test]
    async fn get_nonce_unparseable_body_fails() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path(ITA_NONCE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_string("not valid json"))
            .expect(1)
            .mount(&server)
            .await;

        let converter = ItaConverter::new("key", &server.uri(), &[]).unwrap();
        assert!(converter.get_nonce().await.is_err());
    }
}
