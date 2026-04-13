use std::collections::HashMap;
use std::time::Duration;

use again::RetryPolicy;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::errors::*;
use crate::tee::GenericConverter;

use super::evidence::{ItaEvidence, ItaNonce};
use super::token::ItaToken;

const ITA_RETRY_INITIAL_DELAY: Duration = Duration::from_millis(100);
const ITA_RETRY_MAX_DELAY: Duration = Duration::from_secs(1);
const ITA_RETRY_MAX_ATTEMPTS: usize = 4;

fn is_retryable_ita_error(status: reqwest::StatusCode, body: &str) -> bool {
    status.is_server_error()
        || (status == reqwest::StatusCode::BAD_REQUEST
            && body.contains("Failed to verify GPU evidence"))
}

// ---------------------------------------------------------------------------
// ITA API request/response types (private)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct AttestRequest {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    policy_ids: Vec<String>,
    token_signing_alg: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    policy_must_match: bool,
    tdx: TdxNamespace,
    #[serde(skip_serializing_if = "Option::is_none")]
    nvgpu: Option<NvgpuNamespace>,
}

#[derive(Serialize)]
struct TdxNamespace {
    quote: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    verifier_nonce: Option<ItaNonce>,
    #[serde(skip_serializing_if = "Option::is_none")]
    runtime_data: Option<String>,
}

#[derive(Serialize)]
struct NvgpuNamespace {
    evidence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    verifier_nonce: Option<ItaNonce>,
    gpu_nonce: String,
    certificate: String,
    arch: String,
}

#[derive(Deserialize)]
struct AaGpuDeviceEvidence {
    evidence: String,
    certificate: String,
    #[serde(default = "default_gpu_arch")]
    arch: String,
}

fn default_gpu_arch() -> String {
    "hopper".to_string()
}

#[derive(Deserialize)]
struct DeviceEvidenceList {
    device_evidence_list: Vec<AaGpuDeviceEvidence>,
}

// ---------------------------------------------------------------------------
// ItaConverter
// ---------------------------------------------------------------------------

pub struct ItaConverter {
    http: Client,
    api_key: String,
    base_url: String,
    policy_ids: Vec<String>,
}

impl ItaConverter {
    pub fn new(api_key: &str, base_url: &str, policy_ids: &[String]) -> Result<Self> {
        Ok(Self {
            http: Client::new(),
            api_key: api_key.to_string(),
            base_url: base_url.trim_end_matches('/').to_string(),
            policy_ids: policy_ids.to_vec(),
        })
    }

    /// Re-encode GPU evidence from AA's base64 format to ITA's expected
    /// `base64(hex(raw_bytes))` format.
    fn reencode_gpu_evidence(aa_evidence_base64: &str) -> Result<String> {
        let raw_bytes = BASE64
            .decode(aa_evidence_base64)
            .map_err(Error::Base64DecodeFailed)?;
        let hex_str = hex::encode(&raw_bytes);
        Ok(BASE64.encode(hex_str.as_bytes()))
    }

    /// Parse GPU evidence from CoCo AA's additional_evidence JSON blob.
    /// Returns (re-encoded evidence, certificate, arch) for the first GPU device.
    fn parse_gpu_evidence(additional_evidence: &[u8]) -> Result<(String, String, String)> {
        let evidence_map: HashMap<String, serde_json::Value> =
            serde_json::from_slice(additional_evidence)
                .map_err(Error::ParseAdditionalEvidenceJsonFailed)?;

        for (_tee_type, value) in &evidence_map {
            if let Ok(devices_list) = serde_json::from_value::<DeviceEvidenceList>(value.clone()) {
                if let Some(device) = devices_list.device_evidence_list.into_iter().next() {
                    let reencoded = Self::reencode_gpu_evidence(&device.evidence)?;
                    return Ok((reencoded, device.certificate, device.arch));
                }
            }
        }

        Err(Error::ItaError(
            "No GPU device evidence found in additional_evidence".to_string(),
        ))
    }
}

#[async_trait::async_trait]
impl GenericConverter for ItaConverter {
    type InEvidence = ItaEvidence;
    type OutEvidence = ItaToken;
    type Nonce = String;

    async fn get_nonce(&self) -> Result<String> {
        let url = format!("{}/appraisal/v2/nonce", self.base_url);
        tracing::debug!(url = %url, "Fetching ITA nonce");

        let policy = RetryPolicy::exponential(ITA_RETRY_INITIAL_DELAY)
            .with_max_delay(ITA_RETRY_MAX_DELAY)
            .with_max_retries(ITA_RETRY_MAX_ATTEMPTS);

        let (status, resp_body) = policy
            .retry(|| async {
                let resp = self
                    .http
                    .get(&url)
                    .header("x-api-key", &self.api_key)
                    .header("Accept", "application/json")
                    .send()
                    .await
                    .map_err(|e| Error::ItaHttpRequestFailed {
                        endpoint: url.clone(),
                        source: e,
                    })?;
                let status = resp.status();
                let resp_body = resp
                    .text()
                    .await
                    .unwrap_or_default();
                if is_retryable_ita_error(status, &resp_body) {
                    tracing::warn!(%status, body = %resp_body, "ITA nonce request failed (retrying)");
                    return Err(Error::ItaHttpResponseError {
                        endpoint: url.clone(),
                        status_code: status.as_u16(),
                        response_body: resp_body,
                    });
                }
                Ok((status, resp_body))
            })
            .await?;

        if !status.is_success() {
            return Err(Error::ItaHttpResponseError {
                endpoint: url,
                status_code: status.as_u16(),
                response_body: resp_body,
            });
        }

        let nonce: ItaNonce = serde_json::from_str(&resp_body)
            .map_err(Error::ParseChallengeResponseFailed)?;
        let nonce_str =
            serde_json::to_string(&nonce).map_err(Error::SerializeCanonicalJsonFailed)?;
        tracing::debug!(nonce = %nonce_str, "ITA nonce request succeeded");
        Ok(nonce_str)
    }

    async fn convert(&self, in_evidence: &ItaEvidence) -> Result<ItaToken> {
        let tdx_quote_b64 = BASE64.encode(&in_evidence.tdx_quote);
        let runtime_data_b64 = BASE64.encode(&in_evidence.runtime_data);

        let tdx = TdxNamespace {
            quote: tdx_quote_b64,
            verifier_nonce: in_evidence.nonce.clone(),
            runtime_data: Some(runtime_data_b64),
        };

        let nvgpu = if let (Some(gpu_rd), Some(ref add_ev)) =
            (in_evidence.gpu_runtime_data, &in_evidence.additional_evidence)
        {
            let (reencoded_evidence, certificate, arch) = Self::parse_gpu_evidence(add_ev)?;
            let gpu_nonce_hex = hex::encode(gpu_rd);

            Some(NvgpuNamespace {
                evidence: reencoded_evidence,
                verifier_nonce: in_evidence.nonce.clone(),
                gpu_nonce: gpu_nonce_hex,
                certificate,
                arch,
            })
        } else {
            None
        };

        let body = AttestRequest {
            policy_ids: self.policy_ids.clone(),
            token_signing_alg: "PS384".to_string(),
            policy_must_match: !self.policy_ids.is_empty(),
            tdx,
            nvgpu,
        };

        let url = format!("{}/appraisal/v2/attest", self.base_url);

        tracing::debug!(
            url = %url,
            body = %serde_json::to_string(&body).unwrap_or_default(),
            "Sending ITA attest request"
        );

        let policy = RetryPolicy::exponential(ITA_RETRY_INITIAL_DELAY)
            .with_max_delay(ITA_RETRY_MAX_DELAY)
            .with_max_retries(ITA_RETRY_MAX_ATTEMPTS);

        let (status, resp_body) = policy
            .retry(|| async {
                let resp = self
                    .http
                    .post(&url)
                    .header("x-api-key", &self.api_key)
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .json(&body)
                    .send()
                    .await
                    .map_err(|e| Error::ItaHttpRequestFailed {
                        endpoint: url.clone(),
                        source: e,
                    })?;
                let status = resp.status();
                let resp_body = resp
                    .text()
                    .await
                    .unwrap_or_default();
                if is_retryable_ita_error(status, &resp_body) {
                    tracing::warn!(%status, body = %resp_body, "ITA attest request failed (retrying)");
                    return Err(Error::ItaHttpResponseError {
                        endpoint: url.clone(),
                        status_code: status.as_u16(),
                        response_body: resp_body,
                    });
                }
                Ok((status, resp_body))
            })
            .await?;

        if !status.is_success() {
            return Err(Error::ItaHttpResponseError {
                endpoint: url,
                status_code: status.as_u16(),
                response_body: resp_body,
            });
        }

        #[derive(Deserialize)]
        struct AttestResponse {
            token: String,
        }

        let attest_resp: AttestResponse = serde_json::from_str(&resp_body)
            .map_err(|e| Error::ItaError(format!("Failed to parse ITA attest response: {e}")))?;

        tracing::debug!("ITA attest request succeeded");
        ItaToken::new(attest_resp.token)
    }
}
