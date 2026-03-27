use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::errors::*;
use crate::tee::GenericConverter;

use super::evidence::{ItaEvidence, ItaNonce};
use super::token::ItaToken;

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

/// GPU device evidence as parsed from CoCo AA's additional_evidence JSON.
/// AA returns a JSON map like `{ "nvgpu": { ... } }` where each value contains
/// the device-level fields.
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

    /// Fetch a fresh nonce from ITA. Returns the serialized nonce JSON string
    /// to be used as the `challenge_token` in runtime_data claims.
    pub async fn get_nonce(&self) -> Result<String> {
        let url = format!("{}/appraisal/v2/nonce", self.base_url);
        tracing::debug!(url = %url, "Fetching ITA nonce");
        let resp = self
            .http
            .get(&url)
            .header("x-api-key", &self.api_key)
            .header("Accept", "application/json")
            .send()
            .await
            .context("Failed to request nonce from ITA")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(Error::msg(format!(
                "ITA nonce request failed ({}): {}",
                status, body
            )));
        }

        let nonce: ItaNonce = resp
            .json()
            .await
            .context("Failed to parse ITA nonce response")?;

        serde_json::to_string(&nonce).context("Failed to serialize ITA nonce")
    }

    /// Re-encode GPU evidence from AA's base64 format to ITA's expected
    /// `base64(hex(raw_bytes))` format.
    fn reencode_gpu_evidence(aa_evidence_base64: &str) -> Result<String> {
        let raw_bytes = BASE64
            .decode(aa_evidence_base64)
            .context("Failed to decode GPU evidence base64")?;
        let hex_str = hex::encode(&raw_bytes);
        Ok(BASE64.encode(hex_str.as_bytes()))
    }

    /// Parse GPU evidence from CoCo AA's additional_evidence JSON blob.
    /// Returns (re-encoded evidence, certificate, arch) for the first GPU device.
    fn parse_gpu_evidence(additional_evidence: &[u8]) -> Result<(String, String, String)> {
        let evidence_map: HashMap<String, serde_json::Value> =
            serde_json::from_slice(additional_evidence)
                .context("Failed to parse additional_evidence JSON")?;

        for (_tee_type, value) in &evidence_map {
            if let Ok(devices_list) = serde_json::from_value::<DeviceEvidenceList>(value.clone()) {
                if let Some(device) = devices_list.device_evidence_list.into_iter().next() {
                    let reencoded = Self::reencode_gpu_evidence(&device.evidence)?;
                    return Ok((reencoded, device.certificate, device.arch));
                }
            }
        }

        Err(Error::msg(
            "No GPU device evidence found in additional_evidence",
        ))
    }
}

#[derive(Deserialize)]
struct DeviceEvidenceList {
    device_evidence_list: Vec<AaGpuDeviceEvidence>,
}

#[async_trait::async_trait]
impl GenericConverter for ItaConverter {
    type InEvidence = ItaEvidence;
    type OutEvidence = ItaToken;

    async fn convert(&self, in_evidence: &ItaEvidence) -> Result<ItaToken> {
        let tdx_quote_b64 = BASE64.encode(&in_evidence.tdx_quote);
        let runtime_data_b64 = BASE64.encode(&in_evidence.runtime_data);

        let tdx = TdxNamespace {
            quote: tdx_quote_b64,
            verifier_nonce: Some(in_evidence.nonce.clone()),
            runtime_data: Some(runtime_data_b64),
        };

        // Build the optional nvgpu namespace
        let nvgpu = if let (Some(gpu_rd), Some(ref add_ev)) =
            (in_evidence.gpu_runtime_data, &in_evidence.additional_evidence)
        {
            let (reencoded_evidence, certificate, arch) = Self::parse_gpu_evidence(add_ev)?;
            let gpu_nonce_hex = hex::encode(gpu_rd);

            Some(NvgpuNamespace {
                evidence: reencoded_evidence,
                verifier_nonce: Some(in_evidence.nonce.clone()),
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

        let resp = self
            .http
            .post(&url)
            .header("x-api-key", &self.api_key)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&body)
            .send()
            .await
            .context("Failed to submit attestation to ITA")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(Error::msg(format!(
                "ITA attest request failed ({}): {}",
                status, body
            )));
        }

        #[derive(Deserialize)]
        struct AttestResponse {
            token: String,
        }

        let attest_resp: AttestResponse = resp
            .json()
            .await
            .context("Failed to parse ITA attest response")?;

        ItaToken::new(attest_resp.token)
    }
}
