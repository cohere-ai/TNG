use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use reqwest::Client;

use crate::errors::*;
use crate::tee::coco::evidence::CocoEvidence;
use crate::tee::{GenericAttester, ReportData};

use super::aa_attester::{derive_gpu_runtime_data, derive_tdx_report_data, serialize_canon_json};
use super::evidence::{ItaEvidence, ItaNonce};

pub struct ItaAsrAttester {
    http: Client,
    asr_addr: String,
}

impl ItaAsrAttester {
    pub fn new(asr_addr: &str) -> Result<Self> {
        Ok(Self {
            http: Client::new(),
            asr_addr: asr_addr.trim_end_matches('/').to_string(),
        })
    }

    async fn get_evidence_from_asr(&self, runtime_data: &[u8]) -> Result<Vec<u8>> {
        let runtime_data_b64 = BASE64.encode(runtime_data);
        let url = format!("{}/aa/evidence", self.asr_addr);
        tracing::debug!(url = %url, "Fetching TDX evidence from ASR");

        let resp = self
            .http
            .get(&url)
            .query(&[("runtime_data", &runtime_data_b64), ("encoding", &"base64".to_string())])
            .send()
            .await
            .context("Failed to request evidence from ASR")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(Error::msg(format!(
                "ASR evidence request failed ({}): {}",
                status, body
            )));
        }

        Ok(resp.bytes().await?.to_vec())
    }

    async fn get_additional_evidence_from_asr(&self, runtime_data: &[u8]) -> Result<Option<Vec<u8>>> {
        let runtime_data_b64 = BASE64.encode(runtime_data);
        let url = format!("{}/aa/additional_evidence", self.asr_addr);
        tracing::debug!(url = %url, "Fetching additional evidence from ASR");

        let resp = match self
            .http
            .get(&url)
            .query(&[("runtime_data", &runtime_data_b64), ("encoding", &"base64".to_string())])
            .send()
            .await
        {
            Ok(r) => r,
            Err(error) => {
                tracing::warn!(
                    ?error,
                    "GetAdditionalEvidence request to ASR failed, proceeding without GPU evidence"
                );
                return Ok(None);
            }
        };

        if !resp.status().is_success() {
            tracing::warn!(
                status = %resp.status(),
                "ASR additional_evidence returned non-success, proceeding without GPU evidence"
            );
            return Ok(None);
        }

        let bytes = resp.bytes().await?.to_vec();
        if bytes.is_empty() {
            Ok(None)
        } else {
            Ok(Some(bytes))
        }
    }
}

#[async_trait::async_trait]
impl GenericAttester for ItaAsrAttester {
    type Evidence = ItaEvidence;

    async fn get_evidence(&self, report_data: &ReportData) -> Result<ItaEvidence> {
        let mut runtime_data_value = CocoEvidence::wrap_runtime_data_as_structed(report_data)?;

        let nonce: ItaNonce = {
            let challenge_token = runtime_data_value
                .get("challenge_token")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::msg(
                    "runtime_data claims missing 'challenge_token' field (expected serialized ITA nonce)"
                ))?;
            serde_json::from_str(challenge_token)
                .context("Failed to parse challenge_token as ITA nonce")?
        };

        let gpu_runtime_data = derive_gpu_runtime_data(&nonce)?;

        let additional_evidence = self
            .get_additional_evidence_from_asr(&gpu_runtime_data)
            .await?;

        let gpu_runtime_data_for_evidence = if let Some(ref evidence_bytes) = additional_evidence {
            let gpu_evidence_b64 = BASE64.encode(evidence_bytes);
            if let Some(obj) = runtime_data_value.as_object_mut() {
                obj.insert(
                    "gpu_evidence".to_string(),
                    serde_json::Value::String(gpu_evidence_b64),
                );
            }
            Some(gpu_runtime_data)
        } else {
            None
        };

        let runtime_data_bytes = serialize_canon_json(&runtime_data_value)?;

        let tdx_report_data = derive_tdx_report_data(&nonce, &runtime_data_bytes)?;

        let evidence_bytes = self.get_evidence_from_asr(&tdx_report_data).await?;

        let aa_evidence: serde_json::Value = serde_json::from_slice(&evidence_bytes)
            .context("Failed to parse ASR evidence as JSON")?;
        let tdx_quote_b64 = aa_evidence
            .get("quote")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::msg("ASR evidence JSON missing 'quote' field"))?;
        let tdx_quote = BASE64.decode(tdx_quote_b64)
            .context("Failed to decode TDX quote from ASR evidence")?;

        Ok(ItaEvidence::new(
            tdx_quote,
            nonce,
            runtime_data_bytes,
            gpu_runtime_data_for_evidence,
            additional_evidence,
        ))
    }
}
