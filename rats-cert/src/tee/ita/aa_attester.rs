use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use canon_json::CanonicalFormatter;
use serde::Serialize;
use sha2::{Digest, Sha256, Sha512};

use crate::errors::*;
use crate::tee::coco::attester::ttrpc_protocol::attestation_agent::{
    GetAdditionalEvidenceRequest, GetEvidenceRequest,
};
use crate::tee::coco::attester::ttrpc_protocol::attestation_agent_ttrpc::AttestationAgentServiceClient;
use crate::tee::coco::evidence::CocoEvidence;
use crate::tee::coco::TTRPC_DEFAULT_TIMEOUT_NANO;
use crate::tee::{GenericAttester, ReportData};

use super::evidence::{ItaEvidence, ItaNonce};

pub struct ItaAaAttester {
    client: AttestationAgentServiceClient,
    timeout_nano: i64,
}

impl ItaAaAttester {
    pub fn new(aa_addr: &str) -> Result<Self> {
        Self::new_with_timeout_nano(aa_addr, TTRPC_DEFAULT_TIMEOUT_NANO)
    }

    pub fn new_with_timeout_nano(aa_addr: &str, timeout_nano: i64) -> Result<Self> {
        let inner = ttrpc::Client::connect(aa_addr)
            .context(format!(
                "Failed to connect to attestation-agent ttrpc address {}",
                aa_addr
            ))?;
        let client = AttestationAgentServiceClient::new(inner);
        Ok(Self {
            client,
            timeout_nano,
        })
    }
}

pub(super) fn serialize_canon_json<T: Serialize>(value: T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, CanonicalFormatter::new());
    value.serialize(&mut ser)?;
    Ok(buf)
}

/// Derive `SHA-256(decode(nonce.val) || decode(nonce.iat))` for GPU evidence collection.
pub(super) fn derive_gpu_runtime_data(nonce: &ItaNonce) -> Result<[u8; 32]> {
    let val_bytes = BASE64.decode(&nonce.val).context("Failed to decode nonce.val")?;
    let iat_bytes = BASE64.decode(&nonce.iat).context("Failed to decode nonce.iat")?;
    let mut hasher = Sha256::new();
    hasher.update(&val_bytes);
    hasher.update(&iat_bytes);
    Ok(hasher.finalize().into())
}

/// Derive `SHA-512(decode(nonce.val) || decode(nonce.iat) || runtime_data_bytes)` for TDX REPORTDATA.
pub(super) fn derive_tdx_report_data(nonce: &ItaNonce, runtime_data_bytes: &[u8]) -> Result<Vec<u8>> {
    let val_bytes = BASE64.decode(&nonce.val).context("Failed to decode nonce.val")?;
    let iat_bytes = BASE64.decode(&nonce.iat).context("Failed to decode nonce.iat")?;
    let mut hasher = Sha512::new();
    hasher.update(&val_bytes);
    hasher.update(&iat_bytes);
    hasher.update(runtime_data_bytes);
    Ok(hasher.finalize().to_vec())
}

#[async_trait::async_trait]
impl GenericAttester for ItaAaAttester {
    type Evidence = ItaEvidence;

    async fn get_evidence(&self, report_data: &ReportData) -> Result<ItaEvidence> {
        // Build the structured runtime_data claims (same as CoCo's approach)
        let mut runtime_data_value = CocoEvidence::wrap_runtime_data_as_structed(report_data)?;

        // Extract the ITA nonce from the challenge_token claim
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

        // Step 1: Collect GPU evidence FIRST (order reversed from CoCo).
        // Derive gpu_runtime_data for GPU nonce binding.
        let gpu_runtime_data = derive_gpu_runtime_data(&nonce)?;

        let additional_evidence_res = self.client.get_additional_evidence(
            ttrpc::context::with_timeout(self.timeout_nano),
            &GetAdditionalEvidenceRequest {
                RuntimeData: gpu_runtime_data.to_vec(),
                ..Default::default()
            },
        );

        let additional_evidence = match additional_evidence_res {
            Ok(res) => {
                if res.Evidence.is_empty() {
                    None
                } else {
                    Some(res.Evidence)
                }
            }
            Err(error) => {
                tracing::warn!(
                    ?error,
                    "GetAdditionalEvidence not supported by AA, proceeding without GPU evidence"
                );
                None
            }
        };

        // Step 2: If GPU evidence is present, embed the full evidence (base64-encoded)
        // into the runtime_data claims for cryptographic binding via REPORTDATA.
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

        // Step 3: Serialize runtime_data claims as canonical JSON.
        let runtime_data_bytes = serialize_canon_json(&runtime_data_value)?;

        // Step 4: Derive TDX REPORTDATA = SHA-512(nonce.val || nonce.iat || runtime_data_bytes)
        let tdx_report_data = derive_tdx_report_data(&nonce, &runtime_data_bytes)?;

        // Step 5: Get TDX evidence from CoCo AA
        let get_evidence_req = GetEvidenceRequest {
            RuntimeData: tdx_report_data,
            ..Default::default()
        };
        let get_evidence_res = self
            .client
            .get_evidence(
                ttrpc::context::with_timeout(self.timeout_nano),
                &get_evidence_req,
            )
            .context("Failed to get TDX evidence from AA")?;

        // AA returns evidence as a JSON object (e.g. {"cc_eventlog":"...", "quote":"..."}).
        // Extract just the raw TDX quote for ITA.
        let aa_evidence: serde_json::Value = serde_json::from_slice(&get_evidence_res.Evidence)
            .context("Failed to parse AA evidence as JSON")?;
        let tdx_quote_b64 = aa_evidence
            .get("quote")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::msg("AA evidence JSON missing 'quote' field"))?;
        let tdx_quote = BASE64.decode(tdx_quote_b64)
            .context("Failed to decode TDX quote from AA evidence")?;

        Ok(ItaEvidence::new(
            tdx_quote,
            nonce,
            runtime_data_bytes,
            gpu_runtime_data_for_evidence,
            additional_evidence,
        ))
    }
}
