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

pub struct ItaAttester {
    client: AttestationAgentServiceClient,
    timeout_nano: i64,
}

impl ItaAttester {
    pub fn new(aa_addr: &str) -> Result<Self> {
        Self::new_with_timeout_nano(aa_addr, TTRPC_DEFAULT_TIMEOUT_NANO)
    }

    pub fn new_with_timeout_nano(aa_addr: &str, timeout_nano: i64) -> Result<Self> {
        let inner = ttrpc::Client::connect(aa_addr).map_err(|e| {
            Error::ItaError(format!(
                "Failed to connect to attestation-agent ttrpc address {aa_addr}: {e}"
            ))
        })?;
        let client = AttestationAgentServiceClient::new(inner);
        Ok(Self {
            client,
            timeout_nano,
        })
    }
}

fn serialize_canon_json<T: Serialize>(value: T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, CanonicalFormatter::new());
    value
        .serialize(&mut ser)
        .map_err(Error::SerializeCanonicalJsonFailed)?;
    Ok(buf)
}

/// Derive `SHA-256(decode(nonce.val) || decode(nonce.iat))` for GPU evidence collection.
fn derive_gpu_runtime_data(nonce: &ItaNonce) -> Result<[u8; 32]> {
    let val_bytes = BASE64.decode(&nonce.val).map_err(Error::Base64DecodeFailed)?;
    let iat_bytes = BASE64.decode(&nonce.iat).map_err(Error::Base64DecodeFailed)?;
    let mut hasher = Sha256::new();
    hasher.update(&val_bytes);
    hasher.update(&iat_bytes);
    Ok(hasher.finalize().into())
}

/// Derive TDX REPORTDATA.
/// With nonce: `SHA-512(decode(nonce.val) || decode(nonce.iat) || runtime_data_bytes)`
/// Without nonce (RA-TLS): `SHA-512(runtime_data_bytes)`
fn derive_tdx_report_data(nonce: Option<&ItaNonce>, runtime_data_bytes: &[u8]) -> Result<Vec<u8>> {
    let mut hasher = Sha512::new();
    if let Some(nonce) = nonce {
        let val_bytes = BASE64.decode(&nonce.val).map_err(Error::Base64DecodeFailed)?;
        let iat_bytes = BASE64.decode(&nonce.iat).map_err(Error::Base64DecodeFailed)?;
        hasher.update(&val_bytes);
        hasher.update(&iat_bytes);
    }
    hasher.update(runtime_data_bytes);
    Ok(hasher.finalize().to_vec())
}

#[async_trait::async_trait]
impl GenericAttester for ItaAttester {
    type Evidence = ItaEvidence;

    async fn get_evidence(&self, report_data: &ReportData) -> Result<ItaEvidence> {
        let mut runtime_data_value = CocoEvidence::wrap_runtime_data_as_structed(report_data)?;

        // Nonce is optional: present in OHTTP flows (converter fetches it and puts
        // it into challenge_token), absent in RA-TLS cert generation.
        let nonce: Option<ItaNonce> = runtime_data_value
            .get("challenge_token")
            .and_then(|v| v.as_str())
            .map(|ct| {
                serde_json::from_str(ct).map_err(|e| {
                    Error::ItaError(format!(
                        "Failed to parse challenge_token as ITA nonce: {e}"
                    ))
                })
            })
            .transpose()?;

        // Collect GPU evidence FIRST (order reversed from CoCo).
        // When a nonce is present (OHTTP flow), derive SHA-256(nonce.val || nonce.iat)
        // as the GPU RuntimeData for nonce-binding. Without a nonce (RA-TLS),
        // pass empty RuntimeData -- we still want GPU evidence in the cert.
        let gpu_runtime_data = match nonce {
            Some(ref n) => Some(derive_gpu_runtime_data(n)?),
            None => None,
        };

        let additional_evidence_res = self.client.get_additional_evidence(
            ttrpc::context::with_timeout(self.timeout_nano),
            &GetAdditionalEvidenceRequest {
                RuntimeData: gpu_runtime_data
                    .map(|rd| rd.to_vec())
                    .unwrap_or_default(),
                ..Default::default()
            },
        );

        let additional_evidence = match additional_evidence_res {
            Ok(res) if !res.Evidence.is_empty() => Some(res.Evidence),
            Ok(_) => None,
            Err(error) => {
                tracing::warn!(
                    ?error,
                    "GetAdditionalEvidence not supported by AA, proceeding without GPU evidence"
                );
                None
            }
        };

        // If GPU evidence is present, embed the full evidence (base64-encoded)
        // into the runtime_data claims for cryptographic binding via REPORTDATA.
        let gpu_runtime_data_for_evidence =
            if let Some(ref evidence_bytes) = additional_evidence {
                let gpu_evidence_b64 = BASE64.encode(evidence_bytes);
                if let Some(obj) = runtime_data_value.as_object_mut() {
                    obj.insert(
                        "gpu_evidence".to_string(),
                        serde_json::Value::String(gpu_evidence_b64),
                    );
                }
                gpu_runtime_data
            } else {
                None
            };

        let runtime_data_bytes = serialize_canon_json(&runtime_data_value)?;

        let tdx_report_data = derive_tdx_report_data(nonce.as_ref(), &runtime_data_bytes)?;

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
            .map_err(|e| Error::ItaError(format!("Failed to get TDX evidence from AA: {e}")))?;

        // AA returns evidence as a JSON object (e.g. {"cc_eventlog":"...", "quote":"..."}).
        let aa_evidence: serde_json::Value =
            serde_json::from_slice(&get_evidence_res.Evidence)
                .map_err(Error::ParseEvidenceFromBytesFailed)?;
        let tdx_quote_b64 = aa_evidence
            .get("quote")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                Error::ItaError("AA evidence JSON missing 'quote' field".to_string())
            })?;
        let tdx_quote = BASE64
            .decode(tdx_quote_b64)
            .map_err(Error::Base64DecodeFailed)?;

        Ok(ItaEvidence::new(
            tdx_quote,
            nonce,
            runtime_data_bytes,
            gpu_runtime_data_for_evidence,
            additional_evidence,
        ))
    }
}
