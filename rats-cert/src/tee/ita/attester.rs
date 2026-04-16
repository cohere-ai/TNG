use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use sha2::{Digest, Sha256, Sha512};

use crate::errors::*;
use crate::tee::coco::attester::AaClient;
use crate::tee::{serialize_canon_json, wrap_runtime_data_as_structured, GenericAttester, ReportData};

use super::evidence::{ItaEvidence, ItaNonce};

pub struct ItaAttester {
    aa: AaClient,
}

impl ItaAttester {
    pub fn new(aa_addr: &str) -> Result<Self> {
        Ok(Self {
            aa: AaClient::new(aa_addr)?,
        })
    }

    pub fn new_with_timeout_nano(aa_addr: &str, timeout_nano: i64) -> Result<Self> {
        Ok(Self {
            aa: AaClient::new_with_timeout(aa_addr, timeout_nano)?,
        })
    }
}

/// Derive `SHA-256(decode(nonce.val) || decode(nonce.iat))` for additonal evidence collection 
/// (used in GPU evidence collection).
fn derive_additional_evidence_runtime_data_hash(nonce: &ItaNonce) -> Result<[u8; 32]> {
    let val_bytes = BASE64.decode(&nonce.val).map_err(Error::Base64DecodeFailed)?;
    let iat_bytes = BASE64.decode(&nonce.iat).map_err(Error::Base64DecodeFailed)?;
    let mut hasher = Sha256::new();
    hasher.update(&val_bytes);
    hasher.update(&iat_bytes);
    Ok(hasher.finalize().into())
}

/// Derive runtime data hash according to ITA expectations.
/// With nonce: `SHA-512(decode(nonce.val) || decode(nonce.iat) || runtime_data_bytes)`
/// Without nonce (RA-TLS): `SHA-512(runtime_data_bytes)`
fn derive_runtime_data_hash(nonce: Option<&ItaNonce>, runtime_data_bytes: &[u8]) -> Result<Vec<u8>> {
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
        let mut runtime_data_value = wrap_runtime_data_as_structured(report_data)?;

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

        // Collect addtional evidence FIRST (order reversed from CoCo).
        // When a nonce is present (OHTTP flow), derive appropriate runtime data hash.
        // Without a nonce (RA-TLS), pass empty runtime data (still want addtional evidence).
        let ae_runtime_data_hash = match nonce {
            Some(ref n) => Some(derive_additional_evidence_runtime_data_hash(n)?),
            None => None,
        };

        let additional_evidence = self.aa.get_additional_evidence(
            ae_runtime_data_hash
                .map(|rd| rd.to_vec())
                .unwrap_or_default(),
        );

        // If addtional evidence is present, embed it into the runtime_data for the primary evidence
        // for cryptographic binding.
        let gpu_runtime_data_for_evidence =
            if let Some(ref evidence_bytes) = additional_evidence {
                let additional_evidence_b64 = BASE64.encode(evidence_bytes);
                if let Some(obj) = runtime_data_value.as_object_mut() {
                    obj.insert(
                        "additional_evidence".to_string(),
                        serde_json::Value::String(additional_evidence_b64),
                    );
                }
                ae_runtime_data_hash
            } else {
                None
            };

        let runtime_data_bytes = serialize_canon_json(&runtime_data_value)?;

        let runtime_data_hash = derive_runtime_data_hash(nonce.as_ref(), &runtime_data_bytes)?;

        let evidence_raw = self
            .aa
            .get_evidence(runtime_data_hash)
            .map_err(|e| Error::ItaError(format!("Failed to get primary evidence from AA: {e}")))?;

        // AA returns evidence as a JSON object (e.g. {"cc_eventlog":"...", "quote":"..."}).
        let aa_evidence: serde_json::Value =
            serde_json::from_slice(&evidence_raw)
                .map_err(Error::ParseEvidenceFromBytesFailed)?;
        let quote_b64 = aa_evidence
            .get("quote")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                Error::ItaError("AA evidence JSON missing 'quote' field".to_string())
            })?;
        let quote = BASE64
            .decode(quote_b64)
            .map_err(Error::Base64DecodeFailed)?;

        Ok(ItaEvidence::new(
            quote,
            nonce,
            runtime_data_bytes,
            gpu_runtime_data_for_evidence,
            additional_evidence,
        ))
    }
}
