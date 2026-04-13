use base64::prelude::BASE64_STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::cert::dice::cbor::OCBR_TAG_EVIDENCE_ITA_EVIDENCE;
use crate::errors::*;
use crate::tee::claims::Claims;
use crate::tee::{DiceParseEvidenceOutput, GenericEvidence};

/// Signed nonce from ITA's `GET /appraisal/v2/nonce` endpoint.
/// Carried verbatim from the converter (which fetched it) through the attester
/// and back into the converter's attest request as `verifier_nonce`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItaNonce {
    pub val: String,
    pub iat: String,
    pub signature: String,
}

/// Evidence produced by `ItaAttester` and consumed by `ItaConverter`.
///
/// Contains all fields needed to build the ITA `/appraisal/v2/attest` request.
/// Transmitted over the wire (JSON-serialized) between attester and converter
/// when they run on different TNG instances (background-check model).
#[derive(Clone)]
pub struct ItaEvidence {
    pub(crate) tdx_quote: Vec<u8>,
    /// `None` in the RA-TLS (no-nonce) flow; `Some` in the OHTTP/converter flow
    /// where the converter fetches a nonce from ITA before attestation.
    pub(crate) nonce: Option<ItaNonce>,
    /// `canonical_json(runtime_data_claims)` -- deterministic serialization of
    /// runtime_data claims. These exact bytes are hashed into REPORTDATA and
    /// sent to ITA in the attest request.
    pub(crate) runtime_data: Vec<u8>,
    /// `SHA-256(decode(nonce.val) || decode(nonce.iat))`, passed to GPU evidence
    /// collection. `None` when no GPU is present or no nonce is available.
    pub(crate) gpu_runtime_data: Option<[u8; 32]>,
    /// Raw additional device evidence (e.g., GPU) from CoCo AA's
    /// `get_additional_evidence()`.
    pub(crate) additional_evidence: Option<Vec<u8>>,
}

impl ItaEvidence {
    #[allow(unused)]
    pub fn new(
        tdx_quote: Vec<u8>,
        nonce: Option<ItaNonce>,
        runtime_data: Vec<u8>,
        gpu_runtime_data: Option<[u8; 32]>,
        additional_evidence: Option<Vec<u8>>,
    ) -> Self {
        Self {
            tdx_quote,
            nonce,
            runtime_data,
            gpu_runtime_data,
            additional_evidence,
        }
    }

    pub fn serialize_to_json(&self) -> serde_json::Result<serde_json::Value> {
        serde_json::to_value(self.to_json_helper())
    }

    pub fn deserialize_from_json(value: serde_json::Value) -> Result<Self> {
        Self::from_json_helper(
            serde_json::from_value::<ItaEvidenceJsonHelper>(value)
                .map_err(Error::DeserializeEvidenceFromJsonFailed)?,
        )
    }
}

impl GenericEvidence for ItaEvidence {
    fn get_dice_cbor_tag(&self) -> u64 {
        OCBR_TAG_EVIDENCE_ITA_EVIDENCE
    }

    fn get_dice_raw_evidence(&self) -> Result<Vec<u8>> {
        let mut res = vec![];
        ciborium::into_writer(&self.to_cbor_helper(), &mut res)
            .map_err(Error::CborSerializationFailed)?;
        Ok(res)
    }

    fn get_claims(&self) -> Result<Claims> {
        Ok(Claims::default())
    }

    fn create_evidence_from_dice(
        cbor_tag: u64,
        raw_evidence: &[u8],
    ) -> DiceParseEvidenceOutput<Self> {
        if cbor_tag == OCBR_TAG_EVIDENCE_ITA_EVIDENCE {
            match ciborium::from_reader::<ItaEvidenceCborHelper, _>(raw_evidence)
                .map_err(Error::CborDeserializationFailed)
                .and_then(Self::from_cbor_helper)
            {
                Ok(v) => DiceParseEvidenceOutput::Ok(v),
                Err(e) => DiceParseEvidenceOutput::MatchButInvalid(e),
            }
        } else {
            DiceParseEvidenceOutput::NotMatch
        }
    }
}

// ---------------------------------------------------------------------------
// CBOR serialization helpers (for DICE cert embedding)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct ItaEvidenceCborHelper {
    tdx_quote: ByteBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nonce: Option<ItaNonce>,
    runtime_data: ByteBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gpu_runtime_data: Option<ByteBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    additional_evidence: Option<ByteBuf>,
}

impl ItaEvidence {
    fn to_cbor_helper(&self) -> ItaEvidenceCborHelper {
        ItaEvidenceCborHelper {
            tdx_quote: ByteBuf::from(self.tdx_quote.clone()),
            nonce: self.nonce.clone(),
            runtime_data: ByteBuf::from(self.runtime_data.clone()),
            gpu_runtime_data: self.gpu_runtime_data.map(|b| ByteBuf::from(b.to_vec())),
            additional_evidence: self
                .additional_evidence
                .as_ref()
                .map(|e| ByteBuf::from(e.clone())),
        }
    }

    fn from_cbor_helper(helper: ItaEvidenceCborHelper) -> Result<Self> {
        let gpu_runtime_data = match helper.gpu_runtime_data {
            Some(buf) => {
                let bytes: [u8; 32] = buf.into_vec().try_into().map_err(|v: Vec<u8>| {
                    Error::ItaError(format!(
                        "gpu_runtime_data must be 32 bytes, got {}",
                        v.len()
                    ))
                })?;
                Some(bytes)
            }
            None => None,
        };
        Ok(Self {
            tdx_quote: helper.tdx_quote.into_vec(),
            nonce: helper.nonce,
            runtime_data: helper.runtime_data.into_vec(),
            gpu_runtime_data,
            additional_evidence: helper.additional_evidence.map(|e| e.into_vec()),
        })
    }
}

// ---------------------------------------------------------------------------
// JSON serialization helpers (for wire transport between TNG instances)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct ItaEvidenceJsonHelper {
    tdx_quote: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nonce: Option<ItaNonce>,
    runtime_data: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gpu_runtime_data: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    additional_evidence: Option<String>,
}

impl ItaEvidence {
    fn to_json_helper(&self) -> ItaEvidenceJsonHelper {
        ItaEvidenceJsonHelper {
            tdx_quote: BASE64_STANDARD.encode(&self.tdx_quote),
            nonce: self.nonce.clone(),
            runtime_data: BASE64_STANDARD.encode(&self.runtime_data),
            gpu_runtime_data: self.gpu_runtime_data.map(|b| hex::encode(b)),
            additional_evidence: self
                .additional_evidence
                .as_ref()
                .map(|e| BASE64_STANDARD.encode(e)),
        }
    }

    fn from_json_helper(helper: ItaEvidenceJsonHelper) -> Result<Self> {
        let gpu_runtime_data = match helper.gpu_runtime_data {
            Some(hex_str) => {
                let bytes = hex::decode(&hex_str).map_err(|e| {
                    Error::ItaError(format!("Failed to decode gpu_runtime_data hex: {e}"))
                })?;
                let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
                    Error::ItaError(format!(
                        "gpu_runtime_data must be 32 bytes, got {}",
                        v.len()
                    ))
                })?;
                Some(arr)
            }
            None => None,
        };
        Ok(Self {
            tdx_quote: BASE64_STANDARD
                .decode(&helper.tdx_quote)
                .map_err(Error::Base64DecodeFailed)?,
            nonce: helper.nonce,
            runtime_data: BASE64_STANDARD
                .decode(&helper.runtime_data)
                .map_err(Error::Base64DecodeFailed)?,
            gpu_runtime_data,
            additional_evidence: match helper.additional_evidence {
                Some(b64) => Some(
                    BASE64_STANDARD
                        .decode(&b64)
                        .map_err(Error::Base64DecodeFailed)?,
                ),
                None => None,
            },
        })
    }
}
