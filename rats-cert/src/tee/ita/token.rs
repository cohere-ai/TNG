use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use flatten_json_object::Flattener;
use serde_json::Value;

use crate::cert::dice::cbor::OCBR_TAG_EVIDENCE_ITA_TOKEN;
use crate::errors::*;
use crate::tee::claims::Claims;
use crate::tee::{DiceParseEvidenceOutput, GenericEvidence};

/// A JWT token issued by Intel Trust Authority.
///
/// This is the ITA equivalent of `CocoAsToken`. It wraps the raw JWT string
/// and implements `GenericEvidence` for DICE cert embedding and claims extraction.
#[derive(Clone)]
pub struct ItaToken {
    data: String,
}

impl ItaToken {
    pub fn new(token: String) -> Result<Self> {
        Ok(Self { data: token })
    }

    pub fn as_str(&self) -> &str {
        &self.data
    }

    pub fn into_str(self) -> String {
        self.data
    }

    pub fn exp(&self) -> Result<u64> {
        let split_token: Vec<&str> = self.data.split('.').collect();
        if split_token.len() != 3 {
            return Err(Error::msg("Illegal JWT format"));
        }

        let claims = URL_SAFE_NO_PAD.decode(split_token[1])?;
        let claims_value = serde_json::from_slice::<Value>(&claims)?;

        let Some(exp) = claims_value["exp"].as_u64() else {
            return Err(Error::msg("token expiration unset"));
        };

        Ok(exp)
    }
}

impl GenericEvidence for ItaToken {
    fn get_dice_cbor_tag(&self) -> u64 {
        OCBR_TAG_EVIDENCE_ITA_TOKEN
    }

    fn get_dice_raw_evidence(&self) -> Result<Vec<u8>> {
        Ok(self.data.as_bytes().to_owned())
    }

    fn get_claims(&self) -> Result<Claims> {
        let split_token: Vec<&str> = self.data.split('.').collect();
        if split_token.len() != 3 {
            return Err(Error::msg("Illegal ITA JWT format"));
        }
        let claims = URL_SAFE_NO_PAD.decode(split_token[1])?;
        let claims_value: Value = serde_json::from_slice(&claims)?;

        let flattened = Flattener::new()
            .flatten(&claims_value)
            .context("Failed to flatten ITA JWT claims")?;

        match flattened {
            Value::Object(m) => Ok(m),
            _ => Err(Error::msg(format!(
                "Invalid ITA claims value: {}",
                claims_value
            ))),
        }
    }

    fn create_evidence_from_dice(
        cbor_tag: u64,
        raw_evidence: &[u8],
    ) -> DiceParseEvidenceOutput<Self> {
        if cbor_tag == OCBR_TAG_EVIDENCE_ITA_TOKEN {
            return match std::str::from_utf8(raw_evidence)
                .context("Failed to parse ITA token as utf-8")
                .map(|token| Self::new(token.to_owned()))
            {
                Ok(Ok(v)) => DiceParseEvidenceOutput::Ok(v),
                Ok(Err(e)) => DiceParseEvidenceOutput::MatchButInvalid(e),
                Err(e) => DiceParseEvidenceOutput::MatchButInvalid(e),
            };
        }
        DiceParseEvidenceOutput::NotMatch
    }
}
