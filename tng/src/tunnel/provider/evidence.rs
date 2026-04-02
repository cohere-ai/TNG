use anyhow::{anyhow, Result};
use rats_cert::tee::coco::evidence::CocoEvidence;
use rats_cert::tee::claims::Claims;
use rats_cert::tee::ita::ItaEvidence;
use rats_cert::tee::{DiceParseEvidenceOutput, GenericEvidence};

use super::provider_type::ProviderType;

pub enum TngEvidence {
    Coco(CocoEvidence),
    Ita(ItaEvidence),
}

impl From<CocoEvidence> for TngEvidence {
    fn from(e: CocoEvidence) -> Self {
        Self::Coco(e)
    }
}

impl From<ItaEvidence> for TngEvidence {
    fn from(e: ItaEvidence) -> Self {
        Self::Ita(e)
    }
}

/// Translate a TngEvidence into CocoEvidence if it contains a compatible type.
impl TryFrom<&TngEvidence> for CocoEvidence {
    type Error = anyhow::Error;
    fn try_from(e: &TngEvidence) -> Result<Self> {
        match e {
            TngEvidence::Coco(inner) => Ok(inner.clone()),
            other => Err(anyhow!(
                "{} evidence cannot be translated to CocoEvidence",
                other.provider_type()
            )),
        }
    }
}

/// Translate a TngEvidence into ItaEvidence if it contains a compatible type.
impl TryFrom<&TngEvidence> for ItaEvidence {
    type Error = anyhow::Error;
    fn try_from(e: &TngEvidence) -> Result<Self> {
        match e {
            TngEvidence::Ita(inner) => Ok(inner.clone()),
            other => Err(anyhow!(
                "{} evidence cannot be translated to ItaEvidence",
                other.provider_type()
            )),
        }
    }
}

impl TngEvidence {
    pub fn provider_type(&self) -> ProviderType {
        match self {
            Self::Coco(_) => ProviderType::Coco,
            Self::Ita(_) => ProviderType::Ita,
        }
    }

    /// Serialize to JSON with a provider type envelope for wire safety.
    /// The receiver uses the `"provider"` tag to determine how to deserialize,
    /// since ingress and egress are separate TNG instances with independent configs.
    pub fn serialize_to_json(&self) -> Result<serde_json::Value> {
        match self {
            Self::Coco(e) => Ok(serde_json::json!({
                "provider": self.provider_type(),
                "evidence": e.serialize_to_json()?
            })),
            Self::Ita(e) => Ok(serde_json::json!({
                "provider": self.provider_type(),
                "evidence": e.serialize_to_json()?
            })),
        }
    }

    /// Deserialize from JSON, dispatching on the `"provider"` tag.
    pub fn deserialize_from_json(value: serde_json::Value) -> Result<Self> {
        let mut obj = match value {
            serde_json::Value::Object(map) => map,
            _ => return Err(anyhow!("evidence envelope is not a JSON object")),
        };
        let provider: ProviderType = obj
            .get("provider")
            .ok_or_else(|| anyhow!("missing 'provider' field in evidence"))?
            .as_str()
            .ok_or_else(|| anyhow!("'provider' field is not a string"))?
            .parse()?;
        let inner = obj
            .remove("evidence")
            .ok_or_else(|| anyhow!("missing 'evidence' field"))?;
        match provider {
            ProviderType::Coco => {
                Ok(Self::Coco(CocoEvidence::deserialize_from_json(inner)?))
            }
            ProviderType::Ita => {
                Ok(Self::Ita(ItaEvidence::deserialize_from_json(inner)?))
            }
        }
    }
}

impl GenericEvidence for TngEvidence {
    fn get_dice_cbor_tag(&self) -> u64 {
        match self {
            Self::Coco(e) => e.get_dice_cbor_tag(),
            Self::Ita(e) => e.get_dice_cbor_tag(),
        }
    }

    fn get_dice_raw_evidence(&self) -> rats_cert::errors::Result<Vec<u8>> {
        match self {
            Self::Coco(e) => e.get_dice_raw_evidence(),
            Self::Ita(e) => e.get_dice_raw_evidence(),
        }
    }

    fn get_claims(&self) -> rats_cert::errors::Result<Claims> {
        match self {
            Self::Coco(e) => e.get_claims(),
            Self::Ita(e) => e.get_claims(),
        }
    }

    fn create_evidence_from_dice(
        cbor_tag: u64,
        raw_evidence: &[u8],
    ) -> DiceParseEvidenceOutput<Self> {
        CocoEvidence::create_evidence_from_dice(cbor_tag, raw_evidence)
            .map_ok()
            .or_else(|| ItaEvidence::create_evidence_from_dice(cbor_tag, raw_evidence).map_ok())
    }
}
