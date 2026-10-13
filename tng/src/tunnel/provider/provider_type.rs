use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Canonical provider type enum. The string representation of each variant
/// is defined exactly once in `as_str()`, and all other conversions
/// (Display, FromStr, Serialize, Deserialize) delegate to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderType {
    Coco,
    Ita,
}

impl ProviderType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Coco => "coco",
            Self::Ita => "ita",
        }
    }
}

impl fmt::Display for ProviderType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ProviderType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        const ALL: &[ProviderType] = &[ProviderType::Coco, ProviderType::Ita];
        ALL.iter()
            .find(|p| p.as_str() == s)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("unrecognized provider: {s}"))
    }
}

impl Serialize for ProviderType {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ProviderType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_json_round_trip() {
        for original in [ProviderType::Coco, ProviderType::Ita] {
            let json = serde_json::to_value(original).unwrap();
            let back: ProviderType = serde_json::from_value(json).unwrap();
            assert_eq!(back, original);
        }
    }

    #[test]
    fn display_matches_as_str() {
        for p in [ProviderType::Coco, ProviderType::Ita] {
            assert_eq!(p.to_string(), p.as_str());
        }
    }
}
