//! One way a verifier will accept attestation, shared by the RA-TLS and OHTTP exchanges.
//!
//! A proposal names a scheme, `(model, provider)`, plus the fresh data that scheme needs: a
//! `challenge_token` for background check, and nothing extra for passport.

use std::fmt;
use std::str::FromStr;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use super::provider::ProviderType;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Model {
    BackgroundCheck,
    Passport,
}

impl Model {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BackgroundCheck => "background_check",
            Self::Passport => "passport",
        }
    }
}

impl fmt::Display for Model {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Model {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "background_check" => Ok(Self::BackgroundCheck),
            "passport" => Ok(Self::Passport),
            _ => bail!("unrecognized attestation model {s:?}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "model", rename_all = "snake_case")]
pub enum AttestProposal {
    BackgroundCheck {
        provider: ProviderType,
        challenge_token: String,
    },
    Passport {
        provider: ProviderType,
    },
}

impl AttestProposal {
    pub fn key(&self) -> (Model, ProviderType) {
        match self {
            Self::BackgroundCheck { provider, .. } => (Model::BackgroundCheck, *provider),
            Self::Passport { provider } => (Model::Passport, *provider),
        }
    }

    pub fn challenge_token(&self) -> Option<&str> {
        match self {
            Self::BackgroundCheck {
                challenge_token, ..
            } => Some(challenge_token),
            Self::Passport { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proposal_json_shape() {
        let proposals = [
            AttestProposal::BackgroundCheck {
                provider: ProviderType::Coco,
                challenge_token: "n".into(),
            },
            AttestProposal::Passport {
                provider: ProviderType::Ita,
            },
        ];
        let json = serde_json::to_value(proposals).unwrap();
        assert_eq!(
            json,
            serde_json::json!([
                {"model": "background_check", "provider": "coco", "challenge_token": "n"},
                {"model": "passport", "provider": "ita"},
            ])
        );
        assert!(serde_json::from_value::<AttestProposal>(
            serde_json::json!({"model": "passport", "provider": "bad_provider"})
        )
        .is_err());
    }
}
