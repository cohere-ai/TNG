use rats_cert::errors::*;
use rats_cert::tee::coco::converter::{CoCoNonce, CocoConverter};
use rats_cert::tee::ita::ItaConverter;
use rats_cert::tee::GenericConverter;

use super::evidence::TngEvidence;
use super::token::TngToken;
use super::translate::TranslateTo;

pub enum TngConverter {
    Coco(CocoConverter),
    Ita(ItaConverter),
}

#[async_trait::async_trait]
impl GenericConverter for TngConverter {
    type InEvidence = TngEvidence;
    type OutEvidence = TngToken;

    async fn convert(&self, in_evidence: &TngEvidence) -> Result<TngToken> {
        match self {
            Self::Coco(c) => {
                let inner = in_evidence.translate()?;
                Ok(c.convert(&inner).await?.into())
            }
            Self::Ita(c) => {
                let inner = in_evidence.translate()?;
                Ok(c.convert(&inner).await?.into())
            }
        }
    }
}

impl TngConverter {
    pub async fn get_nonce(&self) -> anyhow::Result<String> {
        match self {
            Self::Coco(c) => {
                let CoCoNonce::Jwt(token) = c.get_nonce().await?;
                Ok(token)
            }
            Self::Ita(c) => Ok(c.get_nonce().await?),
        }
    }
}
