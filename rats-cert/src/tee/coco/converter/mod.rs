use std::collections::HashMap;

use grpc::CocoGrpcConverter;
use kbs_types::Tee;
use restful::CocoRestfulConverter;

use super::evidence::{AttestationServiceHashAlgo, CocoAsToken, CocoEvidence};
use crate::errors::*;
use crate::tee::GenericConverter;

pub mod grpc;
pub mod restful;

pub enum CocoConverter {
    Grpc(CocoGrpcConverter),
    Restful(CocoRestfulConverter),
}

pub enum CoCoNonce {
    Jwt(String),
}

#[async_trait::async_trait]

impl GenericConverter for CocoConverter {
    type InEvidence = CocoEvidence;
    type OutEvidence = CocoAsToken;
    type Nonce = CoCoNonce;

    async fn convert(&self, in_evidence: &Self::InEvidence) -> Result<Self::OutEvidence> {
        match self {
            CocoConverter::Grpc(converter) => converter.convert(in_evidence).await,
            CocoConverter::Restful(converter) => converter.convert(in_evidence).await,
        }
    }

    async fn get_nonce(&self) -> Result<Self::Nonce> {
        match self {
            CocoConverter::Grpc(converter) => converter.get_nonce().await,
            CocoConverter::Restful(converter) => converter.get_nonce().await,
        }
    }
}

pub(crate) fn convert_additional_evidence(
    in_evidence: &CocoEvidence,
) -> Result<Vec<(Tee, serde_json::Value)>> {
    if let Some(json_bytes) = in_evidence.aa_additional_evidence_ref() {
        let additional_evidence_map: HashMap<Tee, serde_json::Value> =
            serde_json::from_slice(json_bytes).map_err(Error::ParseAdditionalEvidenceJsonFailed)?;

        Ok(additional_evidence_map.into_iter().collect())
    } else {
        Ok(Vec::new())
    }
}
