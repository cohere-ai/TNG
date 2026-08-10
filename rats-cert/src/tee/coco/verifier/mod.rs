#[cfg(feature = "__coco-builtin-as")]
pub mod coco_builtin;
mod common;
pub mod remote;
pub mod token;

use super::evidence::CocoAsToken;
use crate::errors::Result;
use crate::tee::{GenericVerifier, ReportData};

/// Unified CocoVerifier enum
pub enum CocoVerifier {
    #[cfg(feature = "__coco-builtin-as")]
    CocoBuiltin(coco_builtin::CocoBuiltinVerifier),
    Remote(remote::CocoRemoteVerifier),
}

#[async_trait::async_trait]
impl GenericVerifier for CocoVerifier {
    type Evidence = CocoAsToken;

    async fn verify_evidence(
        &self,
        evidence: &Self::Evidence,
        report_data: &ReportData,
    ) -> Result<()> {
        match self {
            #[cfg(feature = "__coco-builtin-as")]
            Self::CocoBuiltin(verifier) => verifier.verify_evidence(evidence, report_data).await,
            Self::Remote(verifier) => verifier.verify_evidence(evidence, report_data).await,
        }
    }
}
