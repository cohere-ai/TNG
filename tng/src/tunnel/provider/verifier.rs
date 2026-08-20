use rats_cert::errors::*;
#[cfg(feature = "__coco-builtin-as")]
use rats_cert::tee::coco::verifier::builtin::CocoBuiltinVerifier;
use rats_cert::tee::coco::verifier::remote::CocoRemoteVerifier;
use rats_cert::tee::ita::ItaVerifier;
use rats_cert::tee::{GenericVerifier, ReportData};

use super::token::TngToken;

/// Provider-polymorphic verifier. Verifies an AS token against report data.
///
/// `Coco` covers both service interfaces, since verifying a token does not depend on how it was
/// fetched. `CocoBuiltin` is separate because it trusts the ephemeral key of the service running in
/// this process rather than a configured certificate.
pub enum TngVerifier {
    Coco(CocoRemoteVerifier),
    #[cfg(feature = "__coco-builtin-as")]
    CocoBuiltin(CocoBuiltinVerifier),
    Ita(ItaVerifier),
}

impl TngVerifier {
    pub fn provider_type(&self) -> super::provider_type::ProviderType {
        match self {
            Self::Coco(_) => super::provider_type::ProviderType::Coco,
            #[cfg(feature = "__coco-builtin-as")]
            Self::CocoBuiltin(_) => super::provider_type::ProviderType::Coco,
            Self::Ita(_) => super::provider_type::ProviderType::Ita,
        }
    }
}

#[async_trait::async_trait]
impl GenericVerifier for TngVerifier {
    type Evidence = TngToken;

    async fn verify_evidence(&self, token: &TngToken, report_data: &ReportData) -> Result<()> {
        match (self, token) {
            (Self::Coco(v), TngToken::Coco(t)) => v.verify_evidence(t, report_data).await,
            // A builtin service still mints a CoCo AS token, so it pairs with the same token type.
            #[cfg(feature = "__coco-builtin-as")]
            (Self::CocoBuiltin(v), TngToken::Coco(t)) => v.verify_evidence(t, report_data).await,
            (Self::Ita(v), TngToken::Ita(t)) => v.verify_evidence(t, report_data).await,
            _ => Err(Error::IncompatibleTypes {
                detail: "verifier and token provider mismatch".to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::provider_type::ProviderType;
    use super::*;

    #[tokio::test]
    async fn verify_evidence_rejects_provider_mismatch() {
        let ita_verifier = ItaVerifier::new("https://unused.example.com", &[]).unwrap();
        let verifier = TngVerifier::Ita(ita_verifier);

        let coco_token = TngToken::from_wire(ProviderType::Coco, "fake.jwt.token".into()).unwrap();
        let report_data = ReportData::Claims(Default::default());

        let err = verifier.verify_evidence(&coco_token, &report_data).await;
        assert!(
            matches!(err, Err(Error::IncompatibleTypes { .. })),
            "ITA verifier with Coco token should fail with IncompatibleTypes"
        );
    }
}
