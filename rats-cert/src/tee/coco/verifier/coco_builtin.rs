use super::super::evidence::CocoAsToken;
use crate::tee::coco::verifier::common::CommonCocoVerifier;
use crate::tee::coco::verifier::token::{AttestationTokenVerifierConfig, TokenVerifier};
use crate::tee::ReportData;
use crate::{errors::*, tee::GenericVerifier};

/// Verifier for tokens minted by the in-process [`CocoBuiltinConverter`].
///
/// [`CocoBuiltinConverter`]: crate::tee::coco::converter::coco_builtin::CocoBuiltinConverter
pub struct CocoBuiltinVerifier {
    inner: CommonCocoVerifier,
}

impl CocoBuiltinVerifier {
    pub async fn new(policy_ids: &[String]) -> Result<Self> {
        // `insecure_key` skips endorsement of the token's signing key, which is sound *only*
        // because the token never leaves this process: the in-process AS signs it with an
        // ephemeral key and it is consumed in the same call chain, so the key is not
        // attacker-influenced. What an attacker does control is the evidence, and that is
        // checked by the AS and then by `CommonCocoVerifier` below.
        //
        // If this token ever gets cached and re-ingested, logged and replayed, or reused for
        // passport mode, this becomes wrong and the signer needs a real cert chain.
        let config = AttestationTokenVerifierConfig {
            trusted_certs_paths: vec![],
            trusted_jwk_sets: Default::default(),
            as_addr: None,
            as_headers: None,
            insecure_key: true,
        };

        let token_verifier = TokenVerifier::from_config(config)
            .await
            .map_err(Error::CocoTokenVerifierError)?;

        Ok(Self {
            inner: CommonCocoVerifier {
                token_verifier,
                policy_ids: policy_ids.to_owned(),
            },
        })
    }
}

#[async_trait::async_trait]
impl GenericVerifier for CocoBuiltinVerifier {
    type Evidence = CocoAsToken;

    async fn verify_evidence(
        &self,
        evidence: &Self::Evidence,
        report_data: &ReportData,
    ) -> Result<()> {
        self.inner
            .verify_evidence_internal(evidence, report_data)
            .await
    }
}
