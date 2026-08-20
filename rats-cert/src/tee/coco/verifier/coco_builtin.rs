use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::Value;

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

    /// The converter's token signing key, as the JWK JSON that a genuine token carries.
    signer_key: Value,
}

impl CocoBuiltinVerifier {
    pub async fn new(
        policy_ids: &[String],
        required_tee_classes: &[String],
        signer_key: Value,
    ) -> Result<Self> {
        // `insecure_key` means only that the signing key is taken from the token's own header
        // rather than endorsed by a certificate chain. The service mints an ephemeral key and has
        // no chain to offer, so endorsement cannot apply; `check_signer` pins the key to the
        // converter's instead, which is stricter than a chain could be. Do not drop that check on
        // the grounds that the token is local: the OHTTP client-attestation flow hands tokens to
        // the peer and reads them back.
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
                required_tee_classes: required_tee_classes.to_owned(),
            },
            signer_key,
        })
    }

    /// Rejects any token not signed by the converter's own key.
    ///
    /// Compared as raw JSON, which is exact rather than approximate: the service writes the very
    /// key it publishes into each header it signs. Parsing into a `Jwk` would not help anyway,
    /// since the service's `jsonwebtoken` is not the one this crate reads headers with.
    fn check_signer(&self, token: &str) -> Result<()> {
        let header = token
            .split('.')
            .next()
            .and_then(|header| URL_SAFE_NO_PAD.decode(header).ok())
            .and_then(|header| serde_json::from_slice::<Value>(&header).ok())
            .ok_or_else(|| Error::MissingTokenField {
                detail: "a JWT header of base64url JSON".to_owned(),
            })?;

        if header.get("jwk") != Some(&self.signer_key) {
            return Err(Error::CocoBuiltinAsForeignTokenSigner);
        }

        Ok(())
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
        // Before the claims, since a token signed by anyone else says nothing regardless of them.
        self.check_signer(evidence.as_str())?;

        self.inner
            .verify_evidence_internal(evidence, report_data)
            .await
    }
}
