use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use rats_cert::cert::verify::CertVerifier;
use rats_cert::tee::GenericConverter;
use rats_cert::tee::GenericEvidence;
use rats_cert::tee::GenericVerifier;

use crate::tunnel::attestation_result::AttestationResult;
use crate::tunnel::provider::{TngEvidence, TngToken};
use crate::tunnel::ra_context::VerifyContext;
use crate::tunnel::service_metrics::{AttestationOperation, AttestationProtocol};

fn parse_token_from_dice_cert(cbor_tag: u64, raw_evidence: &[u8]) -> Result<TngToken> {
    rats_cert::errors::Result::from(TngToken::create_evidence_from_dice(cbor_tag, raw_evidence))
        .map_err(|e| {
            anyhow!(
                "Failed to parse AS token from DICE cert (cbor_tag={:#x}): {e:#}",
                cbor_tag
            )
        })
}

fn parse_evidence_from_dice_cert(cbor_tag: u64, raw_evidence: &[u8]) -> Result<TngEvidence> {
    rats_cert::errors::Result::from(TngEvidence::create_evidence_from_dice(
        cbor_tag,
        raw_evidence,
    ))
    .map_err(|e| {
        anyhow!(
            "Failed to parse evidence from DICE cert (cbor_tag={:#x}): {e:#}",
            cbor_tag
        )
    })
}

#[derive(Debug)]
pub struct TngCommonCertVerifier {
    verify_ctx: Arc<VerifyContext>,
    pending_cert: spin::mutex::spin::SpinMutex<Option<Vec<u8>>>,
}

impl TngCommonCertVerifier {
    pub fn new(verify_ctx: Arc<VerifyContext>) -> Self {
        Self {
            verify_ctx,
            pending_cert: spin::mutex::spin::SpinMutex::new(None),
        }
    }

    pub async fn verify_raw_evidence(
        &self,
        cbor_tag: u64,
        raw_evidence: Vec<u8>,
        expected_claims: rats_cert::tee::claims::Claims,
    ) -> Result<AttestationResult> {
        let attestation_attempt = self
            .verify_ctx
            .attestation_metrics()
            .start(AttestationOperation::Verify, AttestationProtocol::RatsTls);
        tracing::debug!("Verifying rats-tls raw evidence");

        let pending_result =
            CertVerifier::pending_from_raw_evidence(cbor_tag, raw_evidence, expected_claims)
                .map_err(|e| anyhow!("Failed to prepare raw evidence for verification: {e:?}"))?;

        let token = match &*self.verify_ctx {
            VerifyContext::Passport { verifier, .. } => {
                let token = parse_token_from_dice_cert(
                    pending_result.cbor_tag,
                    &pending_result.raw_evidence,
                )?;

                verifier
                    .verify_evidence(&token, &pending_result.report_data)
                    .await
                    .map_err(|e| anyhow!("Token verification failed: {:?}", e))?;

                token
            }
            VerifyContext::BackgroundCheck {
                converter,
                verifier,
                ..
            } => {
                let evidence = parse_evidence_from_dice_cert(
                    pending_result.cbor_tag,
                    &pending_result.raw_evidence,
                )?;

                let token = converter
                    .convert(&evidence)
                    .await
                    .map_err(|e| anyhow!("Failed to convert evidence to token: {:?}", e))?;

                verifier
                    .verify_evidence(&token, &pending_result.report_data)
                    .await
                    .map_err(|e| anyhow!("Token verification failed: {:?}", e))?;

                token
            }
        };

        tracing::debug!("rats-rs raw evidence verify finished successfully");
        attestation_attempt.mark_succeeded();

        Ok(AttestationResult::from_token(token))
    }

    pub fn peer_spki_der(&self) -> Result<Vec<u8>> {
        let pending_cert = self
            .pending_cert
            .lock()
            .clone()
            .context("No rats-tls cert received")?;
        rats_cert::cert::spki_der_from_x509_der(&pending_cert)
            .map_err(|e| anyhow!("failed to extract SPKI from peer certificate: {e:?}"))
    }

    pub fn verify_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
    ) -> std::result::Result<(), rustls::Error> {
        // Keep the leaf for SPKI binding after the post-handshake exchange.
        self.pending_cert.lock().replace(end_entity.to_vec());
        Ok(())
    }
}

#[async_trait::async_trait]
impl crate::tunnel::attestation_exchange::RawEvidenceVerifier for TngCommonCertVerifier {
    async fn verify(
        &self,
        cbor_tag: u64,
        raw: Vec<u8>,
        expected: rats_cert::tee::claims::Claims,
    ) -> Result<AttestationResult> {
        self.verify_raw_evidence(cbor_tag, raw, expected).await
    }
}
