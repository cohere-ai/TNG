use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use rats_cert::tee::GenericConverter;
use rats_cert::tee::GenericVerifier;
use rats_cert::tee::ReportData;

use crate::tunnel::attestation_result::AttestationResult;
use crate::tunnel::provider::{ProviderType, TngEvidence, TngToken};
use crate::tunnel::ra_context::VerifyContext;
use crate::tunnel::service_metrics::{AttestationOperation, AttestationProtocol};

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

    pub fn peer_spki_der(&self) -> Result<Vec<u8>> {
        let pending_cert = self
            .pending_cert
            .lock()
            .clone()
            .context("No rats-tls cert received")?;
        rats_cert::cert::verify::spki_der_from_x509_der(&pending_cert)
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
impl crate::tunnel::attestation_exchange::ExchangeVerifier for TngCommonCertVerifier {
    async fn verify_evidence(
        &self,
        provider: &str,
        json: &str,
        expected: rats_cert::tee::claims::Claims,
    ) -> Result<AttestationResult> {
        let attestation_attempt = self
            .verify_ctx
            .attestation_metrics()
            .start(AttestationOperation::Verify, AttestationProtocol::RatsTls);
        tracing::debug!("Verifying rats-tls evidence");

        let provider = ProviderType::from_required_wire_str(provider)?;
        let value: serde_json::Value =
            serde_json::from_str(json).context("evidence JSON is not valid JSON")?;
        let evidence = TngEvidence::deserialize_from_json(provider, value)
            .context("failed to parse evidence JSON")?;

        let token = match &*self.verify_ctx {
            VerifyContext::BackgroundCheck {
                converter,
                verifier,
                ..
            } => {
                let token = converter
                    .convert(&evidence)
                    .await
                    .map_err(|e| anyhow!("Failed to convert evidence to token: {:?}", e))?;

                verifier
                    .verify_evidence(&token, &ReportData::Claims(expected))
                    .await
                    .map_err(|e| anyhow!("Token verification failed: {:?}", e))?;

                token
            }
            VerifyContext::Passport { .. } => {
                anyhow::bail!("passport verifier received evidence");
            }
        };

        tracing::debug!("rats-tls evidence verify finished successfully");
        attestation_attempt.mark_succeeded();
        Ok(AttestationResult::from_token(token))
    }

    async fn verify_token(
        &self,
        provider: &str,
        jwt: &str,
        expected: rats_cert::tee::claims::Claims,
    ) -> Result<AttestationResult> {
        let attestation_attempt = self
            .verify_ctx
            .attestation_metrics()
            .start(AttestationOperation::Verify, AttestationProtocol::RatsTls);
        tracing::debug!("Verifying rats-tls token");

        let provider = ProviderType::from_required_wire_str(provider)?;
        let token = TngToken::from_wire(provider, jwt.to_owned())
            .context("failed to parse attestation token")?;

        match &*self.verify_ctx {
            VerifyContext::Passport { verifier, .. } => {
                verifier
                    .verify_evidence(&token, &ReportData::Claims(expected))
                    .await
                    .map_err(|e| anyhow!("Token verification failed: {:?}", e))?;
            }
            VerifyContext::BackgroundCheck { .. } => {
                anyhow::bail!("background-check verifier received token");
            }
        }

        tracing::debug!("rats-tls token verify finished successfully");
        attestation_attempt.mark_succeeded();
        Ok(AttestationResult::from_token(token))
    }
}
