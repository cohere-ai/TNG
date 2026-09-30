use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use rats_cert::tee::GenericConverter;
use rats_cert::tee::GenericVerifier;
use rats_cert::tee::ReportData;

use crate::tunnel::attestation_result::AttestationResult;
use crate::tunnel::proposal::Model;
use crate::tunnel::provider::{ProviderType, TngEvidence, TngToken};
use crate::tunnel::ra_context::{VerifyContext, VerifyContextSet};

#[derive(Debug)]
pub struct TngCommonCertVerifier {
    verify_set: Arc<VerifyContextSet>,
    pending_cert: spin::mutex::spin::SpinMutex<Option<Vec<u8>>>,
}

impl TngCommonCertVerifier {
    pub fn new(verify_set: Arc<VerifyContextSet>) -> Self {
        Self {
            verify_set,
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
        provider: ProviderType,
        json: &str,
        expected: rats_cert::tee::claims::Claims,
    ) -> Result<AttestationResult> {
        tracing::debug!("Verifying rats-tls evidence");

        let value: serde_json::Value =
            serde_json::from_str(json).context("evidence JSON is not valid JSON")?;
        let evidence = TngEvidence::deserialize_from_json(provider, value)
            .context("failed to parse evidence JSON")?;

        let VerifyContext::BackgroundCheck {
            converter,
            verifier,
        } = self.verify_set.entry(Model::BackgroundCheck, provider)?
        else {
            anyhow::bail!("background-check entry holds no converter");
        };
        let token = converter
            .convert(&evidence)
            .await
            .map_err(|e| anyhow!("Failed to convert evidence to token: {:?}", e))?;
        verifier
            .verify_evidence(&token, &ReportData::Claims(expected))
            .await
            .map_err(|e| anyhow!("Token verification failed: {:?}", e))?;

        tracing::debug!("rats-tls evidence verify finished successfully");
        Ok(AttestationResult::from_token(Model::BackgroundCheck, token))
    }

    async fn verify_token(
        &self,
        provider: ProviderType,
        jwt: &str,
        expected: rats_cert::tee::claims::Claims,
    ) -> Result<AttestationResult> {
        tracing::debug!("Verifying rats-tls token");

        let token = TngToken::from_wire(provider, jwt.to_owned())
            .context("failed to parse attestation token")?;
        self.verify_set
            .entry(Model::Passport, provider)?
            .verifier()
            .verify_evidence(&token, &ReportData::Claims(expected))
            .await
            .map_err(|e| anyhow!("Token verification failed: {:?}", e))?;

        tracing::debug!("rats-tls token verify finished successfully");
        Ok(AttestationResult::from_token(Model::Passport, token))
    }
}
