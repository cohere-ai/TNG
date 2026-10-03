use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use rats_cert::tee::claims::Claims;

use crate::tunnel::attest::AttestVerifier;
use crate::tunnel::attestation_result::AttestationResult;
use crate::tunnel::provider::ProviderType;
use crate::tunnel::ra_context::VerifyContextSet;

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
impl AttestVerifier for TngCommonCertVerifier {
    async fn verify_evidence(
        &self,
        provider: ProviderType,
        evidence: &serde_json::Value,
        expected: Claims,
    ) -> Result<AttestationResult> {
        self.verify_set
            .verify_evidence(provider, evidence, expected)
            .await
    }

    async fn verify_token(
        &self,
        provider: ProviderType,
        jwt: &str,
        expected: Claims,
    ) -> Result<AttestationResult> {
        self.verify_set.verify_token(provider, jwt, expected).await
    }
}
