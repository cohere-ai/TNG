use std::sync::Arc;

use crate::tunnel::ra_context::{RaContext, VerifyContext};
use crate::tunnel::utils::{cert_manager::CertManager, runtime::TokioRuntime};
use anyhow::Result;

pub mod alpn;
pub mod client;
pub mod server;

pub enum TlsConfigGenerator {
    NoRa,
    Verify(TokioRuntime, Arc<VerifyContext>),
    Attest(TokioRuntime, Arc<CertManager>),
    AttestAndVerify(TokioRuntime, Arc<CertManager>, Arc<VerifyContext>),
}

impl TlsConfigGenerator {
    pub async fn new(ra_context: Arc<RaContext>, runtime: TokioRuntime) -> Result<Self> {
        Ok(match ra_context.as_ref() {
            RaContext::AttestOnly(attest_ctx) => Self::Attest(
                runtime.clone(),
                Arc::new(CertManager::new(attest_ctx.clone(), runtime).await?),
            ),
            RaContext::VerifyOnly(verify_ctx) => Self::Verify(runtime, verify_ctx.clone()),
            RaContext::AttestAndVerify { attest, verify } => Self::AttestAndVerify(
                runtime.clone(),
                Arc::new(CertManager::new(attest.clone(), runtime).await?),
                verify.clone(),
            ),
            RaContext::NoRa => Self::NoRa,
        })
    }
}
