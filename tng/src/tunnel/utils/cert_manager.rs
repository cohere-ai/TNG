use anyhow::{Context as _, Result};
use rats_cert::{
    cert::create::generate_key_carrier_cert,
    crypto::{AsymmetricAlgo, HashAlgo},
};
use std::{pin::Pin, sync::Arc};

use crate::{
    tunnel::attest::Prepared,
    tunnel::attestation_exchange::{exporter::spki_from_certified_key, passport_attester_claims},
    tunnel::ra_context::AttestContext,
    tunnel::utils::{
        maybe_cached::{Expire, MaybeCached},
        runtime::TokioRuntime,
    },
};

/// A certificate and what this side attests with for it, rotated together.
pub struct AttestedKey {
    pub cert: rustls::sign::CertifiedKey,
    pub prepared: Prepared,
}

pub struct CertManager {
    cert: MaybeCached<AttestedKey, anyhow::Error>,
}

impl CertManager {
    pub async fn new(attest_ctx: Arc<AttestContext>, runtime: TokioRuntime) -> Result<Self> {
        let refresh_strategy = attest_ctx.refresh_strategy();

        let cert = MaybeCached::new(runtime, refresh_strategy, move || {
            let attest_ctx = attest_ctx.clone();
            Box::pin(async move {
                Self::fetch_new_cert(&attest_ctx)
                    .await
                    .context("Failed to generate new cert")
            }) as Pin<Box<_>>
        })
        .await?;

        Ok(Self { cert })
    }

    async fn fetch_new_cert(attest_ctx: &AttestContext) -> Result<(AttestedKey, Expire)> {
        tracing::debug!("Generate new rats-tls key-carrier certificate");

        let (der_cert, privkey, not_after) = generate_key_carrier_cert(
            "CN=TNG,O=Inclavare Containers",
            HashAlgo::Sha256,
            AsymmetricAlgo::P256,
        )?;

        let crypto_provider = rustls::crypto::CryptoProvider::get_default()
            .context("rustls crypto provider not installed")?;
        let certified_key = rustls::sign::CertifiedKey::new(
            vec![rustls::pki_types::CertificateDer::from(der_cert)],
            crypto_provider.key_provider.load_private_key(
                rustls_pemfile::private_key(&mut privkey.as_bytes())?
                    .context("No private key found")?,
            )?,
        );

        let spki = spki_from_certified_key(&certified_key)?;
        let (prepared, prepared_expire) = attest_ctx
            .prepare(|nonce| passport_attester_claims(&spki, nonce))
            .await;
        let expire = std::cmp::min(Expire::ExpireAt(not_after), prepared_expire);
        Ok((
            AttestedKey {
                cert: certified_key,
                prepared,
            },
            expire,
        ))
    }

    pub async fn get_latest_cert(&self) -> Result<Arc<AttestedKey>> {
        self.cert.get_latest().await
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use anyhow::bail;

    use crate::{
        config::ra::{AttestArgs, AttesterArgs, CocoAttesterArgs},
        tests::run_test_with_tokio_runtime,
    };

    use super::*;

    pub(crate) fn dummy_aa() -> (String, std::os::unix::net::UnixListener) {
        let path = std::env::temp_dir().join(format!(
            "tng-aa-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind dummy aa");
        (format!("unix://{}", path.display()), listener)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_cert_gen_with_nonzero_interval() -> Result<()> {
        run_test_with_tokio_runtime(|runtime| async move {
            let (aa_addr, _listener) = dummy_aa();
            let attest_ctx = AttestContext::from_attest_args(&AttestArgs::BackgroundCheck {
                attester: AttesterArgs::Coco(CocoAttesterArgs::Uds { aa_addr }),
                refresh_interval: Some(3),
                max_retries: None,
            })
            .await?;
            let mut cert_manager = CertManager::new(Arc::new(attest_ctx), runtime).await?;

            let old_cert = cert_manager.get_latest_cert().await?;
            assert!(Arc::ptr_eq(
                &old_cert,
                &cert_manager.get_latest_cert().await?
            ));

            match &mut cert_manager.cert {
                MaybeCached::UpdatePeriodically {
                    interval,
                    ref mut latest,
                    refresh_task,
                    ..
                } => {
                    assert_eq!(*interval, 3);

                    assert!(!refresh_task.is_finished());

                    tokio::select! {
                        _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                            bail!("The test is time out");
                        }
                        res = latest.1.changed() => {
                            res?;

                            let new_cert = (*latest.1.borrow_and_update()).clone();

                            assert!(!Arc::ptr_eq(&old_cert, &new_cert));
                        }
                    };
                }
                MaybeCached::NoCache { .. } => {
                    bail!("wrong strategy")
                }
            }

            Ok(())
        })
        .await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_cert_gen_with_zero_interval() -> Result<()> {
        run_test_with_tokio_runtime(|runtime| async move {
            let (aa_addr, _listener) = dummy_aa();
            let attest_ctx = AttestContext::from_attest_args(&AttestArgs::BackgroundCheck {
                attester: AttesterArgs::Coco(CocoAttesterArgs::Uds { aa_addr }),
                refresh_interval: Some(0),
                max_retries: None,
            })
            .await?;
            let cert_manager = CertManager::new(Arc::new(attest_ctx), runtime).await?;

            let old_cert = cert_manager.get_latest_cert().await?;

            match &cert_manager.cert {
                MaybeCached::UpdatePeriodically { .. } => {
                    bail!("wrong strategy")
                }
                MaybeCached::NoCache { .. } => {}
            }

            let new_cert = cert_manager.get_latest_cert().await?;
            assert!(!Arc::ptr_eq(&old_cert, &new_cert));

            Ok(())
        })
        .await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_key_carrier_cert_has_no_dice_evidence() -> Result<()> {
        use rats_cert::cert::verify::CertVerifier;

        run_test_with_tokio_runtime(|runtime| async move {
            let (aa_addr, _listener) = dummy_aa();
            let attest_ctx = AttestContext::from_attest_args(&AttestArgs::BackgroundCheck {
                attester: AttesterArgs::Coco(CocoAttesterArgs::Uds { aa_addr }),
                refresh_interval: Some(0),
                max_retries: None,
            })
            .await?;
            let cert_manager = CertManager::new(Arc::new(attest_ctx), runtime).await?;

            let attested_key = cert_manager.get_latest_cert().await?;
            let cert_der = attested_key.cert.cert.first().expect("cert chain is empty");
            assert!(
                cert_der.len() < 2048,
                "key-carrier cert should be a few hundred bytes, got {}",
                cert_der.len()
            );
            match CertVerifier::new().verify_der(cert_der.as_ref()).await {
                Ok(_) => bail!("key-carrier cert must not carry DICE evidence"),
                Err(e) => {
                    let msg = format!("{e:?}");
                    assert!(
                        msg.contains("CertExtractExtensionFailed") || msg.contains("extension"),
                        "unexpected verify error: {msg}"
                    );
                }
            }

            Ok(())
        })
        .await
    }
}
