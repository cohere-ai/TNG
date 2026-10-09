//! Fetches the builtin attestation service's policies from a signed release and keeps them on the
//! newest one.

use std::sync::{Arc, Weak};
use std::time::Duration;

use anyhow::{ensure, Context as _, Result};
use rats_cert::tee::coco::converter::builtin::policy::TeeClassPolicies;
use rats_cert::tee::coco::converter::builtin::provenance::{self, ReleaseFile, VerifiedRelease};
use rats_cert::tee::coco::converter::builtin::CocoBuiltinConverter;
use sigstore_trust_root::reqwest::{Certificate, Client};
use sigstore_trust_root::{TrustedRoot, TufConfig};

use crate::config::ra::PolicySourceArgs;

const BUNDLE_FILE: &str = "attestation-bundle.sigstore.json";
const MAX_DOWNLOAD_BYTES: usize = 1 << 20;
const TIMEOUT: Duration = Duration::from_secs(30);

pub struct PolicySource {
    args: PolicySourceArgs,
    policy_id: String,
    client: Client,
    #[cfg(test)]
    trusted_root: Option<Arc<TrustedRoot>>,
}

/// The release whose policies are installed.
pub struct Installed {
    digest: String,
    signed_at: i64,
}

impl PolicySource {
    pub fn new(args: &PolicySourceArgs, policy_id: &str) -> Result<Self> {
        let roots = webpki_root_certs::TLS_SERVER_ROOT_CERTS
            .iter()
            .map(|der| Certificate::from_der(der))
            .collect::<Result<Vec<_>, _>>()?;
        let client = Client::builder()
            .https_only(true)
            .tls_certs_only(roots)
            .connect_timeout(TIMEOUT)
            .timeout(TIMEOUT)
            .build()?;
        Ok(Self {
            args: args.clone(),
            policy_id: policy_id.to_owned(),
            client,
            #[cfg(test)]
            trusted_root: None,
        })
    }

    /// Fetches the release to start with. There is no fallback, so failing here fails startup.
    pub async fn fetch_initial(&self) -> Result<(TeeClassPolicies, Installed)> {
        let (digest, release) = self
            .fetch(None)
            .await?
            .context("No policy release fetched")?;
        let installed = self.log_install(digest, &release);
        Ok((release.policies, installed))
    }

    /// Checks for a newer release every `refresh_interval` until `converter` is dropped, or never
    /// if it is 0.
    pub fn keep_current(self, mut installed: Installed, converter: &Arc<CocoBuiltinConverter>) {
        if self.args.refresh_interval == 0 {
            return;
        }
        let converter: Weak<_> = Arc::downgrade(converter);
        let period = Duration::from_secs(self.args.refresh_interval);

        // No `TokioRuntime` reaches converter construction; the loop ends with the converter.
        #[allow(clippy::disallowed_methods)]
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval_at(tokio::time::Instant::now() + period, period);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                let Some(converter) = converter.upgrade() else {
                    break;
                };
                if let Err(error) = self.refresh(&mut installed, &converter).await {
                    tracing::warn!(
                        ?error,
                        "Policy refresh failed, keeping the installed policies"
                    );
                }
            }
        });
    }

    async fn refresh(
        &self,
        installed: &mut Installed,
        converter: &CocoBuiltinConverter,
    ) -> Result<()> {
        let Some((digest, release)) = self.fetch(Some(&installed.digest)).await? else {
            return Ok(());
        };
        // Otherwise whoever serves the files could roll back to an older signed release.
        if release.signed_at <= installed.signed_at {
            tracing::warn!(
                bundle_sha256 = digest,
                version = ?release.version,
                "Ignoring a policy release signed no later than the installed one"
            );
            return Ok(());
        }
        converter.replace_policies(&release.policies).await?;
        *installed = self.log_install(digest, &release);
        Ok(())
    }

    /// Fetches and verifies the release, unless its bundle digest is `known_digest`.
    async fn fetch(&self, known_digest: Option<&str>) -> Result<Option<(String, VerifiedRelease)>> {
        let bundle = self.download(BUNDLE_FILE).await?;
        let digest = provenance::bundle_digest(&bundle);
        if known_digest == Some(digest.as_str()) {
            return Ok(None);
        }

        // Named after the policy id and a fixed set of classes, so safe to put in a URL.
        let names = provenance::policy_files(&bundle, &self.policy_id)?;
        let mut bodies = Vec::with_capacity(names.len());
        for (_, name) in &names {
            bodies.push(self.download(name).await?);
        }
        let files: Vec<_> = names
            .iter()
            .zip(&bodies)
            .map(|((tee_class, name), bytes)| ReleaseFile {
                tee_class,
                name,
                bytes,
            })
            .collect();

        let release = provenance::verify_release(
            &*self.trusted_root().await?,
            &bundle,
            &self.policy_id,
            &files,
            &self.args.provenance,
        )?;
        Ok(Some((digest, release)))
    }

    async fn trusted_root(&self) -> Result<Arc<TrustedRoot>> {
        #[cfg(test)]
        if let Some(root) = &self.trusted_root {
            return Ok(root.clone());
        }
        let config = TufConfig::production()
            .without_cache()
            .with_http_client(self.client.clone());
        Ok(Arc::new(
            TrustedRoot::from_tuf(config)
                .await
                .context("Failed to fetch the Sigstore trusted root")?,
        ))
    }

    async fn download(&self, name: &str) -> Result<Vec<u8>> {
        let url = format!("{}/{name}", self.args.url.trim_end_matches('/'));
        let mut response = self
            .client
            .get(&url)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .with_context(|| format!("Failed to fetch {url}"))?;
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                body.len() + chunk.len() <= MAX_DOWNLOAD_BYTES,
                "{url} exceeds {MAX_DOWNLOAD_BYTES} bytes"
            );
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    fn log_install(&self, digest: String, release: &VerifiedRelease) -> Installed {
        tracing::info!(
            url = self.args.url,
            bundle_sha256 = digest,
            version = ?release.version,
            signed_at = release.signed_at,
            "Verified policy release"
        );
        Installed {
            digest,
            signed_at: release.signed_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use axum::extract::{Path, State};
    use axum::http::StatusCode;
    use axum::routing::get;
    use axum::Router;
    use sigstore_trust_root::SIGSTORE_PRODUCTION_TRUSTED_ROOT;

    use super::*;

    type Files = Arc<Mutex<HashMap<String, Vec<u8>>>>;

    macro_rules! release {
        ($version:literal) => {{
            let file = |name: &str, bytes: &[u8]| (name.to_owned(), bytes.to_vec());
            macro_rules! fixture {
                ($name:literal) => {
                    include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../rats-cert/src/tee/coco/converter/builtin/test_cases/",
                        $version,
                        "/",
                        $name
                    ))
                };
            }
            HashMap::from([
                file(BUNDLE_FILE, fixture!("attestation-bundle.sigstore.json")),
                file(
                    "trustee_policy_cpu.rego",
                    fixture!("trustee_policy_cpu.rego"),
                ),
                file(
                    "trustee_policy_gpu.rego",
                    fixture!("trustee_policy_gpu.rego"),
                ),
            ])
        }};
    }

    async fn serve(files: Files) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new()
            .route(
                "/{name}",
                get(
                    |State(files): State<Files>, Path(name): Path<String>| async move {
                        files
                            .lock()
                            .unwrap()
                            .get(&name)
                            .cloned()
                            .ok_or(StatusCode::NOT_FOUND)
                    },
                ),
            )
            .with_state(files);
        #[allow(clippy::disallowed_methods)]
        tokio::spawn(async move { axum::serve(listener, app).await });
        format!("http://{addr}")
    }

    fn source(url: String) -> PolicySource {
        let args = serde_json::from_value(serde_json::json!({
            "url": url,
            "provenance": {
                "repo": "cohere-ai/integritee",
                "signer_workflow": ".github/workflows/release-policy.yaml",
                "source_ref": "refs/heads/main",
                "predicate_type": "https://cohere.com/attestation-policy/v1",
                "environment": "release"
            }
        }))
        .unwrap();
        PolicySource {
            args,
            policy_id: "trustee_policy".to_owned(),
            client: Client::new(),
            trusted_root: Some(Arc::new(
                TrustedRoot::from_json(SIGSTORE_PRODUCTION_TRUSTED_ROOT).unwrap(),
            )),
        }
    }

    /// Only a newer, verified release replaces the installed one; anything else keeps it.
    #[tokio::test]
    async fn refresh_installs_only_newer_verified_releases() {
        let files: Files = Arc::new(Mutex::new(release!("v0.0.1a70")));
        let source = source(serve(files.clone()).await);
        let set = |release| *files.lock().unwrap() = release;

        let (policies, mut installed) = source.fetch_initial().await.unwrap();
        let converter = CocoBuiltinConverter::new("trustee_policy", &policies, None, &[])
            .await
            .unwrap();
        let a70 = installed.digest.clone();

        set(release!("v0.0.1a71"));
        source.refresh(&mut installed, &converter).await.unwrap();
        let a71 = installed.digest.clone();
        assert_ne!(a71, a70);

        let mut tampered = release!("v0.0.1a70");
        tampered
            .get_mut("trustee_policy_cpu.rego")
            .unwrap()
            .push(b'\n');
        set(tampered);
        source
            .refresh(&mut installed, &converter)
            .await
            .unwrap_err();

        set(release!("v0.0.1a70"));
        source.refresh(&mut installed, &converter).await.unwrap();
        assert_eq!(installed.digest, a71);

        let mut oversized = release!("v0.0.1a71");
        oversized.insert(BUNDLE_FILE.to_owned(), vec![b' '; MAX_DOWNLOAD_BYTES + 1]);
        set(oversized);
        source
            .refresh(&mut installed, &converter)
            .await
            .unwrap_err();
        assert_eq!(installed.digest, a71);
    }
}
