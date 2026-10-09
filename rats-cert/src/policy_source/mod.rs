//! Fetches attestation policies from a signed release and keeps them on the newest one.

pub mod provenance;

use std::future::Future;
use std::sync::{Arc, Weak};
use std::time::Duration;

use anyhow::{ensure, Context as _};
use serde::{Deserialize, Serialize};
use sigstore_trust_root::reqwest::{Certificate, Client, Url};
use sigstore_trust_root::{TrustedRoot, TufConfig};

use self::provenance::{Provenance, ReleaseFile, VerifiedRelease};
use crate::errors::*;
use crate::tee::coco::converter::builtin::policy::TeeClassPolicies;
use crate::tee::coco::converter::builtin::CocoBuiltinConverter;

const BUNDLE_FILE: &str = "attestation-bundle.sigstore.json";
const MAX_DOWNLOAD_BYTES: usize = 1 << 20;
const TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_REFRESH_INTERVAL: u64 = 300;

/// A signed policy release, as published by a GitHub Actions workflow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySourceArgs {
    /// https prefix the release files are fetched from, e.g. `.../releases/latest/download`
    pub url: String,
    /// Seconds between checks for a newer release. 0 to fetch once at startup only.
    #[serde(default = "default_refresh_interval")]
    pub refresh_interval: u64,
    pub provenance: Provenance,
}

fn default_refresh_interval() -> u64 {
    DEFAULT_REFRESH_INTERVAL
}

impl PolicySourceArgs {
    /// Rejects what is wrong without fetching anything.
    pub fn validate(&self) -> Result<()> {
        let p = &self.provenance;
        let problem = if Url::parse(&self.url).map_or(true, |url| url.scheme() != "https") {
            "'url' must be an https URL"
        } else if [
            &p.repo,
            &p.signer_workflow,
            &p.source_ref,
            &p.predicate_type,
        ]
        .iter()
        .any(|field| field.is_empty())
            || p.repo.split('/').count() != 2
        {
            "'provenance' needs 'repo' as owner/name, 'signer_workflow', 'source_ref' and 'predicate_type'"
        } else {
            return Ok(());
        };
        Err(Error::InvalidPolicySource(problem))
    }
}

pub struct PolicySource {
    args: PolicySourceArgs,
    policy_id: String,
    client: Client,
    #[cfg(test)]
    trusted_root: Option<Arc<TrustedRoot>>,
}

/// Identifies the release whose policies are in use.
pub struct ReleaseInfo {
    digest: String,
    signed_at: i64,
}

impl PolicySource {
    pub fn new(args: &PolicySourceArgs, policy_id: &str) -> Result<Self> {
        let client = webpki_root_certs::TLS_SERVER_ROOT_CERTS
            .iter()
            .map(|der| Certificate::from_der(der))
            .collect::<std::result::Result<Vec<_>, _>>()
            .and_then(|roots| {
                Client::builder()
                    .https_only(true)
                    .tls_certs_only(roots)
                    .connect_timeout(TIMEOUT)
                    .timeout(TIMEOUT)
                    .build()
            })
            .map_err(|e| Error::PolicySourceFailed(Arc::new(e.into())))?;
        Ok(Self {
            args: args.clone(),
            policy_id: policy_id.to_owned(),
            client,
            #[cfg(test)]
            trusted_root: None,
        })
    }

    /// Fetches the release to start with. There is no fallback, so failing here fails startup.
    pub async fn fetch_initial(&self) -> Result<(TeeClassPolicies, ReleaseInfo)> {
        let (digest, release) = self
            .fetch(None)
            .await
            .and_then(|fetched| fetched.context("No policy release fetched"))
            .map_err(|e| Error::PolicySourceFailed(Arc::new(e)))?;
        let current = self.record_current(digest, &release);
        Ok((release.policies, current))
    }

    /// Returns a task that checks for a newer release every `refresh_interval` until `converter`
    /// is dropped, or `None` if the interval is 0. The caller decides where to run it.
    pub fn keep_current(
        self,
        mut current: ReleaseInfo,
        converter: Weak<CocoBuiltinConverter>,
    ) -> Option<impl Future<Output = ()> + Send + 'static> {
        if self.args.refresh_interval == 0 {
            return None;
        }
        let period = Duration::from_secs(self.args.refresh_interval);

        Some(async move {
            let mut interval =
                tokio::time::interval_at(tokio::time::Instant::now() + period, period);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                let Some(converter) = converter.upgrade() else {
                    break;
                };
                if let Err(error) = self.refresh(&mut current, &converter).await {
                    tracing::warn!(
                        ?error,
                        "Policy refresh failed, keeping the current policies"
                    );
                }
            }
        })
    }

    async fn refresh(
        &self,
        current: &mut ReleaseInfo,
        converter: &CocoBuiltinConverter,
    ) -> anyhow::Result<()> {
        let Some((digest, release)) = self.fetch(Some(&current.digest)).await? else {
            return Ok(());
        };
        // Otherwise whoever serves the files could roll back to an older signed release.
        if release.signed_at <= current.signed_at {
            tracing::warn!(
                bundle_sha256 = digest,
                "Ignoring a policy release signed no later than the current one"
            );
            return Ok(());
        }
        converter.replace_policies(&release.policies).await?;
        *current = self.record_current(digest, &release);
        Ok(())
    }

    /// Fetches and verifies the release, unless its bundle digest is `known_digest`.
    async fn fetch(
        &self,
        known_digest: Option<&str>,
    ) -> anyhow::Result<Option<(String, VerifiedRelease)>> {
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

    async fn trusted_root(&self) -> anyhow::Result<Arc<TrustedRoot>> {
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

    async fn download(&self, name: &str) -> anyhow::Result<Vec<u8>> {
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

    fn record_current(&self, digest: String, release: &VerifiedRelease) -> ReleaseInfo {
        tracing::info!(
            url = self.args.url,
            bundle_sha256 = digest,
            signed_at = release.signed_at,
            "Verified policy release"
        );
        ReleaseInfo {
            digest,
            signed_at: release.signed_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::path;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::provenance::tests::{integritee, production_root, A70, A71, POLICY_ID};
    use super::*;

    async fn publish(server: &MockServer, bundle: &[u8], cpu: &[u8], gpu: &[u8]) {
        server.reset().await;
        for (name, bytes) in [
            (BUNDLE_FILE, bundle),
            ("trustee_policy_cpu.rego", cpu),
            ("trustee_policy_gpu.rego", gpu),
        ] {
            Mock::given(path(format!("/{name}")))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes))
                .mount(server)
                .await;
        }
    }

    fn source(url: String) -> PolicySource {
        PolicySource {
            args: PolicySourceArgs {
                url,
                refresh_interval: DEFAULT_REFRESH_INTERVAL,
                provenance: integritee(),
            },
            policy_id: POLICY_ID.to_owned(),
            client: Client::new(),
            trusted_root: Some(Arc::new(production_root())),
        }
    }

    /// Only a newer, verified release replaces the current one; anything else keeps it.
    #[tokio::test]
    async fn refresh_installs_only_newer_verified_releases() {
        let server = MockServer::start().await;
        let source = source(server.uri());

        publish(&server, A70.bundle, A70.cpu, A70.gpu).await;
        let (policies, mut current) = source.fetch_initial().await.unwrap();
        let converter = CocoBuiltinConverter::new(POLICY_ID, &policies, None, &[])
            .await
            .unwrap();
        let a70 = current.digest.clone();

        publish(&server, A71.bundle, A71.cpu, A71.gpu).await;
        source.refresh(&mut current, &converter).await.unwrap();
        let a71 = current.digest.clone();
        assert_ne!(a71, a70);

        let mut tampered = A70.cpu.to_vec();
        tampered.push(b'\n');
        publish(&server, A70.bundle, &tampered, A70.gpu).await;
        source.refresh(&mut current, &converter).await.unwrap_err();

        publish(&server, A70.bundle, A70.cpu, A70.gpu).await;
        source.refresh(&mut current, &converter).await.unwrap();
        assert_eq!(current.digest, a71);

        let oversized = vec![b' '; MAX_DOWNLOAD_BYTES + 1];
        publish(&server, &oversized, A71.cpu, A71.gpu).await;
        source.refresh(&mut current, &converter).await.unwrap_err();
        assert_eq!(current.digest, a71);
    }
}
