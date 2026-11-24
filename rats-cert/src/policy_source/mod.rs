//! Fetches attestation policies from a published release and keeps them on the newest one.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use serde::{Deserialize, Serialize};

use crate::errors::*;
use crate::release::{Release, ReleaseFetcher, ReleaseFetcherArgs};
use crate::tee::coco::converter::builtin::policy::{TeeClassPolicies, CPU_TEE_CLASS, TEE_CLASSES};
use crate::tee::coco::converter::builtin::CocoBuiltinConverter;

const DEFAULT_REFRESH_INTERVAL: u64 = 300;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySourceArgs {
    #[serde(flatten)]
    pub release_fetcher: ReleaseFetcherArgs,
    /// Policy file per TEE class; `cpu` is required
    pub files: BTreeMap<String, String>,
    /// Seconds between checks for a newer release. 0 to fetch once at startup only.
    #[serde(default = "default_refresh_interval")]
    pub refresh_interval: u64,
    /// Seconds after the last successful check from which appraisals are refused. Unset or 0
    /// for no limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_for: Option<u64>,
}

fn default_refresh_interval() -> u64 {
    DEFAULT_REFRESH_INTERVAL
}

impl PolicySourceArgs {
    /// Rejects what is wrong without fetching anything.
    pub fn validate(&self) -> Result<()> {
        if !self.files.contains_key(CPU_TEE_CLASS)
            || self
                .files
                .keys()
                .any(|tee_class| !TEE_CLASSES.contains(&tee_class.as_str()))
        {
            return Err(Error::InvalidRelease(
                "'files' needs a `cpu` policy, and only the TEE classes cpu, gpu, switch and ppcie",
            ));
        }
        if self.fallback_for().is_some_and(|fallback_for| {
            self.refresh_interval == 0 || Duration::from_secs(self.refresh_interval) >= fallback_for
        }) {
            return Err(Error::InvalidRelease(
                "'fallback_for' needs a non-zero 'refresh_interval' below it",
            ));
        }
        self.release_fetcher
            .validate(self.files.values().map(String::as_str))
    }

    fn fallback_for(&self) -> Option<Duration> {
        self.fallback_for
            .filter(|&secs| secs > 0)
            .map(Duration::from_secs)
    }
}

pub struct PolicySource {
    fetcher: ReleaseFetcher,
    /// Policy file entry per TEE class
    entries: BTreeMap<String, String>,
    refresh_interval: Duration,
    fallback_for: Option<Duration>,
}

/// Identifies the release whose policies are in use.
pub struct ReleaseInfo {
    digest: String,
    signed_at: Option<i64>,
    fetched_at: Instant,
}

impl PolicySource {
    pub fn new(args: &PolicySourceArgs) -> Result<Self> {
        Ok(Self {
            fetcher: ReleaseFetcher::new(&args.release_fetcher)?,
            entries: args.files.clone(),
            refresh_interval: Duration::from_secs(args.refresh_interval),
            fallback_for: args.fallback_for(),
        })
    }

    /// Fetches the release to start with. There is no fallback, so failing here fails startup.
    pub async fn fetch_initial(&self) -> Result<(TeeClassPolicies, ReleaseInfo)> {
        self.fetch(None)
            .await
            .and_then(|fetched| fetched.context("No policy release fetched"))
            .map_err(|e| Error::ReleaseFetchFailed(Arc::new(e)))
    }

    /// Starts `converter`'s `fallback_for` from the `current` fetch, and returns a task that checks
    /// for a newer release every `refresh_interval` until `converter` is dropped, or `None` if the
    /// interval is 0. The caller decides where to run it.
    pub fn keep_current(
        self,
        mut current: ReleaseInfo,
        converter: Weak<CocoBuiltinConverter>,
    ) -> Option<impl Future<Output = ()> + Send + 'static> {
        if let Some(converter) = converter.upgrade() {
            self.renew(&converter, current.fetched_at);
        }
        if self.refresh_interval.is_zero() {
            return None;
        }
        let period = self.refresh_interval;

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
        let checked_at = Instant::now();
        let Some((policies, release)) = self.fetch(Some(&current.digest)).await? else {
            self.renew(converter, checked_at);
            return Ok(());
        };
        // Otherwise whoever serves the files could roll back to an older signed release.
        if release.signed_at.is_some() && release.signed_at <= current.signed_at {
            tracing::warn!(
                digest = release.digest,
                "Ignoring a policy release signed no later than the current one"
            );
            return Ok(());
        }
        converter.replace_policies(&policies).await?;
        self.renew(converter, checked_at);
        *current = release;
        Ok(())
    }

    fn renew(&self, converter: &CocoBuiltinConverter, fetched_at: Instant) {
        converter.expire_policies_at(
            self.fallback_for
                .map(|fallback_for| fetched_at + fallback_for),
        );
    }

    /// Fetches the release, unless it still has `current_digest`.
    async fn fetch(
        &self,
        current_digest: Option<&str>,
    ) -> anyhow::Result<Option<(TeeClassPolicies, ReleaseInfo)>> {
        let fetched_at = Instant::now();
        let entries: Vec<_> = self.entries.values().map(String::as_str).collect();
        let Some(Release {
            digest,
            files,
            signed_at,
        }) = self.fetcher.fetch(&entries, current_digest).await?
        else {
            return Ok(None);
        };
        let mut policies = TeeClassPolicies::new();
        for ((tee_class, entry), file) in self.entries.iter().zip(files) {
            let policy =
                String::from_utf8(file).with_context(|| format!("{entry} is not UTF-8"))?;
            policies.insert(tee_class.clone(), policy);
        }
        tracing::info!(
            base_url = self.fetcher.args().base_url,
            digest,
            signed_at,
            "Fetched policy release"
        );
        Ok(Some((
            policies,
            ReleaseInfo {
                digest,
                signed_at,
                fetched_at,
            },
        )))
    }
}

#[cfg(test)]
mod tests {
    use wiremock::MockServer;

    use super::*;
    use crate::release::provenance::tests::{integritee, BUNDLE, V0_0_27, V0_0_28};
    use crate::release::tests::publish;

    async fn publish_release(server: &MockServer, bundle: &[u8], cpu: &[u8], gpu: &[u8]) {
        publish(
            server,
            &[
                (BUNDLE, bundle),
                ("trustee_policy_cpu.rego", cpu),
                ("trustee_policy_gpu.rego", gpu),
            ],
        )
        .await;
    }

    fn policy_source(base_url: String) -> PolicySource {
        let args = PolicySourceArgs {
            release_fetcher: ReleaseFetcherArgs {
                base_url: Some(base_url),
                provenance: Some(integritee()),
            },
            files: BTreeMap::from([
                ("cpu".into(), "trustee_policy_cpu.rego".into()),
                ("gpu".into(), "trustee_policy_gpu.rego".into()),
            ]),
            refresh_interval: DEFAULT_REFRESH_INTERVAL,
            fallback_for: Some(3600),
        };
        PolicySource::new(&args).unwrap()
    }

    /// Only a newer, verified release replaces the current one; anything else keeps it.
    /// `fallback_for` restarts on a newer or unchanged release, and on nothing else.
    #[tokio::test]
    async fn refresh_installs_only_newer_verified_releases() {
        let server = MockServer::start().await;
        let source = policy_source(server.uri());

        publish_release(&server, V0_0_27.bundle, V0_0_27.cpu, V0_0_27.gpu).await;
        let (policies, mut current) = source.fetch_initial().await.unwrap();
        assert_eq!(policies["gpu"].as_bytes(), V0_0_27.gpu);
        let converter = CocoBuiltinConverter::new("trustee_policy", &policies, None, &[])
            .await
            .unwrap();
        let expiry = || converter.policies_expire_at.lock().unwrap().unwrap();
        source.renew(&converter, current.fetched_at);
        let v0_0_27 = current.digest.clone();
        let mut expires = expiry();

        publish_release(&server, V0_0_28.bundle, V0_0_28.cpu, V0_0_28.gpu).await;
        source.refresh(&mut current, &converter).await.unwrap();
        let v0_0_28 = current.digest.clone();
        assert_ne!(v0_0_28, v0_0_27);
        assert!(expiry() > expires);
        expires = expiry();

        let mut tampered = V0_0_27.cpu.to_vec();
        tampered.push(b'\n');
        publish_release(&server, V0_0_27.bundle, &tampered, V0_0_27.gpu).await;
        source.refresh(&mut current, &converter).await.unwrap_err();

        publish_release(&server, V0_0_27.bundle, V0_0_27.cpu, V0_0_27.gpu).await;
        source.refresh(&mut current, &converter).await.unwrap();
        assert_eq!(current.digest, v0_0_28);
        assert_eq!(expiry(), expires);

        publish_release(&server, V0_0_28.bundle, V0_0_28.cpu, V0_0_28.gpu).await;
        source.refresh(&mut current, &converter).await.unwrap();
        assert!(expiry() > expires);
    }
}
