//! Evaluates a relying-party policy, fetched from a published release, against ITA token claims.

use std::future::Future;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use anyhow::{bail, Context as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::errors::*;
use crate::release::{Release, ReleaseFetcher, ReleaseFetcherArgs};

const DEFAULT_REFRESH_INTERVAL: u64 = 300;
const DEFAULT_VALID_FOR: u64 = 24 * 60 * 60;
const FRESH_FOR: Duration = Duration::from_secs(5);
const ALLOW_RULE: &str = "allow";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpPolicySourceArgs {
    #[serde(flatten)]
    pub release_fetcher: ReleaseFetcherArgs,
    /// Rego policy whose package defines `allow`
    pub policy: String,
    /// JSON documents loaded as data
    #[serde(default)]
    pub data: Vec<String>,
    /// Seconds between checks for a newer release. 0 for no checks.
    #[serde(default = "default_refresh_interval")]
    pub refresh_interval: u64,
    /// Seconds a fetched release stays accepted after it was last fetched
    #[serde(default = "default_valid_for")]
    pub valid_for: u64,
}

fn default_refresh_interval() -> u64 {
    DEFAULT_REFRESH_INTERVAL
}

fn default_valid_for() -> u64 {
    DEFAULT_VALID_FOR
}

impl RpPolicySourceArgs {
    /// Rejects what is wrong without fetching anything.
    pub fn validate(&self) -> Result<()> {
        if self.refresh_interval >= self.valid_for {
            return Err(Error::InvalidRelease(
                "'valid_for' must be greater than 'refresh_interval'",
            ));
        }
        self.release_fetcher.validate(self.entries())
    }

    /// The policy, then the data
    fn entries(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.policy.as_str()).chain(self.data.iter().map(String::as_str))
    }
}

pub struct RpPolicySource {
    fetcher: ReleaseFetcher,
    /// The policy, then the data
    entries: Vec<String>,
    refresh_interval: Duration,
    valid_for: Duration,
    /// How long after a fetch finishes a denied token is evaluated again without fetching
    fresh_for: Duration,
    /// Fetched releases, oldest first. Only a fetch replaces them, as a whole, so token checks
    /// evaluate a snapshot without waiting for fetches or for each other.
    releases: Mutex<Arc<Vec<CachedRelease>>>,
    /// Held across a fetch, so fetches run one at a time.
    fetch_state: tokio::sync::Mutex<FetchState>,
}

#[derive(Default)]
struct FetchState {
    /// When the last fetch finished
    finished_at: Option<Instant>,
    /// Why the last fetch failed
    error: Option<Arc<anyhow::Error>>,
    /// Signing time of the newest release accepted, kept after that release expires
    newest_signed_at: Option<i64>,
}

/// A fetched release whose policy evaluates
#[derive(Clone)]
struct CachedRelease {
    digest: String,
    signed_at: Option<i64>,
    policy: String,
    data: Vec<String>,
    fetched_at: Instant,
}

impl CachedRelease {
    /// `entries` are what the files of `release` were fetched as: the policy, then the data.
    fn new(release: Release, entries: &[String], fetched_at: Instant) -> anyhow::Result<Self> {
        let mut files = Vec::new();
        for (file, entry) in release.files.into_iter().zip(entries) {
            files.push(String::from_utf8(file).with_context(|| format!("{entry} is not UTF-8"))?);
        }
        let mut files = files.into_iter();
        let cached = Self {
            digest: release.digest,
            signed_at: release.signed_at,
            policy: files.next().context("no policy fetched")?,
            data: files.collect(),
            fetched_at,
        };
        cached
            .allows("{}")
            .context("the policy does not evaluate")?;
        Ok(cached)
    }

    fn allows(&self, input: &str) -> anyhow::Result<bool> {
        let mut engine = regorus::Engine::new();
        let package = engine.add_policy("rp_policy.rego".to_owned(), self.policy.clone())?;
        for data in &self.data {
            engine.add_data_json(data)?;
        }
        engine.set_input_json(input)?;
        Ok(engine.eval_rule(format!("{package}.{ALLOW_RULE}"))? == regorus::Value::from(true))
    }
}

impl RpPolicySource {
    pub fn new(args: &RpPolicySourceArgs) -> Result<Self> {
        Ok(Self {
            fetcher: ReleaseFetcher::new(&args.release_fetcher)?,
            entries: args.entries().map(str::to_owned).collect(),
            refresh_interval: Duration::from_secs(args.refresh_interval),
            valid_for: Duration::from_secs(args.valid_for),
            fresh_for: FRESH_FOR,
            releases: Mutex::default(),
            fetch_state: tokio::sync::Mutex::default(),
        })
    }

    /// Returns a task that fetches the latest release now and every `refresh_interval` until
    /// `source` is dropped, or `None` if the interval is 0. The caller decides where to run it.
    pub fn keep_current(source: Weak<Self>) -> Option<impl Future<Output = ()> + Send + 'static> {
        let period = source.upgrade()?.refresh_interval;
        if period.is_zero() {
            return None;
        }
        Some(async move {
            let mut interval = tokio::time::interval(period);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                let Some(source) = source.upgrade() else {
                    break;
                };
                // A failure is logged by the fetch, and the cached releases stay.
                let _ = source.fetch_unless_fresh(Duration::ZERO).await;
            }
        })
    }

    /// Accepts claims any release fetched within `valid_for` allows. Otherwise fetches the latest
    /// release, unless a fetch finished within `fresh_for`, and evaluates again.
    pub async fn check(&self, claims: &Value) -> Result<()> {
        let input = claims.to_string();
        if self.any_allows(&self.snapshot(), &input) {
            return Ok(());
        }

        let fetched = self.fetch_unless_fresh(self.fresh_for).await;
        let releases = self.snapshot();
        if self.any_allows(&releases, &input) {
            return Ok(());
        }
        match fetched {
            // Nothing to evaluate against, so why fetching failed is why the claims are refused.
            Err(error) if !releases.iter().any(|cached| self.is_accepted(cached)) => {
                Err(Error::ItaRpPolicyUnavailable(error))
            }
            _ => Err(Error::ItaRpPolicyDenied),
        }
    }

    /// Fetches the latest release unless a fetch finished within `fresh_for`, and returns how the
    /// last fetch went. A caller that waited for a fetch in progress so shares its result.
    async fn fetch_unless_fresh(
        &self,
        fresh_for: Duration,
    ) -> std::result::Result<(), Arc<anyhow::Error>> {
        let mut fetch_state = self.fetch_state.lock().await;
        let fresh = fetch_state
            .finished_at
            .is_some_and(|at| at.elapsed() < fresh_for);
        if !fresh {
            fetch_state.error = match self.fetch(&mut fetch_state.newest_signed_at).await {
                Ok(()) => None,
                Err(error) => {
                    tracing::warn!(
                        ?error,
                        "Failed to fetch the ITA RP policy, keeping the cached releases"
                    );
                    Some(Arc::new(error))
                }
            };
            fetch_state.finished_at = Some(Instant::now());
        }
        match &fetch_state.error {
            None => Ok(()),
            Some(error) => Err(error.clone()),
        }
    }

    /// Fetches the latest release, and replaces the releases with the accepted ones, adding the
    /// fetched release or renewing the newest if it is still the latest.
    async fn fetch(&self, newest_signed_at: &mut Option<i64>) -> anyhow::Result<()> {
        let fetched_at = Instant::now();
        let current = self.snapshot();
        let entries: Vec<&str> = self.entries.iter().map(String::as_str).collect();
        let current_digest = current.last().map(|newest| newest.digest.as_str());
        let fetched = self.fetcher.fetch(&entries, current_digest).await?;

        let mut releases = match fetched {
            None => {
                let mut releases = current.to_vec();
                if let Some(newest) = releases.last_mut() {
                    newest.fetched_at = fetched_at;
                }
                releases
            }
            Some(release) => {
                // Otherwise whoever serves the files could roll back to an older signed release.
                if release.signed_at.is_some() && release.signed_at <= *newest_signed_at {
                    bail!("release signed no later than the newest accepted one");
                }
                let new = CachedRelease::new(release, &self.entries, fetched_at)?;
                *newest_signed_at = new.signed_at.or(*newest_signed_at);
                tracing::info!(
                    digest = new.digest,
                    signed_at = new.signed_at,
                    "Fetched ITA RP policy"
                );
                // Without provenance an earlier release may be published again, and becomes the
                // newest.
                let mut releases: Vec<_> = current
                    .iter()
                    .filter(|cached| cached.digest != new.digest)
                    .cloned()
                    .collect();
                releases.push(new);
                releases
            }
        };
        releases.retain(|cached| self.is_accepted(cached));
        *self.releases.lock().unwrap() = Arc::new(releases);
        Ok(())
    }

    fn snapshot(&self) -> Arc<Vec<CachedRelease>> {
        self.releases.lock().unwrap().clone()
    }

    fn is_accepted(&self, cached: &CachedRelease) -> bool {
        cached.fetched_at.elapsed() < self.valid_for
    }

    fn any_allows(&self, releases: &[CachedRelease], input: &str) -> bool {
        releases
            .iter()
            .filter(|cached| self.is_accepted(cached))
            .any(|cached| {
                cached.allows(input).unwrap_or_else(|error| {
                    tracing::warn!(
                        ?error,
                        digest = cached.digest,
                        "Failed to evaluate the ITA RP policy"
                    );
                    false
                })
            })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wiremock::MockServer;

    use super::*;
    use crate::release::provenance::tests::{integritee, Fixture, BUNDLE, V0_0_27, V0_0_28};
    use crate::release::tests::publish;

    fn test_source(base_url: String, provenance: bool) -> RpPolicySource {
        let args = RpPolicySourceArgs {
            release_fetcher: ReleaseFetcherArgs {
                base_url: Some(base_url),
                provenance: provenance.then(integritee),
            },
            policy: "ita_rp_policy.rego".to_owned(),
            data: vec!["ita_rims.json".to_owned()],
            refresh_interval: 0,
            valid_for: DEFAULT_VALID_FOR,
        };
        let mut source = RpPolicySource::new(&args).unwrap();
        source.fresh_for = Duration::ZERO;
        source
    }

    async fn release(server: &MockServer, fixture: &Fixture) {
        publish(
            server,
            &[
                (BUNDLE, fixture.bundle),
                ("ita_rp_policy.rego", fixture.rp_policy),
                ("ita_rims.json", fixture.rims),
            ],
        )
        .await;
    }

    /// Claims of a token the policy of `fixture` allows.
    fn claims(fixture: &Fixture) -> Value {
        let rims: Value = serde_json::from_slice(fixture.rims).unwrap();
        let v1 = &rims["public"]["cohere"]["v1"];
        json!({
            "policy_ids_matched": [{
                "id": "dddaaee6-7456-42c9-8727-d2f1929144dc",
                "hash": "NEJrRkJvTGJmRWpKQS9UUjl3bDZCK2JwSDJvZjVKTmlEM3o2Tkdaam90d3gvd2lLV3g4VEhYb1VvZDF6TFFCNg==",
            }],
            "tdx": {
                "tdx_rtmr1": v1["platform"]["rtmr1_rtmr2"][0]["rtmr1"],
                "tdx_rtmr2": v1["platform"]["rtmr1_rtmr2"][0]["rtmr2"],
                "tdx_rtmr3": v1["rtmr3"]["s000"]["rtmr3"][0],
            },
            "nvgpu": {"claim_details": [{
                "x-nvidia-gpu-driver-version": v1["platform"]["nvidia_driver_versions"][0],
            }]},
        })
    }

    /// The published policy evaluates, with its signature checked as in production.
    #[tokio::test]
    async fn evaluates_the_published_policy() {
        let server = MockServer::start().await;
        let source = test_source(server.uri(), true);
        assert!(matches!(
            source.check(&claims(&V0_0_28)).await,
            Err(Error::ItaRpPolicyUnavailable(_))
        ));

        release(&server, &V0_0_28).await;
        source.check(&claims(&V0_0_28)).await.unwrap();

        let mut denied = claims(&V0_0_28);
        denied["tdx"]["tdx_rtmr3"] = json!("00".repeat(48));
        assert!(matches!(
            source.check(&denied).await,
            Err(Error::ItaRpPolicyDenied)
        ));
        let mut denied = claims(&V0_0_28);
        denied["policy_ids_matched"][0]["hash"] = json!("other");
        assert!(matches!(
            source.check(&denied).await,
            Err(Error::ItaRpPolicyDenied)
        ));
    }

    /// The task fetches right away, and ends once the source is dropped.
    #[tokio::test]
    async fn keep_current_fetches_until_dropped() {
        let server = MockServer::start().await;
        release(&server, &V0_0_28).await;
        let mut source = test_source(server.uri(), false);
        source.refresh_interval = Duration::from_secs(1);
        let source = Arc::new(source);
        let task = RpPolicySource::keep_current(Arc::downgrade(&source)).unwrap();
        let drop_once_fetched = async move {
            while source.snapshot().is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };

        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(task, drop_once_fetched)
        })
        .await
        .unwrap();
    }

    /// A token denied while another one's fetch runs waits for it and uses its result.
    #[tokio::test]
    async fn concurrent_denials_wait_for_one_fetch() {
        let server = MockServer::start().await;
        release(&server, &V0_0_28).await;
        let mut source = test_source(server.uri(), false);
        source.fresh_for = FRESH_FOR;

        let claims = claims(&V0_0_28);
        let (first, second) = tokio::join!(source.check(&claims), source.check(&claims));
        first.unwrap();
        second.unwrap();
        // One request for the policy and one for the data
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    /// A denial picks up a new release, and every release stays accepted until `valid_for`.
    #[tokio::test]
    async fn denial_refetches_and_releases_expire() {
        let server = MockServer::start().await;
        let mut source = test_source(server.uri(), false);
        let publish_version = |version: u32| {
            let server = &server;
            async move {
                let rego = format!("package rp\nallow if input.version == {version}");
                publish(
                    server,
                    &[
                        ("ita_rp_policy.rego", rego.as_bytes()),
                        ("ita_rims.json", b"{}"),
                    ],
                )
                .await;
            }
        };

        publish_version(1).await;
        source.check(&json!({"version": 1})).await.unwrap();
        publish_version(2).await;
        source.check(&json!({"version": 2})).await.unwrap();
        source.check(&json!({"version": 1})).await.unwrap();

        source.valid_for = Duration::from_millis(500);
        tokio::time::sleep(source.valid_for).await;
        source.check(&json!({"version": 1})).await.unwrap_err();
        source.check(&json!({"version": 2})).await.unwrap();
    }

    /// An older signed release is refused even once every newer one has expired from the cache.
    #[tokio::test]
    async fn rollback_is_refused_after_expiry() {
        let server = MockServer::start().await;
        let mut source = test_source(server.uri(), true);
        release(&server, &V0_0_28).await;
        source.check(&claims(&V0_0_28)).await.unwrap();

        source.valid_for = Duration::ZERO;
        release(&server, &V0_0_27).await;
        let Err(Error::ItaRpPolicyUnavailable(error)) = source.check(&claims(&V0_0_27)).await
        else {
            panic!("v0.0.27 was not refused");
        };
        assert!(error.to_string().contains("signed no later"), "{error:?}");
    }
}
