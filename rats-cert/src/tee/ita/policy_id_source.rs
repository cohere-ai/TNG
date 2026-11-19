//! Fetches the ITA policy ID to request from a published release.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context as _};
use serde::{Deserialize, Serialize};

use crate::errors::*;
use crate::release::{Release, ReleaseFetcher, ReleaseFetcherArgs};

const FRESH_FOR: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyIdSourceArgs {
    #[serde(flatten)]
    pub release_fetcher: ReleaseFetcherArgs,
    /// JSON file with a top-level string `policy_id`
    pub file: String,
    /// Seconds the last fetched ID stays in use while fetches fail. 0 for no limit.
    #[serde(default)]
    pub fallback_for: u64,
}

impl PolicyIdSourceArgs {
    /// Rejects what is wrong without fetching anything.
    pub fn validate(&self) -> Result<()> {
        self.release_fetcher.validate([self.file.as_str()])
    }
}

pub struct PolicyIdSource {
    fetcher: ReleaseFetcher,
    entry: String,
    fallback_for: Duration,
    /// How long the last fetch is reused instead of fetching again
    fresh_for: Duration,
    /// Read to reuse a fresh fetch, and written across a fetch, so callers that need one wait for
    /// it and share its result.
    state: tokio::sync::RwLock<State>,
}

#[derive(Default)]
struct State {
    /// The last successful fetch
    last: Option<Fetched>,
    /// When the last fetch, successful or not, finished
    checked_at: Option<Instant>,
    /// Why the last fetch failed
    error: Option<Arc<anyhow::Error>>,
}

impl State {
    fn is_fresh(&self, fresh_for: Duration) -> bool {
        self.checked_at.is_some_and(|at| at.elapsed() < fresh_for)
    }
}

struct Fetched {
    policy_id: String,
    digest: String,
    signed_at: Option<i64>,
    fetched_at: Instant,
}

impl PolicyIdSource {
    pub fn new(args: &PolicyIdSourceArgs) -> Result<Self> {
        Ok(Self {
            fetcher: ReleaseFetcher::new(&args.release_fetcher)?,
            entry: args.file.clone(),
            fallback_for: Duration::from_secs(args.fallback_for),
            fresh_for: FRESH_FOR,
            state: tokio::sync::RwLock::default(),
        })
    }

    /// Fetches the policy ID to request, unless the last fetch is younger than `fresh_for`. If
    /// fetching fails, the last fetched ID is used while it is younger than a non-zero
    /// `fallback_for`.
    pub async fn current(&self) -> Result<String> {
        {
            let state = self.state.read().await;
            if state.is_fresh(self.fresh_for) {
                return self.policy_id(&state);
            }
        }
        let mut state = self.state.write().await;
        // Another caller may have fetched while this one waited for the write lock.
        if !state.is_fresh(self.fresh_for) {
            state.error = match self.refresh(&mut state.last).await {
                Ok(()) => None,
                Err(error) => Some(Arc::new(error)),
            };
            state.checked_at = Some(Instant::now());
        }
        self.policy_id(&state)
    }

    /// The policy ID to request after the last fetch in `state`
    fn policy_id(&self, state: &State) -> Result<String> {
        match (&state.last, &state.error) {
            (Some(last), None) => Ok(last.policy_id.clone()),
            (Some(last), Some(error))
                if self.fallback_for.is_zero() || last.fetched_at.elapsed() < self.fallback_for =>
            {
                tracing::warn!(?error, "Using the last fetched ITA policy ID");
                Ok(last.policy_id.clone())
            }
            (_, Some(error)) => Err(Error::ItaPolicyIdUnavailable(error.clone())),
            (None, None) => Err(Error::ItaPolicyIdUnavailable(Arc::new(anyhow!(
                "no policy ID fetched"
            )))),
        }
    }

    /// Fetches the latest release into `last`, or renews `last` if it is still the latest.
    async fn refresh(&self, last: &mut Option<Fetched>) -> anyhow::Result<()> {
        let fetched_at = Instant::now();
        let current_digest = last.as_ref().map(|last| last.digest.as_str());
        let Some(new) = self.fetch(current_digest, fetched_at).await? else {
            if let Some(last) = last {
                last.fetched_at = fetched_at;
            }
            return Ok(());
        };
        if let Some(last) = last {
            // Otherwise whoever serves the files could roll back to an older signed release.
            if new.signed_at.is_some()
                && last.digest != new.digest
                && new.signed_at <= last.signed_at
            {
                bail!("release signed no later than the current one");
            }
        }
        tracing::info!(
            policy_id = new.policy_id,
            digest = new.digest,
            signed_at = new.signed_at,
            "Fetched ITA policy ID"
        );
        *last = Some(new);
        Ok(())
    }

    async fn fetch(
        &self,
        current_digest: Option<&str>,
        fetched_at: Instant,
    ) -> anyhow::Result<Option<Fetched>> {
        let Some(Release {
            digest,
            files,
            signed_at,
        }) = self.fetcher.fetch(&[&self.entry], current_digest).await?
        else {
            return Ok(None);
        };
        #[derive(Deserialize)]
        struct PolicyIdFile {
            policy_id: String,
        }
        let [file] = &files[..] else {
            bail!("expected one file, got {}", files.len());
        };
        let PolicyIdFile { policy_id } = serde_json::from_slice(file)
            .with_context(|| format!("{} has no string 'policy_id'", self.entry))?;
        Ok(Some(Fetched {
            policy_id,
            digest,
            signed_at,
            fetched_at,
        }))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use wiremock::MockServer;

    use super::*;
    use crate::release::provenance::tests::{integritee, predicate, BUNDLE, V0_0_27, V0_0_28};
    use crate::release::tests::publish;

    pub(crate) fn test_source(base_url: String, provenance: bool) -> PolicyIdSource {
        let args = PolicyIdSourceArgs {
            release_fetcher: ReleaseFetcherArgs {
                base_url: Some(base_url),
                provenance: provenance.then(integritee),
                no_provenance: !provenance,
            },
            file: "predicate.json".to_owned(),
            fallback_for: 0,
        };
        let mut source = PolicyIdSource::new(&args).unwrap();
        source.fresh_for = Duration::ZERO;
        source
    }

    /// A new ID replaces the cached one; a failed fetch falls back to it until `fallback_for`.
    #[tokio::test]
    async fn falls_back_to_the_last_id_until_fallback_for() {
        let server = MockServer::start().await;
        let mut source = test_source(server.uri(), false);

        source.current().await.unwrap_err();

        publish(&server, &[("predicate.json", br#"{"policy_id": "p1"}"#)]).await;
        assert_eq!(source.current().await.unwrap(), "p1");
        publish(&server, &[("predicate.json", br#"{"policy_id": "p2"}"#)]).await;
        assert_eq!(source.current().await.unwrap(), "p2");

        publish(&server, &[("predicate.json", br#"{"id": "p3"}"#)]).await;
        assert_eq!(source.current().await.unwrap(), "p2");
        server.reset().await;
        assert_eq!(source.current().await.unwrap(), "p2");

        source.fallback_for = Duration::from_nanos(1);
        assert!(matches!(
            source.current().await,
            Err(Error::ItaPolicyIdUnavailable(_))
        ));
    }

    /// Conversions while a fetch runs, or within `fresh_for` of it, use its result.
    #[tokio::test]
    async fn conversions_share_a_fresh_fetch() {
        let server = MockServer::start().await;
        publish(&server, &[("predicate.json", br#"{"policy_id": "p1"}"#)]).await;
        let mut source = test_source(server.uri(), false);
        source.fresh_for = FRESH_FOR;

        let (first, second) = tokio::join!(source.current(), source.current());
        assert_eq!(
            (first.unwrap(), second.unwrap()),
            ("p1".into(), "p1".into())
        );
        assert_eq!(source.current().await.unwrap(), "p1");
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    /// Integritee's `predicate.json` is covered as the predicate, and an older release is
    /// ignored in favour of the cached ID.
    #[tokio::test]
    async fn reads_a_signed_release() {
        let server = MockServer::start().await;
        let source = test_source(server.uri(), true);
        let release = |bundle: &'static [u8], predicate: Vec<u8>| {
            let server = &server;
            async move {
                publish(server, &[(BUNDLE, bundle), ("predicate.json", &predicate)]).await;
            }
        };

        release(V0_0_28.bundle, predicate(&V0_0_28)).await;
        assert_eq!(
            source.current().await.unwrap(),
            "dddaaee6-7456-42c9-8727-d2f1929144dc"
        );
        let digest = || async {
            source
                .state
                .read()
                .await
                .last
                .as_ref()
                .unwrap()
                .digest
                .clone()
        };
        let v0_0_28 = digest().await;

        release(V0_0_27.bundle, predicate(&V0_0_27)).await;
        source.current().await.unwrap();
        assert_eq!(digest().await, v0_0_28);
    }
}
