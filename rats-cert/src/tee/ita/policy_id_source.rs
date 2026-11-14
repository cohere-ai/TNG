//! Fetches the ITA policy ID to request from a published release.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context as _};
use serde::{Deserialize, Serialize};

use crate::errors::*;
use crate::release::{FetchedRelease, Release, ReleaseArgs};

const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_MAX_AGE: u64 = 24 * 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyIdSourceArgs {
    #[serde(flatten)]
    pub release: ReleaseArgs,
    /// JSON file with a top-level string `policy_id`
    pub file: String,
    /// Seconds the last fetched ID stays in use while fetches fail
    #[serde(default = "default_max_age")]
    pub max_age: u64,
}

fn default_max_age() -> u64 {
    DEFAULT_MAX_AGE
}

impl PolicyIdSourceArgs {
    /// Rejects what is wrong without fetching anything.
    pub fn validate(&self) -> Result<()> {
        self.release.validate([self.file.as_str()])
    }
}

pub struct PolicyIdSource {
    args: PolicyIdSourceArgs,
    release: Release,
    last: Mutex<Option<Fetched>>,
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
            args: args.clone(),
            release: Release::new(&args.release)?,
            last: Mutex::new(None),
        })
    }

    /// Fetches the policy ID to request. If that fails, the last fetched ID is used while it is
    /// younger than `max_age`.
    pub async fn current(&self) -> Result<String> {
        let fetched_at = Instant::now();
        let known_digest = self.last().as_ref().map(|last| last.digest.clone());
        let fetched = tokio::time::timeout(
            FETCH_TIMEOUT,
            self.fetch(known_digest.as_deref(), fetched_at),
        )
        .await
        .unwrap_or_else(|_| Err(anyhow!("timed out after {FETCH_TIMEOUT:?}")));

        let mut last = self.last();
        let error = match fetched.and_then(|fetched| self.update(&mut last, fetched, fetched_at)) {
            Ok(policy_id) => return Ok(policy_id),
            Err(error) => error,
        };
        match last.as_ref() {
            Some(last) if last.fetched_at.elapsed() < Duration::from_secs(self.args.max_age) => {
                tracing::warn!(?error, "Using the last fetched ITA policy ID");
                Ok(last.policy_id.clone())
            }
            _ => Err(Error::ItaPolicyIdUnavailable(Arc::new(error))),
        }
    }

    /// Records a successful fetch, `None` meaning the release is unchanged, and returns the
    /// policy ID now in use.
    fn update(
        &self,
        last: &mut Option<Fetched>,
        fetched: Option<Fetched>,
        fetched_at: Instant,
    ) -> anyhow::Result<String> {
        let Some(new) = fetched else {
            // Never fails: `fetch` only reports an unchanged release against a cached digest,
            // and the cache is never cleared.
            let last = last
                .as_mut()
                .context("unchanged release with no cached policy ID")?;
            last.fetched_at = fetched_at;
            return Ok(last.policy_id.clone());
        };
        if let Some(last) = last {
            // Otherwise whoever serves the files could roll back to an older signed release.
            if self.args.release.provenance.is_some()
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
        Ok(last.insert(new).policy_id.clone())
    }

    fn last(&self) -> std::sync::MutexGuard<'_, Option<Fetched>> {
        self.last.lock().unwrap()
    }

    async fn fetch(
        &self,
        known_digest: Option<&str>,
        fetched_at: Instant,
    ) -> anyhow::Result<Option<Fetched>> {
        let Some(FetchedRelease {
            digest,
            files,
            signed_at,
        }) = self.release.fetch(&[&self.args.file], known_digest).await?
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
            .with_context(|| format!("{} has no string 'policy_id'", self.args.file))?;
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
    use crate::release::provenance::tests::{integritee, predicate, A70, A71, BUNDLE};
    use crate::release::tests::{publish, test_release};

    pub(crate) fn test_source(base_url: String, provenance: bool) -> PolicyIdSource {
        let args = PolicyIdSourceArgs {
            release: ReleaseArgs {
                base_url: Some(base_url),
                provenance: provenance.then(integritee),
            },
            file: "predicate.json".to_owned(),
            max_age: DEFAULT_MAX_AGE,
        };
        PolicyIdSource {
            release: test_release(args.release.clone()),
            args,
            last: Mutex::new(None),
        }
    }

    /// A new ID replaces the cached one; a failed fetch falls back to it until `max_age`.
    #[tokio::test]
    async fn falls_back_to_the_last_id_until_max_age() {
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

        source.args.max_age = 0;
        assert!(matches!(
            source.current().await,
            Err(Error::ItaPolicyIdUnavailable(_))
        ));
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

        release(A71.bundle, predicate(&A71)).await;
        assert_eq!(
            source.current().await.unwrap(),
            "cbeedffa-e224-4664-b6b4-573fcd4133d3"
        );
        let a71 = source.last().as_ref().unwrap().digest.clone();

        release(A70.bundle, predicate(&A70)).await;
        source.current().await.unwrap();
        assert_eq!(source.last().as_ref().unwrap().digest, a71);
    }
}
