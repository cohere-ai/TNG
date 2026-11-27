//! Fetches the files of a published release, optionally checking they are covered by a Sigstore
//! bundle.

pub mod provenance;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{ensure, Context as _};
use serde::{Deserialize, Serialize};
use sigstore_trust_root::reqwest::{header, redirect, Certificate, Client, Response, Url};
use sigstore_trust_root::{TrustedRoot, TufConfig};
use sigstore_verify::crypto::sha256;

use self::provenance::{Provenance, ReleaseFile};
use crate::errors::*;

const MAX_DOWNLOAD_BYTES: usize = 4 << 20;
const TIMEOUT: Duration = Duration::from_secs(5);

/// Where published files are fetched from, and optionally who must have signed them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseFetcherArgs {
    /// The URL bare file names are resolved against, e.g. `.../releases/latest/download`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    /// Who must have signed the files. Without it, the files are used as fetched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,
}

impl ReleaseFetcherArgs {
    /// Rejects what is wrong with `entries`, the files to fetch, without fetching anything.
    pub fn validate<'a>(&self, entries: impl IntoIterator<Item = &'a str>) -> Result<()> {
        if let Some(problem) = self.provenance.as_ref().and_then(Provenance::problem) {
            return Err(Error::InvalidRelease(problem));
        }
        if let Some(base) = self.base_url.as_deref().and_then(|b| Url::parse(b).ok()) {
            if base.query().is_some() || base.fragment().is_some() {
                return Err(Error::InvalidRelease(
                    "'base_url' must not have a query or fragment",
                ));
            }
        }
        let base = self.base();
        let is_http = |entry: &str| {
            !entry.is_empty()
                && base.as_ref().is_ok_and(|base| {
                    resolve(base.as_ref(), entry)
                        .is_ok_and(|u| matches!(u.scheme(), "http" | "https"))
                })
        };
        let bundle = self.provenance.as_ref().map(|p| p.bundle.as_str());
        if entries.into_iter().all(is_http) && bundle.is_none_or(is_http) {
            Ok(())
        } else {
            Err(Error::InvalidRelease(
                "files must be http(s) URLs, or names resolved against an http(s) 'base_url'",
            ))
        }
    }

    fn base(&self) -> anyhow::Result<Option<Url>> {
        self.base_url
            .as_ref()
            .map(|base| Ok(Url::parse(&format!("{}/", base.trim_end_matches('/')))?))
            .transpose()
    }
}

/// A full URL is used as is, a bare name replaces the last segment of `base`.
fn resolve(base: Option<&Url>, entry: &str) -> anyhow::Result<Url> {
    Ok(match base {
        Some(base) => base.join(entry)?,
        None => Url::parse(entry)?,
    })
}

fn is_downgrade(from: &Url, to: &Url) -> bool {
    from.scheme() == "https" && to.scheme() != "https"
}

fn file_name(url: &Url) -> &str {
    url.path_segments()
        .and_then(|mut s| s.next_back())
        .unwrap_or_default()
}

/// A published release, as fetched by [`ReleaseFetcher::fetch`]
#[derive(Debug)]
pub struct Release {
    /// Identifies what was fetched: the bundle's digest with provenance, otherwise the files'
    pub digest: String,
    /// In the order they were asked for
    pub files: Vec<Vec<u8>>,
    /// Earliest verified signing time in seconds since the Unix epoch, with provenance only
    pub signed_at: Option<i64>,
}

pub struct ReleaseFetcher {
    args: ReleaseFetcherArgs,
    client: Client,
    no_redirect: Client,
    #[cfg(test)]
    trusted_root: Arc<TrustedRoot>,
}

impl ReleaseFetcher {
    pub fn new(args: &ReleaseFetcherArgs) -> Result<Self> {
        let client = |redirects| {
            webpki_root_certs::TLS_SERVER_ROOT_CERTS
                .iter()
                .map(|der| Certificate::from_der(der))
                .collect::<std::result::Result<Vec<_>, _>>()
                .and_then(|roots| {
                    Client::builder()
                        .tls_certs_only(roots)
                        .redirect(redirects)
                        .connect_timeout(TIMEOUT)
                        .timeout(TIMEOUT)
                        .build()
                })
                .map_err(|e| Error::ReleaseFetchFailed(Arc::new(e.into())))
        };
        // Like reqwest's default policy, but never from https to http.
        let follow = redirect::Policy::custom(|attempt| {
            if attempt
                .previous()
                .iter()
                .any(|from| is_downgrade(from, attempt.url()))
            {
                attempt.error("redirect from https to http")
            } else if attempt.previous().len() >= 10 {
                attempt.error("too many redirects")
            } else {
                attempt.follow()
            }
        });
        if args.provenance.is_none() {
            tracing::warn!(
                base_url = args.base_url,
                "'provenance' is not set, so fetched files are used without a signature check"
            );
        }
        Ok(Self {
            args: args.clone(),
            client: client(follow)?,
            no_redirect: client(redirect::Policy::none())?,
            #[cfg(test)]
            trusted_root: Arc::new(provenance::tests::production_root()),
        })
    }

    pub fn args(&self) -> &ReleaseFetcherArgs {
        &self.args
    }

    /// Fetches `entries` and checks their provenance, or returns `None` if what is published is
    /// still `current_digest`. With provenance that is decided from the bundle alone, before the
    /// files are downloaded.
    pub async fn fetch(
        &self,
        entries: &[&str],
        current_digest: Option<&str>,
    ) -> anyhow::Result<Option<Release>> {
        let mut base = self.args.base()?;
        let (first, rest) = match &self.args.provenance {
            Some(provenance) => (provenance.bundle.as_str(), entries),
            None => entries
                .split_first()
                .map(|(first, rest)| (*first, rest))
                .context("No files to fetch")?,
        };
        let first = self.download_pinning(&mut base, first).await?;
        let urls = rest
            .iter()
            .map(|entry| resolve(base.as_ref(), entry))
            .collect::<anyhow::Result<Vec<_>>>()?;

        let Some(provenance) = &self.args.provenance else {
            let mut files = vec![first];
            files.extend(self.download_all(&urls).await?);
            let digests: String = files.iter().map(|f| sha256(f).to_hex()).collect();
            let digest = sha256(digests.as_bytes()).to_hex();
            return Ok(
                (current_digest != Some(digest.as_str())).then_some(Release {
                    digest,
                    files,
                    signed_at: None,
                }),
            );
        };

        let bundle = first;
        let digest = sha256(&bundle).to_hex();
        if current_digest == Some(digest.as_str()) {
            return Ok(None);
        }
        let files = self.download_all(&urls).await?;
        let named: Vec<_> = urls
            .iter()
            .zip(&files)
            .map(|(url, bytes)| ReleaseFile {
                name: file_name(url),
                bytes,
            })
            .collect();
        let signed_at =
            provenance::verify(&*self.trusted_root().await?, &bundle, &named, provenance)?;
        Ok(Some(Release {
            digest,
            files,
            signed_at: Some(signed_at),
        }))
    }

    #[cfg(test)]
    async fn trusted_root(&self) -> anyhow::Result<Arc<TrustedRoot>> {
        Ok(self.trusted_root.clone())
    }

    #[cfg(not(test))]
    async fn trusted_root(&self) -> anyhow::Result<Arc<TrustedRoot>> {
        let config = TufConfig::production()
            .without_cache()
            .with_http_client(self.client.clone());
        Ok(Arc::new(
            TrustedRoot::from_tuf(config)
                .await
                .context("Failed to fetch the Sigstore trusted root")?,
        ))
    }

    async fn download_all(&self, urls: &[Url]) -> anyhow::Result<Vec<Vec<u8>>> {
        let mut files = Vec::with_capacity(urls.len());
        for url in urls {
            files.push(self.download(url).await?);
        }
        Ok(files)
    }

    /// Downloads `entry`. If it is a bare name and the server redirects it to the same name in
    /// another directory of the same origin, as a "latest" alias does, `base` moves there so the
    /// rest of the fetch comes from the same release.
    async fn download_pinning(
        &self,
        base: &mut Option<Url>,
        entry: &str,
    ) -> anyhow::Result<Vec<u8>> {
        let url = resolve(base.as_ref(), entry)?;
        let response = self
            .no_redirect
            .get(url.clone())
            .send()
            .await
            .with_context(|| format!("Failed to fetch {url}"))?;
        if !response.status().is_redirection() {
            return read_body(response, &url).await;
        }
        let target = response
            .headers()
            .get(header::LOCATION)
            .and_then(|location| url.join(location.to_str().ok()?).ok())
            .with_context(|| format!("{url} redirects without a usable location"))?;
        ensure!(!is_downgrade(&url, &target), "{url} redirects to http");
        if base.is_some()
            && Url::parse(entry).is_err()
            && target.origin() == url.origin()
            && file_name(&target) == file_name(&url)
        {
            *base = Some(target.clone());
        }
        self.download(&target).await
    }

    async fn download(&self, url: &Url) -> anyhow::Result<Vec<u8>> {
        let response = self
            .client
            .get(url.clone())
            .send()
            .await
            .with_context(|| format!("Failed to fetch {url}"))?;
        read_body(response, url).await
    }
}

async fn read_body(response: Response, url: &Url) -> anyhow::Result<Vec<u8>> {
    let mut response = response
        .error_for_status()
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

#[cfg(test)]
pub(crate) mod tests {
    use wiremock::matchers::path;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    pub(crate) async fn publish(server: &MockServer, files: &[(&str, &[u8])]) {
        server.reset().await;
        for (name, bytes) in files {
            Mock::given(path(format!("/{name}")))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes.to_vec()))
                .mount(server)
                .await;
        }
    }

    /// A redirect to the same name elsewhere on the origin pins the rest of the fetch to it; any
    /// other redirect, like GitHub's from a tag to its asset storage, is just followed.
    #[tokio::test]
    async fn latest_alias_redirect_pins_the_release() {
        let server = MockServer::start().await;
        let fetcher = ReleaseFetcher::new(&ReleaseFetcherArgs {
            base_url: Some(format!("{}/latest", server.uri())),
            provenance: None,
        })
        .unwrap();
        let fetch_with_redirect = |target: &'static str| {
            let (server, fetcher) = (&server, &fetcher);
            async move {
                publish(
                    server,
                    &[
                        ("v2/a.json", b"a2"),
                        ("v2/b.json", b"b2"),
                        ("assets/1234", b"a2"),
                        ("latest/b.json", b"b1"),
                    ],
                )
                .await;
                Mock::given(path("/latest/a.json"))
                    .respond_with(ResponseTemplate::new(302).insert_header("location", target))
                    .mount(server)
                    .await;
                fetcher
                    .fetch(&["a.json", "b.json"], None)
                    .await
                    .unwrap()
                    .unwrap()
                    .files
            }
        };

        assert_eq!(fetch_with_redirect("/v2/a.json").await, [b"a2", b"b2"]);
        assert_eq!(fetch_with_redirect("/assets/1234").await, [b"a2", b"b1"]);
    }

    #[test]
    fn validate_requires_http_urls() {
        let args = |base_url: Option<&str>| ReleaseFetcherArgs {
            base_url: base_url.map(str::to_owned),
            provenance: None,
        };
        let https = Some("https://example.com/download");
        args(https).validate(["a.json"]).unwrap();
        args(Some("http://example.com"))
            .validate(["a.json"])
            .unwrap();
        args(None).validate(["http://example.com/a.json"]).unwrap();
        args(https)
            .validate(["https://other.example.com/a.json"])
            .unwrap();

        args(None).validate(["a.json"]).unwrap_err();
        args(Some("https://example.com/download?x=1"))
            .validate(["a.json"])
            .unwrap_err();
        args(Some("https://example.com/download#x"))
            .validate(["a.json"])
            .unwrap_err();
        args(https).validate(["file:///a.json"]).unwrap_err();
        args(https).validate([""]).unwrap_err();
    }

    #[test]
    fn only_https_to_http_is_a_downgrade() {
        let url = |s| Url::parse(s).unwrap();
        assert!(is_downgrade(&url("https://a/x"), &url("http://a/x")));
        assert!(!is_downgrade(&url("https://a/x"), &url("https://b/x")));
        assert!(!is_downgrade(&url("http://a/x"), &url("http://b/x")));
    }

    #[tokio::test]
    async fn without_provenance_files_are_used_as_fetched() {
        let server = MockServer::start().await;
        let fetcher = ReleaseFetcher::new(&ReleaseFetcherArgs {
            base_url: Some(server.uri()),
            provenance: None,
        })
        .unwrap();

        publish(&server, &[("a.json", b"1")]).await;
        let first = fetcher.fetch(&["a.json"], None).await.unwrap().unwrap();
        assert_eq!(first.files, [b"1"]);
        assert_eq!(first.signed_at, None);
        assert!(fetcher
            .fetch(&["a.json"], Some(&first.digest))
            .await
            .unwrap()
            .is_none());

        publish(&server, &[("a.json", b"2")]).await;
        let second = fetcher
            .fetch(&["a.json"], Some(&first.digest))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second.files, [b"2"]);

        publish(&server, &[("a.json", &vec![b' '; MAX_DOWNLOAD_BYTES + 1])]).await;
        fetcher.fetch(&["a.json"], None).await.unwrap_err();
    }
}
