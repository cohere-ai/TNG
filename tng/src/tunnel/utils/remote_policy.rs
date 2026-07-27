use std::time::{Duration, Instant};

use anyhow::{anyhow, Context as _};
use rats_cert::tee::ita::PolicyIdSource;
use reqwest::Client;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

use crate::config::ra::RemotePolicyIdConfig;

/// Expected JSON structure of predicate.json.
#[derive(Deserialize)]
struct Predicate {
    policy_id: String,
}

struct CachedPolicyId {
    policy_ids: Vec<String>,
    fetched_at: Instant,
}

/// Fetches ITA policy IDs from a remote HTTPS URL with time-based caching
/// and optional Sigstore bundle verification.
pub struct RemotePolicyIdProvider {
    predicate_url: String,
    attestation_bundle_url: Option<String>,
    cache_ttl: Duration,
    http: Client,
    cache: RwLock<Option<CachedPolicyId>>,
}

impl RemotePolicyIdProvider {
    pub fn new(config: RemotePolicyIdConfig) -> anyhow::Result<Self> {
        if !config.predicate_url.starts_with("https://") {
            return Err(anyhow!(
                "predicate_url must use HTTPS: {}",
                config.predicate_url
            ));
        }
        if let Some(ref bundle_url) = config.attestation_bundle_url {
            if !bundle_url.starts_with("https://") {
                return Err(anyhow!(
                    "attestation_bundle_url must use HTTPS: {}",
                    bundle_url
                ));
            }
        }

        Ok(Self {
            predicate_url: config.predicate_url,
            attestation_bundle_url: config.attestation_bundle_url,
            cache_ttl: Duration::from_secs(config.cache_ttl_secs),
            http: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .context("failed to build HTTP client for remote policy provider")?,
            cache: RwLock::new(None),
        })
    }

    async fn fetch_policy_ids(&self) -> anyhow::Result<Vec<String>> {
        tracing::debug!(url = %self.predicate_url, "Fetching remote policy predicate");

        let predicate_bytes = self
            .http
            .get(&self.predicate_url)
            .header("Accept", "application/json")
            .send()
            .await
            .with_context(|| format!("failed to fetch predicate from {}", self.predicate_url))?
            .error_for_status()
            .with_context(|| format!("HTTP error fetching predicate from {}", self.predicate_url))?
            .bytes()
            .await
            .with_context(|| {
                format!("failed to read predicate body from {}", self.predicate_url)
            })?;

        if let Some(ref bundle_url) = self.attestation_bundle_url {
            self.verify_sigstore_bundle(&predicate_bytes, bundle_url)
                .await?;
        }

        let predicate: Predicate =
            serde_json::from_slice(&predicate_bytes).context("failed to parse predicate.json")?;

        if predicate.policy_id.is_empty() {
            return Err(anyhow!("predicate.json contains empty policy_id"));
        }

        tracing::info!(
            policy_id = %predicate.policy_id,
            "Successfully fetched remote policy ID"
        );
        Ok(vec![predicate.policy_id])
    }

    async fn verify_sigstore_bundle(
        &self,
        artifact_bytes: &[u8],
        bundle_url: &str,
    ) -> anyhow::Result<()> {
        tracing::debug!(url = %bundle_url, "Fetching Sigstore attestation bundle");

        let bundle_bytes = self
            .http
            .get(bundle_url)
            .send()
            .await
            .with_context(|| format!("failed to fetch attestation bundle from {bundle_url}"))?
            .error_for_status()
            .with_context(|| format!("HTTP error fetching attestation bundle from {bundle_url}"))?
            .bytes()
            .await
            .with_context(|| format!("failed to read attestation bundle from {bundle_url}"))?;

        verify_bundle(artifact_bytes, &bundle_bytes)
            .context("Sigstore bundle verification failed")?;

        tracing::info!("Sigstore attestation bundle verified successfully");
        Ok(())
    }
}

#[async_trait::async_trait]
impl PolicyIdSource for RemotePolicyIdProvider {
    async fn get_policy_ids(&self) -> rats_cert::errors::Result<Vec<String>> {
        {
            let cache = self.cache.read().await;
            if let Some(ref cached) = *cache {
                if cached.fetched_at.elapsed() < self.cache_ttl {
                    tracing::trace!("Returning cached remote policy IDs");
                    return Ok(cached.policy_ids.clone());
                }
            }
        }

        let policy_ids = self.fetch_policy_ids().await.map_err(|e| {
            rats_cert::errors::Error::ItaError(format!(
                "Failed to resolve remote policy IDs: {e:#}"
            ))
        })?;

        {
            let mut cache = self.cache.write().await;
            *cache = Some(CachedPolicyId {
                policy_ids: policy_ids.clone(),
                fetched_at: Instant::now(),
            });
        }

        Ok(policy_ids)
    }
}

/// Minimal Sigstore bundle for structural validation.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigstoreBundle {
    media_type: String,
    verification_material: serde_json::Value,
    message_signature: Option<MessageSignature>,
    dsse_envelope: Option<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MessageSignature {
    message_digest: Option<MessageDigest>,
    #[allow(dead_code)]
    signature: String,
}

#[derive(Deserialize)]
struct MessageDigest {
    algorithm: String,
    digest: String,
}

/// Verify a Sigstore bundle against the artifact bytes.
///
/// Performs structural validation of the bundle and, when the bundle contains
/// a `messageSignature` with a `messageDigest`, verifies that the SHA-256
/// digest matches the artifact.
///
/// Full cryptographic verification (certificate chain, transparency log,
/// timestamp) requires `sigstore-verify` which currently conflicts with the
/// workspace's pinned `hyper-util` version. When that conflict is resolved,
/// this function should be replaced with a call to `sigstore_verify::verify`.
fn verify_bundle(artifact_bytes: &[u8], bundle_bytes: &[u8]) -> anyhow::Result<()> {
    let bundle: SigstoreBundle =
        serde_json::from_slice(bundle_bytes).context("attestation bundle is not valid JSON")?;

    if !bundle.media_type.contains("dev.sigstore.bundle") {
        return Err(anyhow!(
            "unexpected bundle mediaType: {}",
            bundle.media_type
        ));
    }

    if bundle.verification_material.is_null() {
        return Err(anyhow!("bundle missing verificationMaterial"));
    }

    if bundle.message_signature.is_none() && bundle.dsse_envelope.is_none() {
        return Err(anyhow!(
            "bundle must contain either messageSignature or dsseEnvelope"
        ));
    }

    if let Some(ref msg_sig) = bundle.message_signature {
        if let Some(ref digest) = msg_sig.message_digest {
            if digest.algorithm.to_uppercase() != "SHA2_256" && digest.algorithm != "SHA_256" {
                tracing::warn!(
                    algorithm = %digest.algorithm,
                    "Bundle uses non-SHA256 digest algorithm; skipping digest comparison"
                );
            } else {
                let computed = hex::encode(Sha256::digest(artifact_bytes));
                if computed != digest.digest {
                    return Err(anyhow!(
                        "artifact SHA-256 digest mismatch: computed={computed}, \
                         bundle={expected}",
                        expected = digest.digest
                    ));
                }
                tracing::debug!("Artifact SHA-256 digest matches bundle");
            }
        }
    }

    tracing::warn!(
        "Full Sigstore cryptographic verification is not yet available; \
         only structural and digest validation was performed. \
         Add sigstore-verify once the hyper-util version conflict is resolved."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_https_predicate_url() {
        let config = RemotePolicyIdConfig {
            predicate_url: "http://example.com/predicate.json".into(),
            attestation_bundle_url: None,
            cache_ttl_secs: 300,
        };
        assert!(RemotePolicyIdProvider::new(config).is_err());
    }

    #[test]
    fn rejects_non_https_bundle_url() {
        let config = RemotePolicyIdConfig {
            predicate_url: "https://example.com/predicate.json".into(),
            attestation_bundle_url: Some("http://example.com/bundle.json".into()),
            cache_ttl_secs: 300,
        };
        assert!(RemotePolicyIdProvider::new(config).is_err());
    }

    #[test]
    fn accepts_valid_config() {
        let config = RemotePolicyIdConfig {
            predicate_url: "https://example.com/predicate.json".into(),
            attestation_bundle_url: Some("https://example.com/bundle.sigstore.json".into()),
            cache_ttl_secs: 300,
        };
        assert!(RemotePolicyIdProvider::new(config).is_ok());
    }

    #[test]
    fn parse_predicate_json() {
        let json = r#"{"policy_id": "cbeedffa-e224-4664-b6b4-573fcd4133d3"}"#;
        let predicate: Predicate = serde_json::from_str(json).unwrap();
        assert_eq!(predicate.policy_id, "cbeedffa-e224-4664-b6b4-573fcd4133d3");
    }

    #[test]
    fn parse_predicate_empty_id_detected() {
        let json = r#"{"policy_id": ""}"#;
        let predicate: Predicate = serde_json::from_str(json).unwrap();
        assert!(predicate.policy_id.is_empty());
    }

    #[tokio::test]
    async fn cache_returns_fresh_value() {
        let config = RemotePolicyIdConfig {
            predicate_url: "https://example.com/predicate.json".into(),
            attestation_bundle_url: None,
            cache_ttl_secs: 300,
        };
        let provider = RemotePolicyIdProvider::new(config).unwrap();

        {
            let mut cache = provider.cache.write().await;
            *cache = Some(CachedPolicyId {
                policy_ids: vec!["cached-id".into()],
                fetched_at: Instant::now(),
            });
        }

        let ids = provider.get_policy_ids().await.unwrap();
        assert_eq!(ids, vec!["cached-id"]);
    }

    #[tokio::test]
    async fn expired_cache_triggers_refetch() {
        let config = RemotePolicyIdConfig {
            predicate_url: "https://example.com/predicate.json".into(),
            attestation_bundle_url: None,
            cache_ttl_secs: 0,
        };
        let provider = RemotePolicyIdProvider::new(config).unwrap();

        {
            let mut cache = provider.cache.write().await;
            *cache = Some(CachedPolicyId {
                policy_ids: vec!["stale-id".into()],
                fetched_at: Instant::now() - Duration::from_secs(10),
            });
        }

        let result = provider.get_policy_ids().await;
        assert!(
            result.is_err(),
            "expired cache should trigger a refetch which fails (no server)"
        );
    }

    #[test]
    fn verify_bundle_rejects_invalid_json() {
        assert!(verify_bundle(b"artifact", b"not-json").is_err());
    }

    #[test]
    fn verify_bundle_rejects_wrong_media_type() {
        let bundle = serde_json::json!({
            "mediaType": "application/vnd.wrong",
            "verificationMaterial": {},
            "messageSignature": {"signature": "abc", "messageDigest": null}
        });
        assert!(verify_bundle(b"artifact", bundle.to_string().as_bytes()).is_err());
    }

    #[test]
    fn verify_bundle_rejects_missing_verification_material() {
        let bundle = serde_json::json!({
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": null,
            "messageSignature": {"signature": "abc"}
        });
        assert!(verify_bundle(b"artifact", bundle.to_string().as_bytes()).is_err());
    }

    #[test]
    fn verify_bundle_rejects_digest_mismatch() {
        let bundle = serde_json::json!({
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {"content": {}},
            "messageSignature": {
                "signature": "abc",
                "messageDigest": {
                    "algorithm": "SHA2_256",
                    "digest": "0000000000000000000000000000000000000000000000000000000000000000"
                }
            }
        });
        let err = verify_bundle(b"artifact", bundle.to_string().as_bytes());
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(msg.contains("digest mismatch"), "got: {msg}");
    }

    #[test]
    fn verify_bundle_accepts_matching_digest() {
        let artifact = b"hello world";
        let digest = hex::encode(Sha256::digest(artifact));
        let bundle = serde_json::json!({
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {"content": {}},
            "messageSignature": {
                "signature": "abc",
                "messageDigest": {
                    "algorithm": "SHA2_256",
                    "digest": digest
                }
            }
        });
        verify_bundle(artifact, bundle.to_string().as_bytes()).unwrap();
    }

    #[test]
    fn verify_bundle_accepts_dsse_envelope() {
        let bundle = serde_json::json!({
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {"content": {}},
            "dsseEnvelope": {"payloadType": "application/vnd.in-toto+json"}
        });
        verify_bundle(b"artifact", bundle.to_string().as_bytes()).unwrap();
    }

    #[test]
    fn config_deserialize_with_remote_policy() {
        let json = r#"{
            "predicate_url": "https://example.com/predicate.json",
            "attestation_bundle_url": "https://example.com/bundle.sigstore.json",
            "cache_ttl_secs": 120
        }"#;
        let config: RemotePolicyIdConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.predicate_url, "https://example.com/predicate.json");
        assert_eq!(
            config.attestation_bundle_url.as_deref(),
            Some("https://example.com/bundle.sigstore.json")
        );
        assert_eq!(config.cache_ttl_secs, 120);
    }

    #[test]
    fn config_deserialize_defaults() {
        let json = r#"{"predicate_url": "https://example.com/predicate.json"}"#;
        let config: RemotePolicyIdConfig = serde_json::from_str(json).unwrap();
        assert!(config.attestation_bundle_url.is_none());
        assert_eq!(config.cache_ttl_secs, 300);
    }
}
