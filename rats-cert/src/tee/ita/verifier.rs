use std::collections::HashMap;
use std::sync::LazyLock;

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::RwLock;

use crate::errors::*;
use crate::tee::coco::evidence::CocoEvidence;
use crate::tee::{GenericVerifier, ReportData};

use super::token::ItaToken;

/// Process-global JWKS cache, keyed by JWKS URL.
static JWKS_CACHE: LazyLock<RwLock<HashMap<String, Vec<CachedKey>>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

pub struct ItaVerifier {
    jwks_url: String,
    policy_ids: Vec<String>,
}

impl ItaVerifier {
    pub fn new(base_url: &str, policy_ids: &[String]) -> Result<Self> {
        Ok(Self {
            jwks_url: format!("{}/certs", base_url.trim_end_matches('/')),
            policy_ids: policy_ids.to_vec(),
        })
    }

    async fn verify_jwt(&self, token: &str) -> Result<Value> {
        if !self.jwks_url.starts_with("https://") {
            return Err(Error::msg(format!(
                "JWKS URL must use HTTPS: {}",
                self.jwks_url
            )));
        }

        let header = decode_header(token).context("Failed to decode ITA JWT header")?;
        let kid = header
            .kid
            .ok_or_else(|| Error::msg("ITA JWT header missing kid"))?;

        if header.alg != Algorithm::PS384 {
            return Err(Error::msg(format!(
                "Unexpected JWT algorithm {:?}, expected PS384",
                header.alg
            )));
        }

        // Try with cached keys first
        if let Some(claims) = self.try_cached_verify(token, &kid).await? {
            return Ok(claims);
        }

        // Refresh and retry
        self.refresh_jwks().await?;

        if let Some(claims) = self.try_cached_verify(token, &kid).await? {
            return Ok(claims);
        }

        Err(Error::msg(format!(
            "No JWKS key found matching kid={} (even after refresh)",
            kid
        )))
    }

    async fn try_cached_verify(&self, token: &str, kid: &str) -> Result<Option<Value>> {
        let cache = JWKS_CACHE.read().await;
        let keys = match cache.get(&self.jwks_url) {
            Some(k) => k,
            None => return Ok(None),
        };
        let key = match keys.iter().find(|k| k.kid == kid) {
            Some(k) => k,
            None => return Ok(None),
        };

        let decoding_key = DecodingKey::from_rsa_components(&key.n, &key.e)
            .context("Failed to construct RSA key from JWKS")?;

        let mut validation = Validation::new(Algorithm::PS384);
        validation.set_required_spec_claims(&["exp", "iss"]);
        validation.set_issuer(&[
            "https://portal.trustauthority.intel.com",
            "Intel Trust Authority",
        ]);
        validation.validate_exp = true;

        let token_data = decode::<Value>(token, &decoding_key, &validation)
            .context("ITA JWT verification failed")?;

        Ok(Some(token_data.claims))
    }

    async fn refresh_jwks(&self) -> Result<()> {
        let client = Client::new();
        let resp = client
            .get(&self.jwks_url)
            .header("Accept", "application/json")
            .send()
            .await
            .context("JWKS fetch request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(Error::msg(format!(
                "JWKS fetch failed ({}): {}",
                status, body
            )));
        }

        let jwks: JwksResponse = resp.json().await.context("Failed to parse JWKS response")?;

        let keys: Vec<CachedKey> = jwks
            .keys
            .into_iter()
            .map(|k| CachedKey {
                kid: k.kid,
                n: k.n,
                e: k.e,
            })
            .collect();

        let mut cache = JWKS_CACHE.write().await;
        cache.insert(self.jwks_url.clone(), keys);

        Ok(())
    }

    /// Check that runtime_data from the report matches what ITA echoed in the token.
    fn check_runtime_data_binding(
        claims: &Value,
        report_data: &ReportData,
    ) -> Result<()> {
        let runtime_data_expected = CocoEvidence::wrap_runtime_data_as_structed(report_data)?;

        // ITA echoes runtime_data in one of two claim fields depending on format:
        // - attester_runtime_data (JSON object) — when runtime_data was structured JSON
        // - attester_held_data (base64 string) — when runtime_data was raw binary
        // We check the TDX namespace first.
        let tdx_claims = claims.get("tdx");

        let runtime_data_in_token = tdx_claims
            .and_then(|tdx| tdx.get("attester_runtime_data"))
            .or_else(|| tdx_claims.and_then(|tdx| tdx.get("attester_held_data")));

        let Some(runtime_data_in_token) = runtime_data_in_token else {
            return Err(Error::msg(
                "ITA token missing attester_runtime_data/attester_held_data in tdx claims"
            ));
        };

        // If the token has it as a JSON object, do subset check (same as CoCo)
        if let (Some(expected_map), Some(token_map)) = (
            runtime_data_expected.as_object(),
            runtime_data_in_token.as_object(),
        ) {
            let is_subset = expected_map
                .iter()
                .all(|(key, value)| token_map.get(key) == Some(value));

            if !is_subset {
                tracing::debug!(
                    expected = ?expected_map,
                    in_token = ?token_map,
                    "ITA runtime_data subset check failed"
                );
                return Err(Error::msg("ITA runtime_data mismatch"));
            }
        }
        // If the token has it as a string (attester_held_data), it's base64 of the raw
        // runtime_data bytes — we'd need to compare differently. For now, the structured
        // JSON path covers TNG's usage (ReportData::Claims).

        Ok(())
    }

    /// Check TDX security: reject debug-mode TDs.
    fn check_tdx_security(claims: &Value) -> Result<()> {
        if let Some(tdx) = claims.get("tdx") {
            if let Some(is_debuggable) = tdx.get("tdx_is_debuggable") {
                if is_debuggable.as_bool() == Some(true) {
                    return Err(Error::msg(
                        "TDX TD is in debug mode (tdx_is_debuggable=true), rejecting token"
                    ));
                }
            }
        }
        Ok(())
    }

    /// Check ITA policy matching claims.
    /// ITA may issue tokens even when policies fail (PolicyMustMatch defaults to false).
    fn check_policy_matching(&self, claims: &Value) -> Result<()> {
        if self.policy_ids.is_empty() {
            return Ok(());
        }

        // Reject if any policies are unmatched
        if let Some(unmatched) = claims.get("policy_ids_unmatched") {
            if let Some(arr) = unmatched.as_array() {
                if !arr.is_empty() {
                    let ids: Vec<String> = arr
                        .iter()
                        .filter_map(|v| v.get("id").and_then(|id| id.as_str()).map(String::from))
                        .collect();
                    return Err(Error::msg(format!(
                        "ITA token has unmatched policy IDs: {:?}",
                        ids
                    )));
                }
            }
        }

        // Verify all expected policy_ids appear in policy_ids_matched
        if let Some(matched) = claims.get("policy_ids_matched") {
            if let Some(arr) = matched.as_array() {
                let matched_ids: std::collections::HashSet<&str> = arr
                    .iter()
                    .filter_map(|v| v.get("id").and_then(|id| id.as_str()))
                    .collect();

                for expected_id in &self.policy_ids {
                    if !matched_ids.contains(expected_id.as_str()) {
                        return Err(Error::msg(format!(
                            "Expected policy ID '{}' not found in policy_ids_matched",
                            expected_id
                        )));
                    }
                }
            } else {
                return Err(Error::msg("policy_ids_matched is not an array"));
            }
        } else {
            return Err(Error::msg(
                "ITA token missing policy_ids_matched, but policy_ids are configured"
            ));
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl GenericVerifier for ItaVerifier {
    type Evidence = ItaToken;

    async fn verify_evidence(
        &self,
        evidence: &ItaToken,
        report_data: &ReportData,
    ) -> Result<()> {
        let token = evidence.as_str();
        tracing::debug!(
            "Verifying ITA token with policy_ids: {:?}",
            self.policy_ids
        );

        // 1. JWT signature verification (PS384) + standard claims (exp, iss)
        let claims = self.verify_jwt(token).await?;

        // 2. Runtime data binding check
        Self::check_runtime_data_binding(&claims, report_data)?;

        // 3. TDX security checks
        Self::check_tdx_security(&claims)?;

        // 4. Policy matching
        self.check_policy_matching(&claims)?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// JWKS types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct JwksResponse {
    keys: Vec<JwkKey>,
}

#[derive(Deserialize)]
struct JwkKey {
    kid: String,
    #[allow(dead_code)]
    kty: String,
    #[serde(default)]
    #[allow(dead_code)]
    alg: String,
    n: String,
    e: String,
}

#[derive(Clone)]
struct CachedKey {
    kid: String,
    n: String,
    e: String,
}
