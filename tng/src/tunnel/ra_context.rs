//! Pre-instantiated Remote Attestation Context
//!
//! This module provides `RaContext` which holds pre-instantiated attestation
//! components based on `RaArgs` configuration. This avoids repeated creation
//! of attester/converter/verifier instances at each API call.

use std::sync::Arc;

use anyhow::{bail, Context, Result};

#[cfg(unix)]
use crate::config::ra::AttestArgs;
#[cfg(feature = "__coco-builtin-as")]
use crate::config::ra::VerifierArgs;
use crate::config::ra::{RaArgs, VerifyArgs};
#[cfg(unix)]
use crate::tunnel::attestation_exchange::PassportEvidenceCache;
#[cfg(unix)]
use crate::tunnel::attestation_metrics::AttestationMetrics;
use rats_cert::tee::claims::Claims;
use rats_cert::tee::{GenericConverter, GenericVerifier, ReportData};

use crate::tunnel::attest::AttestVerifier;
use crate::tunnel::attestation_result::AttestationResult;
use crate::tunnel::challenge::{ChallengeAttempt, ChallengeSource};
use crate::tunnel::proposal::{AttestProposal, Model};
use crate::tunnel::provider::{ProviderType, TngEvidence, TngToken};
#[cfg(unix)]
use crate::tunnel::utils::maybe_cached::RefreshStrategy;

#[cfg(unix)]
use crate::tunnel::provider::{create_attester, TngAttester};
use crate::tunnel::provider::{create_converter, create_verifier, TngConverter, TngVerifier};

/// Pre-instantiated RA context for OHTTP security
///
/// This enum mirrors the structure of `RaArgs` but holds ready-to-use
/// component instances instead of just configuration.
pub enum RaContext {
    /// Attest only mode - server attests itself
    #[cfg(unix)]
    AttestOnly(Arc<AttestContext>),

    /// Verify only mode - server verifies client
    VerifyOnly(Arc<VerifyContextSet>),

    /// Both attest and verify
    #[cfg(unix)]
    AttestAndVerify {
        attest: Arc<AttestContext>,
        verify: Arc<VerifyContextSet>,
    },

    /// No remote attestation
    NoRa,
}

impl RaContext {
    /// Create pre-instantiated RA context from RaArgs configuration.
    ///
    /// Tests and NoRa paths get a no-op metrics handle. Production tunnels should
    /// call [`Self::from_ra_args_with_metrics`].
    pub async fn from_ra_args(ra_args: &RaArgs) -> Result<Self> {
        #[cfg(unix)]
        {
            Self::from_ra_args_with_metrics(ra_args, AttestationMetrics::noop()).await
        }
        #[cfg(not(unix))]
        {
            Self::from_ra_args_inner(ra_args, ()).await
        }
    }

    #[cfg(unix)]
    /// Inject service-scoped attestation metrics into attest/verify contexts.
    pub async fn from_ra_args_with_metrics(
        ra_args: &RaArgs,
        attestation_metrics: AttestationMetrics,
    ) -> Result<Self> {
        Self::from_ra_args_inner(ra_args, attestation_metrics).await
    }

    async fn from_ra_args_inner(
        ra_args: &RaArgs,
        #[cfg(unix)] attestation_metrics: AttestationMetrics,
        #[cfg(not(unix))] _attestation_metrics: (),
    ) -> Result<Self> {
        match ra_args {
            RaArgs::NoRa => Ok(Self::NoRa),
            RaArgs::VerifyOnly(verify_list) => Ok(Self::VerifyOnly(Arc::new(
                VerifyContextSet::new(
                    verify_list,
                    #[cfg(unix)]
                    attestation_metrics,
                )
                .await?,
            ))),
            #[cfg(unix)]
            RaArgs::AttestOnly(attest_args) => Ok(Self::AttestOnly(Arc::new(
                AttestContext::from_attest_args_with_metrics(attest_args, attestation_metrics)
                    .await?,
            ))),
            #[cfg(unix)]
            RaArgs::AttestAndVerify(attest_args, verify_list) => Ok(Self::AttestAndVerify {
                attest: Arc::new(
                    AttestContext::from_attest_args_with_metrics(
                        attest_args,
                        attestation_metrics.clone(),
                    )
                    .await?,
                ),
                verify: Arc::new(VerifyContextSet::new(verify_list, attestation_metrics).await?),
            }),
        }
    }

    #[cfg(unix)]
    pub fn attestation_metrics(&self) -> Option<&AttestationMetrics> {
        self.verify_set()
            .map(VerifyContextSet::attestation_metrics)
            .or_else(|| {
                self.attest_context()
                    .map(AttestContext::attestation_metrics)
            })
    }

    /// Get the verifiers if this side verifies its peer
    pub fn verify_set(&self) -> Option<&VerifyContextSet> {
        match self {
            Self::VerifyOnly(verify) => Some(verify),
            #[cfg(unix)]
            Self::AttestAndVerify { verify, .. } => Some(verify),
            _ => None,
        }
    }

    /// Get attest context if available
    #[cfg(unix)]
    pub fn attest_context(&self) -> Option<&AttestContext> {
        match self {
            Self::AttestOnly(attest) => Some(attest),
            Self::AttestAndVerify { attest, .. } => Some(attest),
            _ => None,
        }
    }
}

/// The configured `VerifyContext`s, keyed by the `(model, provider)` a peer answers with.
pub struct VerifyContextSet {
    entries: Vec<VerifyContext>,
    #[cfg(unix)]
    metrics: AttestationMetrics,
}

impl std::fmt::Debug for VerifyContextSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.entries.iter().map(VerifyContext::key))
            .finish()
    }
}

impl VerifyContextSet {
    pub async fn new(
        verify_list: &[VerifyArgs],
        #[cfg(unix)] metrics: AttestationMetrics,
    ) -> Result<Self> {
        let mut entries = Vec::with_capacity(verify_list.len());
        for verify_args in verify_list {
            entries.push(VerifyContext::from_verify_args(verify_args).await?);
        }
        check_keys_unique(&entries)?;
        Ok(Self {
            entries,
            #[cfg(unix)]
            metrics,
        })
    }

    #[cfg(unix)]
    pub fn attestation_metrics(&self) -> &AttestationMetrics {
        &self.metrics
    }

    pub fn entry(&self, model: Model, provider: ProviderType) -> Result<&VerifyContext> {
        self.entries
            .iter()
            .find(|e| e.key() == (model, provider))
            .with_context(|| format!("no verifier is configured for ({model}, {provider})"))
    }

    /// One proposal per verifier, fetching a fresh nonce for each background check concurrently. A
    /// failed fetch only drops its own proposal, so an outage at one attestation service does not block
    /// peers using another. `start_challenge` is called once per nonce fetch.
    pub async fn make_proposals<A: ChallengeAttempt>(
        &self,
        start_challenge: impl Fn() -> A,
    ) -> Result<Vec<AttestProposal>> {
        let start_challenge = &start_challenge;
        let proposals: Vec<AttestProposal> =
            futures::future::join_all(self.entries.iter().map(|entry| async move {
                let converter = match entry {
                    VerifyContext::Passport { verifier } => {
                        return Some(AttestProposal::Passport {
                            provider: verifier.provider_type(),
                        })
                    }
                    VerifyContext::BackgroundCheck { converter, .. } => converter,
                };
                let provider = converter.provider_type();
                let attempt = start_challenge();
                let nonce = ChallengeSource::get_nonce(converter)
                    .await
                    .and_then(|nonce| {
                        if nonce.is_empty() {
                            bail!("converter returned an empty nonce");
                        }
                        Ok(nonce)
                    });
                match nonce {
                    Ok(challenge_token) => {
                        attempt.succeeded();
                        Some(AttestProposal::BackgroundCheck {
                            provider,
                            challenge_token,
                        })
                    }
                    Err(error) => {
                        tracing::warn!(%provider, ?error, "Dropping background-check proposal");
                        None
                    }
                }
            }))
            .await
            .into_iter()
            .flatten()
            .collect();

        if !self.entries.is_empty() && proposals.is_empty() {
            bail!("failed to fetch a nonce for any background-check verifier");
        }
        Ok(proposals)
    }
}

#[async_trait::async_trait]
impl AttestVerifier for VerifyContextSet {
    async fn verify_evidence(
        &self,
        provider: ProviderType,
        evidence: &serde_json::Value,
        expected: Claims,
    ) -> Result<AttestationResult> {
        tracing::debug!("Verifying attestation evidence");

        let evidence = TngEvidence::deserialize_from_json(provider, evidence.clone())
            .context("failed to parse evidence JSON")?;

        let VerifyContext::BackgroundCheck {
            converter,
            verifier,
        } = self.entry(Model::BackgroundCheck, provider)?
        else {
            anyhow::bail!("background-check entry holds no converter");
        };
        let token = converter
            .convert(&evidence)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to convert evidence to token: {:?}", e))?;
        verifier
            .verify_evidence(&token, &ReportData::Claims(expected))
            .await
            .map_err(|e| anyhow::anyhow!("Token verification failed: {:?}", e))?;

        tracing::debug!("attestation evidence verify finished successfully");
        Ok(AttestationResult::from_token(Model::BackgroundCheck, token))
    }

    async fn verify_token(
        &self,
        provider: ProviderType,
        jwt: &str,
        expected: Claims,
    ) -> Result<AttestationResult> {
        tracing::debug!("Verifying attestation token");

        let token = TngToken::from_wire(provider, jwt.to_owned())
            .context("failed to parse attestation token")?;
        self.entry(Model::Passport, provider)?
            .verifier()
            .verify_evidence(&token, &ReportData::Claims(expected))
            .await
            .map_err(|e| anyhow::anyhow!("Token verification failed: {:?}", e))?;

        tracing::debug!("attestation token verify finished successfully");
        Ok(AttestationResult::from_token(Model::Passport, token))
    }
}

fn check_keys_unique(entries: &[VerifyContext]) -> Result<()> {
    let mut seen = std::collections::HashSet::new();
    for (model, provider) in entries.iter().map(VerifyContext::key) {
        if !seen.insert((model, provider)) {
            let builtin_note = if provider == ProviderType::Coco {
                " Note that 'coco_builtin' counts as provider 'coco', because the peer's evidence comes from a CoCo attestation agent either way."
            } else {
                ""
            };
            bail!(
                "Two 'verify' entries accept '{model}' attestation from provider '{provider}'. A peer only names the model and provider it used, so at most one entry may accept each pair; put several policies or trust anchors in one entry instead.{builtin_note}"
            );
        }
    }
    Ok(())
}

/// Pre-instantiated attestation context
///
/// Holds attester and converter instances for server attestation.
#[cfg(unix)]
#[allow(clippy::large_enum_variant)] // Passport holds a converter; BackgroundCheck does not.
pub enum AttestContext {
    /// Passport mode - attest via AA, convert via remote AS
    Passport {
        attester: TngAttester,
        converter: TngConverter,
        refresh_strategy: RefreshStrategy,
        max_retries: usize,
        metrics: AttestationMetrics,
        passport_cache: PassportEvidenceCache,
    },

    /// Background check mode - just attest via AA (client verifies)
    BackgroundCheck {
        attester: TngAttester,
        refresh_strategy: RefreshStrategy,
        max_retries: usize,
        metrics: AttestationMetrics,
    },
}

#[cfg(unix)]
impl AttestContext {
    /// Create attestation context from AttestArgs configuration
    pub async fn from_attest_args(attest_args: &AttestArgs) -> Result<Self> {
        Self::from_attest_args_with_metrics(attest_args, AttestationMetrics::noop()).await
    }

    pub async fn from_attest_args_with_metrics(
        attest_args: &AttestArgs,
        metrics: AttestationMetrics,
    ) -> Result<Self> {
        match attest_args {
            AttestArgs::Passport {
                attester: attester_args,
                converter: converter_args,
                ..
            } => {
                let attester = create_attester(attester_args)?;
                let converter = create_converter(converter_args).await?;
                Ok(Self::Passport {
                    attester,
                    converter,
                    refresh_strategy: attest_args.refresh_strategy(),
                    max_retries: attest_args.max_retries(),
                    metrics,
                    passport_cache: PassportEvidenceCache::new(),
                })
            }
            AttestArgs::BackgroundCheck {
                attester: attester_args,
                refresh_interval,
                ..
            } => {
                let attester = create_attester(attester_args)?;

                if refresh_interval.is_some() {
                    tracing::warn!(
                        "`refresh_interval` in your configuration is set, but it will be ignored for background check if you are using OHTTP protocol"
                    );
                }
                Ok(Self::BackgroundCheck {
                    attester,
                    refresh_strategy: attest_args.refresh_strategy(),
                    max_retries: attest_args.max_retries(),
                    metrics,
                })
            }
        }
    }

    pub fn attestation_metrics(&self) -> &AttestationMetrics {
        match self {
            Self::Passport { metrics, .. } | Self::BackgroundCheck { metrics, .. } => metrics,
        }
    }

    /// The `(model, provider)` this attester can answer.
    pub fn proposal_key(&self) -> (Model, ProviderType) {
        match self {
            Self::Passport { converter, .. } => (Model::Passport, converter.provider_type()),
            Self::BackgroundCheck { attester, .. } => {
                (Model::BackgroundCheck, attester.provider_type())
            }
        }
    }

    /// Get refresh strategy for caching
    pub fn refresh_strategy(&self) -> RefreshStrategy {
        match self {
            Self::Passport {
                refresh_strategy, ..
            }
            | Self::BackgroundCheck {
                refresh_strategy, ..
            } => *refresh_strategy,
        }
    }

    pub fn max_retries(&self) -> usize {
        match self {
            Self::Passport { max_retries, .. } | Self::BackgroundCheck { max_retries, .. } => {
                *max_retries
            }
        }
    }
}

/// Pre-instantiated verification context
///
/// Holds components needed for verifying client attestation.
pub enum VerifyContext {
    /// Passport mode - verify token from remote AS
    Passport { verifier: TngVerifier },
    /// Background check - convert evidence via remote AS, then verify
    BackgroundCheck {
        converter: TngConverter,
        verifier: TngVerifier,
    },
}

impl std::fmt::Debug for VerifyContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Passport { .. } => f
                .debug_struct("VerifyContext::Passport")
                .finish_non_exhaustive(),
            Self::BackgroundCheck { .. } => f
                .debug_struct("VerifyContext::BackgroundCheck")
                .finish_non_exhaustive(),
        }
    }
}

impl VerifyContext {
    /// Create verification context from VerifyArgs configuration
    pub async fn from_verify_args(verify_args: &VerifyArgs) -> Result<Self> {
        match verify_args {
            VerifyArgs::Passport {
                verifier: verifier_args,
            } => Ok(Self::Passport {
                verifier: create_verifier(verifier_args).await?,
            }),
            VerifyArgs::BackgroundCheck {
                converter: converter_args,
                verifier: verifier_args,
            } => {
                let converter = create_converter(converter_args).await?;

                // The builtin service signs each token with an ephemeral key it generated, which is
                // not nameable in configuration, so this verifier is built from the converter that
                // holds it instead of from its own args.
                #[cfg(feature = "__coco-builtin-as")]
                if matches!(verifier_args, VerifierArgs::CocoBuiltin) {
                    let TngConverter::CocoBuiltin(builtin) = &converter else {
                        anyhow::bail!(
                            "The `coco_builtin` verifier requires a `coco_builtin` converter, but the configured converter is a different type"
                        );
                    };

                    return Ok(Self::BackgroundCheck {
                        verifier: TngVerifier::CocoBuiltin(builtin.new_verifier().await?),
                        converter,
                    });
                }

                let verifier = create_verifier(verifier_args).await?;
                Ok(Self::BackgroundCheck {
                    converter,
                    verifier,
                })
            }
        }
    }

    pub fn key(&self) -> (Model, ProviderType) {
        match self {
            Self::Passport { verifier } => (Model::Passport, verifier.provider_type()),
            Self::BackgroundCheck { converter, .. } => {
                (Model::BackgroundCheck, converter.provider_type())
            }
        }
    }

    pub fn verifier(&self) -> &TngVerifier {
        match self {
            Self::Passport { verifier } | Self::BackgroundCheck { verifier, .. } => verifier,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ra::{
        AttesterArgs, CocoAttesterArgs, CocoConverterArgs, CocoVerifierArgs, ConverterArgs,
        VerifierArgs,
    };
    use std::collections::HashMap;

    // =========================================================================
    // Test Constants
    // =========================================================================

    const TEST_AA_ADDR: &str =
        "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock";
    const TEST_AS_ADDR: &str = "http://0.0.0.0:8080";
    const TEST_AS_CERT_PATH: &str = "/tmp/as-full.pem";

    // =========================================================================
    // Helper Functions
    // =========================================================================

    fn make_attester_args() -> AttesterArgs {
        AttesterArgs::Coco(CocoAttesterArgs::Uds {
            aa_addr: TEST_AA_ADDR.to_string(),
        })
    }

    fn make_converter_args() -> ConverterArgs {
        ConverterArgs::Coco(CocoConverterArgs::Restful {
            as_addr: TEST_AS_ADDR.to_string(),
            policy_ids: vec!["default".to_string()],
            as_headers: HashMap::new(),
            as_ca_certs: vec![],
        })
    }

    fn make_verifier_args_with_addr() -> VerifierArgs {
        VerifierArgs::Coco(CocoVerifierArgs::Restful {
            as_addr: Some(TEST_AS_ADDR.to_string()),
            policy_ids: vec!["default".to_string()],
            as_headers: HashMap::new(),
            trusted_certs_paths: Some(vec![TEST_AS_CERT_PATH.to_string()]),
        })
    }

    fn make_verifier_args_certs_only() -> VerifierArgs {
        VerifierArgs::Coco(CocoVerifierArgs::Restful {
            as_addr: None,
            policy_ids: vec!["default".to_string()],
            as_headers: HashMap::new(),
            trusted_certs_paths: Some(vec![TEST_AS_CERT_PATH.to_string()]),
        })
    }

    fn make_verify_passport_args() -> VerifyArgs {
        VerifyArgs::Passport {
            verifier: make_verifier_args_with_addr(),
        }
    }

    fn make_verify_bgcheck_args() -> VerifyArgs {
        VerifyArgs::BackgroundCheck {
            converter: make_converter_args(),
            verifier: make_verifier_args_certs_only(),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_ra_context_no_ra() {
        let ra_args = RaArgs::NoRa;
        let result = RaContext::from_ra_args(&ra_args).await;
        assert!(result.is_ok(), "Failed: {:?}", result.err());
        let ctx = result.unwrap();
        assert!(
            matches!(ctx, RaContext::NoRa),
            "Expected NoRa variant, got {:?}",
            std::mem::discriminant(&ctx)
        );
        assert!(
            ctx.verify_set().is_none(),
            "NoRa should have no verify context"
        );
    }

    // =========================================================================
    // Section 2: VerifyOnly Tests
    // =========================================================================

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_ra_context_verify_only_passport() {
        let verify_args = make_verify_passport_args();
        let ra_args = RaArgs::VerifyOnly(vec![verify_args]);
        let result = RaContext::from_ra_args(&ra_args).await;
        assert!(result.is_ok(), "Failed: {:?}", result.err());
        let ctx = result.unwrap();
        assert!(
            matches!(ctx, RaContext::VerifyOnly(_)),
            "Expected VerifyOnly variant"
        );
        assert!(
            ctx.verify_set().is_some(),
            "VerifyOnly should have verify context"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_ra_context_verify_only_background_check() {
        let verify_args = make_verify_bgcheck_args();
        let ra_args = RaArgs::VerifyOnly(vec![verify_args]);
        let result = RaContext::from_ra_args(&ra_args).await;
        assert!(result.is_ok(), "Failed: {:?}", result.err());
        let ctx = result.unwrap();
        assert!(
            matches!(ctx, RaContext::VerifyOnly(_)),
            "Expected VerifyOnly variant"
        );
        assert!(
            ctx.verify_set().is_some(),
            "VerifyOnly should have verify context"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_make_proposals_drops_only_failed_nonce_fetches() {
        let unreachable = || VerifyArgs::BackgroundCheck {
            converter: ConverterArgs::Coco(CocoConverterArgs::Restful {
                as_addr: "http://127.0.0.1:1".to_string(),
                policy_ids: vec!["default".to_string()],
                as_headers: HashMap::new(),
                as_ca_certs: vec![],
            }),
            verifier: make_verifier_args_certs_only(),
        };
        let proposals_for = |verify_list| async move {
            let ctx = RaContext::from_ra_args(&RaArgs::VerifyOnly(verify_list))
                .await
                .unwrap();
            ctx.verify_set().unwrap().make_proposals(|| ()).await
        };

        let proposals = proposals_for(vec![unreachable(), make_verify_passport_args()])
            .await
            .unwrap();
        assert_eq!(
            proposals,
            vec![AttestProposal::Passport {
                provider: ProviderType::Coco
            }]
        );
        let err = proposals_for(vec![unreachable()]).await.unwrap_err();
        assert!(err.to_string().contains("any"), "{err}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn duplicate_verify_keys_are_rejected() {
        let result = RaContext::from_ra_args(&RaArgs::VerifyOnly(vec![
            make_verify_bgcheck_args(),
            make_verify_bgcheck_args(),
        ]))
        .await;
        let message = result
            .err()
            .expect("duplicate verify keys should be rejected")
            .to_string();
        assert!(
            message.contains(
                "Two 'verify' entries accept 'background_check' attestation from provider 'coco'"
            ),
            "{message}"
        );
        assert!(message.contains("coco_builtin"), "{message}");
    }

    // =========================================================================
    // Section 5: Accessor Method Tests
    // =========================================================================

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_accessor_verify_only() {
        let verify_args = make_verify_bgcheck_args();
        let ra_args = RaArgs::VerifyOnly(vec![verify_args]);
        let result = RaContext::from_ra_args(&ra_args).await;
        assert!(result.is_ok(), "Failed: {:?}", result.err());
        let ctx = result.unwrap();
        assert!(
            ctx.verify_set().is_some(),
            "VerifyOnly should have verify context"
        );
    }

    // =========================================================================
    // Section 3-4: Unix-specific tests (AttestOnly and AttestAndVerify)
    // =========================================================================

    #[cfg(unix)]
    mod unix_tests {
        use super::*;
        use crate::tunnel::utils::maybe_cached::RefreshStrategy;

        // Helper functions for Unix tests

        fn make_attest_bgcheck_args() -> AttestArgs {
            AttestArgs::BackgroundCheck {
                attester: make_attester_args(),
                refresh_interval: None,
                max_retries: None,
            }
        }

        fn make_attest_passport_args() -> AttestArgs {
            AttestArgs::Passport {
                attester: make_attester_args(),
                converter: make_converter_args(),
                refresh_interval: None,
                max_retries: None,
            }
        }

        // =====================================================================
        // Section 3: AttestOnly Tests
        // =====================================================================

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn test_ra_context_attest_only_background_check() {
            let attest_args = make_attest_bgcheck_args();
            let ra_args = RaArgs::AttestOnly(attest_args);
            let result = RaContext::from_ra_args(&ra_args).await;
            assert!(result.is_ok(), "Failed: {:?}", result.err());
            let ctx = result.unwrap();
            assert!(
                matches!(ctx, RaContext::AttestOnly(_)),
                "Expected AttestOnly variant"
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn test_ra_context_attest_only_passport() {
            let attest_args = make_attest_passport_args();
            let ra_args = RaArgs::AttestOnly(attest_args);
            let result = RaContext::from_ra_args(&ra_args).await;
            assert!(result.is_ok(), "Failed: {:?}", result.err());
            let ctx = result.unwrap();
            assert!(
                matches!(ctx, RaContext::AttestOnly(_)),
                "Expected AttestOnly variant"
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn test_attest_context_refresh_strategy_periodic() {
            let attest_args = AttestArgs::BackgroundCheck {
                attester: make_attester_args(),
                refresh_interval: Some(600),
                max_retries: None,
            };
            let result = AttestContext::from_attest_args(&attest_args).await;
            assert!(result.is_ok(), "Failed: {:?}", result.err());
            let ctx = result.unwrap();
            assert!(
                matches!(
                    ctx.refresh_strategy(),
                    RefreshStrategy::Periodically { interval: 600 }
                ),
                "Expected Periodically with interval 600"
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn test_attest_context_refresh_strategy_always() {
            let attest_args = AttestArgs::BackgroundCheck {
                attester: make_attester_args(),
                refresh_interval: Some(0),
                max_retries: None,
            };
            let result = AttestContext::from_attest_args(&attest_args).await;
            assert!(result.is_ok(), "Failed: {:?}", result.err());
            let ctx = result.unwrap();
            assert!(
                matches!(ctx.refresh_strategy(), RefreshStrategy::Always),
                "Expected Always refresh strategy"
            );
        }

        // =====================================================================
        // Section 4: AttestAndVerify Combination Tests
        // =====================================================================

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn test_ra_context_two_way_passport_passport() {
            let attest_args = make_attest_passport_args();
            let verify_args = make_verify_passport_args();
            let ra_args = RaArgs::AttestAndVerify(attest_args, vec![verify_args]);
            let result = RaContext::from_ra_args(&ra_args).await;
            assert!(result.is_ok(), "Failed: {:?}", result.err());
            let ctx = result.unwrap();
            assert!(
                matches!(ctx, RaContext::AttestAndVerify { .. }),
                "Expected AttestAndVerify variant"
            );
            assert!(
                ctx.verify_set().is_some(),
                "AttestAndVerify should have verify context"
            );
            assert!(
                ctx.attest_context().is_some(),
                "AttestAndVerify should have attest context"
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn test_ra_context_two_way_bgcheck_bgcheck() {
            let attest_args = make_attest_bgcheck_args();
            let verify_args = make_verify_bgcheck_args();
            let ra_args = RaArgs::AttestAndVerify(attest_args, vec![verify_args]);
            let result = RaContext::from_ra_args(&ra_args).await;
            assert!(result.is_ok(), "Failed: {:?}", result.err());
            let ctx = result.unwrap();
            assert!(
                matches!(ctx, RaContext::AttestAndVerify { .. }),
                "Expected AttestAndVerify variant"
            );
            assert!(
                ctx.verify_set().is_some(),
                "AttestAndVerify should have verify context"
            );
            assert!(
                ctx.attest_context().is_some(),
                "AttestAndVerify should have attest context"
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn test_ra_context_two_way_bgcheck_passport() {
            let attest_args = make_attest_bgcheck_args();
            let verify_args = make_verify_passport_args();
            let ra_args = RaArgs::AttestAndVerify(attest_args, vec![verify_args]);
            let result = RaContext::from_ra_args(&ra_args).await;
            assert!(result.is_ok(), "Failed: {:?}", result.err());
            let ctx = result.unwrap();
            assert!(
                matches!(ctx, RaContext::AttestAndVerify { .. }),
                "Expected AttestAndVerify variant"
            );
            assert!(
                ctx.verify_set().is_some(),
                "AttestAndVerify should have verify context"
            );
            assert!(
                ctx.attest_context().is_some(),
                "AttestAndVerify should have attest context"
            );
        }

        // =====================================================================
        // Section 5: Accessor Method Tests (Unix-specific)
        // =====================================================================

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn test_accessor_attest_only() {
            let attest_args = make_attest_bgcheck_args();
            let ra_args = RaArgs::AttestOnly(attest_args);
            let result = RaContext::from_ra_args(&ra_args).await;
            assert!(result.is_ok(), "Failed: {:?}", result.err());
            let ctx = result.unwrap();
            assert!(
                ctx.verify_set().is_none(),
                "AttestOnly should have no verify context"
            );
            assert!(
                ctx.attest_context().is_some(),
                "AttestOnly should have attest context"
            );
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn test_accessor_attest_and_verify() {
            let attest_args = make_attest_bgcheck_args();
            let verify_args = make_verify_bgcheck_args();
            let ra_args = RaArgs::AttestAndVerify(attest_args, vec![verify_args]);
            let result = RaContext::from_ra_args(&ra_args).await;
            assert!(result.is_ok(), "Failed: {:?}", result.err());
            let ctx = result.unwrap();
            assert!(
                ctx.verify_set().is_some(),
                "AttestAndVerify should have verify context"
            );
            assert!(
                ctx.attest_context().is_some(),
                "AttestAndVerify should have attest context"
            );
        }
    }
}
