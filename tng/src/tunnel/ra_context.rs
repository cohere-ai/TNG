//! Pre-instantiated Remote Attestation Context
//!
//! This module provides `RaContext` which holds pre-instantiated attestation
//! components based on `RaArgs` configuration. This avoids repeated creation
//! of attester/converter/verifier instances at each API call.

use std::sync::Arc;

use anyhow::Result;

#[cfg(unix)]
use crate::config::ra::AttestArgs;
use crate::config::ra::{RaArgs, VerifyArgs};
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
    VerifyOnly(Arc<VerifyContext>),

    /// Both attest and verify
    #[cfg(unix)]
    AttestAndVerify {
        attest: Arc<AttestContext>,
        verify: Arc<VerifyContext>,
    },

    /// No remote attestation
    NoRa,
}

impl RaContext {
    /// Create pre-instantiated RA context from RaArgs configuration
    pub async fn from_ra_args(ra_args: &RaArgs) -> Result<Self> {
        match ra_args {
            RaArgs::NoRa => Ok(Self::NoRa),
            RaArgs::VerifyOnly(verify_args) => Ok(Self::VerifyOnly(Arc::new(
                VerifyContext::from_verify_args(verify_args).await?,
            ))),
            #[cfg(unix)]
            RaArgs::AttestOnly(attest_args) => Ok(Self::AttestOnly(Arc::new(
                AttestContext::from_attest_args(attest_args)?,
            ))),
            #[cfg(unix)]
            RaArgs::AttestAndVerify(attest_args, verify_args) => Ok(Self::AttestAndVerify {
                attest: Arc::new(AttestContext::from_attest_args(attest_args)?),
                verify: Arc::new(VerifyContext::from_verify_args(verify_args).await?),
            }),
        }
    }

    /// Get verify context if available
    pub fn verify_context(&self) -> Option<&VerifyContext> {
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

/// Pre-instantiated attestation context
///
/// Holds attester and converter instances for server attestation.
#[cfg(unix)]
pub enum AttestContext {
    /// Passport mode - attest via AA, convert via remote AS
    Passport {
        attester: TngAttester,
        converter: TngConverter,
        refresh_strategy: RefreshStrategy,
        max_retries: usize,
    },

    /// Background check mode - just attest via AA (client verifies)
    BackgroundCheck {
        attester: TngAttester,
        refresh_strategy: RefreshStrategy,
        max_retries: usize,
    },
}

#[cfg(unix)]
impl AttestContext {
    /// Create attestation context from AttestArgs configuration
    pub fn from_attest_args(attest_args: &AttestArgs) -> Result<Self> {
        match attest_args {
            AttestArgs::Passport {
                attester: attester_args,
                converter: converter_args,
                ..
            } => {
                let attester = create_attester(attester_args)?;
                let converter = create_converter(converter_args)?;
                Ok(Self::Passport {
                    attester,
                    converter,
                    refresh_strategy: attest_args.refresh_strategy(),
                    max_retries: attest_args.max_retries(),
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
                })
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
            } => {
                let verifier = create_verifier(verifier_args).await?;
                Ok(Self::Passport { verifier })
            }
            VerifyArgs::BackgroundCheck {
                converter: converter_args,
                verifier: verifier_args,
            } => {
                let converter = create_converter(converter_args)?;
                let verifier = create_verifier(verifier_args).await?;
                Ok(Self::BackgroundCheck {
                    converter,
                    verifier,
                })
            }
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

    #[allow(dead_code)]
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
            ctx.verify_context().is_none(),
            "NoRa should have no verify context"
        );
    }

    // =========================================================================
    // Section 2: VerifyOnly Tests
    // =========================================================================

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_ra_context_verify_only_passport() {
        let verify_args = make_verify_passport_args();
        let ra_args = RaArgs::VerifyOnly(verify_args);
        let result = RaContext::from_ra_args(&ra_args).await;
        assert!(result.is_ok(), "Failed: {:?}", result.err());
        let ctx = result.unwrap();
        assert!(
            matches!(ctx, RaContext::VerifyOnly(_)),
            "Expected VerifyOnly variant"
        );
        assert!(
            ctx.verify_context().is_some(),
            "VerifyOnly should have verify context"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_ra_context_verify_only_background_check() {
        let verify_args = make_verify_bgcheck_args();
        let ra_args = RaArgs::VerifyOnly(verify_args);
        let result = RaContext::from_ra_args(&ra_args).await;
        assert!(result.is_ok(), "Failed: {:?}", result.err());
        let ctx = result.unwrap();
        assert!(
            matches!(ctx, RaContext::VerifyOnly(_)),
            "Expected VerifyOnly variant"
        );
        assert!(
            ctx.verify_context().is_some(),
            "VerifyOnly should have verify context"
        );
    }

    // =========================================================================
    // Section 5: Accessor Method Tests
    // =========================================================================

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_accessor_verify_only() {
        let verify_args = make_verify_bgcheck_args();
        let ra_args = RaArgs::VerifyOnly(verify_args);
        let result = RaContext::from_ra_args(&ra_args).await;
        assert!(result.is_ok(), "Failed: {:?}", result.err());
        let ctx = result.unwrap();
        assert!(
            ctx.verify_context().is_some(),
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
            let result = AttestContext::from_attest_args(&attest_args);
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
            let result = AttestContext::from_attest_args(&attest_args);
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
            let ra_args = RaArgs::AttestAndVerify(attest_args, verify_args);
            let result = RaContext::from_ra_args(&ra_args).await;
            assert!(result.is_ok(), "Failed: {:?}", result.err());
            let ctx = result.unwrap();
            assert!(
                matches!(ctx, RaContext::AttestAndVerify { .. }),
                "Expected AttestAndVerify variant"
            );
            assert!(
                ctx.verify_context().is_some(),
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
            let ra_args = RaArgs::AttestAndVerify(attest_args, verify_args);
            let result = RaContext::from_ra_args(&ra_args).await;
            assert!(result.is_ok(), "Failed: {:?}", result.err());
            let ctx = result.unwrap();
            assert!(
                matches!(ctx, RaContext::AttestAndVerify { .. }),
                "Expected AttestAndVerify variant"
            );
            assert!(
                ctx.verify_context().is_some(),
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
            let ra_args = RaArgs::AttestAndVerify(attest_args, verify_args);
            let result = RaContext::from_ra_args(&ra_args).await;
            assert!(result.is_ok(), "Failed: {:?}", result.err());
            let ctx = result.unwrap();
            assert!(
                matches!(ctx, RaContext::AttestAndVerify { .. }),
                "Expected AttestAndVerify variant"
            );
            assert!(
                ctx.verify_context().is_some(),
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
                ctx.verify_context().is_none(),
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
            let ra_args = RaArgs::AttestAndVerify(attest_args, verify_args);
            let result = RaContext::from_ra_args(&ra_args).await;
            assert!(result.is_ok(), "Failed: {:?}", result.err());
            let ctx = result.unwrap();
            assert!(
                ctx.verify_context().is_some(),
                "AttestAndVerify should have verify context"
            );
            assert!(
                ctx.attest_context().is_some(),
                "AttestAndVerify should have attest context"
            );
        }
    }
}
