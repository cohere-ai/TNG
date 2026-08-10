use std::collections::BTreeMap;
use std::sync::Arc;

use attestation_service::config::Config;
use attestation_service::ear_token::EarTokenConfiguration;
use attestation_service::{AttestationService, HashAlgorithm, RuntimeData, VerificationRequest};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use key_value_storage::{KeyValueStorageType, KvStorageProvider, StorageBackendConfig};
use rand::RngCore as _;

use super::super::evidence::{AttestationServiceHashAlgo, CocoAsToken, CocoEvidence};
use crate::errors::*;
use crate::tee::coco::converter::{convert_additional_evidence, CoCoNonce};
use crate::tee::GenericConverter;

/// Length of the locally generated nonce, in bytes.
///
/// Upstream has no `generate_challenge`, so TNG mints the nonce itself. That is not a
/// downgrade: TNG is already the nonce authority in background-check mode, and the binding is
/// checked against `runtime_data` by `CommonCocoVerifier` rather than by the AS.
const NONCE_LEN: usize = 32;

/// Rego policies to install, keyed by TEE class (`cpu`, `gpu`).
///
/// The EAR broker resolves a policy as `format!("{policy_id}_{tee_class}")`, so a single
/// attestation covering a CPU and a GPU evaluates two separate policies.
pub type TeeClassPolicies = BTreeMap<String, String>;

/// Converts [`CocoEvidence`] into a [`CocoAsToken`] using an upstream CoCo attestation
/// service running in this process, with no remote AS involved.
pub struct CocoBuiltinConverter {
    /// Boxed to keep this large struct off the stack.
    attestation_service: Box<AttestationService>,

    /// Passed to `evaluate` unsuffixed; the broker appends the TEE class per device.
    policy_id: String,
}

impl CocoBuiltinConverter {
    pub async fn new(
        policy_id: impl Into<String>,
        policies: &TeeClassPolicies,
        verifier_config: Option<serde_json::Value>,
    ) -> Result<Self> {
        let policy_id = policy_id.into();

        // `VerifierConfig` has private fields and only derives `Deserialize`, so pass-through
        // JSON is the only way to construct it.
        let verifier_config = verifier_config
            .map(serde_json::from_value)
            .transpose()
            .map_err(Error::CocoBuiltinAsParseVerifierConfigFailed)?;

        let config = Config {
            // `BuiltIn` is the default and leaves an empty RVPS in place. Golden values live
            // in the policy instead, so nothing is ever registered or queried.
            rvps_config: Default::default(),
            // The default leaves `signer: None`, which makes the AS mint an ephemeral P-256
            // key and publish its public JWK in each token header. That is what lets the
            // verifier skip trust material entirely; see `CocoBuiltinVerifier`.
            attestation_token_broker: EarTokenConfiguration::default(),
            verifier_config,
            storage_backend: StorageBackendConfig {
                storage_type: KeyValueStorageType::Memory,
                backends: Default::default(),
            },
        };

        let storage_provider = KvStorageProvider::new(config.storage_backend.clone());

        let mut attestation_service = Box::new(
            AttestationService::new(config, storage_provider)
                .await
                .map_err(|e| Error::CocoBuiltinAsCreateFailed(Arc::new(e)))?,
        );

        for (tee_class, policy) in policies {
            let policy_id = format!("{policy_id}_{tee_class}");
            // `set_policy` decodes with URL_SAFE_NO_PAD; standard base64 fails here.
            attestation_service
                .set_policy(policy_id.clone(), URL_SAFE_NO_PAD.encode(policy))
                .await
                .map_err(|e| Error::CocoBuiltinAsSetPolicyFailed {
                    policy_id,
                    source: Arc::new(e),
                })?;
        }

        Ok(Self {
            attestation_service,
            policy_id,
        })
    }

    pub async fn new_verifier(
        &self,
    ) -> Result<crate::tee::coco::verifier::coco_builtin::CocoBuiltinVerifier> {
        crate::tee::coco::verifier::coco_builtin::CocoBuiltinVerifier::new(std::slice::from_ref(
            &self.policy_id,
        ))
        .await
    }

    fn hash_algo_to_as(hash_algo: AttestationServiceHashAlgo) -> HashAlgorithm {
        match hash_algo {
            AttestationServiceHashAlgo::Sha256 => HashAlgorithm::Sha256,
            AttestationServiceHashAlgo::Sha384 => HashAlgorithm::Sha384,
            AttestationServiceHashAlgo::Sha512 => HashAlgorithm::Sha512,
        }
    }
}

#[async_trait::async_trait]
impl GenericConverter for CocoBuiltinConverter {
    type InEvidence = CocoEvidence;
    type OutEvidence = CocoAsToken;
    type Nonce = CoCoNonce;

    async fn convert(&self, in_evidence: &Self::InEvidence) -> Result<Self::OutEvidence> {
        let runtime_data_hash_algorithm = Self::hash_algo_to_as(AttestationServiceHashAlgo::from(
            in_evidence.get_aa_runtime_data_hash_algo(),
        ));
        // Held as the raw JSON rather than a `RuntimeData`, which is not `Clone`, so each
        // request below can be given its own copy.
        let runtime_data: serde_json::Value =
            serde_json::from_str(in_evidence.aa_runtime_data_ref())
                .map_err(Error::ParseRuntimeDataJsonFailed)?;

        let evidence = serde_json::from_slice(in_evidence.aa_evidence_ref())
            .map_err(Error::CocoBuiltinAsParseEvidenceJsonFailed)?;

        let verification_requests = std::iter::once(VerificationRequest {
            evidence,
            tee: *in_evidence.get_tee_type(),
            runtime_data: Some(RuntimeData::Structured(runtime_data.clone())),
            runtime_data_hash_algorithm,
            init_data: None,
        })
        // The same runtime data has to ride along with every additional-evidence request:
        // upstream's NVIDIA verifier bails outright when its report data is absent.
        .chain(
            convert_additional_evidence(in_evidence)?
                .into_iter()
                .map(|(tee, evidence)| VerificationRequest {
                    evidence,
                    tee,
                    runtime_data: Some(RuntimeData::Structured(runtime_data.clone())),
                    runtime_data_hash_algorithm,
                    init_data: None,
                }),
        )
        .collect::<Vec<_>>();

        let token = self
            .attestation_service
            .evaluate(verification_requests, vec![self.policy_id.clone()])
            .await
            .map_err(|e| Error::CocoBuiltinAsEvaluateFailed(Arc::new(e)))?;

        CocoAsToken::new(token)
    }

    async fn get_nonce(&self) -> Result<Self::Nonce> {
        let mut buf = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut buf);
        Ok(CoCoNonce::Jwt(URL_SAFE_NO_PAD.encode(buf)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRIVIAL_POLICY: &str = r#"package policy
import rego.v1
default hardware := 97
default executables := 33
default configuration := 36
"#;

    fn policies() -> TeeClassPolicies {
        BTreeMap::from([
            ("cpu".to_string(), TRIVIAL_POLICY.to_string()),
            ("gpu".to_string(), TRIVIAL_POLICY.to_string()),
        ])
    }

    async fn converter(policy_id: &str) -> CocoBuiltinConverter {
        CocoBuiltinConverter::new(policy_id, &policies(), None)
            .await
            .expect("builtin converter should construct with in-memory storage")
    }

    /// The broker looks a policy up as `{policy_id}_{tee_class}`, so installing it under the
    /// bare id would silently fall through to the built-in default.
    #[tokio::test]
    async fn policies_are_installed_per_tee_class() {
        let converter = converter("tng_test").await;

        let installed = converter
            .attestation_service
            .list_policies()
            .await
            .expect("listing policies should succeed");

        assert!(installed.contains(&"tng_test_cpu".to_string()));
        assert!(installed.contains(&"tng_test_gpu".to_string()));
        assert!(!installed.contains(&"tng_test".to_string()));
    }

    /// `set_policy` decodes with URL_SAFE_NO_PAD; encoding with the standard alphabet would
    /// either fail or store the wrong bytes.
    #[tokio::test]
    async fn installed_policy_round_trips() {
        let converter = converter("tng_test").await;

        let stored = converter
            .attestation_service
            .get_policy("tng_test_cpu".to_string())
            .await
            .expect("stored policy should be readable back");

        assert_eq!(stored, TRIVIAL_POLICY);
    }

    /// Installing our own policies must not disturb the four built-in defaults, which are
    /// registered at construction with `overwrite: false`.
    #[tokio::test]
    async fn builtin_default_policies_are_left_alone() {
        let converter = converter("tng_test").await;

        let installed = converter
            .attestation_service
            .list_policies()
            .await
            .expect("listing policies should succeed");

        assert!(installed.contains(&"default_cpu".to_string()));
        assert!(installed.contains(&"default_gpu".to_string()));
    }

    #[tokio::test]
    async fn nonce_is_fresh_and_url_safe() {
        let converter = converter("tng_test").await;

        let CoCoNonce::Jwt(first) = converter.get_nonce().await.unwrap();
        let CoCoNonce::Jwt(second) = converter.get_nonce().await.unwrap();

        assert_ne!(first, second, "each nonce should be freshly generated");
        assert_eq!(
            URL_SAFE_NO_PAD.decode(&first).unwrap().len(),
            NONCE_LEN,
            "nonce should decode to {NONCE_LEN} bytes"
        );
        assert!(
            !first.contains('+') && !first.contains('/') && !first.contains('='),
            "nonce should use the URL-safe unpadded alphabet, got {first}"
        );
    }
}
