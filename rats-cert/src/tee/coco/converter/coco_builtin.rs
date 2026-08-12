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
use crate::tee::coco::converter::policy::{self, TeeClassPolicies};
use crate::tee::coco::converter::{convert_additional_evidence, CoCoNonce};
use crate::tee::GenericConverter;

/// Length of the locally generated nonce, in bytes.
///
/// Upstream has no `generate_challenge`, so TNG mints the nonce itself. That is not a
/// downgrade: TNG is already the nonce authority in background-check mode, and the binding is
/// checked against `runtime_data` by `CommonCocoVerifier` rather than by the AS.
const NONCE_LEN: usize = 32;

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
        policies: &TeeClassPolicies,
        verifier_config: Option<serde_json::Value>,
    ) -> Result<Self> {
        // Derived from the policy contents rather than configured, so the id recorded in every
        // token names exactly what was enforced, and the verifier can arrive at the same id from
        // the same policies without either side having to agree on a label.
        let policy_id = policy::derive_policy_id(policies);

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
            policy::validate(tee_class, policy)?;

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

    /// The content-addressed id the installed policies were registered under.
    pub fn policy_id(&self) -> &str {
        &self.policy_id
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

    /// Complete enough to pass validation, while affirming nothing.
    const TRIVIAL_POLICY: &str = r#"package policy
import rego.v1
default hardware := 97
default executables := 33
default configuration := 36
trust_claims := {
	"executables": executables,
	"hardware": hardware,
	"configuration": configuration,
	"file-system": 0,
	"instance-identity": 0,
	"runtime-opaque": 0,
	"storage-opaque": 0,
	"sourced-data": 0,
}
"#;

    fn policies() -> TeeClassPolicies {
        BTreeMap::from([
            ("cpu".to_string(), TRIVIAL_POLICY.to_string()),
            ("gpu".to_string(), TRIVIAL_POLICY.to_string()),
        ])
    }

    async fn converter() -> CocoBuiltinConverter {
        CocoBuiltinConverter::new(&policies(), None)
            .await
            .expect("builtin converter should construct with in-memory storage")
    }

    /// The broker looks a policy up as `{policy_id}_{tee_class}`, so installing it under the
    /// bare id would silently fall through to the built-in default.
    #[tokio::test]
    async fn policies_are_installed_per_tee_class() {
        let converter = converter().await;
        let policy_id = converter.policy_id();

        let installed = converter
            .attestation_service
            .list_policies()
            .await
            .expect("listing policies should succeed");

        assert!(installed.contains(&format!("{policy_id}_cpu")));
        assert!(installed.contains(&format!("{policy_id}_gpu")));
        assert!(!installed.contains(&policy_id.to_string()));
    }

    /// `set_policy` decodes with URL_SAFE_NO_PAD; encoding with the standard alphabet would
    /// either fail or store the wrong bytes.
    #[tokio::test]
    async fn installed_policy_round_trips() {
        let converter = converter().await;

        let stored = converter
            .attestation_service
            .get_policy(format!("{}_cpu", converter.policy_id()))
            .await
            .expect("stored policy should be readable back");

        assert_eq!(stored, TRIVIAL_POLICY);
    }

    /// Installing our own policies must not disturb the four built-in defaults, which are
    /// registered at construction with `overwrite: false`.
    #[tokio::test]
    async fn builtin_default_policies_are_left_alone() {
        let converter = converter().await;

        let installed = converter
            .attestation_service
            .list_policies()
            .await
            .expect("listing policies should succeed");

        assert!(installed.contains(&"default_cpu".to_string()));
        assert!(installed.contains(&"default_gpu".to_string()));
    }

    /// An invalid policy has to stop construction: the service stores policy bytes without parsing
    /// them, so a policy that only fails at evaluation would take down handshakes instead.
    #[tokio::test]
    async fn invalid_policy_fails_construction() {
        let policies =
            TeeClassPolicies::from([("cpu".to_string(), "package policy\nnot rego".to_string())]);

        // Matched rather than `expect_err`, which would need `Debug` on the converter.
        let err = match CocoBuiltinConverter::new(&policies, None).await {
            Ok(_) => panic!("an unparseable policy should fail construction"),
            Err(err) => err,
        };

        assert!(
            matches!(err, Error::CocoBuiltinAsPolicyInvalid { .. }),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn nonce_is_fresh_and_url_safe() {
        let converter = converter().await;

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

/// End-to-end tests that run real TDX evidence from this host through the in-process service.
///
/// Everything above this point tests the service in isolation, without evidence. These are what
/// establish that the whole path works: hardware evidence to attestation agent, evidence to the
/// in-process attestation service, quote verification against Intel's collateral, policy
/// appraisal, EAR token minting under an ephemeral key, and verification of that token.
///
/// Gated on the verifier feature rather than skipping at runtime. The previous builtin
/// implementation's equivalent tests caught the "feature `tdx-verifier` is not enabled" error
/// and returned success, so they passed on every machine that could not actually run them, which
/// is indistinguishable from having no coverage at all.
///
/// Requirements to run: TDX hardware, the Intel DCAP quote verification library
/// (`libsgx-dcap-quote-verify-dev`), the attestation agent socket (owned by root, so these need
/// `sudo -E`), and outbound access to Intel's PCS. This revision of the verifier fetches
/// collateral itself over HTTPS and fails the verification if it cannot, so unlike the
/// containerized service there is no quote provider library config to set.
#[cfg(all(test, feature = "coco-builtin-as-tdx", feature = "attester-coco"))]
mod tdx_e2e_tests {
    use serial_test::serial;

    use super::*;
    use crate::tee::claims::Claims;
    use crate::tee::coco::attester::CocoAttester;
    use crate::tee::{GenericAttester as _, GenericVerifier as _, ReportData};

    const AA_ADDR: &str =
        "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock";

    /// Accepted TDX module measurements, the same pair the containerized attestation service is
    /// handed through its reference value store in `.github/test-deps`.
    ///
    /// Inlined rather than resolved with `query_reference_value`, which is the point of the
    /// design: the builtin service runs with an empty RVPS, so every reference value lookup
    /// returns nothing and any rule built on one fails.
    const MR_SEAM_ALLOWED: [&str; 2] = [
        "489e585f1c54bc5a02066c8c6ec21619ff0334ec6f21e07e2a35202c59183789c8057e7d97dd591bb08314b185819e72",
        "ab62561a173acbd18ee50ff37750db44184c6cf5e886df74247cc575e163b04c34b9e18374757c235affa614d4127f6b",
    ];

    /// A measurement no TDX module will ever report, used to show the allowlist is load-bearing.
    const MR_SEAM_WRONG: [&str; 1] = [
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    ];

    /// Builds a TDX policy asserting the same properties the shared `default_cpu.rego` does,
    /// with the accepted measurements passed in so a test can substitute a wrong one.
    fn tdx_policy(mr_seam_allowed: &[&str]) -> String {
        let allowed = serde_json::to_string(mr_seam_allowed).expect("allowlist should serialize");

        format!(
            r#"package policy
import rego.v1

default hardware := 97
default executables := 33
default configuration := 36

mr_seam_allowed := {allowed}

# The quote has to be a TDX quote issued by Intel's quoting enclave, carry a TDX module
# measurement we accept, and have been checked against collateral that had not expired.
hardware := 2 if {{
	input.tdx

	input.tdx.quote.header.tee_type == "81000000"
	input.tdx.quote.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607"
	input.tdx.quote.body.mr_seam in mr_seam_allowed
	input.tdx.collateral_expiration_status == "0"
}}

# The guest measurements this would pin (rtmr1/rtmr2, mr_td) are properties of the image under
# test rather than of the attestation path, and the shared policy leaves them commented out for
# the same reason. Asserting only that TDX evidence is present keeps this test from failing every
# time the test image is rebuilt.
executables := 3 if {{
	input.tdx
}}

configuration := 2 if {{
	input.tdx

	input.tdx.td_attributes.debug == false
}}

trust_claims := {{
	"executables": executables,
	"hardware": hardware,
	"configuration": configuration,
	"file-system": 0,
	"instance-identity": 0,
	"runtime-opaque": 0,
	"storage-opaque": 0,
	"sourced-data": 0,
}}
"#
        )
    }

    /// A syntactically complete policy that asserts nothing, so every claim keeps its
    /// non-affirming default.
    const INERT_POLICY: &str = r#"package policy
import rego.v1

default hardware := 97
default executables := 33
default configuration := 36

trust_claims := {
	"executables": executables,
	"hardware": hardware,
	"configuration": configuration,
	"file-system": 0,
	"instance-identity": 0,
	"runtime-opaque": 0,
	"storage-opaque": 0,
	"sourced-data": 0,
}
"#;

    async fn converter_with(policy: String) -> CocoBuiltinConverter {
        let policies = BTreeMap::from([("cpu".to_owned(), policy)]);

        CocoBuiltinConverter::new(&policies, None)
            .await
            .expect("converter should construct")
    }

    /// Stands in for what TNG binds in a real handshake: the nonce and the hash of the
    /// certificate key. Any map works, as long as the same one is used to request the evidence
    /// and to verify the token.
    fn report_data(nonce: &str) -> ReportData {
        let mut claims = Claims::new();
        claims.insert("nonce".to_owned(), serde_json::json!(nonce));
        ReportData::Claims(claims)
    }

    async fn evidence_for(report_data: &ReportData) -> CocoEvidence {
        CocoAttester::new(AA_ADDR)
            .expect("attester should be constructible")
            .get_evidence(report_data)
            .await
            .expect("the attestation agent should produce TDX evidence")
    }

    /// The one that matters: real hardware evidence all the way to an accepted token. The
    /// previous builtin implementation never had this, only a test asserting the token was
    /// rejected.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn real_tdx_evidence_is_affirmed() {
        let converter = converter_with(tdx_policy(&MR_SEAM_ALLOWED)).await;
        let verifier = converter.new_verifier().await.expect("verifier");
        let report_data = report_data("dGVzdC1ub25jZS1hZmZpcm0");

        let token = converter
            .convert(&evidence_for(&report_data).await)
            .await
            .expect("the in-process service should verify this host's TDX quote");

        verifier
            .verify_evidence(&token, &report_data)
            .await
            .expect("a token appraised under an affirming policy should verify");
    }

    /// Without this, an affirming result proves only that the pipeline runs, not that the policy
    /// decides anything. Swapping in a measurement the hardware cannot report has to flip the
    /// outcome.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn a_policy_with_an_unmatched_measurement_is_rejected() {
        let converter = converter_with(tdx_policy(&MR_SEAM_WRONG)).await;
        let verifier = converter.new_verifier().await.expect("verifier");
        let report_data = report_data("dGVzdC1ub25jZS1tcnNlYW0");

        let token = converter
            .convert(&evidence_for(&report_data).await)
            .await
            .expect("evidence is still valid, only the appraisal should fail");

        let err = verifier
            .verify_evidence(&token, &report_data)
            .await
            .expect_err("an unmatched measurement must not be affirmed");

        assert!(
            matches!(err, Error::EarStatusNotAffirming { .. }),
            "expected a non-affirming appraisal, got {err:?}"
        );
    }

    /// A policy that leaves its claims at the defaults must fail closed, which is what makes an
    /// ungenerated or truncated policy safe.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn a_policy_asserting_nothing_is_rejected() {
        let converter = converter_with(INERT_POLICY.to_owned()).await;
        let verifier = converter.new_verifier().await.expect("verifier");
        let report_data = report_data("dGVzdC1ub25jZS1pbmVydA");

        let token = converter
            .convert(&evidence_for(&report_data).await)
            .await
            .expect("conversion should succeed regardless of the appraisal");

        let err = verifier
            .verify_evidence(&token, &report_data)
            .await
            .expect_err("a policy asserting nothing must not affirm");

        assert!(
            matches!(err, Error::EarStatusNotAffirming { .. }),
            "expected a non-affirming appraisal, got {err:?}"
        );
    }

    /// The freshness guarantee: evidence is bound to the runtime data it was requested with, so a
    /// token cannot be replayed against a different nonce. This is the check that stands in for
    /// the challenge the upstream service does not provide.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn a_token_bound_to_another_nonce_is_rejected() {
        let converter = converter_with(tdx_policy(&MR_SEAM_ALLOWED)).await;
        let verifier = converter.new_verifier().await.expect("verifier");

        let token = converter
            .convert(&evidence_for(&report_data("dGVzdC1ub25jZS1vbmU")).await)
            .await
            .expect("conversion should succeed");

        let err = verifier
            .verify_evidence(&token, &report_data("dGVzdC1ub25jZS10d28"))
            .await
            .expect_err("a token bound to a different nonce must be refused");

        assert!(
            matches!(err, Error::RuntimeDataMismatch),
            "expected a runtime data mismatch, got {err:?}"
        );
    }
}
