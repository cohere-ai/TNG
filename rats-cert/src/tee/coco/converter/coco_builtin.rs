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

    /// Handed to the verifier this converter derives; see [`CommonCocoVerifier`].
    ///
    /// [`CommonCocoVerifier`]: crate::tee::coco::verifier::common::CommonCocoVerifier
    required_tee_classes: Vec<String>,
}

impl CocoBuiltinConverter {
    pub async fn new(
        policies: &TeeClassPolicies,
        verifier_config: Option<serde_json::Value>,
        required_tee_classes: &[String],
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
            required_tee_classes: required_tee_classes.to_owned(),
        })
    }

    /// The content-addressed id the installed policies were registered under.
    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }

    pub async fn new_verifier(
        &self,
    ) -> Result<crate::tee::coco::verifier::coco_builtin::CocoBuiltinVerifier> {
        crate::tee::coco::verifier::coco_builtin::CocoBuiltinVerifier::new(
            std::slice::from_ref(&self.policy_id),
            &self.required_tee_classes,
        )
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
        CocoBuiltinConverter::new(&policies(), None, &[])
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
        let err = match CocoBuiltinConverter::new(&policies, None, &[]).await {
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

/// Scaffolding shared by the hardware-backed end-to-end tests below.
///
/// Each TEE gets its own module, because each needs a different verifier feature and a different
/// policy, but the way evidence is requested and the service is built is identical.
#[cfg(all(
    test,
    feature = "attester-coco",
    any(feature = "coco-builtin-as-tdx", feature = "coco-builtin-as-azsnp")
))]
mod hardware_support {
    use super::*;
    use crate::tee::claims::Claims;
    use crate::tee::coco::attester::CocoAttester;
    use crate::tee::{GenericAttester as _, ReportData};

    pub(super) const AA_ADDR: &str =
        "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock";

    /// A syntactically complete policy that asserts nothing, so every claim keeps its
    /// non-affirming default.
    pub(super) const INERT_POLICY: &str = r#"package policy
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

    /// Affirms on the mere presence of GPU evidence, pinning nothing.
    ///
    /// The mirror image of the GPU module's `CPU_PRESENCE_POLICY`, and installed for the same
    /// reason: these modules are about the CPU class, but the broker demands a policy for every
    /// class the evidence carries. Without this, a host that attests a GPU as well as a CPU would
    /// fail evaluation outright, before the CPU policy under test was ever consulted.
    pub(super) const GPU_PRESENCE_POLICY: &str = r#"package policy
import rego.v1

default hardware := 97
default executables := 33
default configuration := 36

gpu := input.nvidia

hardware := 2 if gpu

executables := 3 if gpu

configuration := 2 if gpu

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

    /// Installs the CPU policy under test, plus a permissive GPU policy so the same tests run on
    /// GPU and GPU-less hosts alike. A policy is only consulted for a class the evidence actually
    /// carries, so the GPU one costs nothing on a host without a device.
    pub(super) async fn converter_with(policy: String) -> CocoBuiltinConverter {
        converter_with_policies(
            BTreeMap::from([
                ("cpu".to_owned(), policy),
                ("gpu".to_owned(), GPU_PRESENCE_POLICY.to_owned()),
            ]),
            &[],
        )
        .await
    }

    /// For hosts that attest devices as well as a CPU. Every TEE class present in the evidence
    /// needs a policy of its own: the broker looks one up per class, and evaluation fails
    /// outright if the class has none.
    pub(super) async fn converter_with_policies(
        policies: TeeClassPolicies,
        required_tee_classes: &[String],
    ) -> CocoBuiltinConverter {
        CocoBuiltinConverter::new(&policies, None, required_tee_classes)
            .await
            .expect("converter should construct")
    }

    /// Stands in for what TNG binds in a real handshake: the nonce and the hash of the
    /// certificate key. Any map works, as long as the same one is used to request the evidence
    /// and to verify the token.
    pub(super) fn report_data(nonce: &str) -> ReportData {
        let mut claims = Claims::new();
        claims.insert("nonce".to_owned(), serde_json::json!(nonce));
        ReportData::Claims(claims)
    }

    pub(super) async fn evidence_for(report_data: &ReportData) -> CocoEvidence {
        CocoAttester::new(AA_ADDR)
            .expect("attester should be constructible")
            .get_evidence(report_data)
            .await
            .expect("the attestation agent should produce evidence")
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

    use super::hardware_support::*;
    use super::*;
    use crate::tee::GenericVerifier as _;

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

/// End-to-end tests that run real Azure SEV-SNP evidence from this host through the in-process
/// service.
///
/// Azure confidential VMs run SEV-SNP under a paravisor in vTOM mode, so the guest has no
/// `/dev/sev-guest` to ask for a report. Evidence instead comes from the vTPM: the paravisor puts
/// the SNP report in an NV index, and the guest wraps it in a TPM quote that binds the report data
/// as the quote nonce. That is a different attester and a different verifier from raw SEV-SNP,
/// which is why this is gated on `coco-builtin-as-azsnp` and not `coco-builtin-as-snp`.
///
/// Unlike the TDX path, verification here is fully offline: the attester fetches the VCEK and
/// ships it inside the evidence, and the verifier checks it against AMD root and intermediate
/// certificates compiled into the verifier, so nothing has to reach a collateral service.
///
/// Requirements to run: an Azure SEV-SNP confidential VM, the TPM2 TSS libraries
/// (`libtss2-dev`), and an attestation agent built with the `az-cvm-vtpm` attester, reachable on
/// the socket below. The agent needs the vTPM, so it and these tests run as root.
#[cfg(all(test, feature = "coco-builtin-as-azsnp", feature = "attester-coco"))]
mod azsnp_e2e_tests {
    use serial_test::serial;

    use super::hardware_support::*;
    use super::*;
    use crate::tee::GenericVerifier as _;

    /// The SNP launch measurement this host reports, base64 as the verifier emits it.
    ///
    /// On an Azure CVM in vTOM mode this measures the paravisor launch context, not the guest OS
    /// disk: the guest boot chain is measured into the vTPM PCRs instead. So this value survives
    /// swapping the guest image and only moves when Azure updates the paravisor, which makes it
    /// the SEV-SNP counterpart of pinning `mr_seam` on the TDX side.
    const PARAVISOR_MEASUREMENT_ALLOWED: [&str; 1] =
        ["qnydpVwThuWxZTsSWXi+2ns/laha6w+d2723g84FaijJ0CHaI5w0pYw6ZXZUJw7v"];

    /// A measurement no SNP platform will report: 48 zero bytes, the right shape but not a value
    /// any launch can produce.
    const PARAVISOR_MEASUREMENT_WRONG: [&str; 1] =
        ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"];

    /// Builds an Azure SEV-SNP policy, with the accepted measurements passed in so a test can
    /// substitute one the hardware cannot report.
    ///
    /// This deliberately pins nothing that depends on the guest image. The point of these tests is
    /// that a golden measurement is compared at all and that the comparison decides the outcome;
    /// deciding which measurements a real deployment should accept belongs in the policy repo, not
    /// here.
    ///
    /// Note the claims are reached through `input["az-snp-vtpm"]`. The attestation service nests a
    /// verifier's claims under the serde name of its TEE type, and for this one that name contains
    /// hyphens, so the dotted form used by the TDX policy is not available here. Writing
    /// `input.azsnpvtpm` compiles but matches nothing, which fails closed and so looks like a
    /// rejected appraisal rather than a broken policy.
    fn azsnp_policy(measurement_allowed: &[&str]) -> String {
        let allowed = serde_json::to_string(measurement_allowed).expect("allowlist serializes");

        format!(
            r#"package policy
import rego.v1

default hardware := 97
default executables := 33
default configuration := 36

measurement_allowed := {allowed}

snp := input["az-snp-vtpm"]

# The launch measurement has to be one we accept. Under vTOM this is the paravisor's measurement,
# which is why it is the only golden value here: it does not move when the guest image changes.
hardware := 2 if {{
	snp

	snp.measurement in measurement_allowed
}}

# The guest measurements a real policy would pin live in the vTPM PCRs, and they change every time
# the guest image is rebuilt, so they are deliberately not asserted. Asserting only that SNP
# evidence is present keeps this test about the attestation path.
executables := 3 if {{
	snp
}}

# Debug being allowed would let the host read guest memory. This is set by the host from the VM's
# launch policy rather than by the guest image, so it is stable across image changes, and it
# mirrors the `td_attributes.debug` check in the TDX policy above.
configuration := 2 if {{
	snp

	snp.policy_debug_allowed == "false"
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

    /// Real hardware evidence all the way to an accepted token.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn real_azure_snp_evidence_is_affirmed() {
        let converter = converter_with(azsnp_policy(&PARAVISOR_MEASUREMENT_ALLOWED)).await;
        let verifier = converter.new_verifier().await.expect("verifier");
        let report_data = report_data("dGVzdC1ub25jZS1hZmZpcm0");

        let token = converter
            .convert(&evidence_for(&report_data).await)
            .await
            .expect("the in-process service should verify this host's SNP report and TPM quote");

        verifier
            .verify_evidence(&token, &report_data)
            .await
            .expect("a token appraised under an affirming policy should verify");
    }

    /// Without this, an affirming result proves only that the pipeline runs, not that the policy
    /// decides anything. The measurement is the only difference between this test and the one
    /// above.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn a_policy_with_an_unmatched_measurement_is_rejected() {
        let converter = converter_with(azsnp_policy(&PARAVISOR_MEASUREMENT_WRONG)).await;
        let verifier = converter.new_verifier().await.expect("verifier");
        let report_data = report_data("dGVzdC1ub25jZS1tZWFz");

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

    /// A policy that leaves its claims at the defaults must fail closed.
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

    /// The freshness guarantee. On this path the nonce is bound twice over, as the TPM quote nonce
    /// and as the SNP report data, and the verifier checks both before any claim is emitted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn a_token_bound_to_another_nonce_is_rejected() {
        let converter = converter_with(azsnp_policy(&PARAVISOR_MEASUREMENT_ALLOWED)).await;
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

    /// Prints only the two platform values the policy above asserts on, so the measurement can be
    /// re-pinned after Azure updates the paravisor. These are golden values of the same kind
    /// already committed to this repo's policies, not evidence or key material.
    ///
    /// Ignored so it never runs as part of the suite: `--ignored --nocapture` to use it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    #[ignore = "diagnostic, reports this host's expected measurement rather than asserting"]
    async fn print_expected_platform_values() {
        let converter = converter_with(INERT_POLICY.to_owned()).await;
        let report_data = report_data("dGVzdC1ub25jZS1kdW1w");

        let token = converter
            .convert(&evidence_for(&report_data).await)
            .await
            .expect("conversion should succeed");

        let payload = token
            .as_str()
            .split('.')
            .nth(1)
            .expect("a JWT should have a payload segment");
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .expect("the payload should be base64url");
        let payload: serde_json::Value =
            serde_json::from_slice(&payload).expect("the payload should be JSON");

        // Searched for by name rather than by path, so this does not depend on how the EAR token
        // happens to nest a verifier's claims.
        fn find<'a>(value: &'a serde_json::Value, key: &str) -> Option<&'a serde_json::Value> {
            match value {
                serde_json::Value::Object(map) => map
                    .get(key)
                    .or_else(|| map.values().find_map(|nested| find(nested, key))),
                serde_json::Value::Array(items) => items.iter().find_map(|item| find(item, key)),
                _ => None,
            }
        }

        for field in ["measurement", "policy_debug_allowed"] {
            println!(
                "PLATFORM_VALUE {field} = {}",
                find(&payload, field).unwrap_or(&serde_json::Value::Null)
            );
        }
    }
}

/// End-to-end tests that run real NVIDIA GPU evidence from this host through the in-process
/// service.
///
/// A GPU is never attested on its own. The agent returns the CPU's evidence plus a map of
/// *additional* evidence per device, and the converter turns each entry into its own verification
/// request bound to the same runtime data. The service appraises each request under the policy for
/// its TEE class and emits one EAR submodule per device, so a token from this host carries both a
/// `cpu0` and a `gpu0` appraisal, and `CommonCocoVerifier` requires every submodule to be
/// affirming. That is why this module needs a CPU verifier feature alongside the NVIDIA one, and
/// why a GPU host must be configured with a `gpu` policy: the broker looks a policy up per class
/// and evaluation fails outright when the class has none.
///
/// Verification is local and fully offline. Upstream's NVIDIA verifier defaults to `Local`, which
/// checks the SPDM attestation report against the device certificate chain carried inside the
/// evidence and binds the report to the nonce, reaching neither NRAS nor the RIM service. Local
/// mode deliberately does no reference-value comparison of its own: it reports what the device
/// measured and leaves the golden-value check to the policy, which is the split this whole design
/// relies on.
///
/// Requirements to run: an NVIDIA Hopper GPU in confidential-compute mode (local verification
/// refuses other architectures), an agent built with the `nvidia` attester in addition to a CPU
/// one, and `libnvat` available to that agent. The agent needs the GPU and the vTPM, so it and
/// these tests run as root.
#[cfg(all(
    test,
    feature = "coco-builtin-as-nvidia",
    feature = "attester-coco",
    any(feature = "coco-builtin-as-azsnp", feature = "coco-builtin-as-tdx")
))]
mod nvidia_e2e_tests {
    use serial_test::serial;

    use super::hardware_support::*;
    use super::*;
    use crate::tee::GenericVerifier as _;

    /// The measurement registers this host's GPU reports, as index to hex digest.
    ///
    /// Unlike a guest measurement these describe GPU firmware and VBIOS, so they are independent
    /// of the guest image and only move when the GPU firmware is updated. Which registers a real
    /// deployment should pin, and to what, is a question for the policy repo; the point here is
    /// that a golden value is compared at all and that the comparison decides the outcome.
    ///
    /// The device reports 64 registers, most of them zero. A representative few are pinned rather
    /// than all of them, because the aim is to exercise the comparison, not to describe an
    /// acceptable GPU.
    ///
    /// Re-pin with the `print_gpu_appraisal` diagnostic below.
    const GOLDEN_MEASUREMENTS: &str = r#"{
	"2": "8048dfd18fe229bf16eb9d30cca0f11a24dafe6eb731de1462984645a0b189b77c4e4e17de727a5e19e3d07de51da338",
	"3": "3ef2c048688f734018cb8a52ef0e445d09b2705d707e0183de62ffda1d4caf60bfee15c66665c45eb40e73397d353a42",
	"4": "73bbf35822549e28ba8fb2671fb7b58f46424a0069205b3ecf1d0fa762adef90b538cc9d692eb5c050147f2f1e8214ab"
}"#;

    /// A digest no GPU will report: 48 zero bytes, the right shape but not a value any firmware
    /// measures. Pinned at a register the device does populate, so the comparison actually runs
    /// instead of failing for want of the register.
    const WRONG_MEASUREMENTS: &str = r#"{
	"2": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
}"#;

    /// The VBIOS this GPU reports. Device firmware rather than anything the guest controls, so like
    /// the measurements above it survives a guest image change and only moves when the VBIOS does.
    const GOLDEN_VBIOS_VERSION: &str = "96.00.9f.00.04";

    /// Affirms on the mere presence of CPU evidence, pinning nothing.
    ///
    /// These tests are about the GPU class, and the CPU class already has its own modules above
    /// with real golden values. Keeping this policy free of host-specific values is what lets the
    /// same GPU tests run on an Azure SEV-SNP host and a TDX one.
    const CPU_PRESENCE_POLICY: &str = r#"package policy
import rego.v1

default hardware := 97
default executables := 33
default configuration := 36

cpu_evidence_present if input["az-snp-vtpm"]

cpu_evidence_present if input.tdx

hardware := 2 if cpu_evidence_present

executables := 3 if cpu_evidence_present

configuration := 2 if cpu_evidence_present

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

    /// Builds a GPU policy, with the accepted measurements passed in so a test can substitute ones
    /// the device cannot report.
    ///
    /// The claims arrive under `input.nvidia`, the serde name of the evidence's TEE type, even
    /// though the TEE *class* this policy is installed under is `gpu`.
    fn gpu_policy(golden_measurements: &str) -> String {
        format!(
            r#"package policy
import rego.v1

default hardware := 97
default executables := 33
default configuration := 36

golden_measurements := {golden_measurements}

gpu := input.nvidia

# Local verification only supports Hopper, so a non-Hopper architecture here would mean the
# claims came from somewhere other than the verifier we think we are running.
hardware := 2 if {{
	gpu
	gpu.arch == "Hopper"
}}

# Every pinned register has to match what the device reported. A register absent from the
# evidence makes the comparison undefined, so `every` fails closed rather than skipping it.
# The count guard matters: `every` over an empty set is vacuously true, so without it an empty
# golden map would affirm everything.
executables := 3 if {{
	gpu
	count(golden_measurements) > 0
	every index, digest in golden_measurements {{
		gpu.measurements[index] == digest
	}}
}}

# The device's own firmware version, which is the closest thing on this path to the
# host-controlled configuration the CPU policies assert on. The driver version is also reported
# here but is deliberately not pinned: it comes from the guest image.
configuration := 2 if {{
	gpu
	gpu.config.vbios_version == "{GOLDEN_VBIOS_VERSION}"
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

    async fn converter_with_gpu_policy(
        gpu_policy: String,
        required_tee_classes: &[String],
    ) -> CocoBuiltinConverter {
        converter_with_policies(
            BTreeMap::from([
                ("cpu".to_owned(), CPU_PRESENCE_POLICY.to_owned()),
                ("gpu".to_owned(), gpu_policy),
            ]),
            required_tee_classes,
        )
        .await
    }

    fn payload_of(token: &CocoAsToken) -> serde_json::Value {
        let payload = token
            .as_str()
            .split('.')
            .nth(1)
            .expect("a JWT should have a payload segment");
        let payload = URL_SAFE_NO_PAD
            .decode(payload)
            .expect("the payload should be base64url");

        serde_json::from_slice(&payload).expect("the payload should be JSON")
    }

    fn submodule_names(token: &CocoAsToken) -> Vec<String> {
        payload_of(token)
            .pointer("/submods")
            .and_then(|submods| submods.as_object())
            .expect("an EAR token should carry submodules")
            .keys()
            .cloned()
            .collect()
    }

    /// Real GPU evidence all the way to an accepted token.
    ///
    /// The submodule assertion is what keeps this honest. Without it the test would pass on a host
    /// whose agent returned no device evidence at all, because the CPU appraisal alone would
    /// affirm and the GPU policy would simply never be consulted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn real_gpu_evidence_is_affirmed() {
        let converter = converter_with_gpu_policy(gpu_policy(GOLDEN_MEASUREMENTS), &[]).await;
        let verifier = converter.new_verifier().await.expect("verifier");
        let report_data = report_data("dGVzdC1ub25jZS1ncHUtYWZmaXJt");

        let token = converter
            .convert(&evidence_for(&report_data).await)
            .await
            .expect("the in-process service should verify this host's GPU attestation report");

        let submodules = submodule_names(&token);
        assert!(
            submodules.iter().any(|name| name == "gpu0"),
            "the token must carry a GPU appraisal, got submodules {submodules:?}"
        );

        verifier
            .verify_evidence(&token, &report_data)
            .await
            .expect("a token appraised under an affirming policy should verify");
    }

    /// Swapping in digests the GPU cannot report has to flip the outcome, and it has to be the GPU
    /// appraisal that fails: the error names the submodule, so this also rules out the CPU
    /// appraisal accidentally standing in for the GPU one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn a_gpu_policy_with_unmatched_measurements_is_rejected() {
        let converter = converter_with_gpu_policy(gpu_policy(WRONG_MEASUREMENTS), &[]).await;
        let verifier = converter.new_verifier().await.expect("verifier");
        let report_data = report_data("dGVzdC1ub25jZS1ncHUtbWVhcw");

        let token = converter
            .convert(&evidence_for(&report_data).await)
            .await
            .expect("evidence is still valid, only the appraisal should fail");

        let err = verifier
            .verify_evidence(&token, &report_data)
            .await
            .expect_err("unmatched GPU measurements must not be affirmed");

        match err {
            Error::EarStatusNotAffirming { tee_type, .. } => assert_eq!(
                tee_type, "gpu0",
                "the GPU appraisal should be the one that fails"
            ),
            other => panic!("expected a non-affirming GPU appraisal, got {other:?}"),
        }
    }

    /// A GPU policy that leaves its claims at the defaults must fail closed, which is what makes an
    /// ungenerated or truncated GPU policy safe.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn a_gpu_policy_asserting_nothing_is_rejected() {
        let converter = converter_with_gpu_policy(INERT_POLICY.to_owned(), &[]).await;
        let verifier = converter.new_verifier().await.expect("verifier");
        let report_data = report_data("dGVzdC1ub25jZS1ncHUtaW5lcnQ");

        let token = converter
            .convert(&evidence_for(&report_data).await)
            .await
            .expect("conversion should succeed regardless of the appraisal");

        let err = verifier
            .verify_evidence(&token, &report_data)
            .await
            .expect_err("a GPU policy asserting nothing must not affirm");

        match err {
            Error::EarStatusNotAffirming { tee_type, .. } => assert_eq!(
                tee_type, "gpu0",
                "the GPU appraisal should be the one that fails"
            ),
            other => panic!("expected a non-affirming GPU appraisal, got {other:?}"),
        }
    }

    /// Requiring the classes this host does present has to be satisfied by it.
    ///
    /// This is the verifier-side counterpart to the GPU policy: the policy constrains a GPU that
    /// shows up, while this insists one shows up at all.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn requiring_the_classes_this_host_presents_is_satisfied() {
        let required = ["cpu".to_owned(), "gpu".to_owned()];
        let converter = converter_with_gpu_policy(gpu_policy(GOLDEN_MEASUREMENTS), &required).await;
        let verifier = converter.new_verifier().await.expect("verifier");
        let report_data = report_data("dGVzdC1ub25jZS1yZXF1aXJlZA");

        let token = converter
            .convert(&evidence_for(&report_data).await)
            .await
            .expect("conversion should succeed");

        verifier
            .verify_evidence(&token, &report_data)
            .await
            .expect("this host attests both a CPU and a GPU, so both requirements hold");
    }

    /// Requiring a class the host cannot present must be refused, which is the case that matters:
    /// a peer that quietly omits a device it was supposed to attest is exactly what this check
    /// exists to catch, and no policy can catch it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn requiring_a_class_the_host_cannot_present_is_rejected() {
        // NVLink switches, which a single-GPU host has none of.
        let required = ["switch".to_owned()];
        let converter = converter_with_gpu_policy(gpu_policy(GOLDEN_MEASUREMENTS), &required).await;
        let verifier = converter.new_verifier().await.expect("verifier");
        let report_data = report_data("dGVzdC1ub25jZS1zd2l0Y2g");

        let token = converter
            .convert(&evidence_for(&report_data).await)
            .await
            .expect("the evidence is valid; only the class requirement should fail");

        let err = verifier
            .verify_evidence(&token, &report_data)
            .await
            .expect_err("a class the host never attested must not be treated as satisfied");

        match err {
            Error::MissingRequiredTeeClass { tee_class, present } => {
                assert_eq!(tee_class, "switch");
                assert!(
                    present.contains(&"gpu".to_owned()),
                    "the classes actually attested should be reported, got {present:?}"
                );
            }
            other => panic!("expected a missing required class, got {other:?}"),
        }
    }

    /// Prints the GPU claims exactly as the policy sees them, so the golden measurements above can
    /// be pinned or re-pinned. These are device firmware measurements, the same kind of golden
    /// value already committed to this repo's policies, not evidence or key material.
    ///
    /// Ignored so it never runs as part of the suite: `--ignored --nocapture` to use it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    #[ignore = "diagnostic, reports this host's GPU claims rather than asserting"]
    async fn print_gpu_appraisal() {
        let converter = converter_with_gpu_policy(INERT_POLICY.to_owned(), &[]).await;
        let report_data = report_data("dGVzdC1ub25jZS1ncHUtZHVtcA");

        let token = converter
            .convert(&evidence_for(&report_data).await)
            .await
            .expect("conversion should succeed");

        println!("SUBMODULES {:?}", submodule_names(&token));

        let payload = payload_of(&token);
        let claims = payload
            .pointer("/submods/gpu0/ear.veraison.annotated-evidence")
            .expect("the GPU submodule should carry annotated evidence");

        println!(
            "GPU_CLAIMS {}",
            serde_json::to_string_pretty(claims).expect("claims should serialize")
        );
    }
}
