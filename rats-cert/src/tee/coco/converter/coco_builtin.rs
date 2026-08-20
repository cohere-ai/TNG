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
    ///
    /// Names the policy set an operator chose, matching the filenames it was loaded from.
    policy_id: String,

    /// Handed to the verifier this converter derives; see [`CommonCocoVerifier`].
    ///
    /// [`CommonCocoVerifier`]: crate::tee::coco::verifier::common::CommonCocoVerifier
    required_tee_classes: Vec<String>,
}

impl CocoBuiltinConverter {
    pub async fn new(
        policy_id: &str,
        policies: &TeeClassPolicies,
        verifier_config: Option<serde_json::Value>,
        required_tee_classes: &[String],
    ) -> Result<Self> {
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
            // `set_policy` decodes with URL_SAFE_NO_PAD, which rejects both the `+` and `/` of the
            // standard alphabet and its `=` padding, so encoding with the standard engine fails.
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
            policy_id: policy_id.to_owned(),
            required_tee_classes: required_tee_classes.to_owned(),
        })
    }

    /// The id the installed policies were registered under.
    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }

    /// Derives the verifier for the tokens this converter mints.
    ///
    /// The verifier needs the signer's public key, which is generated at construction and appears
    /// nowhere in configuration, so it can only be had from the converter holding the private half.
    pub async fn new_verifier(
        &self,
    ) -> Result<crate::tee::coco::verifier::coco_builtin::CocoBuiltinVerifier> {
        let unavailable = |e: anyhow::Error| Error::CocoBuiltinAsSignerKeyUnavailable(Arc::new(e));

        // As JSON, because the service's `jsonwebtoken` is not the one the verifier reads token
        // headers with, so the two `Jwk` types cannot meet. The broker publishes the single key it
        // signs with.
        let signer_key = self
            .attestation_service
            .get_token_signer_jwks()
            .and_then(|jwks| {
                let [key] = <[_; 1]>::try_from(jwks.keys).map_err(|keys| {
                    anyhow::anyhow!("expected one signing key, got {}", keys.len())
                })?;
                Ok(serde_json::to_value(key)?)
            })
            .map_err(unavailable)?;

        crate::tee::coco::verifier::coco_builtin::CocoBuiltinVerifier::new(
            std::slice::from_ref(&self.policy_id),
            &self.required_tee_classes,
            signer_key,
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

/// Wraps `rules` in the envelope every policy needs, so only the rules differ below.
///
/// The claims a rule affirms with are AR4SI tiers: 2 to 31 affirm, and the defaults here do not.
/// A policy with no rules is therefore complete but affirms nothing, which is what the diagnostics
/// want.
///
/// Rules have to compare against values written into the policy itself. The builtin service runs
/// with an empty reference value store, so `query_reference_value` resolves to nothing and any
/// rule built on one fails.
#[cfg(test)]
fn policy(rules: &str) -> String {
    format!(
        r#"package policy
import rego.v1

default hardware := 97
default executables := 33
default configuration := 36

{rules}

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

#[cfg(test)]
mod tests {
    use super::*;

    /// Stands in for the id an operator configures; the value is arbitrary.
    const TEST_POLICY_ID: &str = "test";

    fn policies() -> TeeClassPolicies {
        BTreeMap::from([
            ("cpu".to_string(), policy("")),
            ("gpu".to_string(), policy("")),
        ])
    }

    async fn converter() -> CocoBuiltinConverter {
        CocoBuiltinConverter::new(TEST_POLICY_ID, &policies(), None, &[])
            .await
            .expect("builtin converter should construct with in-memory storage")
    }

    /// The broker looks a policy up as `{policy_id}_{tee_class}`, so installing under the bare id
    /// would leave that lookup with nothing to find. Reading one back also covers the encoding:
    /// `set_policy` decodes with URL_SAFE_NO_PAD, and a policy encoded with the standard alphabet
    /// is rejected on its padding rather than stored.
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

        let stored = converter
            .attestation_service
            .get_policy(format!("{policy_id}_cpu"))
            .await
            .expect("stored policy should be readable back");

        assert_eq!(stored, policy(""));
    }

    /// An invalid policy has to stop construction: the service stores policy bytes without parsing
    /// them, so a policy that only fails at evaluation would take down handshakes instead.
    #[tokio::test]
    async fn invalid_policy_fails_construction() {
        let policies =
            TeeClassPolicies::from([("cpu".to_string(), "package policy\nnot rego".to_string())]);

        // Matched rather than `expect_err`, which would need `Debug` on the converter.
        let err = match CocoBuiltinConverter::new(TEST_POLICY_ID, &policies, None, &[]).await {
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
/// Everything above this point tests the service in isolation, without evidence. These are what
/// establish that the whole path works: hardware to attestation agent, evidence to the in-process
/// service, verification against the platform's trust roots, policy appraisal, EAR token minting
/// under an ephemeral key, and verification of that token.
///
/// Each TEE gets its own module, because each needs a different verifier feature and a different
/// policy, but the flow is identical and so lives here. They are gated on the verifier feature
/// rather than skipped at runtime.
#[cfg(all(
    test,
    feature = "attester-coco",
    any(feature = "coco-builtin-as-tdx", feature = "coco-builtin-as-azsnp")
))]
mod hardware_support {
    use serial_test::serial;

    use super::*;
    use crate::tee::claims::Claims;
    use crate::tee::coco::attester::CocoAttester;
    use crate::tee::{GenericAttester as _, GenericVerifier as _, ReportData};

    pub(super) const AA_ADDR: &str =
        "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock";

    /// Affirms on the mere presence of GPU evidence, pinning nothing.
    ///
    /// The mirror image of the GPU module's `cpu_presence_policy`, and installed for the same
    /// reason: these modules are about the CPU class, but the broker demands a policy for every
    /// class the evidence carries. Without this, a host that attests a GPU as well as a CPU would
    /// fail evaluation outright, before the CPU policy under test was ever consulted.
    fn gpu_presence_policy() -> String {
        policy(
            r#"hardware := 2 if input.nvidia
executables := 3 if input.nvidia
configuration := 2 if input.nvidia"#,
        )
    }

    /// Installs the CPU policy under test, plus the permissive GPU policy above so the same tests
    /// run on GPU and GPU-less hosts alike.
    pub(super) async fn converter_with(cpu_policy: String) -> CocoBuiltinConverter {
        converter_with_policies(
            BTreeMap::from([
                ("cpu".to_owned(), cpu_policy),
                ("gpu".to_owned(), gpu_presence_policy()),
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
        CocoBuiltinConverter::new("test", &policies, None, required_tee_classes)
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

    /// A token minted by another instance must be refused, however well-formed its claims.
    ///
    /// This is the sole basis for `insecure_key`: the signature is checked against the key the
    /// token itself names, so without the pin a peer could sign an affirming token with a key it
    /// generated and skip attestation entirely. Reachable input, not a hypothetical, because the
    /// OHTTP client-attestation flow hands tokens to the peer and reads them back. The refusal
    /// also holds between replicas, each of which signs with its own ephemeral key.
    ///
    /// Lives here rather than beside the tests above because only a real token proves this, and
    /// the appraisal is deliberately unconditional so that any TEE's evidence will do.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn a_token_from_another_signer_is_refused() {
        let affirming = "hardware := 2\nexecutables := 3\nconfiguration := 2";
        let mine = converter_with(policy(affirming)).await;
        let theirs = converter_with(policy(affirming)).await;
        let report_data = report_data("dGVzdC1ub25jZS1zaWduZXI");

        let token = mine
            .convert(&evidence_for(&report_data).await)
            .await
            .expect("this host's evidence should convert");

        mine.new_verifier()
            .await
            .expect("verifier")
            .verify_evidence(&token, &report_data)
            .await
            .expect("a token this instance signed should verify");

        let err = theirs
            .new_verifier()
            .await
            .expect("verifier")
            .verify_evidence(&token, &report_data)
            .await
            .expect_err("a token another instance signed must not verify");

        assert!(
            matches!(err, Error::CocoBuiltinAsForeignTokenSigner),
            "got {err:?}"
        );
    }

    pub(super) fn payload_of(token: &CocoAsToken) -> serde_json::Value {
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

    /// The CPU end-to-end tests are the same flow for every TEE — request evidence from the agent,
    /// convert it, verify the token — differing only in the policy, so the flow lives here and each
    /// module below supplies its own.
    pub(super) async fn assert_evidence_is_affirmed(cpu_policy: String, nonce: &str) {
        let converter = converter_with(cpu_policy).await;
        let verifier = converter.new_verifier().await.expect("verifier");
        let report_data = report_data(nonce);

        let token = converter
            .convert(&evidence_for(&report_data).await)
            .await
            .expect("the in-process service should verify this host's evidence");

        verifier
            .verify_evidence(&token, &report_data)
            .await
            .expect("a token appraised under an affirming policy should verify");
    }

    /// Without this, an affirming result proves only that the pipeline runs, not that the policy
    /// decides anything: a golden value the hardware cannot report has to flip the outcome.
    pub(super) async fn assert_evidence_is_not_affirmed(cpu_policy: String, nonce: &str) {
        let converter = converter_with(cpu_policy).await;
        let verifier = converter.new_verifier().await.expect("verifier");
        let report_data = report_data(nonce);

        let token = converter
            .convert(&evidence_for(&report_data).await)
            .await
            .expect("evidence is still valid, only the appraisal should fail");

        let err = verifier
            .verify_evidence(&token, &report_data)
            .await
            .expect_err("an unmatched golden value must not be affirmed");

        assert!(
            matches!(err, Error::EarStatusNotAffirming { .. }),
            "expected a non-affirming appraisal, got {err:?}"
        );
    }

    /// A value this host actually reports, read back from a token appraised under a policy that
    /// pins nothing.
    ///
    /// The affirming tests need a golden value that matches, and writing one down as a literal
    /// would tie the suite to a paravisor, TDX module or GPU firmware release. Those move on the
    /// platform owner's schedule, so a literal turns someone else's update into a red build that
    /// says nothing about this code. Calibrating against the host keeps the affirming case
    /// exercising a real comparison without this repo owning the value, which belongs to whoever
    /// writes the deployment's policy.
    ///
    /// `pointer` is the path a policy would use, because a submodule's annotated evidence is
    /// exactly the policy's `input`.
    pub(super) async fn host_claim(tee_class: &str, pointer: &str) -> serde_json::Value {
        let converter = converter_with(policy("")).await;
        let report_data = report_data("dGVzdC1ub25jZS1jYWxpYnJhdGU");

        let token = converter
            .convert(&evidence_for(&report_data).await)
            .await
            .expect("conversion should succeed");

        let payload = payload_of(&token);
        let submodules = payload
            .pointer("/submods")
            .and_then(|submods| submods.as_object())
            .expect("an EAR token should carry submodules");

        let (name, appraisal) = submodules
            .iter()
            .find(|(name, _)| name.starts_with(tee_class))
            .unwrap_or_else(|| panic!("this host attests no {tee_class}, got {submodules:?}"));

        let value = appraisal
            .pointer(&format!("/ear.veraison.annotated-evidence{pointer}"))
            .unwrap_or_else(|| panic!("{name} reports nothing at {pointer}"))
            .clone();

        // Without this an extraction that came back empty would still build a policy, and that
        // policy would be trivially satisfiable rather than a comparison, so the affirming test
        // would pass for the wrong reason.
        let empty = match &value {
            serde_json::Value::String(text) => text.is_empty(),
            serde_json::Value::Object(map) => map.is_empty(),
            serde_json::Value::Null => true,
            _ => false,
        };
        assert!(!empty, "{name} reports an empty {pointer}");

        value
    }

    /// The freshness guarantee: evidence is bound to the runtime data it was requested with, so a
    /// token cannot be replayed against another nonce. This is the check that stands in for the
    /// challenge the upstream service does not provide.
    pub(super) async fn assert_a_replayed_nonce_is_rejected(cpu_policy: String) {
        let converter = converter_with(cpu_policy).await;
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

    /// Prints every submodule's claims exactly as a policy sees them, which is how you find the
    /// paths a policy can assert on and the values this host would satisfy them with. These are
    /// measurements of the kind a policy pins, not evidence or key material.
    ///
    /// Ignored so it never runs as part of the suite: `--ignored --nocapture` to use it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    #[ignore = "diagnostic, reports this host's claims rather than asserting"]
    async fn print_appraisal() {
        let converter = converter_with(policy("")).await;
        let report_data = report_data("dGVzdC1ub25jZS1kdW1w");

        let token = converter
            .convert(&evidence_for(&report_data).await)
            .await
            .expect("conversion should succeed");

        let payload = payload_of(&token);
        let submodules = payload
            .pointer("/submods")
            .and_then(|submods| submods.as_object())
            .expect("an EAR token should carry submodules");

        for (name, appraisal) in submodules {
            let claims = appraisal
                .pointer("/ear.veraison.annotated-evidence")
                .unwrap_or(&serde_json::Value::Null);

            println!(
                "SUBMODULE {name} {}",
                serde_json::to_string_pretty(claims).expect("claims should serialize")
            );
        }
    }
}

/// Real TDX evidence from this host, appraised in-process.
///
/// Needs TDX hardware and the Intel DCAP quote verification library
/// (`libsgx-dcap-quote-verify-dev`). Verification is online: this revision of the verifier fetches
/// collateral from Intel's PCS itself and fails if it cannot, so unlike the containerized service
/// there is no quote provider library config to set.
#[cfg(all(test, feature = "coco-builtin-as-tdx", feature = "attester-coco"))]
mod tdx_e2e_tests {
    use serial_test::serial;

    use super::hardware_support::*;
    use super::policy;

    /// A measurement no TDX module will ever report, used to show the allowlist is load-bearing.
    const MR_SEAM_WRONG: [&str; 1] = [
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    ];

    /// The TDX module measurement this host reports. Note the value the affirming tests accept is
    /// whatever the host says, since it moves whenever Intel updates the module.
    async fn mr_seam() -> String {
        host_claim("cpu", "/tdx/quote/body/mr_seam")
            .await
            .as_str()
            .expect("mr_seam should be a hex string")
            .to_owned()
    }

    /// The accepted measurements are a parameter so a test can substitute one the hardware cannot
    /// report. The guest measurements a real policy would also pin (rtmr1/rtmr2, mr_td) are
    /// properties of the image under test rather than of the attestation path, so asserting only
    /// the presence of TDX evidence for `executables` keeps this from failing on every rebuild.
    fn tdx_policy(mr_seam_allowed: &[&str]) -> String {
        let allowed = serde_json::to_string(mr_seam_allowed).expect("allowlist should serialize");

        policy(&format!(
            r#"mr_seam_allowed := {allowed}

# A TDX quote from Intel's quoting enclave, carrying a module measurement we accept, checked
# against collateral that had not expired.
hardware := 2 if {{
	input.tdx.quote.header.tee_type == "81000000"
	input.tdx.quote.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607"
	input.tdx.quote.body.mr_seam in mr_seam_allowed
	input.tdx.collateral_expiration_status == "0"
}}

executables := 3 if input.tdx

configuration := 2 if input.tdx.td_attributes.debug == false"#
        ))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn real_tdx_evidence_is_affirmed() {
        let mr_seam = mr_seam().await;

        assert_evidence_is_affirmed(tdx_policy(&[&mr_seam]), "dGVzdC1ub25jZS1hZmZpcm0").await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn a_policy_with_an_unmatched_mr_seam_is_rejected() {
        assert_evidence_is_not_affirmed(tdx_policy(&MR_SEAM_WRONG), "dGVzdC1ub25jZS1tcnNlYW0")
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn a_token_bound_to_another_nonce_is_rejected() {
        let mr_seam = mr_seam().await;

        assert_a_replayed_nonce_is_rejected(tdx_policy(&[&mr_seam])).await;
    }
}

/// Real Azure SEV-SNP evidence from this host, appraised in-process.
///
/// Azure confidential VMs run SEV-SNP under a paravisor in vTOM mode, so the guest has no
/// `/dev/sev-guest` to ask for a report. Evidence comes from the vTPM instead: the paravisor puts
/// the SNP report in an NV index, and the guest wraps it in a TPM quote binding the report data as
/// the quote nonce. That is a different attester and verifier from raw SEV-SNP, hence the gate on
/// `coco-builtin-as-azsnp` rather than `coco-builtin-as-snp`.
///
/// Unlike TDX, verification is fully offline: the attester ships the VCEK inside the evidence and
/// the verifier checks it against AMD certificates compiled into it.
///
/// Needs an Azure SEV-SNP confidential VM, the TPM2 TSS libraries (`libtss2-dev`), and an agent
/// built with the `az-cvm-vtpm` attester.
#[cfg(all(test, feature = "coco-builtin-as-azsnp", feature = "attester-coco"))]
mod azsnp_e2e_tests {
    use serial_test::serial;

    use super::hardware_support::*;
    use super::policy;

    /// A measurement no SNP platform will report: 48 zero bytes, the right shape but not a value
    /// any launch can produce.
    const MEASUREMENT_WRONG: [&str; 1] =
        ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"];

    /// The SNP launch measurement this host reports, base64 as the verifier emits it.
    ///
    /// On an Azure CVM in vTOM mode this measures the paravisor launch context, not the guest OS
    /// disk: the guest boot chain is measured into the vTPM PCRs instead. It therefore survives
    /// swapping the guest image and moves when Azure updates the paravisor, which is why the
    /// affirming tests read it from the host rather than pinning it, exactly as with `mr_seam`.
    async fn measurement() -> String {
        host_claim("cpu", "/az-snp-vtpm/measurement")
            .await
            .as_str()
            .expect("measurement should be a base64 string")
            .to_owned()
    }

    /// As with TDX, the accepted measurements are a parameter, and the guest measurements a real
    /// policy would pin — here the vTPM PCRs — are left out because they move with the image.
    ///
    /// Note the claims are reached through `input["az-snp-vtpm"]`. The attestation service nests a
    /// verifier's claims under the serde name of its TEE type, and for this one that name contains
    /// hyphens, so the dotted form the TDX policy uses is not available. Writing `input.azsnpvtpm`
    /// compiles but matches nothing, which fails closed and so looks like a rejected appraisal
    /// rather than a broken policy.
    fn azsnp_policy(measurement_allowed: &[&str]) -> String {
        let allowed = serde_json::to_string(measurement_allowed).expect("allowlist serializes");

        policy(&format!(
            r#"measurement_allowed := {allowed}

snp := input["az-snp-vtpm"]

hardware := 2 if snp.measurement in measurement_allowed

executables := 3 if snp

# Debug being allowed would let the host read guest memory. The host sets this from the VM's launch
# policy rather than the guest image, so it is stable across image changes, mirroring the TDX
# policy's `td_attributes.debug`.
configuration := 2 if snp.policy_debug_allowed == "false""#
        ))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn real_azure_snp_evidence_is_affirmed() {
        let measurement = measurement().await;

        assert_evidence_is_affirmed(azsnp_policy(&[&measurement]), "dGVzdC1ub25jZS1hZmZpcm0").await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn a_policy_with_an_unmatched_measurement_is_rejected() {
        assert_evidence_is_not_affirmed(azsnp_policy(&MEASUREMENT_WRONG), "dGVzdC1ub25jZS1tZWFz")
            .await;
    }

    /// On this path the nonce is bound twice over, as the TPM quote nonce and as the SNP report
    /// data, and the verifier checks both before any claim is emitted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn a_token_bound_to_another_nonce_is_rejected() {
        let measurement = measurement().await;

        assert_a_replayed_nonce_is_rejected(azsnp_policy(&[&measurement])).await;
    }
}

/// Real NVIDIA GPU evidence from this host, appraised in-process.
///
/// A GPU is never attested on its own. The agent returns the CPU's evidence plus a map of
/// *additional* evidence per device, each of which becomes its own verification request bound to
/// the same runtime data, appraised under the policy for its TEE class. A token from this host
/// therefore carries both a `cpu0` and a `gpu0` appraisal and `CommonCocoVerifier` requires every
/// submodule to affirm, which is why this module needs a CPU verifier feature alongside the NVIDIA
/// one and a `gpu` policy installed.
///
/// Verification is local and offline: upstream's NVIDIA verifier defaults to `Local`, which checks
/// the SPDM report against the device certificate chain inside the evidence and binds it to the
/// nonce, reaching neither NRAS nor the RIM service. It deliberately does no reference-value
/// comparison of its own, reporting what the device measured and leaving the golden-value check to
/// the policy — the split this whole design relies on.
///
/// Needs a Hopper GPU in confidential-compute mode (local verification refuses other
/// architectures) and an agent built with the `nvidia` attester alongside a CPU one, with `libnvat`
/// available to it.
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

    /// A digest no GPU will report: 48 zero bytes, the right shape but not a value any firmware
    /// measures. Set at register 2, which the device does populate, so the comparison actually runs
    /// instead of failing for want of the register.
    fn wrong_measurements() -> serde_json::Value {
        serde_json::json!({
            "2": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        })
    }

    /// The firmware values this GPU reports: the measurement registers as index to hex digest, and
    /// the VBIOS version. Both describe the device rather than the guest, so they survive an image
    /// change and move when the GPU firmware does — hence read from the host, like the CPU
    /// measurements above. Which of them a real deployment should pin is a policy question.
    async fn golden_values() -> (serde_json::Value, String) {
        let gpu = host_claim("gpu", "/nvidia").await;

        let vbios_version = gpu["config"]["vbios_version"]
            .as_str()
            .expect("the GPU should report a VBIOS version")
            .to_owned();

        (gpu["measurements"].clone(), vbios_version)
    }

    /// Affirms on the mere presence of CPU evidence, pinning nothing.
    ///
    /// These tests are about the GPU class, and the CPU class has its own modules above with real
    /// golden values. Keeping this free of host-specific values is what lets the same GPU tests run
    /// on an Azure SEV-SNP host and a TDX one.
    fn cpu_presence_policy() -> String {
        policy(
            r#"cpu_present if input["az-snp-vtpm"]
cpu_present if input.tdx

hardware := 2 if cpu_present
executables := 3 if cpu_present
configuration := 2 if cpu_present"#,
        )
    }

    /// The claims arrive under `input.nvidia`, the serde name of the evidence's TEE type, even
    /// though the TEE *class* this policy is installed under is `gpu`.
    fn gpu_policy(golden_measurements: &serde_json::Value, vbios_version: &str) -> String {
        policy(&format!(
            r#"golden_measurements := {golden_measurements}

gpu := input.nvidia

# Local verification only supports Hopper, so a non-Hopper architecture would mean the claims came
# from somewhere other than the verifier we think we are running.
hardware := 2 if gpu.arch == "Hopper"

# A register absent from the evidence makes the comparison undefined, so `every` fails closed
# rather than skipping it. The count guard matters too: `every` over an empty set is vacuously
# true, so without it an empty golden map would affirm everything.
executables := 3 if {{
	count(golden_measurements) > 0
	every index, digest in golden_measurements {{
		gpu.measurements[index] == digest
	}}
}}

# Device firmware, the closest thing on this path to the host-controlled configuration the CPU
# policies assert on. The driver version is reported here too but comes from the guest image, so it
# is deliberately not pinned.
configuration := 2 if gpu.config.vbios_version == "{vbios_version}""#
        ))
    }

    async fn converter_with_gpu_policy(
        gpu_policy: String,
        required_tee_classes: &[String],
    ) -> CocoBuiltinConverter {
        converter_with_policies(
            BTreeMap::from([
                ("cpu".to_owned(), cpu_presence_policy()),
                ("gpu".to_owned(), gpu_policy),
            ]),
            required_tee_classes,
        )
        .await
    }

    /// Real GPU evidence all the way to an accepted token.
    ///
    /// The submodule assertion is what keeps this honest. Without it the test would pass on a host
    /// whose agent returned no device evidence at all, because the CPU appraisal alone would
    /// affirm and the GPU policy would simply never be consulted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn real_gpu_evidence_is_affirmed() {
        let (measurements, vbios_version) = golden_values().await;
        let converter =
            converter_with_gpu_policy(gpu_policy(&measurements, &vbios_version), &[]).await;
        let verifier = converter.new_verifier().await.expect("verifier");
        let report_data = report_data("dGVzdC1ub25jZS1ncHUtYWZmaXJt");

        let token = converter
            .convert(&evidence_for(&report_data).await)
            .await
            .expect("the in-process service should verify this host's GPU attestation report");

        let payload = payload_of(&token);
        let submodules = payload
            .pointer("/submods")
            .expect("an EAR token should carry submodules");
        assert!(
            submodules.get("gpu0").is_some(),
            "the token must carry a GPU appraisal, got submodules {submodules}"
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
        // The VBIOS is the one this host reports, so the measurements are the only thing that can
        // account for the rejection.
        let (_, vbios_version) = golden_values().await;
        let converter =
            converter_with_gpu_policy(gpu_policy(&wrong_measurements(), &vbios_version), &[]).await;
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

    /// Requiring a class is checked against real submodule names here; that the check accepts and
    /// rejects the right sets is covered by unit tests over a recorded token in the verifier. What
    /// this adds is that a `gpu0` submodule really does satisfy a requirement written as `gpu`.
    ///
    /// It is also the verifier-side counterpart to the GPU policy: the policy constrains a GPU that
    /// shows up, while this insists one shows up at all.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial]
    async fn requiring_the_classes_this_host_presents_is_satisfied() {
        let required = ["cpu".to_owned(), "gpu".to_owned()];
        let (measurements, vbios_version) = golden_values().await;
        let converter =
            converter_with_gpu_policy(gpu_policy(&measurements, &vbios_version), &required).await;
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
}
