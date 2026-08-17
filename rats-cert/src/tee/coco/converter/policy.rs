//! Loading and validating the Rego policies the in-process attestation service enforces.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use sha2::{Digest as _, Sha256};

use crate::errors::*;

/// Rego policies to install, keyed by TEE class (`cpu`, `gpu`).
///
/// The EAR broker resolves a policy as `format!("{policy_id}_{tee_class}")`, so a single
/// attestation covering a CPU and a GPU evaluates two separate policies.
pub type TeeClassPolicies = BTreeMap<String, String>;

/// The TEE classes upstream's verifiers emit, and so the only classes a policy is ever resolved
/// for.
const TEE_CLASSES: &[&str] = &["cpu", "gpu", "switch", "ppcie"];

/// The class every attestation appraises, and so the one policy a deployment cannot omit.
///
/// The others are optional: a policy is only looked up for a class the evidence carries. If a
/// device does turn up with no policy installed for its class, that lookup misses and the whole
/// appraisal fails with `PolicyNotFound`, so the omission fails closed rather than admitting the
/// device.
const CPU_TEE_CLASS: &str = "cpu";

/// The rule the EAR broker reads an appraisal's trust claims from.
const TRUST_CLAIMS_RULE: &str = "data.policy.trust_claims";

/// The claims the broker copies into an appraisal's trustworthiness vector.
///
/// A policy that omits one leaves it unset, and the broker then reports a status other than
/// affirming, which fails the handshake. Checking for them here turns a policy authoring mistake
/// into a startup error instead of an attestation failure.
const REQUIRED_CLAIMS: &[&str] = &[
    "configuration",
    "executables",
    "file-system",
    "hardware",
    "instance-identity",
    "runtime-opaque",
    "sourced-data",
    "storage-opaque",
];

/// Reads the policies belonging to `policy_id` out of `dir`.
///
/// The layout follows the attestation service's own: a policy is stored under the key
/// `{policy_id}_{tee_class}`, and its filesystem backend maps that key straight onto a file with a
/// `.rego` suffix. So `myorg_gpu.rego` is the GPU policy of the policy id `myorg`, and a directory
/// can hold several policy ids side by side. Files carrying another id are left alone.
pub async fn load_from_dir(dir: &Path, policy_id: &str) -> Result<TeeClassPolicies> {
    let mut policies = TeeClassPolicies::new();

    for tee_class in TEE_CLASSES {
        let path = dir.join(format!("{policy_id}_{tee_class}.rego"));

        let policy = match tokio::fs::read_to_string(&path).await {
            Ok(policy) => policy,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && *tee_class != CPU_TEE_CLASS => {
                continue
            }
            Err(e) => {
                return Err(Error::CocoBuiltinAsReadPolicyFailed {
                    path: path.display().to_string(),
                    source: Arc::new(e),
                })
            }
        };

        // Logged so a deployment can tell after the fact which bytes were in force, which the
        // policy id alone no longer says now that it is a name rather than a digest.
        tracing::info!(
            policy_id = %format!("{policy_id}_{tee_class}"),
            sha256 = %hex::encode(Sha256::digest(policy.as_bytes())),
            "Loaded policy"
        );

        policies.insert((*tee_class).to_owned(), policy);
    }

    Ok(policies)
}

/// Checks a policy compiles and produces a complete set of trust claims.
///
/// `set_policy` stores bytes without looking at them and the Rego is only compiled when a handshake
/// evaluates it, so without this check a malformed policy would first surface as a failed
/// attestation on a live connection.
pub fn validate(tee_class: &str, policy: &str) -> Result<()> {
    let mut engine = regorus::Engine::new();

    engine
        .add_policy(format!("{tee_class}.rego"), policy.to_owned())
        .map_err(|e| Error::CocoBuiltinAsPolicyInvalid {
            tee_class: tee_class.to_owned(),
            source: Arc::new(e),
        })?;

    // Evaluated against empty input so every rule body falls through to its default. This asks
    // whether the policy is complete, not whether it would accept any particular evidence.
    engine.set_input(regorus::Value::new_object());

    let claims = engine
        .eval_rule(TRUST_CLAIMS_RULE.to_owned())
        .and_then(|claims| claims.as_object().cloned())
        .map_err(|e| Error::CocoBuiltinAsPolicyInvalid {
            tee_class: tee_class.to_owned(),
            source: Arc::new(e),
        })?;

    for claim in REQUIRED_CLAIMS {
        if !claims.contains_key(&regorus::Value::from(*claim)) {
            return Err(Error::CocoBuiltinAsPolicyMissingClaim {
                tee_class: tee_class.to_owned(),
                claim: (*claim).to_owned(),
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal policy that satisfies the completeness check without affirming anything.
    const COMPLETE_POLICY: &str = r#"package policy
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

    #[test]
    fn complete_policy_validates() {
        validate("cpu", COMPLETE_POLICY).unwrap();
    }

    #[test]
    fn malformed_policy_is_rejected() {
        let err = validate("cpu", "package policy\nthis is not rego").unwrap_err();

        assert!(
            matches!(err, Error::CocoBuiltinAsPolicyInvalid { .. }),
            "expected a compile failure, got {err:?}"
        );
    }

    /// Regorus refuses to parse a source line longer than 1024 characters, which is short enough
    /// that a golden-value map serialized onto one line trips it. The generator has to wrap, and
    /// this check is what tells us when it did not.
    #[test]
    fn overlong_line_is_rejected() {
        let long_line = format!(
            "package policy\nimport rego.v1\nallowed := [\"{}\"]\n",
            "a".repeat(1100)
        );

        let err = validate("cpu", &long_line).unwrap_err();

        assert!(
            matches!(err, Error::CocoBuiltinAsPolicyInvalid { .. }),
            "expected an overlong line to be rejected, got {err:?}"
        );
    }

    /// A policy missing a claim still compiles, and the broker would silently report a
    /// non-affirming status for it, so the gap has to be caught here.
    #[test]
    fn policy_missing_a_claim_is_rejected() {
        let incomplete = COMPLETE_POLICY.replace("\t\"sourced-data\": 0,\n", "");

        let err = validate("cpu", &incomplete).unwrap_err();

        assert!(
            matches!(
                &err,
                Error::CocoBuiltinAsPolicyMissingClaim { claim, .. } if claim == "sourced-data"
            ),
            "expected the missing claim to be named, got {err:?}"
        );
    }

    /// A policy with no `trust_claims` rule at all compiles fine but leaves the broker with
    /// nothing to appraise.
    #[test]
    fn policy_without_trust_claims_is_rejected() {
        let err = validate(
            "cpu",
            "package policy\nimport rego.v1\ndefault hardware := 97\n",
        )
        .unwrap_err();

        assert!(
            matches!(err, Error::CocoBuiltinAsPolicyInvalid { .. }),
            "expected a policy without trust_claims to be rejected, got {err:?}"
        );
    }

    /// Covers the whole file contract: only the configured id is read, the CPU policy is required
    /// and the rest are not.
    #[tokio::test]
    async fn only_the_configured_id_is_read_and_only_cpu_is_required() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["theirs_cpu.rego", "theirs_gpu.rego"] {
            tokio::fs::write(dir.path().join(name), COMPLETE_POLICY)
                .await
                .unwrap();
        }

        let err = load_from_dir(dir.path(), "mine").await.unwrap_err();
        assert!(
            matches!(err, Error::CocoBuiltinAsReadPolicyFailed { .. }),
            "a missing CPU policy should fail, got {err:?}"
        );

        tokio::fs::write(dir.path().join("mine_cpu.rego"), COMPLETE_POLICY)
            .await
            .unwrap();
        let policies = load_from_dir(dir.path(), "mine").await.unwrap();
        assert_eq!(policies.keys().collect::<Vec<_>>(), vec!["cpu"]);

        tokio::fs::write(dir.path().join("mine_gpu.rego"), COMPLETE_POLICY)
            .await
            .unwrap();
        let policies = load_from_dir(dir.path(), "mine").await.unwrap();
        assert_eq!(policies.keys().collect::<Vec<_>>(), vec!["cpu", "gpu"]);
    }
}
