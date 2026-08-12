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

/// Filename read for the CPU policy. Every attestation produces a CPU submodule, so this one is
/// mandatory.
const CPU_POLICY_FILE: &str = "tng_cpu.rego";

/// Filename read for the GPU policy. Optional, so a deployment without GPUs does not have to carry
/// one. If a GPU does turn up with no policy installed the service falls back to its own default,
/// which cannot affirm without the NRAS claims that a local verifier never produces, so the
/// omission fails closed rather than admitting the device.
const GPU_POLICY_FILE: &str = "tng_gpu.rego";

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

/// Reads the policies out of `dir`, using the fixed filenames above.
pub async fn load_from_dir(dir: &Path) -> Result<TeeClassPolicies> {
    let mut policies = TeeClassPolicies::new();

    let cpu_path = dir.join(CPU_POLICY_FILE);
    let cpu_policy = tokio::fs::read_to_string(&cpu_path).await.map_err(|e| {
        Error::CocoBuiltinAsReadPolicyFailed {
            path: cpu_path.display().to_string(),
            source: Arc::new(e),
        }
    })?;
    policies.insert("cpu".to_owned(), cpu_policy);

    let gpu_path = dir.join(GPU_POLICY_FILE);
    match tokio::fs::read_to_string(&gpu_path).await {
        Ok(gpu_policy) => {
            policies.insert("gpu".to_owned(), gpu_policy);
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::info!(
                path = %gpu_path.display(),
                "No GPU policy present, GPU evidence will not be accepted"
            );
        }
        Err(e) => {
            return Err(Error::CocoBuiltinAsReadPolicyFailed {
                path: gpu_path.display().to_string(),
                source: Arc::new(e),
            })
        }
    }

    Ok(policies)
}

/// Derives a content-addressed id covering every policy in the set.
///
/// Naming the policies after their contents means the id recorded in a token identifies exactly
/// what was enforced, and a revised policy can never be mistaken for the one it replaced.
pub fn derive_policy_id(policies: &TeeClassPolicies) -> String {
    let mut hasher = Sha256::new();

    // Lengths are hashed alongside the values so that no two distinct sets can collide by shifting
    // bytes across a field boundary. The map is ordered, so the digest is stable.
    for (tee_class, policy) in policies {
        hasher.update((tee_class.len() as u64).to_le_bytes());
        hasher.update(tee_class.as_bytes());
        hasher.update((policy.len() as u64).to_le_bytes());
        hasher.update(policy.as_bytes());
    }

    format!("tng_{}", hex::encode(hasher.finalize()))
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

    #[test]
    fn policy_id_is_content_addressed() {
        let a = TeeClassPolicies::from([("cpu".to_owned(), COMPLETE_POLICY.to_owned())]);
        let mut b = a.clone();
        b.insert("gpu".to_owned(), COMPLETE_POLICY.to_owned());

        assert_eq!(derive_policy_id(&a), derive_policy_id(&a));
        assert_ne!(
            derive_policy_id(&a),
            derive_policy_id(&b),
            "adding a policy should change the id"
        );
    }

    /// The id is used as `{id}_{tee_class}` and ends up in tokens and logs, so it has to stay
    /// within a conservative character set.
    #[test]
    fn policy_id_is_alphanumeric() {
        let policies = TeeClassPolicies::from([("cpu".to_owned(), COMPLETE_POLICY.to_owned())]);

        let id = derive_policy_id(&policies);

        assert!(id.starts_with("tng_"));
        assert!(
            id.strip_prefix("tng_")
                .unwrap()
                .chars()
                .all(|c| c.is_ascii_hexdigit()),
            "unexpected characters in {id}"
        );
    }

    /// The policies shipped in `policies/` are what CI rewrites the golden values into, so they
    /// have to satisfy the same checks a fetched policy does. This is the guard that catches an
    /// overlong generated line or a claim dropped while editing.
    #[test]
    fn shipped_policies_validate() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../policies");

        for (tee_class, file) in [("cpu", CPU_POLICY_FILE), ("gpu", GPU_POLICY_FILE)] {
            let path = dir.join(file);
            let policy = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));

            validate(tee_class, &policy)
                .unwrap_or_else(|e| panic!("{} is not a usable policy: {e}", path.display()));
        }
    }

    /// With no golden values generated in, the shipped policies must reject rather than admit.
    #[test]
    fn shipped_policies_reject_by_default() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../policies/tng_cpu.rego");
        let policy = std::fs::read_to_string(path).unwrap();

        let mut engine = regorus::Engine::new();
        engine.add_policy("cpu.rego".to_owned(), policy).unwrap();
        engine.set_input(regorus::Value::new_object());

        let claims = engine
            .eval_rule(TRUST_CLAIMS_RULE.to_owned())
            .unwrap()
            .as_object()
            .unwrap()
            .clone();

        // 2..31 is affirming under AR4SI, so an ungenerated policy must land outside that band on
        // the claims it is responsible for.
        for claim in ["hardware", "executables", "configuration"] {
            let value = claims
                .get(&regorus::Value::from(claim))
                .and_then(|v| v.as_i64().ok())
                .unwrap_or_else(|| panic!("{claim} should be a number"));

            assert!(
                !(2..=31).contains(&value),
                "{claim} is {value}, which would affirm without any golden values"
            );
        }
    }

    #[tokio::test]
    async fn gpu_policy_is_optional_but_cpu_policy_is_not() {
        let dir = tempfile::tempdir().unwrap();

        let err = load_from_dir(dir.path()).await.unwrap_err();
        assert!(
            matches!(err, Error::CocoBuiltinAsReadPolicyFailed { .. }),
            "a missing CPU policy should fail, got {err:?}"
        );

        tokio::fs::write(dir.path().join(CPU_POLICY_FILE), COMPLETE_POLICY)
            .await
            .unwrap();

        let policies = load_from_dir(dir.path()).await.unwrap();
        assert_eq!(policies.keys().collect::<Vec<_>>(), vec!["cpu"]);

        tokio::fs::write(dir.path().join(GPU_POLICY_FILE), COMPLETE_POLICY)
            .await
            .unwrap();

        let policies = load_from_dir(dir.path()).await.unwrap();
        assert_eq!(policies.keys().collect::<Vec<_>>(), vec!["cpu", "gpu"]);
    }
}
