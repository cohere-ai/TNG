//! Checks a policy release's Sigstore bundle offline, the way `gh attestation verify` does for a
//! GitHub Actions signer.

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{bail, ensure, Context as _};
use serde::{Deserialize, Serialize};
use sigstore_trust_root::TrustedRoot;
use sigstore_types::{Bundle, SignatureContent, Statement};
use sigstore_verify::{crypto::sha256, IdentityMatcher, VerificationPolicy, Verifier};

use super::policy::{TeeClassPolicies, CPU_TEE_CLASS, TEE_CLASSES};
use crate::errors::*;

const GITHUB_ACTIONS_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// The GitHub Actions workflow a release has to be signed by.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// `owner/name` of the repository the release is built from
    pub repo: String,
    /// Path of the signing workflow in `repo`, e.g. `.github/workflows/release.yaml`
    pub signer_workflow: String,
    /// Git ref the workflow ran on, e.g. `refs/heads/main`
    pub source_ref: String,
    /// in-toto predicate type of the signed statement
    pub predicate_type: String,
    /// Top-level string fields the predicate must declare with exactly these values
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub predicate_claims: BTreeMap<String, String>,
    /// GitHub environment the signing job ran in
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
}

/// One policy file of a release, as downloaded.
pub struct ReleaseFile<'a> {
    pub tee_class: &'a str,
    pub name: &'a str,
    pub bytes: &'a [u8],
}

#[derive(Debug)]
pub struct VerifiedRelease {
    pub policies: TeeClassPolicies,
    /// Earliest verified timestamp of the signature, in seconds since the Unix epoch.
    pub signed_at: i64,
    /// The `version` the release's predicate declares, if any.
    pub version: Option<String>,
}

/// Identifies a release by its bundle, without verifying anything.
pub fn bundle_digest(bundle_json: &[u8]) -> String {
    sha256(bundle_json).to_hex()
}

/// Lists the policy files a release signs for `policy_id`, as `(tee_class, file name)`, without
/// verifying anything. Only tells the caller what to download for [`verify_release`].
pub fn policy_files(bundle_json: &[u8], policy_id: &str) -> Result<Vec<(String, String)>> {
    parse(bundle_json)
        .and_then(|(_, statement)| named_policies(&statement, policy_id))
        .map_err(|e| Error::CocoBuiltinAsPolicyProvenanceFailed(Arc::new(e)))
}

/// Verifies every file against the bundle and returns them as policies. `files` must be exactly
/// the ones [`policy_files`] lists.
pub fn verify_release(
    trusted_root: &TrustedRoot,
    bundle_json: &[u8],
    policy_id: &str,
    files: &[ReleaseFile<'_>],
    provenance: &Provenance,
) -> Result<VerifiedRelease> {
    verify(trusted_root, bundle_json, policy_id, files, provenance)
        .map_err(|e| Error::CocoBuiltinAsPolicyProvenanceFailed(Arc::new(e)))
}

fn parse(bundle_json: &[u8]) -> anyhow::Result<(Bundle, Statement)> {
    let bundle = Bundle::from_json(std::str::from_utf8(bundle_json)?)?;
    let SignatureContent::DsseEnvelope(envelope) = &bundle.content else {
        bail!("bundle does not hold a DSSE envelope");
    };
    let statement = serde_json::from_slice(envelope.payload.as_bytes())?;
    Ok((bundle, statement))
}

/// Policy files are named like the policy directory's, `{policy_id}_{tee_class}.rego`.
fn named_policies(statement: &Statement, policy_id: &str) -> anyhow::Result<Vec<(String, String)>> {
    let named: Vec<_> = TEE_CLASSES
        .iter()
        .map(|tee_class| {
            (
                tee_class.to_string(),
                format!("{policy_id}_{tee_class}.rego"),
            )
        })
        .filter(|(_, name)| statement.subject.iter().any(|s| &s.name == name))
        .collect();
    ensure!(
        named
            .iter()
            .any(|(tee_class, _)| tee_class == CPU_TEE_CLASS),
        "release has no {CPU_TEE_CLASS} policy for {policy_id:?}"
    );
    Ok(named)
}

fn verify(
    trusted_root: &TrustedRoot,
    bundle_json: &[u8],
    policy_id: &str,
    files: &[ReleaseFile<'_>],
    provenance: &Provenance,
) -> anyhow::Result<VerifiedRelease> {
    let (bundle, statement) = parse(bundle_json)?;
    // Otherwise whoever serves the files could leave out a class the release signed.
    ensure!(
        named_policies(&statement, policy_id)?
            .iter()
            .map(|(tee_class, name)| (tee_class.as_str(), name.as_str()))
            .eq(files.iter().map(|f| (f.tee_class, f.name))),
        "files do not match the release's policies"
    );
    ensure!(
        statement.predicate_type == provenance.predicate_type,
        "unexpected predicate type {:?}",
        statement.predicate_type
    );

    for (field, want) in &provenance.predicate_claims {
        let got = statement.predicate[field].as_str();
        ensure!(
            got == Some(want.as_str()),
            "predicate declares {field} {got:?}, not {want:?}"
        );
    }
    let version = statement.predicate["version"].as_str().map(str::to_owned);

    let verifier = Verifier::new(trusted_root)?;
    let identity = format!(
        "https://github.com/{}/{}@{}",
        provenance.repo, provenance.signer_workflow, provenance.source_ref
    );
    let policy = VerificationPolicy::new(IdentityMatcher::Uri(identity), GITHUB_ACTIONS_ISSUER);

    let mut policies = TeeClassPolicies::new();
    let mut signed_at = None;
    for file in files {
        let result = verifier.verify(file.bytes, &bundle, &policy)?;
        ensure!(
            result.certificate_verified() && result.sct_verified() && result.tlog_verified(),
            "certificate, SCT or transparency log not verified"
        );
        signed_at = Some(
            result
                .verified_timestamps()
                .iter()
                .min()
                .context("no verified timestamp")?
                .as_second(),
        );
        check_claims(
            &result.certificate().context("no certificate")?.ci_claims,
            provenance,
        )?;

        // The verifier matches the digest against any subject, so bind the file to its own name.
        let [subject] = statement
            .subject
            .iter()
            .filter(|s| s.name == file.name)
            .collect::<Vec<_>>()[..]
        else {
            bail!("expected exactly one subject named {:?}", file.name);
        };
        ensure!(
            subject.digest.sha256 == Some(sha256(file.bytes)),
            "{:?} does not match its subject digest",
            file.name
        );

        policies.insert(
            file.tee_class.to_owned(),
            String::from_utf8(file.bytes.to_vec())?,
        );
    }

    Ok(VerifiedRelease {
        policies,
        signed_at: signed_at.context("no files to verify")?,
        version,
    })
}

fn check_claims(
    claims: &sigstore_verify::crypto::FulcioCiClaims,
    provenance: &Provenance,
) -> anyhow::Result<()> {
    let repo_uri = format!("https://github.com/{}", provenance.repo);
    let owner = provenance.repo.split('/').next().unwrap_or_default();
    let owner_uri = format!("https://github.com/{owner}");
    let matches_ignoring_case = |claim: &Option<String>, want: &str| {
        claim
            .as_deref()
            .is_some_and(|c| c.eq_ignore_ascii_case(want))
    };

    ensure!(
        matches_ignoring_case(&claims.source_repository_uri, &repo_uri),
        "unexpected source repository {:?}",
        claims.source_repository_uri
    );
    ensure!(
        matches_ignoring_case(&claims.source_repository_owner_uri, &owner_uri),
        "unexpected source repository owner {:?}",
        claims.source_repository_owner_uri
    );
    ensure!(
        claims.source_repository_ref.as_deref() == Some(&provenance.source_ref),
        "unexpected source ref {:?}",
        claims.source_repository_ref
    );
    ensure!(
        claims.runner_environment.as_deref() == Some("github-hosted"),
        "unexpected runner environment {:?}",
        claims.runner_environment
    );
    if let Some(environment) = &provenance.environment {
        ensure!(
            claims.deployment_environment.as_ref() == Some(environment),
            "unexpected deployment environment {:?}",
            claims.deployment_environment
        );
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use sigstore_trust_root::SIGSTORE_PRODUCTION_TRUSTED_ROOT;

    use super::*;

    pub(crate) struct Fixture {
        pub bundle: &'static [u8],
        pub cpu: &'static [u8],
        pub gpu: &'static [u8],
    }

    macro_rules! fixture {
        ($version:literal) => {
            Fixture {
                bundle: include_bytes!(concat!(
                    "test_cases/",
                    $version,
                    "/attestation-bundle.sigstore.json"
                )),
                cpu: include_bytes!(concat!("test_cases/", $version, "/trustee_policy_cpu.rego")),
                gpu: include_bytes!(concat!("test_cases/", $version, "/trustee_policy_gpu.rego")),
            }
        };
    }

    pub(crate) const A70: Fixture = fixture!("v0.0.1a70");
    pub(crate) const A71: Fixture = fixture!("v0.0.1a71");

    pub(crate) fn integritee() -> Provenance {
        Provenance {
            repo: "cohere-ai/integritee".to_owned(),
            signer_workflow: ".github/workflows/release-policy.yaml".to_owned(),
            source_ref: "refs/heads/main".to_owned(),
            predicate_type: "https://cohere.com/attestation-policy/v1".to_owned(),
            predicate_claims: BTreeMap::new(),
            environment: Some("release".to_owned()),
        }
    }

    pub(crate) fn production_root() -> TrustedRoot {
        TrustedRoot::from_json(SIGSTORE_PRODUCTION_TRUSTED_ROOT).unwrap()
    }

    fn files<'a>(cpu: &'a [u8], gpu: &'a [u8]) -> [ReleaseFile<'a>; 2] {
        [
            ReleaseFile {
                tee_class: "cpu",
                name: "trustee_policy_cpu.rego",
                bytes: cpu,
            },
            ReleaseFile {
                tee_class: "gpu",
                name: "trustee_policy_gpu.rego",
                bytes: gpu,
            },
        ]
    }

    pub(crate) const POLICY_ID: &str = "trustee_policy";

    #[test]
    fn real_releases_verify() {
        let root = production_root();
        let names = policy_files(A71.bundle, POLICY_ID).unwrap();
        assert!(names
            .iter()
            .map(|(c, n)| (c.as_str(), n.as_str()))
            .eq(files(&[], &[]).iter().map(|f| (f.tee_class, f.name))));

        let a71 = verify(
            &root,
            A71.bundle,
            POLICY_ID,
            &files(A71.cpu, A71.gpu),
            &Provenance {
                predicate_claims: BTreeMap::from([("version".into(), "v0.0.1a71".into())]),
                ..integritee()
            },
        )
        .unwrap();
        assert_eq!(a71.version.as_deref(), Some("v0.0.1a71"));
        assert_eq!(a71.policies["cpu"].as_bytes(), A71.cpu);
        assert_eq!(a71.policies["gpu"].as_bytes(), A71.gpu);

        let a70 = verify(
            &root,
            A70.bundle,
            POLICY_ID,
            &files(A70.cpu, A70.gpu),
            &integritee(),
        )
        .unwrap();
        assert!(a70.signed_at < a71.signed_at);
    }

    #[test]
    fn mismatches_are_rejected() {
        let root = production_root();
        let mut tampered = A71.cpu.to_vec();
        tampered.push(b'\n');
        let with = |edit: fn(&mut Provenance)| {
            let mut provenance = integritee();
            edit(&mut provenance);
            provenance
        };
        let [cpu_only, _] = files(A71.cpu, A71.gpu);
        let unsigned = [ReleaseFile {
            tee_class: "cpu",
            name: "unsigned.rego",
            bytes: A71.cpu,
        }];

        let cases: [(&str, &[ReleaseFile], Provenance); 12] = [
            ("tampered file", &files(&tampered, A71.gpu), integritee()),
            ("swapped files", &files(A71.gpu, A71.cpu), integritee()),
            ("omitted class", &[cpu_only], integritee()),
            ("unsigned file", &unsigned, integritee()),
            (
                "wrong predicate claim",
                &files(A71.cpu, A71.gpu),
                with(|p| {
                    p.predicate_claims
                        .insert("version".into(), "v0.0.1a70".into());
                }),
            ),
            (
                "missing predicate claim",
                &files(A71.cpu, A71.gpu),
                with(|p| {
                    p.predicate_claims.insert("channel".into(), "stable".into());
                }),
            ),
            (
                "wrong repo",
                &files(A71.cpu, A71.gpu),
                with(|p| p.repo = "cohere-ai/other".into()),
            ),
            (
                "wrong workflow",
                &files(A71.cpu, A71.gpu),
                with(|p| p.signer_workflow = ".github/workflows/other.yaml".into()),
            ),
            (
                "wrong ref",
                &files(A71.cpu, A71.gpu),
                with(|p| p.source_ref = "refs/heads/dev".into()),
            ),
            (
                "wrong predicate",
                &files(A71.cpu, A71.gpu),
                with(|p| p.predicate_type = "https://example.com/v1".into()),
            ),
            (
                "wrong environment",
                &files(A71.cpu, A71.gpu),
                with(|p| p.environment = Some("staging".into())),
            ),
            (
                "other release's files",
                &files(A70.cpu, A70.gpu),
                integritee(),
            ),
        ];
        for (case, files, provenance) in cases {
            assert!(
                verify(&root, A71.bundle, POLICY_ID, files, &provenance).is_err(),
                "{case} should be rejected"
            );
        }
    }
}
