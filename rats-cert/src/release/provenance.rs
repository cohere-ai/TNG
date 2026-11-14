//! Checks published files against a Sigstore bundle offline, the way `gh attestation verify` does
//! for a GitHub Actions signer.

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{bail, ensure, Context as _};
use serde::{Deserialize, Serialize};
use sigstore_trust_root::TrustedRoot;
use sigstore_types::{Artifact, Bundle, SignatureContent, Statement};
use sigstore_verify::{crypto::sha256, IdentityMatcher, VerificationPolicy, Verifier};

use crate::errors::*;

const GITHUB_ACTIONS_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// The Sigstore bundle covering the files, and the GitHub Actions workflow it has to be signed by.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// Location of the bundle, resolved like a file entry
    pub bundle: String,
    /// `owner/name` of the repository the files are built from
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

impl Provenance {
    pub(super) fn problem(&self) -> Option<&'static str> {
        let missing = [
            &self.bundle,
            &self.repo,
            &self.signer_workflow,
            &self.source_ref,
            &self.predicate_type,
        ]
        .iter()
        .any(|field| field.is_empty());
        (missing || self.repo.split('/').count() != 2).then_some(
            "'provenance' needs 'bundle', 'repo' as owner/name, 'signer_workflow', 'source_ref' and 'predicate_type'",
        )
    }
}

/// A downloaded file, named as a statement subject would name it.
pub struct ReleaseFile<'a> {
    pub name: &'a str,
    pub bytes: &'a [u8],
}

/// Verifies the bundle's signer and that it covers every file, either as a subject with the file's
/// name and digest, or as JSON equal to the statement's predicate. Returns the earliest verified
/// signing time, in seconds since the Unix epoch.
pub fn verify(
    trusted_root: &TrustedRoot,
    bundle_json: &[u8],
    files: &[ReleaseFile<'_>],
    provenance: &Provenance,
) -> Result<i64> {
    check(trusted_root, bundle_json, files, provenance)
        .map_err(|e| Error::ProvenanceCheckFailed(Arc::new(e)))
}

fn parse(bundle_json: &[u8]) -> anyhow::Result<(Bundle, Statement)> {
    let bundle = Bundle::from_json(std::str::from_utf8(bundle_json)?)?;
    let SignatureContent::DsseEnvelope(envelope) = &bundle.content else {
        bail!("bundle does not hold a DSSE envelope");
    };
    let statement = serde_json::from_slice(envelope.payload.as_bytes())?;
    Ok((bundle, statement))
}

fn check(
    trusted_root: &TrustedRoot,
    bundle_json: &[u8],
    files: &[ReleaseFile<'_>],
    provenance: &Provenance,
) -> anyhow::Result<i64> {
    let (bundle, statement) = parse(bundle_json)?;
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

    // The signature covers the statement's exact bytes, so it vouches for every subject and
    // the predicate. `verify` also wants an artifact matching some subject; the first
    // subject's listed digest satisfies that, and the loop below binds each file instead.
    let any_subject_digest = statement
        .subject
        .iter()
        .find_map(|s| s.digest.sha256)
        .context("statement has no sha256 subject")?;
    let identity = format!(
        "https://github.com/{}/{}@{}",
        provenance.repo, provenance.signer_workflow, provenance.source_ref
    );
    let result = Verifier::new(trusted_root)?.verify(
        Artifact::from_digest(any_subject_digest),
        &bundle,
        &VerificationPolicy::new(IdentityMatcher::Uri(identity), GITHUB_ACTIONS_ISSUER),
    )?;
    ensure!(
        result.certificate_verified() && result.sct_verified() && result.tlog_verified(),
        "certificate, SCT or transparency log not verified"
    );
    check_claims(
        &result.certificate().context("no certificate")?.ci_claims,
        provenance,
    )?;

    for file in files {
        let digest = sha256(file.bytes);
        let covered = statement
            .subject
            .iter()
            .any(|s| s.name == file.name && s.digest.sha256 == Some(digest))
            || serde_json::from_slice::<serde_json::Value>(file.bytes)
                .is_ok_and(|json| json == statement.predicate);
        ensure!(covered, "{:?} is not covered by the bundle", file.name);
    }

    Ok(result
        .verified_timestamps()
        .iter()
        .min()
        .context("no verified timestamp")?
        .as_second())
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

    pub(crate) const BUNDLE: &str = "attestation-bundle.sigstore.json";
    pub(crate) const A70: Fixture = fixture!("v0.0.1a70");
    pub(crate) const A71: Fixture = fixture!("v0.0.1a71");

    pub(crate) fn integritee() -> Provenance {
        Provenance {
            bundle: BUNDLE.to_owned(),
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
                name: "trustee_policy_cpu.rego",
                bytes: cpu,
            },
            ReleaseFile {
                name: "trustee_policy_gpu.rego",
                bytes: gpu,
            },
        ]
    }

    pub(crate) fn predicate(fixture: &Fixture) -> Vec<u8> {
        serde_json::to_vec_pretty(&parse(fixture.bundle).unwrap().1.predicate).unwrap()
    }

    #[test]
    fn real_releases_verify() {
        let root = production_root();
        let a71 = verify(
            &root,
            A71.bundle,
            &files(A71.cpu, A71.gpu),
            &Provenance {
                predicate_claims: BTreeMap::from([("version".into(), "v0.0.1a71".into())]),
                ..integritee()
            },
        )
        .unwrap();
        let a70 = verify(&root, A70.bundle, &files(A70.cpu, A70.gpu), &integritee()).unwrap();
        assert!(a70 < a71);

        let predicate = predicate(&A71);
        let as_predicate = [ReleaseFile {
            name: "predicate.json",
            bytes: &predicate,
        }];
        verify(&root, A71.bundle, &as_predicate, &integritee()).unwrap();
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
        let unsigned = [ReleaseFile {
            name: "unsigned.rego",
            bytes: A71.cpu,
        }];
        let other_predicate = predicate(&A70);
        let other_predicate = [ReleaseFile {
            name: "predicate.json",
            bytes: &other_predicate,
        }];

        let cases: [(&str, &[ReleaseFile], Provenance); 12] = [
            ("tampered file", &files(&tampered, A71.gpu), integritee()),
            ("swapped files", &files(A71.gpu, A71.cpu), integritee()),
            ("unsigned file", &unsigned, integritee()),
            ("other release's predicate", &other_predicate, integritee()),
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
                verify(&root, A71.bundle, files, &provenance).is_err(),
                "{case} should be rejected"
            );
        }
    }
}
