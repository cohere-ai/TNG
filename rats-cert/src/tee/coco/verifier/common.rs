use super::super::evidence::CocoAsToken;
use crate::tee::ReportData;
use crate::{errors::*, tee::GenericVerifier};

use serde_json::Value;

use std::collections::{HashMap, HashSet};

use super::token::{AttestationTokenVerifierConfig, TokenVerifier};

pub(super) struct CommonCocoVerifier {
    /// The token verifier used for validating JWT.
    pub token_verifier: TokenVerifier,
    /// The policy ids need to check
    pub policy_ids: Vec<String>,
    /// TEE classes that must appear in the token, rejecting it if any is absent.
    ///
    /// A policy cannot express this. Policies are only evaluated against evidence that arrived,
    /// so a peer that simply never offers its GPU is appraised on its CPU alone and its `gpu`
    /// policy, however strict, is never consulted. Demanding a class is therefore a decision for
    /// the party doing the verifying, not something the evidence can be trusted to declare.
    pub required_tee_classes: Vec<String>,
}

/// Submodules are named `{tee_class}{index}`, as in `cpu0` or `gpu0`, so the class is the name
/// with its trailing index removed. No class upstream defines ends in a digit.
fn tee_class_of(submodule_name: &str) -> &str {
    submodule_name.trim_end_matches(|c: char| c.is_ascii_digit())
}

impl CommonCocoVerifier {
    pub async fn verify_evidence_internal(
        &self,
        evidence: &CocoAsToken,
        report_data: &ReportData,
    ) -> Result<()> {
        let token = evidence.as_str();
        tracing::debug!(
            "Verify CoCo AS token \"{token}\" with policy ids: {:?}",
            self.policy_ids
        );

        let claims_value = self
            .token_verifier
            .verify(token.to_string())
            .await
            .map_err(Error::CocoTokenVerifierError)?;

        let is_ear = if let Some(eat_profile) = claims_value.get("eat_profile") {
            if eat_profile != "tag:github.com,2024:confidential-containers/Trustee" {
                return Err(Error::UnsupportedEatProfile {
                    profile: eat_profile.to_string(),
                });
            }
            true
        } else {
            false
        };

        /* Check report_data matchs */
        let runtime_data_expected = crate::tee::wrap_runtime_data_as_structed(report_data)?;
        let runtime_data_in_token = if is_ear {
            // EAR JWT route
            claims_value
                .pointer("/submods/cpu0/ear.veraison.annotated-evidence/runtime_data_claims")
                .ok_or_else(|| Error::MissingTokenField {
                    detail: "runtime_data_claims".to_string(),
                })?
        } else {
            // Standard CoCo AS token route
            claims_value
                .pointer("/customized_claims/runtime_data")
                .ok_or_else(|| Error::MissingTokenField {
                    detail: "runtime_data".to_string(),
                })?
        };

        let runtime_data_expected_map =
            runtime_data_expected
                .as_object()
                .ok_or_else(|| Error::MissingTokenField {
                    detail: "runtime_data_expected is not a map".to_string(),
                })?;

        let runtime_data_in_token_map =
            runtime_data_in_token
                .as_object()
                .ok_or_else(|| Error::MissingTokenField {
                    detail: "runtime_data_in_token is not a map".to_string(),
                })?;

        let is_subset = runtime_data_expected_map
            .iter()
            .all(|(key, value)| runtime_data_in_token_map.get(key) == Some(value));

        tracing::debug!(
            expected = ?runtime_data_expected_map,
            actually = ?runtime_data_in_token_map,
            is_subset,
            "compare runtime_data"
        );

        if !is_subset {
            return Err(Error::RuntimeDataMismatch);
        }

        // Check expected policy-ids
        let mut present_tee_classes: HashSet<&str> = HashSet::new();
        let allowed_policy_ids = if is_ear {
            let submods = claims_value
                .pointer("/submods")
                .and_then(|v| v.as_object())
                .ok_or_else(|| Error::MissingTokenField {
                    detail: "/submods".to_string(),
                })?;

            let mut policy_ids = HashSet::new();
            for (key, value) in submods {
                let policy_id = value
                    .pointer("/ear.appraisal-policy-id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| Error::MissingTokenField {
                        detail: format!("/submods/{}/ear.appraisal-policy-id", key),
                    })?;

                // Check ear.status and trustworthiness-vector, the value of ear.status should be one of (affirming, warning, contraindicated)
                let status = value
                    .pointer("/ear.status")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| Error::MissingTokenField {
                        detail: format!("/submods/{}/ear.status", key),
                    })?;

                let trustworthiness_vector = value
                    .pointer("/ear.trustworthiness-vector")
                    .ok_or_else(|| Error::MissingTokenField {
                        detail: format!("/submods/{}/ear.trustworthiness-vector", key),
                    })?;

                if status != "affirming" {
                    return Err(Error::EarStatusNotAffirming {
                        status: status.to_string(),
                        tee_type: key.to_string(),
                        trustworthiness: trustworthiness_vector.to_string(),
                    });
                }

                present_tee_classes.insert(tee_class_of(key));
                policy_ids.insert(policy_id.to_owned());
            }

            if policy_ids.len() > 1 {
                return Err(Error::MultiplePolicyIds);
            }

            if policy_ids.is_empty() {
                return Err(Error::NoValidPolicyId);
            }
            policy_ids
        } else {
            /*
             * The content format of evaluation-reports is documented here: https://github.com/confidential-containers/trustee/blob/43d56f3a4a92a1cc691f63a8e1311bcc0d2b3fc8/attestation-service/docs/example.token.json#L6
             */
            claims_value
                .get("evaluation-reports")
                .and_then(|o| o.as_array())
                .ok_or_else(|| Error::MissingTokenField {
                    detail: "evaluation-reports".to_string(),
                })?
                .iter()
                .enumerate()
                .map(|(i, o)| -> Result<_> {
                    let policy_id =
                        o.get("policy-id").and_then(|v| v.as_str()).ok_or_else(|| {
                            Error::MissingTokenField {
                                detail: format!("evaluation-reports[{i}].policy-id"),
                            }
                        })?;
                    Ok(policy_id.to_string())
                })
                .collect::<Result<HashSet<_>>>()?
        };

        if !self.required_tee_classes.is_empty() {
            if !is_ear {
                return Err(Error::RequiredTeeClassesUnsupported {
                    required: self.required_tee_classes.clone(),
                });
            }

            for required in &self.required_tee_classes {
                if !present_tee_classes.contains(required.as_str()) {
                    return Err(Error::MissingRequiredTeeClass {
                        tee_class: required.clone(),
                        present: present_tee_classes
                            .iter()
                            .map(|class| (*class).to_owned())
                            .collect(),
                    });
                }
            }
        }

        /* We accept the token only when all of the expected policy ids has { "allow": true } */
        for policy_id in &self.policy_ids {
            if !allowed_policy_ids.contains(policy_id.as_str()) {
                return Err(Error::PolicyEvaluationFailed {
                    policy_id: policy_id.to_string(),
                });
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tee::claims::Claims;

    /// Builds a verifier over one of the committed token fixtures, trusting the CA that signed it.
    ///
    /// Constructs [`CommonCocoVerifier`] directly rather than going through a provider, because no
    /// provider exposes `required_tee_classes` except the builtin one, and that one needs an
    /// in-process attestation service and real hardware evidence to produce a token at all.
    async fn verifier_over(
        ca_pem: &str,
        required_tee_classes: &[&str],
    ) -> (tempfile::TempDir, CommonCocoVerifier) {
        let dir = tempfile::tempdir().expect("temp dir");
        let cert_path = dir.path().join("as-ca.pem");
        std::fs::write(&cert_path, ca_pem).expect("writing the CA should succeed");

        let token_verifier = TokenVerifier::from_config(AttestationTokenVerifierConfig {
            trusted_certs_paths: vec![cert_path.to_string_lossy().into_owned()],
            trusted_jwk_sets: Default::default(),
            as_addr: None,
            as_headers: None,
            insecure_key: false,
        })
        .await
        .expect("token verifier");

        let verifier = CommonCocoVerifier {
            token_verifier,
            policy_ids: vec!["default".to_owned()],
            required_tee_classes: required_tee_classes
                .iter()
                .map(|class| (*class).to_owned())
                .collect(),
        };

        (dir, verifier)
    }

    async fn verify(
        token: &str,
        ca_pem: &str,
        required_tee_classes: &[&str],
    ) -> crate::errors::Result<()> {
        let (_dir, verifier) = verifier_over(ca_pem, required_tee_classes).await;
        let token = CocoAsToken::new(token.trim().to_owned()).expect("fixture should parse");

        verifier
            .verify_evidence_internal(&token, &ReportData::Claims(Claims::default()))
            .await
    }

    /// This fixture carries both a `cpu0` and a `gpu0` appraisal.
    const EAR_WITH_DEVICE: &str = include_str!("test_cases/ear_with_additional_device.jwt");
    const EAR_WITH_DEVICE_CA: &str =
        include_str!("test_cases/ear_with_additional_device.as-ca.pem");

    #[tokio::test]
    async fn requiring_classes_the_token_covers_is_accepted() {
        verify(EAR_WITH_DEVICE, EAR_WITH_DEVICE_CA, &["cpu", "gpu"])
            .await
            .expect("both classes are appraised in this token");
    }

    #[tokio::test]
    async fn requiring_a_class_the_token_omits_is_rejected() {
        let err = verify(EAR_WITH_DEVICE, EAR_WITH_DEVICE_CA, &["switch"])
            .await
            .expect_err("a class with no appraisal must not count as attested");

        match err {
            Error::MissingRequiredTeeClass { tee_class, present } => {
                assert_eq!(tee_class, "switch");
                assert!(
                    present.contains(&"cpu".to_owned()) && present.contains(&"gpu".to_owned()),
                    "the attested classes should be reported, got {present:?}"
                );
            }
            other => panic!("expected a missing required class, got {other:?}"),
        }
    }

    /// Requiring nothing has to leave the existing behaviour alone, since that is what every other
    /// provider passes.
    #[tokio::test]
    async fn requiring_nothing_accepts_the_same_token() {
        verify(EAR_WITH_DEVICE, EAR_WITH_DEVICE_CA, &[])
            .await
            .expect("this token verifies when no classes are demanded");
    }

    /// Only EAR tokens carry per-class appraisals, so on any other format the requirement cannot be
    /// evaluated and has to be refused rather than quietly skipped.
    #[tokio::test]
    async fn requiring_a_class_on_a_non_ear_token_is_refused() {
        let err = verify(
            include_str!("test_cases/simple.jwt"),
            include_str!("test_cases/simple.as-ca.pem"),
            &["gpu"],
        )
        .await
        .expect_err("a non-EAR token cannot satisfy a class requirement");

        assert!(
            matches!(err, Error::RequiredTeeClassesUnsupported { .. }),
            "expected the requirement to be refused as uncheckable, got {err:?}"
        );
    }

    #[test]
    fn a_submodule_name_reduces_to_its_tee_class() {
        assert_eq!(tee_class_of("cpu0"), "cpu");
        assert_eq!(tee_class_of("gpu0"), "gpu");
        assert_eq!(tee_class_of("switch3"), "switch");

        // Indices are not assumed to be single digits.
        assert_eq!(tee_class_of("gpu11"), "gpu");

        // A name carrying no index is already the class.
        assert_eq!(tee_class_of("ppcie"), "ppcie");
    }
}
