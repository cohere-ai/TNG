//! Attestation request and response shared by RA-TLS and OHTTP.
//!
//! A request is the verifier's proposal list. A response is [`AttestResponse`]: `Ok(None)`
//! acks an empty request, `Ok(Some)` is the evidence or token, and `Err` is a reason string.
//! [`produce_attest_response`] fills that response for a proposal [`pick_proposal`] already matched.
//! It chooses background check or passport. The caller supplies the claims and a passport-token cache.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use again::RetryPolicy;
use anyhow::{anyhow, bail, Context, Result};
use rats_cert::tee::claims::Claims;
use rats_cert::tee::{GenericAttester, ReportData};
use serde::{Deserialize, Serialize};

use crate::tunnel::attestation_result::AttestationResult;
use crate::tunnel::proposal::{AttestProposal, Model};
use crate::tunnel::provider::{ProviderType, TngEvidence, TngToken};
use crate::tunnel::select_proposal::{find_proposal, match_proposal};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AttestRequest {
    /// Empty when this side does not verify its peer.
    #[serde(default)]
    pub proposals: Vec<AttestProposal>,
}

/// Evidence or a passport token. The producing side chooses the arm its matched proposal asked for.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AttestOutput {
    BackgroundCheck {
        provider: ProviderType,
        evidence: serde_json::Value,
    },
    Passport {
        provider: ProviderType,
        token: String,
    },
}

impl AttestOutput {
    pub fn key(&self) -> (Model, ProviderType) {
        match self {
            Self::BackgroundCheck { provider, .. } => (Model::BackgroundCheck, *provider),
            Self::Passport { provider, .. } => (Model::Passport, *provider),
        }
    }
}

/// `Ok(None)` acks an empty proposal list. `Err` is a public reason; serde writes it as a JSON string.
pub type AttestResponse = Result<Option<AttestOutput>, String>;

pub fn ack_response() -> AttestResponse {
    Ok(None)
}

pub fn error_response(reason: impl Into<String>) -> AttestResponse {
    Err(reason.into())
}

pub fn evidence_response(provider: ProviderType, evidence: serde_json::Value) -> AttestResponse {
    Ok(Some(AttestOutput::BackgroundCheck { provider, evidence }))
}

pub fn token_response(provider: ProviderType, token: impl Into<String>) -> AttestResponse {
    Ok(Some(AttestOutput::Passport {
        provider,
        token: token.into(),
    }))
}

pub fn produced_error_reason(response: &AttestResponse) -> Option<&str> {
    response.as_ref().err().map(String::as_str)
}

/// What the attester should do with a received request.
pub enum Answer<'a> {
    /// The peer sent no proposals.
    Ack,
    /// The one proposal this attester answers.
    Matched(&'a AttestProposal),
    /// The peer asked and this side will not answer. The string is safe to send back.
    Reject(String),
}

/// `Ack` only when `proposals` is empty. A non-empty list that this side cannot answer is `Reject`.
pub fn pick_proposal<'a>(
    proposals: &'a [AttestProposal],
    own_key: Option<(Model, ProviderType)>,
) -> Answer<'a> {
    if proposals.is_empty() {
        return Answer::Ack;
    }
    let Some(own_key) = own_key else {
        return Answer::Reject("not configured to attest".into());
    };
    match_proposal(own_key, proposals)
        .map(Answer::Matched)
        .unwrap_or_else(|error| Answer::Reject(error.to_string()))
}

#[async_trait::async_trait]
pub trait AttestVerifier: Send + Sync {
    async fn verify_evidence(
        &self,
        provider: ProviderType,
        evidence: &serde_json::Value,
        expected: Claims,
    ) -> Result<AttestationResult>;

    async fn verify_token(
        &self,
        provider: ProviderType,
        jwt: &str,
        expected: Claims,
    ) -> Result<AttestationResult>;
}

/// Check `got` against the proposals in `sent`.
///
/// An empty request accepts only `Ok(None)`. A non-empty request accepts only the arm that
/// proposal asked for, and that arm has to verify against the claims `expected_claims` builds
/// for the matched proposal.
pub async fn check_response(
    sent: &AttestRequest,
    got: &AttestResponse,
    verifier: Option<&dyn AttestVerifier>,
    expected_claims: impl Fn(&AttestProposal) -> Result<Claims>,
) -> Result<Option<AttestationResult>> {
    if sent.proposals.is_empty() {
        return match got {
            Ok(None) => Ok(None),
            Ok(Some(_)) => bail!("unsolicited credentials"),
            Err(reason) => bail!("peer sent an error: {reason}"),
        };
    }

    let output = match got {
        Err(reason) => bail!("peer attestation failed: {reason}"),
        Ok(None) => bail!("peer did not attest"),
        Ok(Some(output)) => output,
    };
    let verifier = verifier.context("verifying side has no verifier")?;
    let (model, provider) = output.key();
    let proposal = find_proposal(&sent.proposals, model, provider)?;
    let expected = expected_claims(proposal)?;
    match output {
        AttestOutput::BackgroundCheck { provider, evidence } => {
            verifier
                .verify_evidence(*provider, evidence, expected)
                .await
        }
        AttestOutput::Passport { provider, token } => {
            verifier.verify_token(*provider, token, expected).await
        }
    }
    .context("evidence conversion or verification failed")
    .map(Some)
}

pub struct Evidence {
    pub provider: ProviderType,
    pub evidence: serde_json::Value,
}

#[async_trait::async_trait]
pub trait EvidenceProducer: Send + Sync {
    async fn produce(&self, claims: Claims) -> Result<Evidence>;
}

#[async_trait::async_trait]
pub trait TokenProducer: Send + Sync {
    async fn produce(&self, claims: Claims) -> Result<TngToken>;
}

/// Sent in place of the local error chain, which must not reach an unverified peer.
pub const ATTESTATION_UNAVAILABLE: &str = "attestation unavailable";

/// A background-check proposal arrived with an empty nonce.
pub const MISSING_NONCE: &str = "missing nonce";

/// Builds the transport's runtime data for the proposal [`pick_proposal`] matched.
pub trait AttestClaims: Sync {
    fn claims<'a>(
        &'a self,
        proposal: &'a AttestProposal,
    ) -> Pin<Box<dyn Future<Output = Result<Claims>> + Send + 'a>>;
}

/// A passport token cache whose lookup key stays inside the implementation.
pub trait PassportTokenCache: Sync {
    fn get_or_mint<'a>(
        &'a self,
        mint: Box<
            dyn FnOnce() -> Pin<Box<dyn Future<Output = Result<TngToken>> + Send + 'a>> + Send + 'a,
        >,
    ) -> Pin<Box<dyn Future<Output = Result<TngToken>> + Send + 'a>>;
}

/// Produce the output for a proposal that [`pick_proposal`] already matched.
///
/// `claims` builds this transport's runtime data for that proposal. Background check runs the
/// evidence producer. Passport reads `passport_cache` and mints on a miss. An empty background-check
/// nonce and a missing producer are public reasons. An attester or claims failure is
/// [`ATTESTATION_UNAVAILABLE`].
pub async fn produce_attest_response<C, R>(
    proposal: &AttestProposal,
    claims: &R,
    evidence_producer: Option<&dyn EvidenceProducer>,
    token_producer: Option<&dyn TokenProducer>,
    passport_cache: Option<&C>,
    max_retries: usize,
) -> AttestResponse
where
    C: PassportTokenCache,
    R: AttestClaims,
{
    match proposal {
        AttestProposal::BackgroundCheck {
            challenge_token, ..
        } => {
            if challenge_token.is_empty() {
                return error_response(MISSING_NONCE);
            }
            let Some(producer) = evidence_producer else {
                return error_response("not configured to attest");
            };
            let claims = match claims.claims(proposal).await {
                Ok(claims) => claims,
                Err(error) => {
                    tracing::error!(?error, "failed to build background-check claims");
                    return error_response(ATTESTATION_UNAVAILABLE);
                }
            };
            match produce_evidence_with_retry(producer, claims, max_retries).await {
                Ok(evidence) => evidence_response(evidence.provider, evidence.evidence),
                Err(error) => {
                    tracing::error!(?error, "Failed to produce background-check evidence");
                    error_response(ATTESTATION_UNAVAILABLE)
                }
            }
        }
        AttestProposal::Passport { .. } => {
            let Some(producer) = token_producer else {
                return error_response("not configured to attest");
            };
            let Some(cache) = passport_cache else {
                return error_response("not configured to attest");
            };
            match cache
                .get_or_mint(Box::new(move || {
                    let claims = claims.claims(proposal);
                    Box::pin(async move {
                        let claims = claims.await?;
                        produce_token_with_retry(producer, claims, max_retries).await
                    })
                }))
                .await
            {
                Ok(token) => token_response(token.provider_type(), token.as_str()),
                Err(error) => {
                    tracing::error!(?error, "Failed to produce passport token");
                    error_response(ATTESTATION_UNAVAILABLE)
                }
            }
        }
    }
}

async fn produce_token_with_retry<P: TokenProducer + ?Sized>(
    producer: &P,
    claims: Claims,
    max_retries: usize,
) -> Result<TngToken> {
    let policy = RetryPolicy::fixed(Duration::from_secs(1)).with_max_retries(max_retries);
    policy
        .retry(|| {
            let claims = claims.clone();
            async move {
                producer
                    .produce(claims)
                    .await
                    .context("Failed to generate attestation evidence")
            }
        })
        .await
}

async fn produce_evidence_with_retry<P: EvidenceProducer + ?Sized>(
    producer: &P,
    claims: Claims,
    max_retries: usize,
) -> Result<Evidence> {
    let policy = RetryPolicy::fixed(Duration::from_secs(1)).with_max_retries(max_retries);
    policy
        .retry(|| {
            let claims = claims.clone();
            async move {
                producer
                    .produce(claims)
                    .await
                    .context("Failed to generate attestation evidence")
            }
        })
        .await
}

#[async_trait::async_trait]
impl<A> EvidenceProducer for A
where
    A: GenericAttester<Evidence = TngEvidence> + Send + Sync,
{
    async fn produce(&self, claims: Claims) -> Result<Evidence> {
        let evidence = self
            .get_evidence(&ReportData::Claims(claims))
            .await
            .map_err(|error| anyhow!("attester failed: {error}"))?;
        Ok(Evidence {
            provider: evidence.provider_type(),
            evidence: evidence.serialize_to_json()?,
        })
    }
}

#[async_trait::async_trait]
impl<A> TokenProducer for A
where
    A: GenericAttester<Evidence = TngToken> + Send + Sync,
{
    async fn produce(&self, claims: Claims) -> Result<TngToken> {
        self.get_evidence(&ReportData::Claims(claims))
            .await
            .map_err(|error| anyhow!("attester failed: {error}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn response_json_shape() {
        assert_eq!(
            serde_json::to_value(error_response("not configured to attest")).unwrap(),
            json!({"Err": "not configured to attest"})
        );
        assert_eq!(
            serde_json::to_value(ack_response()).unwrap(),
            json!({"Ok": null})
        );
        assert_eq!(
            serde_json::to_value(evidence_response(ProviderType::Coco, json!({}))).unwrap(),
            json!({"Ok": {"background_check": {"provider": "coco", "evidence": {}}}})
        );
        assert_eq!(
            serde_json::to_value(token_response(ProviderType::Coco, "jwt")).unwrap(),
            json!({"Ok": {"passport": {"provider": "coco", "token": "jwt"}}})
        );
        assert!(serde_json::from_str::<AttestResponse>(r#"{"type":"ack"}"#).is_err());
    }

    #[test]
    fn pick_proposal_acks_only_an_empty_list() {
        assert!(matches!(pick_proposal(&[], None), Answer::Ack));
        assert!(matches!(
            pick_proposal(
                &[AttestProposal::Passport {
                    provider: ProviderType::Coco
                }],
                None
            ),
            Answer::Reject(_)
        ));
        let proposals = [AttestProposal::Passport {
            provider: ProviderType::Coco,
        }];
        assert!(matches!(
            pick_proposal(&proposals, Some((Model::Passport, ProviderType::Coco))),
            Answer::Matched(_)
        ));
    }

    #[tokio::test]
    async fn empty_request_accepts_only_an_ack() {
        let sent = AttestRequest::default();
        assert!(
            check_response(&sent, &ack_response(), None, |_| bail!("unused"))
                .await
                .unwrap()
                .is_none()
        );
        let err = check_response(
            &sent,
            &evidence_response(ProviderType::Coco, json!({})),
            None,
            |_| bail!("unused"),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("unsolicited"));
        let err = check_response(&sent, &error_response("nope"), None, |_| bail!("unused"))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("nope"));
    }
}
