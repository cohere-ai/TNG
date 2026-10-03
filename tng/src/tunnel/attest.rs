//! Attestation request and response shared by RA-TLS and OHTTP.
//!
//! A request is the verifier's proposal list. A response is [`AttestResponse`]: `Ok(None)`
//! acks an empty request, `Ok(Some)` is the evidence or token, and `Err` is an [`AttestError`].
//! [`produce_attest_response`] selects the proposal and fills that response. It chooses
//! background check or passport. The caller supplies the claims and a passport-token cache.
//! A failure is [`crate::error::AttestError`].

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use again::RetryPolicy;
use anyhow::{anyhow, bail, Context, Result};
use rats_cert::tee::claims::Claims;
use rats_cert::tee::{GenericAttester, ReportData};
use serde::{Deserialize, Serialize};

use crate::error::AttestError;
use crate::tunnel::attestation_result::AttestationResult;
use crate::tunnel::proposal::{AttestProposal, Model};
use crate::tunnel::provider::{ProviderType, TngEvidence, TngToken};

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

/// `Ok(None)` acks an empty proposal list. `Err` is the [`AttestError`] the peer matches.
pub type AttestResponse = Result<Option<AttestOutput>, AttestError>;

pub fn ack_response() -> AttestResponse {
    Ok(None)
}

pub fn error_response(error: AttestError) -> AttestResponse {
    Err(error)
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

/// The proposal this attester answers.
///
/// An empty list is `Ok(None)`. A non-empty list needs an exact `(model, provider)` match.
/// A duplicate key is an error, and so is a list this side cannot answer.
fn pick_proposal<'a>(
    proposals: &'a [AttestProposal],
    own_key: Option<(Model, ProviderType)>,
) -> Result<Option<&'a AttestProposal>, AttestError> {
    if proposals.is_empty() {
        return Ok(None);
    }
    let Some(own_key) = own_key else {
        return Err(AttestError::NotConfigured);
    };
    let mut seen = HashSet::new();
    if let Some((model, provider)) = proposals
        .iter()
        .map(AttestProposal::key)
        .find(|key| !seen.insert(*key))
    {
        return Err(AttestError::DuplicateProposal { model, provider });
    }
    proposals
        .iter()
        .find(|proposal| proposal.key() == own_key)
        .map(Some)
        .ok_or_else(|| {
            let proposed: Vec<_> = proposals.iter().map(AttestProposal::key).collect();
            tracing::warn!(
                ?proposed,
                ?own_key,
                "no proposal matches the local attester"
            );
            AttestError::NoCompatibleProposal
        })
}

/// The proposal the peer's answer belongs to, so evidence is checked against the nonce issued
/// for its own provider and never against another one.
fn find_proposal(
    proposals: &[AttestProposal],
    model: Model,
    provider: ProviderType,
) -> Result<&AttestProposal> {
    proposals
        .iter()
        .find(|p| p.key() == (model, provider))
        .ok_or_else(|| anyhow!("peer answered with ({model}, {provider}), which was not proposed"))
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
            Err(error) => bail!("peer sent an error: {error}"),
        };
    }

    let output = match got {
        Err(error) => bail!("peer attestation failed: {error}"),
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

/// Builds the transport's runtime data for the proposal this side answers.
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

/// Select a proposal from `request` and produce its output.
///
/// An empty list is an ack. `claims` builds this transport's runtime data for the matched
/// proposal. Background check runs the evidence producer. Passport reads `passport_cache` and
/// mints on a miss. [`AttestError::Unavailable`] is an attester or claims failure. Every
/// other error is a request this side will not answer.
pub async fn produce_attest_response<C, R>(
    request: &AttestRequest,
    own_key: Option<(Model, ProviderType)>,
    claims: &R,
    evidence_producer: Option<&dyn EvidenceProducer>,
    token_producer: Option<&dyn TokenProducer>,
    passport_cache: Option<&C>,
    max_retries: usize,
) -> Result<AttestResponse, AttestError>
where
    C: PassportTokenCache,
    R: AttestClaims,
{
    let Some(proposal) = pick_proposal(&request.proposals, own_key)? else {
        return Ok(ack_response());
    };
    match proposal {
        AttestProposal::BackgroundCheck {
            challenge_token, ..
        } => {
            if challenge_token.is_empty() {
                return Err(AttestError::MissingNonce);
            }
            let Some(producer) = evidence_producer else {
                return Err(AttestError::NotConfigured);
            };
            let claims = match claims.claims(proposal).await {
                Ok(claims) => claims,
                Err(error) => {
                    tracing::error!(?error, "failed to build background-check claims");
                    return Err(AttestError::Unavailable);
                }
            };
            match produce_evidence_with_retry(producer, claims, max_retries).await {
                Ok(evidence) => Ok(evidence_response(evidence.provider, evidence.evidence)),
                Err(error) => {
                    tracing::error!(?error, "Failed to produce background-check evidence");
                    Err(AttestError::Unavailable)
                }
            }
        }
        AttestProposal::Passport { .. } => {
            let Some(producer) = token_producer else {
                return Err(AttestError::NotConfigured);
            };
            let Some(cache) = passport_cache else {
                return Err(AttestError::NotConfigured);
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
                Ok(token) => Ok(token_response(token.provider_type(), token.as_str())),
                Err(error) => {
                    tracing::error!(?error, "Failed to produce passport token");
                    Err(AttestError::Unavailable)
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
            serde_json::to_value(error_response(AttestError::NotConfigured)).unwrap(),
            json!({"Err": "not_configured"})
        );
        assert_eq!(
            serde_json::to_value(error_response(AttestError::DuplicateProposal {
                model: Model::BackgroundCheck,
                provider: ProviderType::Coco,
            }))
            .unwrap(),
            json!({"Err": {"duplicate_proposal": {"model": "background_check", "provider": "coco"}}})
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

    struct UnusedClaims;

    impl AttestClaims for UnusedClaims {
        fn claims<'a>(
            &'a self,
            _proposal: &'a AttestProposal,
        ) -> Pin<Box<dyn Future<Output = Result<Claims>> + Send + 'a>> {
            Box::pin(async { bail!("claims should not be built") })
        }
    }

    struct NoCache;

    impl PassportTokenCache for NoCache {
        fn get_or_mint<'a>(
            &'a self,
            _mint: Box<
                dyn FnOnce() -> Pin<Box<dyn Future<Output = Result<TngToken>> + Send + 'a>>
                    + Send
                    + 'a,
            >,
        ) -> Pin<Box<dyn Future<Output = Result<TngToken>> + Send + 'a>> {
            Box::pin(async { bail!("cache should not be consulted") })
        }
    }

    fn request(proposals: Vec<AttestProposal>) -> AttestRequest {
        AttestRequest { proposals }
    }

    #[tokio::test]
    async fn produce_acks_an_empty_list_and_rejects_one_it_cannot_answer() {
        let ack = produce_attest_response(
            &request(vec![]),
            None,
            &UnusedClaims,
            None,
            None,
            None::<&NoCache>,
            0,
        )
        .await
        .unwrap();
        assert_eq!(ack, ack_response());

        let err = produce_attest_response(
            &request(vec![AttestProposal::Passport {
                provider: ProviderType::Coco,
            }]),
            None,
            &UnusedClaims,
            None,
            None,
            None::<&NoCache>,
            0,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AttestError::NotConfigured));

        let err = produce_attest_response(
            &request(vec![AttestProposal::BackgroundCheck {
                provider: ProviderType::Coco,
                challenge_token: String::new(),
            }]),
            Some((Model::BackgroundCheck, ProviderType::Coco)),
            &UnusedClaims,
            None,
            None,
            None::<&NoCache>,
            0,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AttestError::MissingNonce));
    }

    const COCO: ProviderType = ProviderType::Coco;
    const ITA: ProviderType = ProviderType::Ita;

    fn bc(provider: ProviderType, nonce: &str) -> AttestProposal {
        AttestProposal::BackgroundCheck {
            provider,
            challenge_token: nonce.into(),
        }
    }

    #[test]
    fn pick_proposal_matches_exactly() {
        let proposals = [bc(COCO, "n"), AttestProposal::Passport { provider: ITA }];
        assert_eq!(
            pick_proposal(&proposals, Some((Model::Passport, ITA)))
                .unwrap()
                .unwrap(),
            &proposals[1]
        );
        assert_eq!(
            pick_proposal(&proposals, Some((Model::BackgroundCheck, COCO)))
                .unwrap()
                .unwrap(),
            &proposals[0]
        );
        assert!(matches!(
            pick_proposal(&proposals, Some((Model::Passport, COCO))).unwrap_err(),
            AttestError::NoCompatibleProposal
        ));
        assert!(pick_proposal(&[], Some((Model::Passport, COCO)))
            .unwrap()
            .is_none());
    }

    #[test]
    fn pick_proposal_rejects_duplicates() {
        let proposals = [bc(COCO, "a"), bc(COCO, "b")];
        let err = pick_proposal(&proposals, Some((Model::BackgroundCheck, COCO))).unwrap_err();
        assert!(
            matches!(err, AttestError::DuplicateProposal { .. }),
            "{err}"
        );
    }

    #[test]
    fn find_proposal_binds_nonce_to_provider() {
        let proposals = [bc(COCO, "coco-nonce"), bc(ITA, "ita-nonce")];
        let proposal = find_proposal(&proposals, Model::BackgroundCheck, ITA).unwrap();
        assert_eq!(proposal.challenge_token(), Some("ita-nonce"));
        assert!(find_proposal(&proposals, Model::Passport, ITA).is_err());
        assert!(find_proposal(&[], Model::Passport, ITA).is_err());
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
        let err = check_response(
            &sent,
            &error_response(AttestError::Unavailable),
            None,
            |_| bail!("unused"),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("attestation unavailable"));
    }
}
