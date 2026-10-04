//! Attestation request and response shared by RA-TLS and OHTTP.
//!
//! A request is the verifier's proposal list. A response is [`AttestResponse`]: `Ok(None)`
//! acks an empty request, `Ok(Some)` is the evidence or token, and `Err` is an [`AttestError`].
//! [`respond`] selects the proposal and fills that response. Background check produces evidence
//! per request; passport returns the [`Prepared`] token the transport minted with
//! [`mint_passport`] when it last rotated its key. A failure is [`crate::error::AttestError`].

use std::collections::HashSet;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use again::RetryPolicy;
use anyhow::{anyhow, bail, Context, Result};
use rats_cert::tee::claims::Claims;
use rats_cert::tee::{GenericAttester, ReportData};
use serde::{Deserialize, Serialize};

use crate::error::AttestError;
use crate::tunnel::attestation_result::AttestationResult;
use crate::tunnel::challenge::{ChallengeAttempt, ChallengeSource};
use crate::tunnel::proposal::{AttestProposal, Model};
use crate::tunnel::provider::{ProviderType, TngEvidence, TngToken};
use crate::tunnel::utils::maybe_cached::Expire;

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

pub fn evidence_response(provider: ProviderType, evidence: serde_json::Value) -> AttestResponse {
    Ok(Some(AttestOutput::BackgroundCheck { provider, evidence }))
}

pub fn token_response(provider: ProviderType, token: impl Into<String>) -> AttestResponse {
    Ok(Some(AttestOutput::Passport {
        provider,
        token: token.into(),
    }))
}

/// One proposal per verifier, fetching a fresh nonce for each background check concurrently. A
/// failed fetch only drops its own proposal, so an outage at one attestation service does not block
/// peers using another. `start_challenge` is called once per nonce fetch.
pub async fn make_proposals<A: ChallengeAttempt>(
    proposers: Vec<(ProviderType, Option<&dyn ChallengeSource>)>,
    start_challenge: impl Fn() -> A,
) -> Result<Vec<AttestProposal>> {
    let start_challenge = &start_challenge;
    let proposals: Vec<AttestProposal> = futures::future::join_all(proposers.iter().map(
        |&(provider, nonce_source)| async move {
            let Some(nonce_source) = nonce_source else {
                return Some(AttestProposal::Passport { provider });
            };
            let attempt = start_challenge();
            let nonce = nonce_source.get_nonce().await.and_then(|nonce| {
                if nonce.is_empty() {
                    bail!("converter returned an empty nonce");
                }
                Ok(nonce)
            });
            match nonce {
                Ok(challenge_token) => {
                    attempt.succeeded();
                    Some(AttestProposal::BackgroundCheck {
                        provider,
                        challenge_token,
                    })
                }
                Err(error) => {
                    tracing::warn!(%provider, ?error, "Dropping background-check proposal");
                    None
                }
            }
        },
    ))
    .await
    .into_iter()
    .flatten()
    .collect();

    if !proposers.is_empty() && proposals.is_empty() {
        bail!("failed to fetch a nonce for any background-check verifier");
    }
    Ok(proposals)
}

/// The proposal this attester answers.
///
/// An empty list is `Ok(None)`. A non-empty list needs an exact `(model, provider)` match.
/// A duplicate key is an error, and so is a list this side cannot answer.
fn pick_proposal(
    proposals: &[AttestProposal],
    own_key: Option<(Model, ProviderType)>,
) -> Result<Option<&AttestProposal>, AttestError> {
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

/// The local attester as [`respond`] sees it.
#[derive(Clone, Copy)]
pub enum Attester<'a> {
    BackgroundCheck {
        provider: ProviderType,
        producer: &'a dyn EvidenceProducer,
        max_retries: usize,
    },
    /// Answers only from a [`Prepared`] token.
    Passport { provider: ProviderType },
}

impl Attester<'_> {
    pub fn key(&self) -> (Model, ProviderType) {
        match self {
            Self::BackgroundCheck { provider, .. } => (Model::BackgroundCheck, *provider),
            Self::Passport { provider } => (Model::Passport, *provider),
        }
    }
}

/// How long before a prepared token's `exp` its snapshot is rebuilt, so the new token is
/// published before the old one lapses.
const PREPARED_EARLY_REFRESH: Duration = Duration::from_secs(30);

/// What this side attests with before any request arrives: nothing for background check, the
/// passport token for passport. Transports keep it beside the key it binds and never look inside.
#[derive(Clone, Default)]
pub struct Prepared(Option<Arc<TngToken>>);

impl Prepared {
    /// When the snapshot holding this value should be rebuilt.
    pub fn expire(&self) -> Result<Expire> {
        let Some(token) = &self.0 else {
            return Ok(Expire::NoExpire);
        };
        let exp = token.exp()?;
        let early = exp.saturating_sub(PREPARED_EARLY_REFRESH.as_secs());
        // Too close to `exp` to refresh early: refresh at `exp` instead of in a tight loop.
        Expire::from_timestamp(early).or_else(|_| Expire::from_timestamp(exp))
    }

    fn unexpired_token(&self) -> Option<&TngToken> {
        self.0
            .as_deref()
            .filter(|token| token.exp().and_then(Expire::from_timestamp).is_ok())
    }
}

/// Mint a passport token over `claims(nonce)`, with a fresh nonce from this side's own
/// attestation service on every attempt.
pub async fn mint_passport(
    nonce_source: &dyn ChallengeSource,
    producer: &dyn TokenProducer,
    claims: impl Fn(&str) -> Result<Claims>,
    max_retries: usize,
) -> Result<Prepared> {
    let token = with_retry(max_retries, || async {
        let nonce = nonce_source.get_nonce().await?;
        producer.produce(claims(&nonce)?).await
    })
    .await?;
    Ok(Prepared(Some(Arc::new(token))))
}

/// Select a proposal from `request` and produce its output.
///
/// An empty list is an ack. Background check runs the evidence producer over
/// `claims(verifier_nonce)`. Passport returns the `prepared` token and never mints; a missing
/// or expired token is [`AttestError::Unavailable`], as is an attester or claims failure.
/// Every other error is a request this side will not answer.
pub async fn respond(
    request: &AttestRequest,
    attester: Option<Attester<'_>>,
    prepared: &Prepared,
    claims: impl Fn(&str) -> Result<Claims>,
) -> AttestResponse {
    let Some(proposal) = pick_proposal(&request.proposals, attester.map(|a| a.key()))? else {
        return Ok(None);
    };
    match (proposal, attester) {
        (
            AttestProposal::BackgroundCheck {
                challenge_token, ..
            },
            Some(Attester::BackgroundCheck {
                producer,
                max_retries,
                ..
            }),
        ) => {
            if challenge_token.is_empty() {
                return Err(AttestError::MissingNonce);
            }
            let claims = match claims(challenge_token) {
                Ok(claims) => claims,
                Err(error) => {
                    tracing::error!(?error, "failed to build background-check claims");
                    return Err(AttestError::Unavailable);
                }
            };
            match with_retry(max_retries, || producer.produce(claims.clone())).await {
                Ok(evidence) => evidence_response(evidence.provider, evidence.evidence),
                Err(error) => {
                    tracing::error!(?error, "Failed to produce background-check evidence");
                    Err(AttestError::Unavailable)
                }
            }
        }
        (AttestProposal::Passport { .. }, Some(Attester::Passport { .. })) => {
            match prepared.unexpired_token() {
                Some(token) => token_response(token.provider_type(), token.as_str()),
                None => {
                    tracing::error!("no unexpired prepared passport token");
                    Err(AttestError::Unavailable)
                }
            }
        }
        _ => Err(AttestError::NotConfigured),
    }
}

async fn with_retry<T, F, Fut>(max_retries: usize, task: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    RetryPolicy::fixed(Duration::from_secs(1))
        .with_max_retries(max_retries)
        .retry(task)
        .await
        .context("Failed to generate attestation evidence")
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
            serde_json::to_value::<AttestResponse>(Err(AttestError::NotConfigured)).unwrap(),
            json!({"Err": "not_configured"})
        );
        assert_eq!(
            serde_json::to_value::<AttestResponse>(Err(AttestError::DuplicateProposal {
                model: Model::BackgroundCheck,
                provider: ProviderType::Coco,
            }))
            .unwrap(),
            json!({"Err": {"duplicate_proposal": {"model": "background_check", "provider": "coco"}}})
        );
        assert_eq!(
            serde_json::to_value::<AttestResponse>(Ok(None)).unwrap(),
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

    fn request(proposals: Vec<AttestProposal>) -> AttestRequest {
        AttestRequest { proposals }
    }

    fn unused_claims(_nonce: &str) -> Result<Claims> {
        bail!("claims should not be built")
    }

    struct FailingProducer;

    #[async_trait::async_trait]
    impl EvidenceProducer for FailingProducer {
        async fn produce(&self, _claims: Claims) -> Result<Evidence> {
            bail!("attester down")
        }
    }

    fn failing_bc_attester() -> Attester<'static> {
        Attester::BackgroundCheck {
            provider: COCO,
            producer: &FailingProducer,
            max_retries: 0,
        }
    }

    #[tokio::test]
    async fn respond_acks_an_empty_list_and_rejects_one_it_cannot_answer() {
        let none = Prepared::default();
        let ack = respond(&request(vec![]), None, &none, unused_claims).await;
        assert_eq!(ack, Ok(None));

        let err = respond(
            &request(vec![AttestProposal::Passport { provider: COCO }]),
            None,
            &none,
            unused_claims,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AttestError::NotConfigured));

        let err = respond(
            &request(vec![bc(COCO, "")]),
            Some(failing_bc_attester()),
            &none,
            unused_claims,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AttestError::MissingNonce));
    }

    #[tokio::test]
    async fn respond_fails_closed_when_attesting_is_unavailable() {
        let resp = respond(
            &request(vec![bc(COCO, "n")]),
            Some(failing_bc_attester()),
            &Prepared::default(),
            |_| Ok(Claims::new()),
        )
        .await;
        assert_eq!(resp, Err(AttestError::Unavailable));

        let passport = request(vec![AttestProposal::Passport { provider: COCO }]);
        let attester = Some(Attester::Passport { provider: COCO });
        for prepared in [Prepared::default(), prepared_with_exp(now_secs() - 1)] {
            let resp = respond(&passport, attester, &prepared, unused_claims).await;
            assert_eq!(resp, Err(AttestError::Unavailable));
        }

        let fresh = prepared_with_exp(now_secs() + 3600);
        let resp = respond(&passport, attester, &fresh, unused_claims).await;
        assert!(matches!(resp, Ok(Some(AttestOutput::Passport { .. }))));
    }

    #[test]
    fn prepared_expires_early_unless_too_close() {
        assert_eq!(Prepared::default().expire().unwrap(), Expire::NoExpire);

        let exp = now_secs() + 3600;
        assert_eq!(
            prepared_with_exp(exp).expire().unwrap(),
            Expire::ExpireAt(at(exp) - PREPARED_EARLY_REFRESH)
        );

        let exp = now_secs() + 10;
        assert_eq!(
            prepared_with_exp(exp).expire().unwrap(),
            Expire::ExpireAt(at(exp))
        );
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn at(secs: u64) -> std::time::SystemTime {
        std::time::UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn prepared_with_exp(exp: u64) -> Prepared {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        let payload = URL_SAFE_NO_PAD.encode(json!({ "exp": exp }).to_string());
        let jwt = format!("e30.{payload}.c2ln");
        Prepared(Some(Arc::new(TngToken::from_wire(COCO, jwt).unwrap())))
    }

    const COCO: ProviderType = ProviderType::Coco;
    const ITA: ProviderType = ProviderType::Ita;

    fn bc(provider: ProviderType, nonce: &str) -> AttestProposal {
        AttestProposal::BackgroundCheck {
            provider,
            challenge_token: nonce.into(),
        }
    }

    struct FixedNonce(Option<&'static str>);

    #[async_trait::async_trait]
    impl ChallengeSource for FixedNonce {
        async fn get_nonce(&self) -> Result<String> {
            self.0
                .map(str::to_string)
                .context("attestation service down")
        }
    }

    #[tokio::test]
    async fn make_proposals_drops_only_failed_nonce_fetches() {
        let (up, down) = (FixedNonce(Some("n")), FixedNonce(None));
        let proposals = make_proposals(
            vec![(COCO, Some(&down)), (ITA, Some(&up)), (COCO, None)],
            || (),
        )
        .await
        .unwrap();
        assert_eq!(
            proposals,
            vec![bc(ITA, "n"), AttestProposal::Passport { provider: COCO }]
        );

        let err = make_proposals(vec![(COCO, Some(&down))], || ())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("any"), "{err}");
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
        assert!(check_response(&sent, &Ok(None), None, |_| bail!("unused"))
            .await
            .unwrap()
            .is_none());
        let err = check_response(
            &sent,
            &evidence_response(ProviderType::Coco, json!({})),
            None,
            |_| bail!("unused"),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("unsolicited"));
        let err = check_response(&sent, &Err(AttestError::Unavailable), None, |_| {
            bail!("unused")
        })
        .await
        .unwrap_err();
        assert!(err.to_string().contains("attestation unavailable"));
    }
}
