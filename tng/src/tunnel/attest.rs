//! Attestation request and response shared by RA-TLS and OHTTP.
//!
//! A request is the verifier's proposal list. A response is [`AttestResponse`]: `Ok(None)`
//! acks an empty request, `Ok(Some)` is the evidence or token, and `Err` is an [`AttestError`].
//! [`respond`] selects the proposal and fills that response. Background check produces evidence
//! per request; passport returns the [`Prepared`] token the transport minted when it last
//! rotated its key. A failure is [`crate::error::AttestError`].

use std::collections::HashSet;
use std::fmt;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use again::RetryPolicy;
use anyhow::{anyhow, bail, Context, Result};
use rats_cert::tee::claims::Claims;
use rats_cert::tee::GenericConverter;
use serde::{Deserialize, Serialize};

use crate::error::AttestError;
use crate::tunnel::attestation_result::AttestationResult;
use crate::tunnel::provider::{ProviderType, TngToken};
use crate::tunnel::utils::maybe_cached::Expire;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Model {
    BackgroundCheck,
    Passport,
}

impl fmt::Display for Model {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BackgroundCheck => "background_check",
            Self::Passport => "passport",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "model", rename_all = "snake_case")]
/// One way a verifier will accept attestation: a scheme, `(model, provider)`, plus the fresh
/// data that scheme needs.
pub enum AttestProposal {
    BackgroundCheck {
        provider: ProviderType,
        challenge_token: String,
    },
    Passport {
        provider: ProviderType,
    },
}

impl AttestProposal {
    pub fn key(&self) -> (Model, ProviderType) {
        match self {
            Self::BackgroundCheck { provider, .. } => (Model::BackgroundCheck, *provider),
            Self::Passport { provider } => (Model::Passport, *provider),
        }
    }

    pub fn challenge_token(&self) -> Option<&str> {
        match self {
            Self::BackgroundCheck {
                challenge_token, ..
            } => Some(challenge_token),
            Self::Passport { .. } => None,
        }
    }
}

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

/// A source of fresh nonces: the verifier's for a background-check proposal, the attester's own
/// for minting a passport token.
#[async_trait::async_trait]
pub trait ChallengeSource: Send + Sync {
    async fn get_nonce(&self) -> Result<String>;
}

#[async_trait::async_trait]
impl<C> ChallengeSource for C
where
    C: GenericConverter<Nonce = String> + Send + Sync,
{
    async fn get_nonce(&self) -> Result<String> {
        GenericConverter::get_nonce(self)
            .await
            .map_err(|e| anyhow!("converter errors while fetching the nonce: {e}"))
    }
}

/// A nonce fetch in progress; dropping it without [`Self::succeeded`] records a failure, so a
/// fetch cut short by a timeout still counts.
pub trait ChallengeAttempt {
    fn succeeded(self);
}

impl ChallengeAttempt for () {
    fn succeeded(self) {}
}

#[cfg(unix)]
impl ChallengeAttempt for Option<crate::tunnel::attestation_metrics::AttestationAttempt> {
    fn succeeded(self) {
        if let Some(attempt) = self {
            attempt.mark_succeeded();
        }
    }
}

/// One configured verifier as a request sees it: its provider and, for background check, where to
/// fetch the nonce (`None` is passport).
pub type Proposer<'a> = (ProviderType, Option<&'a dyn ChallengeSource>);

/// The request for one exchange: one proposal per verifier, fetching a fresh nonce for each
/// background check concurrently. A failed fetch only drops its own proposal, so an outage at one
/// attestation service does not block peers using another. No proposers is an empty request.
///
/// `start_challenge` starts a metrics record before each nonce fetch; the attempt counts as failed
/// unless the fetch succeeds. Pass `|| ()` to record nothing.
pub async fn make_request<A: ChallengeAttempt>(
    proposers: &[Proposer<'_>],
    start_challenge: impl Fn() -> A,
) -> Result<AttestRequest> {
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

    // Check if a proposer failed to fetch nonce, passport proposer cannot fail
    if !proposers.is_empty() && proposals.is_empty() {
        bail!("failed to fetch a nonce for any background-check verifier");
    }
    Ok(AttestRequest { proposals })
}

/// One configured verifier, which checks answers for its own `(model, provider)`.
#[async_trait::async_trait]
pub trait Verifier: Send + Sync {
    fn key(&self) -> (Model, ProviderType);

    async fn verify_evidence(
        &self,
        evidence: &serde_json::Value,
        expected: Claims,
    ) -> Result<AttestationResult>;

    async fn verify_token(&self, jwt: &str, expected: Claims) -> Result<AttestationResult>;
}

/// Check `got` against the proposals in `sent`.
///
/// An empty request accepts only `Ok(None)`. A non-empty request accepts only an answer whose
/// `(model, provider)` was proposed, checked by the verifier with that key against the claims
/// `expected_claims` builds for the matched proposal.
pub async fn check_response(
    sent: &AttestRequest,
    got: &AttestResponse,
    verifiers: &[&dyn Verifier],
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
    let (model, provider) = output.key();
    // Evidence is checked against the nonce issued for its own provider, never another one.
    let proposal = sent
        .proposals
        .iter()
        .find(|p| p.key() == (model, provider))
        .with_context(|| {
            format!("peer answered with ({model}, {provider}), which was not proposed")
        })?;
    let verifier = verifiers
        .iter()
        .find(|v| v.key() == (model, provider))
        .with_context(|| format!("no verifier is configured for ({model}, {provider})"))?;
    let expected = expected_claims(proposal)?;
    match output {
        AttestOutput::BackgroundCheck { evidence, .. } => {
            verifier.verify_evidence(evidence, expected).await
        }
        AttestOutput::Passport { token, .. } => verifier.verify_token(token, expected).await,
    }
    .context("evidence conversion or verification failed")
    .map(Some)
}

/// The local attester, which answers proposals for its own `(model, provider)`.
#[async_trait::async_trait]
pub trait Attester: Send + Sync {
    fn key(&self) -> (Model, ProviderType);

    /// Background check only: evidence over `claims`, as sent on the wire. Passport answers from
    /// a [`Prepared`] token instead.
    async fn produce_evidence(&self, claims: Claims) -> Result<serde_json::Value>;
}

/// How long before a prepared token's `exp` its snapshot is rebuilt, so the new token is
/// published before the old one lapses.
const PREPARED_EARLY_REFRESH: Duration = Duration::from_secs(30);

/// What attesting side attests with before any request arrives: nothing for background check, the
/// passport token for passport. Transports keep it beside the key it binds and never look inside.
#[derive(Clone, Default)]
pub struct Prepared(Option<Arc<TngToken>>);

impl Prepared {
    pub fn new(token: TngToken) -> Self {
        Self(Some(Arc::new(token)))
    }

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

/// Select a proposal from `request` and produce its output.
///
/// An empty list is an ack. Background check runs the evidence producer over
/// `claims(verifier_nonce)`. Passport returns the `prepared` token and never mints; a missing
/// or expired token is [`AttestError::Unavailable`], as is an attester or claims failure.
/// Every other error is a request this side will not answer.
pub async fn respond(
    request: &AttestRequest,
    attester: Option<&dyn Attester>,
    prepared: &Prepared,
    claims: impl Fn(&str) -> Result<Claims>,
) -> AttestResponse {
    let Some(proposal) = pick_proposal(&request.proposals, attester.map(|a| a.key()))? else {
        return Ok(None);
    };
    let attester = attester.ok_or(AttestError::NotConfigured)?;
    match proposal {
        AttestProposal::BackgroundCheck {
            provider,
            challenge_token,
        } => {
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
            match attester.produce_evidence(claims).await {
                Ok(evidence) => evidence_response(*provider, evidence),
                Err(error) => {
                    tracing::error!(?error, "Failed to produce background-check evidence");
                    Err(AttestError::Unavailable)
                }
            }
        }
        AttestProposal::Passport { .. } => match prepared.unexpired_token() {
            Some(token) => token_response(token.provider_type(), token.as_str()),
            None => {
                tracing::error!("no unexpired prepared passport token");
                Err(AttestError::Unavailable)
            }
        },
    }
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
    let own_key = own_key.ok_or(AttestError::NotConfigured)?;
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

pub(crate) async fn with_retry<T, F, Fut>(max_retries: usize, task: F) -> Result<T>
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn proposal_json_shape() {
        let proposals = [
            AttestProposal::BackgroundCheck {
                provider: ProviderType::Coco,
                challenge_token: "n".into(),
            },
            AttestProposal::Passport {
                provider: ProviderType::Ita,
            },
        ];
        let json = serde_json::to_value(proposals).unwrap();
        assert_eq!(
            json,
            serde_json::json!([
                {"model": "background_check", "provider": "coco", "challenge_token": "n"},
                {"model": "passport", "provider": "ita"},
            ])
        );
        assert!(serde_json::from_value::<AttestProposal>(
            serde_json::json!({"model": "passport", "provider": "bad_provider"})
        )
        .is_err());
    }

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

    /// An attester whose evidence production always fails.
    struct FailingAttester(Model);

    #[async_trait::async_trait]
    impl Attester for FailingAttester {
        fn key(&self) -> (Model, ProviderType) {
            (self.0, COCO)
        }

        async fn produce_evidence(&self, _claims: Claims) -> Result<serde_json::Value> {
            bail!("attester down")
        }
    }

    const FAILING_BC: FailingAttester = FailingAttester(Model::BackgroundCheck);

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
            Some(&FAILING_BC),
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
            Some(&FAILING_BC),
            &Prepared::default(),
            |_| Ok(Claims::new()),
        )
        .await;
        assert_eq!(resp, Err(AttestError::Unavailable));

        let passport = request(vec![AttestProposal::Passport { provider: COCO }]);
        let attester: Option<&dyn Attester> = Some(&FailingAttester(Model::Passport));
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
    async fn make_request_drops_only_failed_nonce_fetches() {
        let (up, down) = (FixedNonce(Some("n")), FixedNonce(None));
        let request = make_request(
            &[(COCO, Some(&down)), (ITA, Some(&up)), (COCO, None)],
            || (),
        )
        .await
        .unwrap();
        assert_eq!(
            request.proposals,
            vec![bc(ITA, "n"), AttestProposal::Passport { provider: COCO }]
        );
        assert_eq!(
            make_request(&[], || ()).await.unwrap(),
            AttestRequest::default()
        );

        let err = make_request(&[(COCO, Some(&down))], || ())
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

    struct UnusedVerifier;

    #[async_trait::async_trait]
    impl Verifier for UnusedVerifier {
        fn key(&self) -> (Model, ProviderType) {
            (Model::BackgroundCheck, ITA)
        }

        async fn verify_evidence(
            &self,
            _: &serde_json::Value,
            _: Claims,
        ) -> Result<AttestationResult> {
            bail!("unused")
        }

        async fn verify_token(&self, _: &str, _: Claims) -> Result<AttestationResult> {
            bail!("unused")
        }
    }

    #[tokio::test]
    async fn check_response_binds_the_answer_to_its_own_proposal() {
        let sent = AttestRequest {
            proposals: vec![bc(COCO, "coco-nonce"), bc(ITA, "ita-nonce")],
        };
        let check = |got| {
            let sent = &sent;
            async move {
                check_response(sent, &got, &[&UnusedVerifier], |p| {
                    bail!("claims for {:?}", p.challenge_token())
                })
                .await
                .unwrap_err()
                .to_string()
            }
        };
        assert!(check(evidence_response(ITA, json!({})))
            .await
            .contains("ita-nonce"));
        assert!(check(token_response(ITA, "t"))
            .await
            .contains("not proposed"));
    }

    #[tokio::test]
    async fn empty_request_accepts_only_an_ack() {
        let sent = AttestRequest::default();
        assert!(check_response(&sent, &Ok(None), &[], |_| bail!("unused"))
            .await
            .unwrap()
            .is_none());
        let err = check_response(
            &sent,
            &evidence_response(ProviderType::Coco, json!({})),
            &[],
            |_| bail!("unused"),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("unsolicited"));
        let err = check_response(&sent, &Err(AttestError::Unavailable), &[], |_| {
            bail!("unused")
        })
        .await
        .unwrap_err();
        assert!(err.to_string().contains("attestation unavailable"));
    }
}
