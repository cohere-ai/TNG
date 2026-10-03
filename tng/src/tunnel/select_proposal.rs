//! Matching one [`AttestProposal`] out of a list.
//!
//! The attester uses [`match_proposal`] for an exact `(model, provider)` match. The verifier
//! uses [`find_proposal`] on the list it sent. [`crate::tunnel::attest::pick_proposal`] decides
//! whether that match is an ack, a proposal to answer, or a reject.

use std::collections::HashSet;

use anyhow::{anyhow, bail, Result};

use super::proposal::{AttestProposal, Model};
use super::provider::ProviderType;

/// Sent in place of the local configuration when nothing matches, which an unverified peer
/// has no need to learn.
#[cfg_attr(not(unix), allow(dead_code))]
pub const NO_COMPATIBLE_PROPOSAL: &str = "no compatible attestation proposal";

/// The proposal this attester answers. The attester never switches models, so anything but an
/// exact match is an error. A duplicate key in the received list is also an error.
#[cfg_attr(not(unix), allow(dead_code))]
pub fn match_proposal(
    own: (Model, ProviderType),
    proposals: &[AttestProposal],
) -> Result<&AttestProposal> {
    let mut seen = HashSet::new();
    if let Some((model, provider)) = proposals
        .iter()
        .map(AttestProposal::key)
        .find(|k| !seen.insert(*k))
    {
        bail!("duplicate proposal for ({model}, {provider})");
    }
    proposals.iter().find(|p| p.key() == own).ok_or_else(|| {
        let proposed: Vec<_> = proposals.iter().map(AttestProposal::key).collect();
        tracing::warn!(?proposed, ?own, "no proposal matches the local attester");
        anyhow!(NO_COMPATIBLE_PROPOSAL)
    })
}

/// The proposal the peer's answer belongs to, so evidence is checked against the nonce issued
/// for its own provider and never against another one.
pub fn find_proposal(
    proposals: &[AttestProposal],
    model: Model,
    provider: ProviderType,
) -> Result<&AttestProposal> {
    proposals
        .iter()
        .find(|p| p.key() == (model, provider))
        .ok_or_else(|| anyhow!("peer answered with ({model}, {provider}), which was not proposed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const COCO: ProviderType = ProviderType::Coco;
    const ITA: ProviderType = ProviderType::Ita;

    fn bc(provider: ProviderType, nonce: &str) -> AttestProposal {
        AttestProposal::BackgroundCheck {
            provider,
            challenge_token: nonce.into(),
        }
    }

    #[test]
    fn match_proposal_matches_exactly() {
        let proposals = [bc(COCO, "n"), AttestProposal::Passport { provider: ITA }];
        assert_eq!(
            match_proposal((Model::Passport, ITA), &proposals).unwrap(),
            &proposals[1]
        );
        assert_eq!(
            match_proposal((Model::BackgroundCheck, COCO), &proposals).unwrap(),
            &proposals[0]
        );
        let err = match_proposal((Model::Passport, COCO), &proposals).unwrap_err();
        assert_eq!(err.to_string(), NO_COMPATIBLE_PROPOSAL);
        assert!(match_proposal((Model::Passport, COCO), &[]).is_err());
    }

    #[test]
    fn match_proposal_rejects_duplicates() {
        let proposals = [bc(COCO, "a"), bc(COCO, "b")];
        let err = match_proposal((Model::BackgroundCheck, COCO), &proposals).unwrap_err();
        assert!(err.to_string().contains("duplicate"), "{err}");
    }

    #[test]
    fn find_proposal_binds_nonce_to_provider() {
        let proposals = [bc(COCO, "coco-nonce"), bc(ITA, "ita-nonce")];
        let proposal = find_proposal(&proposals, Model::BackgroundCheck, ITA).unwrap();
        assert_eq!(proposal.challenge_token(), Some("ita-nonce"));
        assert!(find_proposal(&proposals, Model::Passport, ITA).is_err());
        assert!(find_proposal(&[], Model::Passport, ITA).is_err());
    }
}
