//! Length-prefixed JSON bodies for the RA-TLS attestation exchange.
//!
//! A request is the verifier's [`AttestProposal`] list. A response is the one answer
//! the attester sends back, or an ack or error when there is nothing to attest.

use serde::{Deserialize, Serialize};

use crate::tunnel::proposal::AttestProposal;
use crate::tunnel::provider::ProviderType;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Empty when this side does not verify its peer.
    #[serde(default)]
    pub proposals: Vec<AttestProposal>,
}

/// One frame after the request. `ack` answers an empty proposal list. `error` is how this
/// handshake reports a failure, since it has no HTTP status.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    Ack,
    Evidence {
        provider: ProviderType,
        evidence: serde_json::Value,
    },
    Token {
        provider: ProviderType,
        token: String,
    },
    Error {
        reason: String,
    },
}
