use serde::{Deserialize, Serialize};

use crate::tunnel::attest::{AttestRequest, AttestResponse};

pub mod header;
pub mod metadata;
pub mod userdata;

/// Request structure for the key configuration endpoint
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct KeyConfigRequest {
    /// Proposals from the client. Empty when it does not verify the server.
    #[serde(default)]
    pub attest_request: AttestRequest,
}

/// Successful key-config body. An attestation failure is an HTTP error, not this struct.
#[derive(Serialize, Deserialize, Debug)]
pub struct KeyConfigResponse {
    /// HPKE (Hybrid Public Key Encryption) key configuration
    pub hpke_key_config: HpkeKeyConfig,

    pub attest_response: AttestResponse,
}

/// HPKE key configuration structure
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct HpkeKeyConfig {
    /// Expiration timestamp for this configuration
    pub expire_timestamp: u64,

    /// A base64 encoded list of key configurations, each entry is a Individual key configuration entry. Defined in Section 3.1 of RFC 9458.
    pub encoded_key_config_list: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::attest::AttestProposal;
    use crate::tunnel::provider::ProviderType;
    use serde_json::json;

    #[test]
    fn key_config_request_wire_shape() {
        let req: KeyConfigRequest = serde_json::from_value(json!({
            "attest_request": {"proposals": [{"model": "passport", "provider": "ita"}]}
        }))
        .unwrap();
        assert_eq!(
            req.attest_request.proposals,
            vec![AttestProposal::Passport {
                provider: ProviderType::Ita
            }]
        );
        assert!(serde_json::from_value::<KeyConfigRequest>(json!({}))
            .unwrap()
            .attest_request
            .proposals
            .is_empty());
        // A bare proposal list is not a key-config request.
        assert!(serde_json::from_value::<KeyConfigRequest>(
            json!({"proposals": [{"model": "passport", "provider": "ita"}]})
        )
        .is_err());
    }

    #[test]
    fn key_config_response_includes_the_key() {
        let ok = KeyConfigResponse {
            hpke_key_config: HpkeKeyConfig {
                expire_timestamp: 1,
                encoded_key_config_list: "a".into(),
            },
            attest_response: Ok(None),
        };
        let value = serde_json::to_value(&ok).unwrap();
        assert!(value.get("hpke_key_config").is_some());
        assert_eq!(value["attest_response"], json!({"Ok": null}));
    }
}
