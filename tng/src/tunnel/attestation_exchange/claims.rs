use anyhow::Result;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use rats_cert::cert::dice::cbor::generate_pubkey_hash_value_buffer;
use rats_cert::crypto::{DefaultCrypto, HashAlgo};
use rats_cert::tee::claims::Claims;

pub const CLAIM_PUBKEY_HASH: &str = "pubkey-hash";
pub const CLAIM_CHALLENGE_TOKEN: &str = "challenge_token";
pub const CLAIM_TLS_BINDER: &str = "tls-binder";

/// TLS-Exporter label from `draft-fossati-seat-expat` §5.1.
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-SEAT-Attestation";
pub const EXPORTER_LEN: usize = 32;

/// Inputs required to build a background-check expectation. All fields are required so a
/// partial map cannot be constructed and then silently pass the subset comparison.
pub struct BackgroundCheckExpectation<'a> {
    pub peer_spki_der: &'a [u8],
    pub issued_nonce: &'a str,
    pub exporter: &'a [u8],
}

/// Passport expectation is SPKI only: no binder, no nonce comparison.
pub struct PassportExpectation<'a> {
    pub peer_spki_der: &'a [u8],
}

pub fn background_check_claims(
    spki_der: &[u8],
    challenge_token: &str,
    exporter: &[u8],
) -> Result<Claims> {
    let mut claims = Claims::new();
    insert_pubkey_hash(&mut claims, spki_der)?;
    claims.insert(
        CLAIM_CHALLENGE_TOKEN.to_string(),
        serde_json::Value::String(challenge_token.to_string()),
    );
    claims.insert(
        CLAIM_TLS_BINDER.to_string(),
        serde_json::Value::String(BASE64_STANDARD.encode(tls_binder(spki_der, exporter))),
    );
    Ok(claims)
}

pub fn passport_attester_claims(spki_der: &[u8], own_as_nonce: &str) -> Result<Claims> {
    let mut claims = Claims::new();
    insert_pubkey_hash(&mut claims, spki_der)?;
    claims.insert(
        CLAIM_CHALLENGE_TOKEN.to_string(),
        serde_json::Value::String(own_as_nonce.to_string()),
    );
    Ok(claims)
}

impl BackgroundCheckExpectation<'_> {
    pub fn to_claims(&self) -> Result<Claims> {
        background_check_claims(self.peer_spki_der, self.issued_nonce, self.exporter)
    }
}

impl PassportExpectation<'_> {
    pub fn to_claims(&self) -> Result<Claims> {
        let mut claims = Claims::new();
        insert_pubkey_hash(&mut claims, self.peer_spki_der)?;
        Ok(claims)
    }
}

pub fn tls_binder(spki_der: &[u8], exporter: &[u8]) -> Vec<u8> {
    let mut material = Vec::with_capacity(spki_der.len() + exporter.len());
    material.extend_from_slice(spki_der);
    material.extend_from_slice(exporter);
    DefaultCrypto::hash(HashAlgo::Sha256, &material)
}

#[cfg(test)]
pub fn expected_subset_of(expected: &Claims, actual: &Claims) -> bool {
    expected.iter().all(|(k, v)| actual.get(k) == Some(v))
}

fn insert_pubkey_hash(claims: &mut Claims, spki_der: &[u8]) -> Result<()> {
    let pubkey_hash = DefaultCrypto::hash(HashAlgo::Sha256, spki_der);
    let buf = generate_pubkey_hash_value_buffer(HashAlgo::Sha256, &pubkey_hash)?;
    claims.insert(
        CLAIM_PUBKEY_HASH.to_string(),
        serde_json::Value::String(BASE64_STANDARD.encode(buf)),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPKI: &[u8] = b"fake-spki-der";
    const NONCE: &str = "as-issued-nonce";
    const EXPORTER: &[u8] = b"0123456789abcdef0123456789abcdef";

    #[test]
    fn background_check_expected_claims_contain_all_three_keys() {
        let claims = BackgroundCheckExpectation {
            peer_spki_der: SPKI,
            issued_nonce: NONCE,
            exporter: EXPORTER,
        }
        .to_claims()
        .unwrap();

        assert!(claims.contains_key(CLAIM_PUBKEY_HASH));
        assert_eq!(
            claims.get(CLAIM_CHALLENGE_TOKEN).unwrap().as_str(),
            Some(NONCE)
        );
        let expected_binder = BASE64_STANDARD.encode(tls_binder(SPKI, EXPORTER));
        assert_eq!(
            claims.get(CLAIM_TLS_BINDER).unwrap().as_str(),
            Some(expected_binder.as_str())
        );
    }

    #[test]
    fn passport_expected_claims_are_spki_only() {
        let claims = PassportExpectation {
            peer_spki_der: SPKI,
        }
        .to_claims()
        .unwrap();
        assert!(claims.contains_key(CLAIM_PUBKEY_HASH));
        assert!(!claims.contains_key(CLAIM_TLS_BINDER));
        assert!(!claims.contains_key(CLAIM_CHALLENGE_TOKEN));
    }

    #[test]
    fn passport_attester_claims_carry_own_nonce_and_no_binder() {
        let claims = passport_attester_claims(SPKI, NONCE).unwrap();
        assert!(claims.contains_key(CLAIM_PUBKEY_HASH));
        assert_eq!(
            claims.get(CLAIM_CHALLENGE_TOKEN).unwrap().as_str(),
            Some(NONCE)
        );
        assert!(!claims.contains_key(CLAIM_TLS_BINDER));
    }

    #[test]
    fn peer_supplied_binder_does_not_alter_verifier_expectation() {
        let expected = BackgroundCheckExpectation {
            peer_spki_der: SPKI,
            issued_nonce: NONCE,
            exporter: EXPORTER,
        }
        .to_claims()
        .unwrap();

        let mut peer_token = Claims::new();
        peer_token.insert(
            CLAIM_TLS_BINDER.to_string(),
            serde_json::Value::String("self-chosen".into()),
        );
        assert_ne!(
            expected.get(CLAIM_TLS_BINDER),
            peer_token.get(CLAIM_TLS_BINDER)
        );
    }

    #[test]
    fn background_check_evidence_missing_binder_fails_subset() {
        let expected = BackgroundCheckExpectation {
            peer_spki_der: SPKI,
            issued_nonce: NONCE,
            exporter: EXPORTER,
        }
        .to_claims()
        .unwrap();
        let actual = passport_attester_claims(SPKI, NONCE).unwrap();
        assert!(!expected_subset_of(&expected, &actual));
    }

    #[test]
    fn challenge_token_kept_byte_identical() {
        let ita = r#"{"val":"abc+/=","iat":1}"#;
        let claims = background_check_claims(SPKI, ita, EXPORTER).unwrap();
        assert_eq!(
            claims.get(CLAIM_CHALLENGE_TOKEN).unwrap().as_str(),
            Some(ita)
        );
    }
}
