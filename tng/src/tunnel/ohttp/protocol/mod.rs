use serde::{Deserialize, Serialize};

use crate::tunnel::attest::{AttestRequest, AttestResponse};

pub mod header;
pub mod metadata;
pub mod userdata;

/// Capacity of the in-memory pipes and stream readers that carry OHTTP bodies
/// between the HTTP stacks and the encryptor/decryptor.
///
/// Each OHTTP chunk seals one write, and a write can be no larger than the
/// pipe in front of the encryptor, so a 4 KiB pipe caps chunks at 4 KiB even
/// though the format allows 16 KiB (`MAX_CHUNK_PLAINTEXT` in the ohttp
/// crate). Every chunk then costs a seal, several copies, a task hand-off per
/// stage, an outer HTTP/1 chunk, and, behind a gateway that streams bodies to
/// an ext_proc filter, one more round trip. 64 KiB lets chunks reach the
/// 16 KiB maximum and leaves room to queue a few of them, so a large response
/// crosses the tunnel in about a quarter as many chunks.
pub const OHTTP_STREAM_BUFFER_SIZE: usize = 64 * 1024;

// The ohttp crate seals at most 16 KiB of plaintext per chunk (MAX_CHUNK_PLAINTEXT);
// a smaller buffer would cap every chunk below that again.
const _: () = assert!(OHTTP_STREAM_BUFFER_SIZE >= 16 * 1024);

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

    #[tokio::test]
    async fn copy_buf_hands_the_writer_writes_larger_than_4k() {
        use std::pin::Pin;
        use std::task::{Context, Poll};
        use tokio::io::{AsyncWrite, AsyncWriteExt as _};

        /// Records the largest single write, standing in for the OHTTP encryptor,
        /// which seals each write as one chunk.
        #[derive(Default)]
        struct MaxWrite(usize);
        impl AsyncWrite for MaxWrite {
            fn poll_write(
                mut self: Pin<&mut Self>,
                _: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                self.0 = self.0.max(buf.len());
                Poll::Ready(Ok(buf.len()))
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        // Same pipeline shape as the encryption tasks: a body stream read through a
        // BufReader of OHTTP_STREAM_BUFFER_SIZE and copied with copy_buf.
        let (mut tx, rx) = tokio::io::duplex(OHTTP_STREAM_BUFFER_SIZE);
        let produce = async move {
            tx.write_all(&vec![7u8; 1 << 20]).await.unwrap();
        };
        let mut reader = tokio::io::BufReader::with_capacity(OHTTP_STREAM_BUFFER_SIZE, rx);
        let mut writer = MaxWrite::default();
        let ((), copied) = tokio::join!(produce, tokio::io::copy_buf(&mut reader, &mut writer));
        assert_eq!(copied.unwrap(), 1 << 20);

        assert!(
            writer.0 > 4096,
            "largest write was {} bytes; chunks would be capped at 4 KiB",
            writer.0
        );
    }

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
