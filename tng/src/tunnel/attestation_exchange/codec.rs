use std::error::Error;
use std::fmt;

use anyhow::{bail, Context, Result};
use serde::{de::DeserializeOwned, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::tunnel::attest::{AttestRequest, AttestResponse};

/// Cap sized for a TEE quote or passport token, not an OHTTP keyset.
pub const MAX_FRAME_SIZE: u32 = 256 * 1024;

/// Marks a frame whose JSON is not an [`AttestRequest`] or [`AttestResponse`].
#[derive(Debug)]
struct MalformedMessage;

impl fmt::Display for MalformedMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("malformed attestation exchange message")
    }
}

impl Error for MalformedMessage {}

pub fn is_malformed(err: &anyhow::Error) -> bool {
    err.is::<MalformedMessage>()
}

async fn write_msg<W, M>(writer: &mut W, msg: &M) -> Result<()>
where
    W: AsyncWrite + Unpin,
    M: Serialize,
{
    let buf = serde_json::to_vec(msg).context("failed to encode exchange message")?;
    let len = u32::try_from(buf.len()).context("exchange message larger than u32")?;
    if len > MAX_FRAME_SIZE {
        bail!("exchange message size ({len} bytes) exceeds maximum ({MAX_FRAME_SIZE} bytes)");
    }
    writer.write_u32(len).await?;
    writer.write_all(&buf).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_msg<R, M>(reader: &mut R) -> Result<M>
where
    R: AsyncRead + Unpin,
    M: DeserializeOwned,
{
    let buf = read_frame(reader).await?;
    serde_json::from_slice(&buf).context(MalformedMessage)
}

pub async fn write_request<W: AsyncWrite + Unpin>(
    writer: &mut W,
    msg: &AttestRequest,
) -> Result<()> {
    write_msg(writer, msg).await
}

pub async fn read_request<R: AsyncRead + Unpin>(reader: &mut R) -> Result<AttestRequest> {
    read_msg(reader).await
}

pub async fn write_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    msg: &AttestResponse,
) -> Result<()> {
    write_msg(writer, msg).await
}

pub async fn read_response<R: AsyncRead + Unpin>(reader: &mut R) -> Result<AttestResponse> {
    read_msg(reader).await
}

async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .context("truncated exchange frame length")?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_SIZE {
        bail!("peer exchange message size ({len} bytes) exceeds maximum ({MAX_FRAME_SIZE} bytes)");
    }

    let mut buf = vec![0u8; len as usize];
    reader
        .read_exact(&mut buf)
        .await
        .context("truncated exchange frame body")?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AttestError;
    use crate::tunnel::attest::{
        evidence_response, token_response, AttestProposal, AttestResponse, Model,
    };
    use crate::tunnel::provider::ProviderType;
    use serde_json::json;

    async fn round_trip_request(sent: AttestRequest) -> AttestRequest {
        let (mut a, mut b) = tokio::io::duplex(256);
        write_request(&mut a, &sent).await.unwrap();
        read_request(&mut b).await.unwrap()
    }

    async fn round_trip_response(sent: AttestResponse) -> AttestResponse {
        let (mut a, mut b) = tokio::io::duplex(256);
        write_response(&mut a, &sent).await.unwrap();
        read_response(&mut b).await.unwrap()
    }

    #[tokio::test]
    async fn request_and_response_round_trips() {
        let none = AttestRequest::default();
        assert_eq!(round_trip_request(none.clone()).await, none);
        assert_eq!(
            serde_json::to_value(&none).unwrap(),
            json!({"proposals": []})
        );

        let proposals = AttestRequest {
            proposals: vec![
                AttestProposal::BackgroundCheck {
                    provider: ProviderType::Ita,
                    challenge_token: r#"{"val":"abc+/=","iat":1}"#.into(),
                },
                AttestProposal::Passport {
                    provider: ProviderType::Coco,
                },
            ],
        };
        assert_eq!(round_trip_request(proposals.clone()).await, proposals);

        let evidence = evidence_response(
            ProviderType::Coco,
            json!({"aa_tee_type": "tdx", "aa_evidence": "aGVsbG8="}),
        );
        assert_eq!(round_trip_response(evidence.clone()).await, evidence);

        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let token = token_response(ProviderType::Ita, jwt);
        assert_eq!(round_trip_response(token.clone()).await, token);

        let err = Err(AttestError::NotConfigured);
        assert_eq!(round_trip_response(err.clone()).await, err);
        let duplicate = Err(AttestError::DuplicateProposal {
            model: Model::BackgroundCheck,
            provider: ProviderType::Coco,
        });
        assert_eq!(round_trip_response(duplicate.clone()).await, duplicate);

        assert_eq!(round_trip_response(Ok(None)).await, Ok(None));
    }

    #[tokio::test]
    async fn oversized_or_truncated_frame_is_rejected() {
        let (mut a, mut b) = tokio::io::duplex(16);
        a.write_all(&(MAX_FRAME_SIZE + 1).to_be_bytes())
            .await
            .unwrap();
        a.flush().await.unwrap();
        let err = read_request(&mut b).await.unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"));
        assert!(!is_malformed(&err));

        let (mut a, mut b) = tokio::io::duplex(16);
        a.write_all(&8u32.to_be_bytes()).await.unwrap();
        a.write_all(&[1, 2, 3]).await.unwrap();
        a.flush().await.unwrap();
        drop(a);
        let err = read_request(&mut b).await.unwrap_err();
        assert!(err.to_string().contains("truncated"));
        assert!(!is_malformed(&err));
    }

    #[tokio::test]
    async fn invalid_json_is_malformed() {
        let (mut a, mut b) = tokio::io::duplex(256);
        let body = br#"{"proposals":[{"model":"passport","provider":"bad_provider"}]}"#;
        a.write_u32(body.len() as u32).await.unwrap();
        a.write_all(body).await.unwrap();
        a.flush().await.unwrap();
        let err = read_request(&mut b).await.unwrap_err();
        assert!(is_malformed(&err));
        assert!(
            format!("{err:#}").contains("no recognized proposal"),
            "{err:#}"
        );
    }
}
