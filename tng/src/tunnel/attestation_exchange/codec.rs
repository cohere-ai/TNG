use anyhow::{bail, Context, Result};
use prost::Message;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::pb;

/// Cap sized for a TEE quote or passport token, not an OHTTP keyset.
pub const MAX_FRAME_SIZE: u32 = 256 * 1024;

async fn write_msg<W, M>(writer: &mut W, msg: &M) -> Result<()>
where
    W: AsyncWrite + Unpin,
    M: Message,
{
    let buf = msg.encode_to_vec();
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
    M: Message + Default,
{
    let buf = read_frame(reader).await?;
    M::decode(buf.as_slice()).context("failed to decode exchange message")
}

pub async fn write_declaration<W: AsyncWrite + Unpin>(
    writer: &mut W,
    msg: &pb::Declaration,
) -> Result<()> {
    write_msg(writer, msg).await
}

pub async fn read_declaration<R: AsyncRead + Unpin>(reader: &mut R) -> Result<pb::Declaration> {
    read_msg(reader).await
}

pub async fn write_evidence<W: AsyncWrite + Unpin>(
    writer: &mut W,
    msg: &pb::Evidence,
) -> Result<()> {
    write_msg(writer, msg).await
}

pub async fn read_evidence<R: AsyncRead + Unpin>(reader: &mut R) -> Result<pb::Evidence> {
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
    use crate::tunnel::attestation_exchange::pb::{
        evidence::Payload, AttestationFailed, Declaration, Evidence, Refusal,
    };

    fn declaration() -> Declaration {
        Declaration {
            will_attest: true,
            wants_evidence: true,
            challenge_token: b"{\"n\":\"ita\"}".to_vec(),
            certificate_request_context: vec![],
        }
    }

    #[tokio::test]
    async fn declaration_round_trip() {
        let (mut a, mut b) = tokio::io::duplex(64);
        let sent = declaration();
        write_declaration(&mut a, &sent).await.unwrap();
        let got = read_declaration(&mut b).await.unwrap();
        assert_eq!(got, sent);
    }

    #[tokio::test]
    async fn declaration_without_token_round_trip() {
        let (mut a, mut b) = tokio::io::duplex(64);
        let sent = Declaration {
            will_attest: false,
            wants_evidence: false,
            challenge_token: vec![],
            certificate_request_context: vec![],
        };
        write_declaration(&mut a, &sent).await.unwrap();
        let got = read_declaration(&mut b).await.unwrap();
        assert_eq!(got, sent);
    }

    #[tokio::test]
    async fn refusal_and_attestation_failed_round_trip() {
        let (mut a, mut b) = tokio::io::duplex(256);
        let refusal = Evidence {
            payload: Some(Payload::Refusal(Refusal {
                reason: "not configured to attest".into(),
            })),
        };
        write_evidence(&mut a, &refusal).await.unwrap();
        match read_evidence(&mut b).await.unwrap().payload {
            Some(Payload::Refusal(r)) => assert_eq!(r.reason, "not configured to attest"),
            other => panic!("expected refusal, got {other:?}"),
        }

        let failed = Evidence {
            payload: Some(Payload::AttestationFailed(AttestationFailed {
                reason: "attester exhausted retries".into(),
            })),
        };
        write_evidence(&mut a, &failed).await.unwrap();
        match read_evidence(&mut b).await.unwrap().payload {
            Some(Payload::AttestationFailed(r)) => {
                assert_eq!(r.reason, "attester exhausted retries")
            }
            other => panic!("expected attestation-failed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn length_prefix_over_maximum_rejected_before_allocating() {
        let (mut a, mut b) = tokio::io::duplex(16);
        let fake_len = MAX_FRAME_SIZE + 1;
        a.write_all(&fake_len.to_be_bytes()).await.unwrap();
        a.flush().await.unwrap();
        let err = read_declaration(&mut b).await.unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"));
    }

    #[tokio::test]
    async fn truncated_frame_errors() {
        let (mut a, mut b) = tokio::io::duplex(16);
        a.write_all(&8u32.to_be_bytes()).await.unwrap();
        a.write_all(&[1, 2, 3]).await.unwrap();
        a.flush().await.unwrap();
        drop(a);
        let err = read_declaration(&mut b).await.unwrap_err();
        assert!(err.to_string().contains("truncated"));
    }

    #[tokio::test]
    async fn ita_shaped_nonce_survives_round_trip_byte_identical() {
        let (mut a, mut b) = tokio::io::duplex(128);
        let token = br#"{"val":"abc+/=","iat":1}"#;
        let sent = Declaration {
            will_attest: true,
            wants_evidence: true,
            challenge_token: token.to_vec(),
            certificate_request_context: vec![],
        };
        write_declaration(&mut a, &sent).await.unwrap();
        let got = read_declaration(&mut b).await.unwrap();
        assert_eq!(got.challenge_token, token);
    }
}
