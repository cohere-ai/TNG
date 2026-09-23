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

pub async fn write_request<W: AsyncWrite + Unpin>(writer: &mut W, msg: &pb::Request) -> Result<()> {
    write_msg(writer, msg).await
}

pub async fn read_request<R: AsyncRead + Unpin>(reader: &mut R) -> Result<pb::Request> {
    read_msg(reader).await
}

pub async fn write_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    msg: &pb::Response,
) -> Result<()> {
    write_msg(writer, msg).await
}

pub async fn read_response<R: AsyncRead + Unpin>(reader: &mut R) -> Result<pb::Response> {
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
        request, response, BackgroundCheck, Evidence, Passport, Request, Response, Token,
    };

    async fn round_trip_request(sent: Request) -> Request {
        let (mut a, mut b) = tokio::io::duplex(256);
        write_request(&mut a, &sent).await.unwrap();
        read_request(&mut b).await.unwrap()
    }

    async fn round_trip_response(sent: Response) -> Response {
        let (mut a, mut b) = tokio::io::duplex(256);
        write_response(&mut a, &sent).await.unwrap();
        read_response(&mut b).await.unwrap()
    }

    #[tokio::test]
    async fn request_and_response_round_trips() {
        let none = Request {
            body: Some(request::Body::None(pb::None {})),
        };
        assert_eq!(round_trip_request(none.clone()).await, none);

        let nonce = br#"{"val":"abc+/=","iat":1}"#;
        let got = round_trip_request(Request {
            body: Some(request::Body::BackgroundCheck(BackgroundCheck {
                nonce: nonce.to_vec(),
            })),
        })
        .await;
        match got.body {
            Some(request::Body::BackgroundCheck(bc)) => assert_eq!(bc.nonce, nonce),
            other => panic!("expected background_check, got {other:?}"),
        }

        let passport = Request {
            body: Some(request::Body::Passport(Passport {})),
        };
        assert_eq!(round_trip_request(passport.clone()).await, passport);

        match round_trip_response(Response {
            body: Some(response::Body::Evidence(Evidence {
                provider: "coco".into(),
                json: r#"{"aa_tee_type":"tdx","aa_evidence":"aGVsbG8="}"#.into(),
            })),
        })
        .await
        .body
        {
            Some(response::Body::Evidence(ev)) => {
                assert_eq!(ev.provider, "coco");
                assert!(ev.json.contains("aa_tee_type"));
            }
            other => panic!("expected evidence, got {other:?}"),
        }

        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        match round_trip_response(Response {
            body: Some(response::Body::Token(Token {
                provider: "ita".into(),
                jwt: jwt.into(),
            })),
        })
        .await
        .body
        {
            Some(response::Body::Token(t)) => {
                assert_eq!(t.provider, "ita");
                assert_eq!(t.jwt, jwt);
            }
            other => panic!("expected token, got {other:?}"),
        }

        match round_trip_response(Response {
            body: Some(response::Body::Error(pb::Error {
                reason: "not configured to attest".into(),
            })),
        })
        .await
        .body
        {
            Some(response::Body::Error(e)) => assert_eq!(e.reason, "not configured to attest"),
            other => panic!("expected error, got {other:?}"),
        }

        match round_trip_response(Response {
            body: Some(response::Body::Ack(pb::None {})),
        })
        .await
        .body
        {
            Some(response::Body::Ack(_)) => {}
            other => panic!("expected ack, got {other:?}"),
        }
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

        let (mut a, mut b) = tokio::io::duplex(16);
        a.write_all(&8u32.to_be_bytes()).await.unwrap();
        a.write_all(&[1, 2, 3]).await.unwrap();
        a.flush().await.unwrap();
        drop(a);
        let err = read_request(&mut b).await.unwrap_err();
        assert!(err.to_string().contains("truncated"));
    }
}
