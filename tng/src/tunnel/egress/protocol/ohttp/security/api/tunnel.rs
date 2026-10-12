use std::pin::Pin;
use std::task::{ready, Context, Poll};

use anyhow::{anyhow, Result};
use bhttp::http_compat::decode::{BhttpDecoder, HttpMessage};
use bhttp::http_compat::encode::BhttpEncoder;
use bytes::{Bytes, BytesMut};
use futures::{AsyncWriteExt, Stream, StreamExt as _, TryStreamExt as _};
use prost::Message as _;
use tokio::io::AsyncReadExt;
use tokio_util::compat::FuturesAsyncReadCompatExt as _;
use tokio_util::compat::FuturesAsyncWriteCompatExt as _;
use tokio_util::compat::TokioAsyncReadCompatExt as _;
use tokio_util::io::ReaderStream;

use crate::error::TngError;
use crate::tunnel::egress::protocol::ohttp::security::api::OhttpServerApi;
use crate::tunnel::egress::protocol::ohttp::security::context::TngStreamContext;
use crate::tunnel::ohttp::key_config::PublicKeyData;
use crate::tunnel::ohttp::protocol::header::{
    OHTTP_CHUNKED_REQUEST_CONTENT_TYPE, OHTTP_CHUNKED_RESPONSE_CONTENT_TYPE,
};
use crate::tunnel::ohttp::protocol::metadata::{Metadata, METADATA_MAX_LEN};
use crate::TokioRuntime;

impl OhttpServerApi {
    /// Interface 2: Process Encrypted Request
    /// x-tng-ohttp-api: /tng/tunnel (or user specified path via path_rewrites)
    ///
    /// Clients use the hpke_key_config obtained from Interface 1 to encrypt a standard HTTP request,
    /// and send the encrypted ciphertext as the request body to the server. The server decrypts and processes
    /// the request, then encrypts the HTTP response and returns it.
    pub async fn process_encrypted_request(
        &self,
        payload: axum::extract::Request,
        context: TngStreamContext,
    ) -> Result<axum::response::Response, TngError> {
        // Check content-type
        match payload.headers().get(http::header::CONTENT_TYPE) {
            Some(value) => {
                if value != OHTTP_CHUNKED_REQUEST_CONTENT_TYPE {
                    return Err(TngError::InvalidOHttpRequest(anyhow!(
                        "Wrong content-type header"
                    )));
                }
            }
            None => {
                return Err(TngError::InvalidOHttpRequest(anyhow!(
                    "Wrong content-type header"
                )));
            }
        }

        let mut reader = tokio_util::io::StreamReader::new(
            DrainOnDrop::new(
                payload.into_body().into_data_stream(),
                context.runtime.clone(),
            )
            .map(|result| result.map_err(std::io::Error::other)),
        );

        // Read and decode matadata
        let metadata = {
            let metadata_len = reader
                .read_u32() // big-endian
                .await
                .map_err(TngError::MetadataReadError)?;

            let metadata_len =
                usize::try_from(metadata_len).map_err(|_| TngError::MetadataTooLong)?;

            if metadata_len > METADATA_MAX_LEN {
                return Err(TngError::MetadataTooLong);
            }

            let mut buf = BytesMut::with_capacity(metadata_len);

            while buf.len() < metadata_len {
                reader
                    .read_buf(&mut buf)
                    .await
                    .map_err(TngError::MetadataReadError)?;
            }

            Metadata::decode(buf.as_ref()).map_err(TngError::MetadataDecodeError)?
        };

        let header_decoded = ohttp::Server::decode_header(reader.compat()).await?;

        tracing::debug!(
            ?metadata,
            key_id = header_decoded.key_id(),
            "Received OHTTP request"
        );

        let key_info = if let Some(hint) = metadata.key_config_hint {
            // Get key by hint
            self.key_manager
                .get_key_by_public_key_data(&PublicKeyData::new(hint.public_key))
                .await?
        } else {
            // Check key id, this make it compatible with old tng clients versions
            self.key_manager
                .get_fist_key_by_key_id(header_decoded.key_id())
                .await?
        };

        // Decrypt the ohttp message
        let plain_text = header_decoded.into_server_request(key_info.key_config);

        // Decode the bhttp binary message
        let decode_result = BhttpDecoder::new(plain_text).decode_message().await?;
        let server_response_encapsulator = decode_result.reader_ref().response_encapsulator()?;

        let HttpMessage::Request(request) = decode_result.into_full_message()? else {
            return Err(TngError::InvalidHttpRequest);
        };

        tracing::debug!(
            method = ?request.method(),
            version = ?request.version(),
            uri = ?request.uri(),
            "Forwarding request to upstream server"
        );

        // Forward the request to the upstream server
        let response = context.forward_request(request, None).await?;

        tracing::debug!(
            status = ?response.status(),
            version = ?response.version(),
            "Received response from upstream server"
        );

        // Encode the response to bhttp message
        let bhttp_encoder = BhttpEncoder::from_response(response);
        // Encrypt to get the ohttp message
        let encrypted_response = {
            let (response_read, response_write) = tokio::io::duplex(4096);
            let server_response =
                server_response_encapsulator.encapsulate_response(response_write.compat())?;
            context.runtime.spawn_supervised_task_current_span(async {
                async {
                    let mut server_response = server_response.compat_write();
                    tokio::io::copy(
                        &mut bhttp_encoder
                            .map_err(std::io::Error::other)
                            .into_async_read()
                            .compat(),
                        &mut server_response,
                    )
                    .await?;
                    let mut server_response = server_response.into_inner();
                    server_response.close().await?; // Remember to close the response stream

                    Ok::<_, anyhow::Error>(())
                }
                .await
                .unwrap_or_else(|error| tracing::error!(?error, "Error when encrypting response"))
            });

            response_read
        };

        // Return the response
        let response = http::Response::builder()
            .status(axum::http::StatusCode::OK)
            .header(
                http::header::CONTENT_TYPE,
                OHTTP_CHUNKED_RESPONSE_CONTENT_TYPE,
            )
            .body(axum::body::Body::from_stream(ReaderStream::new(
                encrypted_response,
            )))
            .map_err(TngError::ConstructHttpResponseFailed)?;

        Ok(response)
    }
}

/// Outer request body that is read to EOF in the background once the OHTTP decoder drops it.
///
/// The bhttp decoder stops at the inner message's trailers, before the final OHTTP chunk and the
/// outer chunked terminator. If hyper sees the body dropped with those bytes unread, it closes the
/// connection after the response, and the kernel turns that close into an RST that discards any
/// response bytes still queued for the client.
struct DrainOnDrop {
    inner: Option<axum::body::BodyDataStream>,
    runtime: TokioRuntime,
}

impl DrainOnDrop {
    fn new(inner: axum::body::BodyDataStream, runtime: TokioRuntime) -> Self {
        Self {
            inner: Some(inner),
            runtime,
        }
    }
}

impl Stream for DrainOnDrop {
    type Item = Result<Bytes, axum::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let Some(inner) = self.inner.as_mut() else {
            return Poll::Ready(None);
        };
        let item = ready!(inner.poll_next_unpin(cx));
        if item.is_none() {
            self.inner = None;
        }
        Poll::Ready(item)
    }
}

impl Drop for DrainOnDrop {
    fn drop(&mut self) {
        if let Some(mut inner) = self.inner.take() {
            self.runtime.spawn_supervised_task_current_span(async move {
                while let Some(Ok(_)) = inner.next().await {}
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;
    use crate::tests::run_test_with_tokio_runtime;

    #[tokio::test]
    async fn dropped_body_is_read_to_eof() -> Result<()> {
        run_test_with_tokio_runtime(|runtime| async move {
            let reached_eof = Arc::new(AtomicBool::new(false));
            let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(4);
            let body_stream = {
                let reached_eof = reached_eof.clone();
                futures::stream::unfold(rx, |mut rx| async move {
                    rx.recv().await.map(|item| (item, rx))
                })
                .chain(futures::stream::once(async move {
                    reached_eof.store(true, Ordering::SeqCst);
                    Ok(Bytes::new())
                }))
            };
            let body = axum::body::Body::from_stream(body_stream).into_data_stream();

            let mut stream = DrainOnDrop::new(body, runtime);
            tx.send(Ok(Bytes::from_static(b"head"))).await?;
            assert_eq!(
                stream.next().await.transpose()?,
                Some(Bytes::from_static(b"head"))
            );
            drop(stream);

            tx.send(Ok(Bytes::from_static(b"tail"))).await?;
            drop(tx);

            tokio::time::timeout(Duration::from_secs(5), async {
                while !reached_eof.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await?;
            Ok(())
        })
        .await
    }
}
