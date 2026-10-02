use std::sync::Arc;

use crate::{
    tunnel::{
        egress::{
            protocol::rats_tls::{security::RatsTlsSecurityLayer, wrapping::RatsTlsWrappingLayer},
            stream_manager::trusted::{ProtocolStreamDecoder, ProtocolStreamDecoderOutput},
        },
        ra_context::RaContext,
    },
    CommonStreamTrait, TokioRuntime,
};

use anyhow::Result;
use async_stream::stream;
use async_trait::async_trait;
use futures::StreamExt;

pub mod security;
pub mod wrapping;

pub struct RatsTlsStreamDecoder {
    security_layer: RatsTlsSecurityLayer,
    runtime: TokioRuntime,
}

impl RatsTlsStreamDecoder {
    pub async fn new(ra_context: Arc<RaContext>, runtime: TokioRuntime) -> Result<Self> {
        Ok(Self {
            security_layer: RatsTlsSecurityLayer::new(ra_context, runtime.clone()).await?,
            runtime,
        })
    }
}

#[async_trait]
impl ProtocolStreamDecoder for RatsTlsStreamDecoder {
    async fn decode_stream(
        &self,
        input: Box<dyn CommonStreamTrait + Sync + 'static>,
    ) -> Result<ProtocolStreamDecoderOutput> {
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();

        let (tls_stream, attestation_result) = self.security_layer.handshake(input).await?;

        // Should be spawned as background task
        self.runtime
            .spawn_supervised_task_fn_current_span(move |runtime| async move {
                RatsTlsWrappingLayer::unwrap_stream(
                    tls_stream,
                    attestation_result,
                    sender,
                    runtime,
                )
                .await;
            });

        Ok(stream! {
            while let Some(value) = receiver.recv().await {
                yield Ok(value); // TODO: remove the spawn_supervised_task_fn_current_span above and pass error here
            }
        }
        .boxed())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use anyhow::Context as _;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;
    use crate::tests::run_test_with_tokio_runtime;
    use crate::tunnel::{
        endpoint::TngEndpoint, ingress::protocol::rats_tls::RatsTlsStreamForwarder,
    };

    async fn accept(
        listener: &TcpListener,
        decoder: &RatsTlsStreamDecoder,
    ) -> Result<Box<dyn CommonStreamTrait + Sync>> {
        let (tcp, _) = listener.accept().await?;
        let mut streams = decoder.decode_stream(Box::new(tcp)).await?;
        Ok(streams.next().await.context("no tunnel")??.0)
    }

    /// Opens a tunnel through a pooled rats-tls session, then connects again with a zero pool TTL
    /// so the session is evicted and its last hyper Client dropped (the second `accept` only
    /// returns if a new connection is made). The first tunnel must still carry data afterwards.
    #[tokio::test]
    async fn live_stream_survives_pool_ttl_eviction() -> Result<()> {
        run_test_with_tokio_runtime(|runtime| async move {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let endpoint = TngEndpoint::new("127.0.0.1", listener.local_addr()?.port());
            let decoder =
                RatsTlsStreamDecoder::new(Arc::new(RaContext::NoRa), runtime.clone()).await?;
            let forwarder = RatsTlsStreamForwarder::new(
                #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                None,
                Arc::new(RaContext::NoRa),
                runtime,
                Duration::ZERO,
            )
            .await?;

            tokio::time::timeout(Duration::from_secs(10), async {
                let ((mut client, ..), mut server) = tokio::try_join!(
                    forwarder.connect(endpoint.clone()),
                    accept(&listener, &decoder)
                )?;
                let _replacement =
                    tokio::try_join!(forwarder.connect(endpoint), accept(&listener, &decoder))?;
                tokio::time::sleep(Duration::from_millis(100)).await;

                client.write_all(b"still alive").await?;
                let mut buf = [0u8; 11];
                server.read_exact(&mut buf).await?;
                assert_eq!(&buf, b"still alive");
                Ok(())
            })
            .await
            .context("test timed out")?
        })
        .await
    }
}
