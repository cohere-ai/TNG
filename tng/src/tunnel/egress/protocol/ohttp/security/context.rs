use std::future::Future;
use std::task::Poll;
use std::time::Duration;

use axum::response::IntoResponse;
use http::uri::{PathAndQuery, Scheme};
use http::{header::HOST, HeaderMap, Uri};
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::client::legacy::Client;
use tokio::io::DuplexStream;

use crate::tunnel::ohttp::protocol::OHTTP_STREAM_BUFFER_SIZE;
use crate::{error::TngError, AttestationResult, CommonStreamTrait, TokioIo, TokioRuntime};

/// Kept below common upstream keep-alive timeouts (uvicorn's is 5s), so that an idle connection is
/// dropped here before the upstream closes it under a request being sent on it.
const UPSTREAM_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(2);

type StreamSender = tokio::sync::mpsc::UnboundedSender<(
    Box<dyn CommonStreamTrait + Sync>,
    Option<AttestationResult>,
)>;

#[derive(Clone)]
pub struct TngStreamContext {
    pub runtime: TokioRuntime,
    /// Pools connections to the upstream of one downstream connection only: in netfilter mode each
    /// downstream connection has its own upstream, so this must not be shared across them.
    client: Client<UpstreamConnector, axum::body::Body>,
}

impl TngStreamContext {
    pub fn new(runtime: TokioRuntime, sender: StreamSender) -> Self {
        let client = Client::builder(UnsupervisedExecutor(runtime.clone()))
            .pool_idle_timeout(UPSTREAM_POOL_IDLE_TIMEOUT)
            .build(UpstreamConnector(sender));
        Self { runtime, client }
    }

    pub async fn forward_request<B>(
        &self,
        req: http::Request<B>,
    ) -> Result<axum::response::Response, TngError>
    where
        B: http_body::Body<Data = bytes::Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let (mut parts, body) = req.into_parts();
        parts.uri = absolute_uri(parts.uri, &parts.headers)?;

        self.client
            .request(http::Request::from_parts(
                parts,
                axum::body::Body::new(body),
            ))
            .await
            .map(axum::response::Response::into_response)
            .map_err(TngError::HttpPlainTextForwardError)
    }
}

/// The pooled client only accepts absolute URIs. The connector ignores the authority, which only
/// keys the pool and fills in a missing `Host`, so take it from `Host` when there is one.
fn absolute_uri(uri: Uri, headers: &HeaderMap) -> Result<Uri, TngError> {
    if uri.scheme().is_some() && uri.authority().is_some() {
        return Ok(uri);
    }
    let authority = headers
        .get(HOST)
        .and_then(|host| host.to_str().ok())
        .unwrap_or("localhost");
    let mut parts = uri.into_parts();
    parts.scheme = Some(Scheme::HTTP);
    parts.authority = Some(
        authority
            .parse()
            .map_err(|_| TngError::InvalidHttpRequest)?,
    );
    parts
        .path_and_query
        .get_or_insert(PathAndQuery::from_static("/"));
    Uri::from_parts(parts).map_err(|_| TngError::InvalidHttpRequest)
}

/// Opens each upstream connection as a pipe handed to the egress flow, which connects it to the
/// upstream.
#[derive(Clone)]
struct UpstreamConnector(StreamSender);

impl tower::Service<Uri> for UpstreamConnector {
    type Response = TokioIo<DuplexStream>;
    type Error = TngError;
    type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: Uri) -> Self::Future {
        // The upstream response body crosses this pipe on its way to the OHTTP encryptor, so
        // its capacity bounds the body frames hyper reads and, through them, the chunk size.
        let (s1, s2) = tokio::io::duplex(OHTTP_STREAM_BUFFER_SIZE);
        std::future::ready(
            self.0
                .send((Box::new(s2), None))
                .map(|()| TokioIo::new(s1))
                .map_err(|_| TngError::ConnectUpstreamFailed),
        )
    }
}

impl Connection for TokioIo<DuplexStream> {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

/// Runs upstream connections unsupervised, so that an in-flight response still finishes on
/// shutdown.
#[derive(Clone)]
struct UnsupervisedExecutor(TokioRuntime);

impl<F> hyper::rt::Executor<F> for UnsupervisedExecutor
where
    F: Future<Output = ()> + Send + 'static,
{
    fn execute(&self, fut: F) {
        self.0.spawn_unsupervised_task_current_span(fut);
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use bytes::Bytes;
    use http_body_util::{BodyExt as _, Empty, Full};

    use super::*;
    use crate::tests::run_test_with_tokio_runtime;

    #[tokio::test]
    async fn sequential_requests_share_one_upstream_connection() -> anyhow::Result<()> {
        run_test_with_tokio_runtime(|runtime| async move {
            let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
            let context = TngStreamContext::new(runtime.clone(), sender);

            let upstream = runtime.spawn_unsupervised_task_current_span({
                let runtime = runtime.clone();
                async move {
                    let mut connections = 0;
                    while let Some((stream, _)) = receiver.recv().await {
                        connections += 1;
                        let service = hyper::service::service_fn(|_| async {
                            Ok::<_, Infallible>(http::Response::new(Full::new(Bytes::from_static(
                                b"ok",
                            ))))
                        });
                        runtime.spawn_unsupervised_task_current_span(
                            hyper::server::conn::http1::Builder::new()
                                .serve_connection(TokioIo::new(stream), service),
                        );
                    }
                    connections
                }
            });

            for _ in 0..5 {
                let response = context
                    .forward_request(http::Request::new(Empty::<Bytes>::new()))
                    .await?;
                assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
            }
            drop(context);
            assert_eq!(upstream.await?, 1);
            Ok(())
        })
        .await
    }
}
