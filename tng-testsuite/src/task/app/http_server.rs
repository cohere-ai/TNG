use std::net::SocketAddr;

use anyhow::{bail, Result};
use axum::{body::Body, extract::Request, routing::any, Router};
use axum_extra::extract::Host;
use http::{Method, StatusCode};
use http_body_util::BodyExt as _;
use tokio::{net::TcpListener, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::task::app::HTTP_RESPONSE_BODY;

pub async fn launch_http_server(
    token: CancellationToken,
    port: u16,
    expected_host_header: &str,
    expected_path_and_query: &str,
) -> Result<JoinHandle<Result<()>>> {
    let expected_host_header = expected_host_header.to_owned();
    let expected_path_and_query = expected_path_and_query.to_owned();

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("Listening on 0.0.0.0:{port} and waiting for connection from client");

    Ok(tokio::task::spawn(async move {
        let app = Router::new().route(
            "/{*path}",
            any(|Host(hostname): Host, request: Request<Body>| async move {
                (async {
                    if hostname != expected_host_header {
                        bail!("Got hostname `{hostname}`, but `{expected_host_header}` is expected");
                    }

                    let path_and_query = request.uri().path_and_query();
                    if path_and_query.map(|t| t.as_str()) != Some(&expected_path_and_query) {
                        bail!("Got path and query `{path_and_query:?}`, but `{expected_path_and_query}` is expected");
                    }

                    tracing::info!("Got request from client, now sending response to client");

                    let method = request.method().clone();
                    if method == Method::POST || method == Method::PUT {
                        let body_bytes = request.into_body().collect().await?.to_bytes();
                        Ok((StatusCode::OK, body_bytes.to_vec()))
                    } else {
                        Ok((StatusCode::OK, HTTP_RESPONSE_BODY.as_bytes().to_vec()))
                    }
                })
                .await
                .unwrap_or_else(|e: anyhow::Error| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Something went wrong: {e}").into_bytes(),
                    )
                })
            }),
        );
        let server = axum::serve(listener, app);

        tokio::select! {
            _ = token.cancelled() => {}
            res = server => {
                res?;
            }
        }

        tracing::info!("The HTTP server task normally exited");
        Ok(())
    }))
}
