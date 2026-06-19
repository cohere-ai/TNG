use std::net::SocketAddr;

use anyhow::{bail, Result};
use axum::{body::Body, extract::Request, response::Response, routing::any, Router};
use axum_extra::extract::Host;
use http::{Method, StatusCode};
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

                    // Stream request body back as response for POST/PUT
                    // so tests can verify streaming round-trip.
                    let method = request.method().clone();
                    if method == Method::POST || method == Method::PUT {
                        Ok(Response::new(request.into_body()))
                    } else {
                        Ok(Response::builder()
                            .status(StatusCode::OK)
                            .body(Body::from(HTTP_RESPONSE_BODY))
                            .unwrap())
                    }
                })
                .await
                .unwrap_or_else(|e: anyhow::Error| {
                    Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::from(format!("Something went wrong: {e}")))
                        .unwrap()
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
