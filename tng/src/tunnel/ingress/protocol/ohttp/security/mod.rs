pub mod client;
mod path_rewrite;

use std::{collections::HashMap, sync::Arc};

#[cfg(unix)]
use crate::tunnel::utils::socket::{
    TCP_KEEPALIVE_IDLE_SECS, TCP_KEEPALIVE_INTERVAL_SECS, TCP_KEEPALIVE_PROBE_COUNT,
};
use crate::{
    config::{ingress::OHttpArgs, ra::RaArgs},
    error::TngError,
    tunnel::{
        endpoint::TngEndpoint,
        ingress::protocol::ohttp::security::{client::OHttpClient, path_rewrite::PathRewriteGroup},
    },
    AttestationResult, TokioRuntime, HTTP_REQUEST_USER_AGENT_HEADER,
};
use anyhow::{Context, Result};
use http::{header::HeaderName, HeaderValue};
use tokio::sync::{OnceCell, RwLock};
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct OHttpClientCacheKey {
    base_url: Url,
    forwarded_headers: Vec<(String, String)>,
}

pub struct OHttpSecurityLayer {
    ra_args: RaArgs,
    http_client: Arc<reqwest::Client>,
    ohttp_clients: RwLock<HashMap<OHttpClientCacheKey, Arc<OnceCell<Arc<OHttpClient>>>>>,
    path_rewrite_group: PathRewriteGroup,
    forward_header_names: Vec<HeaderName>,
    runtime: TokioRuntime,
}

impl OHttpSecurityLayer {
    pub async fn new(
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        transport_so_mark: Option<u32>,
        ohttp_args: &OHttpArgs,
        ra_args: RaArgs,
        runtime: TokioRuntime,
    ) -> Result<Self> {
        let http_client = {
            let mut builder = reqwest::Client::builder();
            builder = builder.default_headers({
                let mut headers = reqwest::header::HeaderMap::new();
                headers.insert(
                    http::header::USER_AGENT,
                    HeaderValue::from_static(HTTP_REQUEST_USER_AGENT_HEADER),
                );
                headers
            });

            #[cfg(unix)]
            {
                use std::time::Duration;
                builder =
                    builder.tcp_keepalive(Duration::from_secs(TCP_KEEPALIVE_IDLE_SECS as u64));
                builder = builder.tcp_keepalive_interval(Duration::from_secs(
                    TCP_KEEPALIVE_INTERVAL_SECS as u64,
                ));
                builder = builder.tcp_keepalive_retries(TCP_KEEPALIVE_PROBE_COUNT);
                // TODO: update reqwest and hyper-util version to support tcp_user_timeout()
                // builder = builder.tcp_user_timeout(Duration::from_secs(TCP_USER_TIMEOUT_SECS as u64));
            }

            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            {
                builder = builder.tcp_mark(transport_so_mark);
            }

            for path in &ohttp_args.tls_ca_certs {
                let pem = std::fs::read(path)
                    .with_context(|| format!("Failed to read TLS CA cert: {path}"))?;
                let cert = reqwest::Certificate::from_pem(&pem)
                    .with_context(|| format!("Failed to parse TLS CA cert: {path}"))?;
                builder = builder.add_root_certificate(cert);
            }

            builder.build()?
        };
        let mut forward_header_names = ohttp_args
            .forward_headers
            .iter()
            .map(|name| {
                HeaderName::from_bytes(name.as_bytes())
                    .with_context(|| format!("Invalid forward_headers entry: {name}"))
            })
            .collect::<Result<Vec<_>>>()?;
        forward_header_names.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        forward_header_names.dedup();

        Ok(Self {
            ra_args,
            http_client: Arc::new(http_client),
            ohttp_clients: Default::default(),
            path_rewrite_group: PathRewriteGroup::new(&ohttp_args.path_rewrites)?,
            forward_header_names,
            runtime,
        })
    }

    pub async fn forward_http_request(
        &self,
        endpoint: &TngEndpoint,
        request: axum::extract::Request,
    ) -> Result<(axum::response::Response, Option<AttestationResult>), TngError> {
        async {
            let base_url = self.construct_base_url(endpoint, &request)?;
            let (forward_headers, cache_key_forwarded_headers) =
                Self::extract_forward_headers(&request, &self.forward_header_names);

            let ohttp_client = self
                .get_or_create_ohttp_client(base_url, forward_headers, cache_key_forwarded_headers)
                .await?;

            ohttp_client.forward_request(request).await
        }
        .await
        .map_err(|error| {
            tracing::error!(?error, "Failed to forward HTTP request");
            error
        })
    }

    fn construct_base_url(
        &self,
        endpoint: &TngEndpoint,
        request: &axum::extract::Request,
    ) -> Result<Url, TngError> {
        let old_uri = request.uri();
        let base_url = {
            let original_path = old_uri.path();
            let mut rewrited_path = self
                .path_rewrite_group
                .rewrite(original_path)
                .unwrap_or_else(|| "/".to_string());

            if !rewrited_path.starts_with('/') {
                rewrited_path.insert(0, '/');
            }

            tracing::debug!(original_path, rewrited_path, "path is rewrited");

            let url = format!(
                "{}://{}:{}{rewrited_path}",
                endpoint.scheme().unwrap_or("http"),
                endpoint.host(),
                endpoint.port()
            );

            url.parse::<Url>()
                .with_context(|| format!("Not a valid URL: {url}"))
                .map_err(TngError::CreateOHttpClientFailed)?
        };
        Ok(base_url)
    }

    async fn get_or_create_ohttp_client(
        &self,
        base_url: Url,
        forward_headers: reqwest::header::HeaderMap,
        cache_key_forwarded_headers: Vec<(String, String)>,
    ) -> Result<Arc<OHttpClient>, TngError> {
        let client_cache_key = OHttpClientCacheKey {
            base_url: base_url.clone(),
            forwarded_headers: cache_key_forwarded_headers,
        };

        // Try to read the ohttp client entry.
        let cell = {
            let read = self.ohttp_clients.read().await;
            read.get(&client_cache_key).cloned()
        };

        // If no entry exists, create one with uninitialized value.
        let cell = match cell {
            Some(cell) => cell,
            _ => {
                let mut map = self.ohttp_clients.write().await;
                let cell = map.entry(client_cache_key).or_default().clone();
                if map.len() > 100 && map.len().is_power_of_two() {
                    tracing::warn!(
                        cache_size = map.len(),
                        "OHTTP client cache is large; high-cardinality forward_headers may cause unbounded growth"
                    );
                }
                cell
            }
        };

        // read from the cell
        cell.get_or_try_init(|| async {
            Ok(Arc::new(
                OHttpClient::new(
                    self.ra_args.clone(),
                    self.http_client.clone(),
                    base_url,
                    forward_headers,
                    self.runtime.clone(),
                )
                .await
                .map_err(TngError::CreateOHttpClientFailed)?,
            ))
        })
        .await
        .cloned()
    }

    fn extract_forward_headers(
        request: &axum::extract::Request,
        header_names: &[HeaderName],
    ) -> (reqwest::header::HeaderMap, Vec<(String, String)>) {
        let mut forward_headers = reqwest::header::HeaderMap::new();
        let mut cache_key_forwarded_headers = Vec::new();

        for header_name in header_names {
            if let Some(header_value) = request.headers().get(header_name) {
                forward_headers.insert(header_name.clone(), header_value.clone());
                cache_key_forwarded_headers.push((
                    header_name.as_str().to_owned(),
                    String::from_utf8_lossy(header_value.as_bytes()).into_owned(),
                ));
            }
        }
        // Already in sorted order because header_names is sorted at construction time.
        debug_assert!(cache_key_forwarded_headers.windows(2).all(|w| w[0] <= w[1]));

        (forward_headers, cache_key_forwarded_headers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    #[test]
    fn test_extract_forward_headers() {
        let request = axum::extract::Request::builder()
            .uri("http://example.com/v1/chat/completions")
            .header("x-routing-key", "route-a")
            .header("x-unrelated", "ignored")
            .body(Body::empty())
            .expect("request should be built");
        let header_names = vec![
            HeaderName::from_static("x-routing-key"),
            HeaderName::from_static("x-not-present"),
        ];

        let (forward_headers, cache_key_forwarded_headers) =
            OHttpSecurityLayer::extract_forward_headers(&request, &header_names);

        assert_eq!(forward_headers.len(), 1);
        assert_eq!(
            forward_headers
                .get("x-routing-key")
                .and_then(|value| value.to_str().ok()),
            Some("route-a")
        );
        assert_eq!(
            cache_key_forwarded_headers,
            vec![("x-routing-key".to_owned(), "route-a".to_owned())]
        );
    }

    #[test]
    fn test_ohttp_client_cache_key_depends_on_forwarded_headers() {
        let base_url = "http://127.0.0.1:30001/"
            .parse::<Url>()
            .expect("base url should be valid");
        let key_for_route_a = OHttpClientCacheKey {
            base_url: base_url.clone(),
            forwarded_headers: vec![("x-routing-key".to_owned(), "route-a".to_owned())],
        };
        let key_for_route_b = OHttpClientCacheKey {
            base_url,
            forwarded_headers: vec![("x-routing-key".to_owned(), "route-b".to_owned())],
        };

        assert_ne!(key_for_route_a, key_for_route_b);
    }
}
