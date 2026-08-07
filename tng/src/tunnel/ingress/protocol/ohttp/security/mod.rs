pub mod client;
mod path_rewrite;

use std::{collections::HashMap, sync::Arc};

#[cfg(unix)]
use crate::tunnel::utils::socket::{
    TCP_KEEPALIVE_IDLE_SECS, TCP_KEEPALIVE_INTERVAL_SECS, TCP_KEEPALIVE_PROBE_COUNT,
};
use crate::{
    config::ingress::OHttpArgs,
    error::TngError,
    tunnel::{
        endpoint::TngEndpoint,
        ingress::protocol::ohttp::security::{client::OHttpClient, path_rewrite::PathRewriteGroup},
        ra_context::RaContext,
        utils::direct_forward::DirectForwardTrafficDetector,
    },
    AttestationResult, TokioRuntime, HTTP_REQUEST_USER_AGENT_HEADER,
};
use anyhow::{Context, Result};
use http::{header, header::HeaderName, HeaderValue};
use http_body::Body as _;
use tokio::sync::{OnceCell, RwLock};
use url::Url;

// Headers that apply only to a single transport-level connection and must not
// be forwarded by proxies (RFC 7230 §6.1).
const HOP_BY_HOP_HEADERS: &[header::HeaderName] = &[
    header::CONNECTION,
    header::TRANSFER_ENCODING,
    header::PROXY_AUTHENTICATE,
    header::PROXY_AUTHORIZATION,
    header::TE,
    header::TRAILER,
    header::UPGRADE,
];

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct OHttpClientCacheKey {
    base_url: Url,
    forwarded_headers: Vec<(String, String)>,
}

const BODY_FIELD_PROMOTION_MAX_BYTES: usize = 64 * 1024 * 1024;

pub struct OHttpSecurityLayer {
    ra_context: Arc<RaContext>,
    http_client: Arc<reqwest::Client>,
    ohttp_clients: RwLock<HashMap<OHttpClientCacheKey, Arc<OnceCell<Arc<OHttpClient>>>>>,
    path_rewrite_group: PathRewriteGroup,
    forward_header_names: Vec<HeaderName>,
    body_field_headers: Vec<(String, HeaderName)>,
    key_refresh_before_expiry_seconds: Option<u64>,
    direct_forward_detector: Option<DirectForwardTrafficDetector>,
    runtime: TokioRuntime,
}

impl OHttpSecurityLayer {
    pub async fn new(
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        transport_so_mark: Option<u32>,
        ohttp_args: &OHttpArgs,
        ra_context: Arc<RaContext>,
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
                let certs = reqwest::Certificate::from_pem_bundle(&pem)
                    .with_context(|| format!("Failed to parse TLS CA certs: {path}"))?;
                for cert in certs {
                    builder = builder.add_root_certificate(cert);
                }
            }

            builder = builder.redirect(reqwest::redirect::Policy::none());
            builder = builder.no_proxy();
            builder = builder.no_gzip().no_brotli().no_zstd();

            builder.build()?
        };
        let body_field_headers = ohttp_args
            .body_field_headers
            .iter()
            .map(|bfh| {
                let header_name =
                    HeaderName::from_bytes(bfh.header_name.as_bytes()).with_context(|| {
                        format!(
                            "Invalid body_field_headers header_name: {}",
                            bfh.header_name
                        )
                    })?;
                Ok((bfh.field_name.clone(), header_name))
            })
            .collect::<Result<Vec<_>>>()?;

        let mut forward_header_names = ohttp_args
            .forward_headers
            .iter()
            .map(|name| {
                HeaderName::from_bytes(name.as_bytes())
                    .with_context(|| format!("Invalid forward_headers entry: {name}"))
            })
            .collect::<Result<Vec<_>>>()?;
        for (_, header_name) in &body_field_headers {
            forward_header_names.push(header_name.clone());
        }
        forward_header_names.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        forward_header_names.dedup();

        let direct_forward_detector = ohttp_args
            .direct_forward
            .as_ref()
            .map(|rules| DirectForwardTrafficDetector::new(rules.clone()))
            .transpose()
            .context("Failed to initialize direct_forward detector")
            .map_err(TngError::InvalidParameter)?;

        Ok(Self {
            ra_context,
            http_client: Arc::new(http_client),
            ohttp_clients: Default::default(),
            path_rewrite_group: PathRewriteGroup::new(&ohttp_args.path_rewrites)?,
            forward_header_names,
            body_field_headers,
            key_refresh_before_expiry_seconds: ohttp_args.key_refresh_before_expiry_seconds,
            direct_forward_detector,
            runtime,
        })
    }

    pub async fn forward_http_request(
        &self,
        endpoint: &TngEndpoint,
        request: axum::extract::Request,
    ) -> Result<(axum::response::Response, Option<AttestationResult>), TngError> {
        if let Some(detector) = &self.direct_forward_detector {
            if detector.matches_path(request.uri().path()) {
                tracing::debug!(
                    path = request.uri().path(),
                    "Direct forwarding request (bypassing OHTTP)"
                );
                return self.forward_directly(endpoint, request).await;
            }
        }

        async {
            let request = if !self.body_field_headers.is_empty() {
                self.promote_body_fields_to_headers(request).await?
            } else {
                request
            };

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

    async fn promote_body_fields_to_headers(
        &self,
        request: axum::extract::Request,
    ) -> Result<axum::extract::Request, TngError> {
        promote_body_fields(&self.body_field_headers, request).await
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
                endpoint.scheme(),
                endpoint.host(),
                endpoint.port()
            );

            url.parse::<Url>()
                .with_context(|| format!("Not a valid URL: {url}"))
                .map_err(TngError::CreateOHttpClientFailed)?
        };
        Ok(base_url)
    }

    async fn forward_directly(
        &self,
        endpoint: &TngEndpoint,
        request: axum::extract::Request,
    ) -> Result<(axum::response::Response, Option<AttestationResult>), TngError> {
        let method = request.method().clone();
        let url = format!(
            "{}://{}:{}{}",
            endpoint.scheme(),
            endpoint.host(),
            endpoint.port(),
            request
                .uri()
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/")
        );

        let has_body = request.body().size_hint().upper() != Some(0)
            && (request.headers().contains_key(header::CONTENT_LENGTH)
                || request.headers().contains_key(header::TRANSFER_ENCODING));

        let mut req_builder = self.http_client.request(method, &url);
        for (name, value) in request.headers() {
            if HOP_BY_HOP_HEADERS.contains(name) {
                continue;
            }
            req_builder = req_builder.header(name, value);
        }

        if has_body {
            let reqwest_body = reqwest::Body::wrap_stream(request.into_body().into_data_stream());
            req_builder = req_builder.body(reqwest_body);
        }

        let response = req_builder.send().await.map_err(|e| {
            TngError::DirectForwardFailed(anyhow::anyhow!("request to upstream failed: {e}"))
        })?;

        let status = response.status();
        let headers = response.headers().clone();
        let resp_body_stream = response.bytes_stream();

        let mut resp = axum::response::Response::builder().status(status);
        for (name, value) in headers.iter() {
            if HOP_BY_HOP_HEADERS.contains(name) {
                continue;
            }
            resp = resp.header(name, value);
        }
        let resp = resp
            .body(axum::body::Body::from_stream(resp_body_stream))
            .map_err(|e| {
                TngError::DirectForwardFailed(anyhow::anyhow!("response build failed: {e}"))
            })?;

        Ok((resp, None))
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
                    self.ra_context.clone(),
                    self.http_client.clone(),
                    base_url,
                    forward_headers,
                    self.key_refresh_before_expiry_seconds,
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

async fn promote_body_fields(
    body_field_headers: &[(String, HeaderName)],
    request: axum::extract::Request,
) -> Result<axum::extract::Request, TngError> {
    let all_present = body_field_headers
        .iter()
        .all(|(_, header_name)| request.headers().contains_key(header_name));
    if all_present {
        tracing::debug!("All body_field_headers already present, skipping body parsing");
        return Ok(request);
    }

    let content_type = request
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let content_type = content_type.to_ascii_lowercase();
    if !content_type.starts_with("application/json") {
        tracing::debug!(
            content_type,
            "Non-JSON content type, skipping body field promotion"
        );
        return Ok(request);
    }

    let (parts, body) = request.into_parts();
    let bytes = axum::body::to_bytes(body, BODY_FIELD_PROMOTION_MAX_BYTES)
        .await
        .map_err(|e| {
            TngError::InvalidOHttpRequest(anyhow::anyhow!(
                "Failed to buffer request body for field promotion: {e}"
            ))
        })?;

    let json_value: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("Failed to parse JSON body for field promotion: {e}");
            return Ok(axum::extract::Request::from_parts(
                parts,
                axum::body::Body::from(bytes),
            ));
        }
    };

    let mut parts = parts;
    if let serde_json::Value::Object(ref map) = json_value {
        for (field_name, header_name) in body_field_headers {
            if parts.headers.contains_key(header_name) {
                continue;
            }
            if let Some(serde_json::Value::String(value)) = map.get(field_name.as_str()) {
                match HeaderValue::from_str(value) {
                    Ok(header_value) => {
                        tracing::debug!(
                            field = field_name,
                            header = header_name.as_str(),
                            value = value,
                            "Promoted body field to header"
                        );
                        parts.headers.insert(header_name.clone(), header_value);
                    }
                    Err(e) => {
                        tracing::debug!(
                            field = field_name,
                            value = value,
                            "Skipping body field promotion, invalid header value: {e}"
                        );
                    }
                }
            } else {
                tracing::debug!(
                    field = field_name,
                    "Body field not found or not a string, skipping promotion"
                );
            }
        }
    }

    Ok(axum::extract::Request::from_parts(
        parts,
        axum::body::Body::from(bytes),
    ))
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

    #[tokio::test]
    async fn test_promote_body_fields_json_happy_path() {
        let config = vec![(
            "model".to_owned(),
            HeaderName::from_static("x-gateway-model-name"),
        )];
        let body = serde_json::json!({"model": "command-r-plus", "message": "hello"});
        let request = axum::extract::Request::builder()
            .uri("http://example.com/v1/chat")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let result = promote_body_fields(&config, request).await.unwrap();

        assert_eq!(
            result
                .headers()
                .get("x-gateway-model-name")
                .and_then(|v| v.to_str().ok()),
            Some("command-r-plus")
        );
    }

    #[tokio::test]
    async fn test_promote_body_fields_non_json_skipped() {
        let config = vec![(
            "model".to_owned(),
            HeaderName::from_static("x-gateway-model-name"),
        )];
        let request = axum::extract::Request::builder()
            .uri("http://example.com/v1/audio/transcriptions")
            .header("content-type", "multipart/form-data; boundary=---abc")
            .body(Body::from("some binary data"))
            .unwrap();

        let result = promote_body_fields(&config, request).await.unwrap();

        assert!(result.headers().get("x-gateway-model-name").is_none());
    }
}
