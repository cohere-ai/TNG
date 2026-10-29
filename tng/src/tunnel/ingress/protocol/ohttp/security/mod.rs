pub mod client;
mod path_rewrite;

use std::{collections::HashMap, sync::Arc};

#[cfg(unix)]
use crate::tunnel::utils::socket::{
    TCP_KEEPALIVE_IDLE_SECS, TCP_KEEPALIVE_INTERVAL_SECS, TCP_KEEPALIVE_PROBE_COUNT,
};
use crate::{
    config::ingress::{ForwardHeader, OHttpArgs},
    error::TngError,
    tunnel::{
        endpoint::TngEndpoint,
        ingress::protocol::ohttp::security::{client::OHttpClient, path_rewrite::PathRewriteGroup},
        ohttp::protocol::header::OhttpApi,
        ra_context::RaContext,
        utils::direct_forward::DirectForwardTrafficDetector,
    },
    AttestationResult, TokioRuntime, HTTP_REQUEST_USER_AGENT_HEADER,
};
use anyhow::{Context, Result};
use http::{header, header::HeaderName, HeaderValue};
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

/// Returns true if the header is hop-by-hop per RFC 7230 §6.1: either in the
/// static list or named by a Connection header token.
fn is_hop_by_hop(name: &http::header::HeaderName, headers: &http::HeaderMap) -> bool {
    HOP_BY_HOP_HEADERS.contains(name)
        || headers
            .get_all(header::CONNECTION)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .any(|t| t.trim().eq_ignore_ascii_case(name.as_str()))
}

/// Header names from `forward_headers`, split by where each one is sent.
#[derive(Debug, PartialEq, Eq)]
struct ForwardHeaderNames {
    /// Sent on every outer request of the client they select, including
    /// key-config requests. Includes the `body_field_headers` headers.
    default: Vec<HeaderName>,
    /// Sent only on the tunnel request of the inner request they came from.
    tunnel_only: Vec<HeaderName>,
}

/// Parses `forward_headers` and adds the `body_field_headers` headers as default
/// entries, since key-config requests must carry them. Rejects a
/// name listed with different `tunnel_only` values, a `tunnel_only` entry for a
/// promoted body field, and a `tunnel_only` entry for a header TNG sets itself on
/// the outer request or that is hop-by-hop.
fn parse_forward_header_names(
    entries: &[ForwardHeader],
    body_field_headers: &[(String, HeaderName)],
) -> Result<ForwardHeaderNames> {
    let mut tunnel_only_by_name: Vec<(HeaderName, bool)> = Vec::with_capacity(entries.len());
    for entry in entries {
        let header_name = HeaderName::from_bytes(entry.name.as_bytes())
            .with_context(|| format!("Invalid forward_headers entry: {}", entry.name))?;
        match tunnel_only_by_name
            .iter()
            .find(|(name, _)| *name == header_name)
        {
            Some((_, tunnel_only)) if *tunnel_only != entry.tunnel_only => anyhow::bail!(
                "forward_headers entry {} is listed both with and without tunnel_only",
                entry.name
            ),
            Some(_) => continue,
            None => {}
        }
        if entry.tunnel_only {
            if HOP_BY_HOP_HEADERS.contains(&header_name)
                || header_name == header::CONTENT_TYPE
                || header_name == header::CONTENT_LENGTH
                || header_name == header::HOST
                || header_name.as_str() == OhttpApi::HEADER_NAME
            {
                anyhow::bail!(
                    "forward_headers entry {} is reserved or hop-by-hop and cannot be tunnel_only",
                    entry.name
                );
            }
            if body_field_headers
                .iter()
                .any(|(_, promoted)| *promoted == header_name)
            {
                anyhow::bail!(
                    "forward_headers entry {} is promoted by body_field_headers, which key-config requests must carry, so it cannot be tunnel_only",
                    entry.name
                );
            }
        }
        tunnel_only_by_name.push((header_name, entry.tunnel_only));
    }

    let mut names = ForwardHeaderNames {
        default: Vec::new(),
        tunnel_only: Vec::new(),
    };
    for (header_name, tunnel_only) in tunnel_only_by_name {
        if tunnel_only {
            names.tunnel_only.push(header_name);
        } else {
            names.default.push(header_name);
        }
    }
    for (_, header_name) in body_field_headers {
        names.default.push(header_name.clone());
    }
    for list in [&mut names.default, &mut names.tunnel_only] {
        list.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        list.dedup();
    }
    Ok(names)
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct OHttpClientCacheKey {
    base_url: Url,
    forwarded_headers: Vec<(String, String)>,
}

const BODY_FIELD_PROMOTION_MAX_BYTES: usize = 64 * 1024 * 1024;
const MULTIPART_PROMOTION_MAX_BYTES: usize = 64 * 1024;

pub struct OHttpSecurityLayer {
    ra_context: Arc<RaContext>,
    http_client: Arc<reqwest::Client>,
    ohttp_clients: RwLock<HashMap<OHttpClientCacheKey, Arc<OnceCell<Arc<OHttpClient>>>>>,
    path_rewrite_group: PathRewriteGroup,
    forward_header_names: Vec<HeaderName>,
    tunnel_only_header_names: Vec<HeaderName>,
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
        // The HTTP client cannot set SO_MARK on its own sockets, so an ingress that relies on a
        // mark to keep its iptables rules from capturing TNG's own egress traffic would send this
        // client's requests back into the tunnel. Refuse the combination instead of looping.
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        if transport_so_mark.is_some() {
            anyhow::bail!(
                "The `ohttp` protocol is not supported on an ingress that requires SO_MARK (such as `netfilter`). \
                 Use the `rats_tls` protocol with a `netfilter` ingress, or switch the ingress to `mapping`, `http_proxy` or `socks5`."
            );
        }

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

            // On wasm32 the browser owns the trust store: reqwest exposes neither
            // `Certificate` nor `add_root_certificate`, and there is no filesystem to read from.
            #[cfg(not(wasm))]
            for path in &ohttp_args.tls_ca_certs {
                let pem = std::fs::read(path)
                    .with_context(|| format!("Failed to read TLS CA cert: {path}"))?;
                let certs = reqwest::Certificate::from_pem_bundle(&pem)
                    .with_context(|| format!("Failed to parse TLS CA certs: {path}"))?;
                for cert in certs {
                    builder = builder.add_root_certificate(cert);
                }
            }

            // On wasm32 fetch owns all three of these, so reqwest exposes no way to set them: the
            // browser applies its own redirect and proxy behaviour and decodes Content-Encoding
            // transparently. A wasm ingress therefore follows redirects rather than surfacing them,
            // which is the browser's policy and not ours to override.
            #[cfg(not(wasm))]
            {
                builder = builder.redirect(reqwest::redirect::Policy::none());
                builder = builder.no_proxy();
                builder = builder.no_gzip().no_brotli().no_zstd();
            }

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

        let ForwardHeaderNames {
            default: forward_header_names,
            tunnel_only: tunnel_only_header_names,
        } = parse_forward_header_names(&ohttp_args.forward_headers, &body_field_headers)
            .map_err(TngError::InvalidParameter)?;

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
            tunnel_only_header_names,
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
            let tunnel_only_headers =
                Self::extract_tunnel_only_headers(&request, &self.tunnel_only_header_names);

            let ohttp_client = self
                .get_or_create_ohttp_client(base_url, forward_headers, cache_key_forwarded_headers)
                .await?;

            ohttp_client
                .forward_request(request, tunnel_only_headers)
                .await
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

        let mut req_builder = self.http_client.request(method, &url);
        for (name, value) in request.headers() {
            if is_hop_by_hop(name, request.headers()) {
                continue;
            }
            req_builder = req_builder.header(name, value);
        }

        let reqwest_body = reqwest::Body::wrap_stream(request.into_body().into_data_stream());
        req_builder = req_builder.body(reqwest_body);

        let response = req_builder.send().await.map_err(|e| {
            TngError::DirectForwardFailed(anyhow::anyhow!("request to upstream failed: {e}"))
        })?;

        let status = response.status();
        let headers = response.headers().clone();

        // Streamed natively, buffered on wasm: fetch's response stream is built on JS futures and so
        // is not `Send`, which `Body::from_stream` requires. Buffering costs the memory of one
        // response body, which the browser would hold anyway.
        #[cfg(not(wasm))]
        let resp_body = axum::body::Body::from_stream(response.bytes_stream());
        #[cfg(wasm)]
        let resp_body = axum::body::Body::from(response.bytes().await.map_err(|e| {
            TngError::DirectForwardFailed(anyhow::anyhow!("reading upstream response failed: {e}"))
        })?);

        let mut resp = axum::response::Response::builder().status(status);
        for (name, value) in headers.iter() {
            if is_hop_by_hop(name, &headers) {
                continue;
            }
            resp = resp.header(name, value);
        }
        let resp = resp.body(resp_body).map_err(|e| {
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

        // If no entry exists, or its client stopped refreshing, create one with uninitialized value.
        // Stopped clients for other egresses are dropped here too.
        let cell = match cell {
            Some(cell) if !cell.get().is_some_and(|client| client.is_stopped()) => cell,
            _ => {
                let mut map = self.ohttp_clients.write().await;
                map.retain(|_, cell| !cell.get().is_some_and(|client| client.is_stopped()));
                let cell = map.entry(client_cache_key).or_default().clone();
                if map.len() > 100 && map.len().is_power_of_two() {
                    tracing::warn!(
                        cache_size = map.len(),
                        "OHTTP client cache is large; high-cardinality forward_headers may cause unbounded growth (mark per-request headers tunnel_only)"
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

    /// Copies the tunnel-only headers present on the inner request, all values of each.
    /// The result goes on that request's outer OHTTP request only, never into the client
    /// cache key.
    fn extract_tunnel_only_headers(
        request: &axum::extract::Request,
        header_names: &[HeaderName],
    ) -> reqwest::header::HeaderMap {
        let mut tunnel_only_headers = reqwest::header::HeaderMap::new();
        for header_name in header_names {
            for header_value in request.headers().get_all(header_name) {
                tunnel_only_headers.append(header_name.clone(), header_value.clone());
            }
        }
        tunnel_only_headers
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
    let is_json = content_type.starts_with("application/json");
    let is_multipart = content_type.starts_with("multipart/form-data");
    if !is_json && !is_multipart {
        tracing::debug!(
            content_type,
            "Unsupported content type, skipping body field promotion"
        );
        return Ok(request);
    }

    let (parts, body) = request.into_parts();
    let (json_value, body) = if is_multipart {
        read_multipart_fields(&parts.headers, body).await?
    } else {
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
        (json_value, axum::body::Body::from(bytes))
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

    Ok(axum::extract::Request::from_parts(parts, body))
}

/// Holds at most MULTIPART_PROMOTION_MAX_BYTES before forwarding the rest of
/// the stream, so only form fields that precede the file part are promoted.
async fn read_multipart_fields(
    headers: &http::HeaderMap,
    body: axum::body::Body,
) -> Result<(serde_json::Value, axum::body::Body), TngError> {
    use futures::StreamExt as _;

    let Some(boundary) = headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| header_param(v, "boundary"))
        .filter(|b| !b.is_empty())
    else {
        tracing::debug!("Multipart boundary missing, skipping body field promotion");
        return Ok((serde_json::Value::Null, body));
    };

    let mut stream = body.into_data_stream();
    let mut prefix = bytes::BytesMut::new();
    while prefix.len() < MULTIPART_PROMOTION_MAX_BYTES {
        let Some(chunk) = stream.next().await else {
            break;
        };
        prefix.extend_from_slice(&chunk.map_err(|e| {
            TngError::InvalidOHttpRequest(anyhow::anyhow!(
                "Failed to read request body for field promotion: {e}"
            ))
        })?);
    }

    let fields = multipart_fields(&prefix, boundary);
    let prefix = prefix.freeze();
    let body = axum::body::Body::from_stream(
        futures::stream::once(async { Ok::<_, axum::Error>(prefix) }).chain(stream),
    );
    Ok((serde_json::Value::Object(fields), body))
}

fn multipart_fields(prefix: &[u8], boundary: &str) -> serde_json::Map<String, serde_json::Value> {
    let body = format!("\r\n{}", String::from_utf8_lossy(prefix));
    let segments: Vec<&str> = body.split(&format!("\r\n--{boundary}")).collect();
    let mut fields = serde_json::Map::new();
    // Skip the preamble and the last segment, which is the epilogue or a part
    // cut off at the read limit.
    for segment in segments
        .iter()
        .take(segments.len().saturating_sub(1))
        .skip(1)
    {
        let Some((headers, value)) = segment
            .strip_prefix("\r\n")
            .and_then(|part| part.split_once("\r\n\r\n"))
        else {
            break;
        };
        let Some(disposition) = headers.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-disposition")
                .then_some(value)
        }) else {
            continue;
        };
        if header_param(disposition, "filename").is_some()
            || header_param(disposition, "filename*").is_some()
        {
            break;
        }
        if let Some(name) = header_param(disposition, "name") {
            fields.entry(name).or_insert_with(|| value.into());
        }
    }
    fields
}

fn header_param<'a>(value: &'a str, key: &str) -> Option<&'a str> {
    let mut in_quotes = false;
    let separator = move |c: char| {
        if c == '"' {
            in_quotes = !in_quotes;
        }
        c == ';' && !in_quotes
    };
    value.split(separator).find_map(|param| {
        let (name, value) = param.split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case(key)
            .then(|| value.trim().trim_matches('"'))
    })
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

    #[test]
    fn test_extract_tunnel_only_headers_keeps_every_value() {
        let request = axum::extract::Request::builder()
            .uri("http://example.com/v1/embed")
            .header("x-request-id", "req-1")
            .header("traceparent", "00-aaaa-bbbb-01")
            .header("tracestate", "a=1")
            .header("tracestate", "b=2")
            .header("authorization", "Bearer secret")
            .body(Body::empty())
            .expect("request should be built");
        let header_names = parse_forward_header_names(
            &[
                tunnel_only("X-Request-Id"),
                tunnel_only("tracestate"),
                tunnel_only("traceparent"),
                tunnel_only("x-not-present"),
            ],
            &[],
        )
        .expect("names should parse")
        .tunnel_only;

        let tunnel_only_headers =
            OHttpSecurityLayer::extract_tunnel_only_headers(&request, &header_names);

        assert_eq!(tunnel_only_headers.len(), 4);
        assert_eq!(
            tunnel_only_headers
                .get("x-request-id")
                .and_then(|v| v.to_str().ok()),
            Some("req-1")
        );
        assert_eq!(
            tunnel_only_headers
                .get_all("tracestate")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .collect::<Vec<_>>(),
            vec!["a=1", "b=2"]
        );
        assert!(tunnel_only_headers.get("authorization").is_none());
    }

    fn tunnel_only(name: &str) -> ForwardHeader {
        ForwardHeader {
            name: name.to_owned(),
            tunnel_only: true,
        }
    }

    #[test]
    fn test_parse_forward_header_names_splits_entries() {
        let body_field_headers = vec![(
            "model".to_owned(),
            HeaderName::from_static("x-gateway-model-name"),
        )];
        let names = parse_forward_header_names(
            &[
                "x-routing-key".into(),
                tunnel_only("x-request-id"),
                tunnel_only("X-Request-Id"),
                "authorization".into(),
                // A promoted header may also be listed as a default entry.
                "x-gateway-model-name".into(),
            ],
            &body_field_headers,
        )
        .expect("names should parse");

        assert_eq!(
            names,
            ForwardHeaderNames {
                default: vec![
                    HeaderName::from_static("authorization"),
                    HeaderName::from_static("x-gateway-model-name"),
                    HeaderName::from_static("x-routing-key"),
                ],
                tunnel_only: vec![HeaderName::from_static("x-request-id")],
            }
        );
    }

    #[test]
    fn test_parse_forward_header_names_rejects_conflicts() {
        let body_field_headers = vec![(
            "model".to_owned(),
            HeaderName::from_static("x-gateway-model-name"),
        )];
        for entries in [
            vec![tunnel_only("x-gateway-model-name")],
            vec![tunnel_only("content-type")],
            vec![tunnel_only("Content-Length")],
            vec![tunnel_only("host")],
            vec![tunnel_only("transfer-encoding")],
            vec![tunnel_only("x-tng-ohttp-api")],
            vec![tunnel_only("not a header")],
            vec!["not a header".into()],
            vec!["x-request-id".into(), tunnel_only("X-Request-Id")],
            vec![tunnel_only("x-request-id"), "x-request-id".into()],
        ] {
            assert!(
                parse_forward_header_names(&entries, &body_field_headers).is_err(),
                "{entries:?} should be rejected"
            );
        }
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
            .header("content-type", "application/octet-stream")
            .body(Body::from("some binary data"))
            .unwrap();

        let result = promote_body_fields(&config, request).await.unwrap();

        assert!(result.headers().get("x-gateway-model-name").is_none());
    }

    #[tokio::test]
    async fn test_promote_body_fields_multipart() {
        let config = vec![(
            "model".to_owned(),
            HeaderName::from_static("x-gateway-model-name"),
        )];
        let model =
            "--b\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\ncohere-transcribe\r\n";
        let file = "--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.wav\"\r\n\r\nRIFF\0--b\r\n";
        let encoded_file = "--b\r\nContent-Disposition: form-data; name=\"file\"; filename*=UTF-8''a.wav\r\n\r\nRIFF\0--b\r\n";
        for (body, expected) in [
            (format!("{model}{file}--b--\r\n"), Some("cohere-transcribe")),
            (format!("{file}{model}--b--\r\n"), None),
            (format!("{encoded_file}{model}--b--\r\n"), None),
        ] {
            // One byte per chunk, so fields straddle chunk boundaries.
            let chunks: Vec<Result<Vec<u8>, std::io::Error>> =
                body.bytes().map(|byte| Ok(vec![byte])).collect();
            let request = axum::extract::Request::builder()
                .uri("http://example.com/v2/audio/transcriptions")
                .header("content-type", "multipart/form-data; boundary=\"b\"")
                .body(Body::from_stream(futures::stream::iter(chunks)))
                .unwrap();

            let result = promote_body_fields(&config, request).await.unwrap();

            assert_eq!(
                result
                    .headers()
                    .get("x-gateway-model-name")
                    .and_then(|v| v.to_str().ok()),
                expected
            );
            let forwarded = axum::body::to_bytes(result.into_body(), usize::MAX)
                .await
                .unwrap();
            assert_eq!(forwarded.as_ref(), body.as_bytes());
        }
    }

    #[test]
    fn test_header_param_quoted_semicolon() {
        let disposition = r#"form-data; name="a;filename=b"; x=1"#;
        assert_eq!(header_param(disposition, "name"), Some("a;filename=b"));
        assert_eq!(header_param(disposition, "filename"), None);
    }

    /// Verifies forward_directly preserves request framing across all common cases.
    #[tokio::test]
    #[allow(clippy::disallowed_methods)]
    async fn test_direct_forward_preserves_request_framing() {
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        use crate::config::ingress::OHttpArgs;
        use crate::config::ra::RaArgs;
        use crate::config::{DirectForwardRule, DirectForwardRules};
        use crate::tunnel::endpoint::TngEndpoint;
        use crate::tunnel::ra_context::RaContext;

        let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
        let port = listener.local_addr().unwrap().port();

        let shutdown = tokio_graceful::Shutdown::new(futures::future::pending::<()>());
        let runtime = TokioRuntime::current(shutdown.guard()).unwrap();
        let layer = Arc::new(
            OHttpSecurityLayer::new(
                #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                None,
                &OHttpArgs {
                    direct_forward: Some(DirectForwardRules(vec![DirectForwardRule {
                        http_path: "/.*".to_owned(),
                    }])),
                    ..Default::default()
                },
                Arc::new(
                    RaContext::from_ra_args(&RaArgs::NoRa, &runtime)
                        .await
                        .unwrap(),
                ),
                runtime,
            )
            .await
            .unwrap(),
        );
        let endpoint = TngEndpoint::new("127.0.0.1", port).with_scheme("http");

        // Send a request and return the raw bytes the upstream received
        let forward = |req: axum::extract::Request| {
            let l = listener.clone();
            let layer = layer.clone();
            let endpoint = endpoint.clone();
            async move {
                let srv = tokio::spawn(async move {
                    let (mut s, _) = l.accept().await.unwrap();
                    let mut buf = vec![0u8; 8192];
                    let n = s.read(&mut buf).await.unwrap();
                    s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
                        .await
                        .unwrap();
                    String::from_utf8_lossy(&buf[..n]).to_string()
                });
                layer.forward_http_request(&endpoint, req).await.unwrap();
                srv.await.unwrap()
            }
        };

        // GET with Body::empty (sidecar path)
        let raw = forward(
            axum::extract::Request::builder()
                .method("GET")
                .uri(format!("http://127.0.0.1:{port}/v1/models"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert!(
            !raw.to_lowercase().contains("transfer-encoding"),
            "GET (empty): {raw}"
        );

        // GET with Body::from_stream (Python SDK path — empty duplex)
        let (rd, wr) = tokio::io::duplex(1024);
        drop(wr);
        let raw = forward(
            axum::extract::Request::builder()
                .method("GET")
                .uri(format!("http://127.0.0.1:{port}/v1/models"))
                .body(Body::from_stream(tokio_util::io::ReaderStream::new(rd)))
                .unwrap(),
        )
        .await;
        assert!(
            !raw.to_lowercase().contains("transfer-encoding"),
            "GET (stream): {raw}"
        );

        // POST with Content-Length
        let raw = forward(
            axum::extract::Request::builder()
                .method("POST")
                .uri(format!("http://127.0.0.1:{port}/v1/chat"))
                .header("content-length", "11")
                .body(Body::from("hello world"))
                .unwrap(),
        )
        .await;
        assert!(
            raw.to_lowercase().contains("content-length: 11"),
            "POST CL: {raw}"
        );
        assert!(
            !raw.to_lowercase().contains("transfer-encoding"),
            "POST CL TE: {raw}"
        );
        assert!(raw.ends_with("hello world"), "POST CL body: {raw}");

        // POST streaming (no Content-Length)
        let (mut tx, rx) = tokio::io::duplex(1024);
        let req = axum::extract::Request::builder()
            .method("POST")
            .uri(format!("http://127.0.0.1:{port}/v1/stream"))
            .body(Body::from_stream(tokio_util::io::ReaderStream::new(rx)))
            .unwrap();
        let l = listener.clone();
        let srv = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            loop {
                let n = s.read(&mut tmp).await.unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(8).any(|w| w == b"streamed") {
                    break;
                }
            }
            s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
                .await
                .unwrap();
            String::from_utf8_lossy(&buf).to_string()
        });
        let fwd = tokio::spawn({
            let layer = layer.clone();
            let endpoint = endpoint.clone();
            async move { layer.forward_http_request(&endpoint, req).await.unwrap() }
        });
        tx.write_all(b"streamed").await.unwrap();
        drop(tx);
        fwd.await.unwrap();
        let raw = srv.await.unwrap();
        assert!(raw.contains("streamed"), "POST stream body: {raw}");
        assert!(
            !raw.to_lowercase().contains("content-length"),
            "POST stream CL: {raw}"
        );
    }
}
