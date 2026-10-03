use anyhow::{anyhow, bail, Context, Result};
use base64::{prelude::BASE64_STANDARD, Engine};
use bhttp::http_compat::{
    decode::{BhttpDecoder, HttpMessage},
    encode::BhttpEncoder,
};
use bytes::{BufMut, BytesMut};
use futures::{AsyncWriteExt as _, StreamExt, TryStreamExt as _};
use hpke::{kem::X25519HkdfSha256, Kem};
use http::StatusCode;
use ohttp::KeyConfig;
use prost::Message;
#[cfg(unix)]
use tokio::io::AsyncReadExt;
use tokio_util::{
    compat::{
        FuturesAsyncReadCompatExt as _, FuturesAsyncWriteCompatExt as _,
        TokioAsyncReadCompatExt as _,
    },
    io::StreamReader,
};
use url::Url;

use std::{pin::Pin, sync::Arc, time::Duration};

#[cfg(unix)]
use std::time::SystemTime;
#[cfg(wasm)]
use web_time::SystemTime;

#[cfg(unix)]
use crate::tunnel::service_metrics::{AttestationOperation, AttestationProtocol};
use crate::{
    error::CheckErrorResponse as _,
    tunnel::{
        attest::{check_response, AttestRequest},
        ohttp::protocol::{
            metadata::{metadata::ClientAuth, Metadata, NoAuth, METADATA_MAX_LEN},
            userdata::ServerUserData,
            KeyConfigRequest, KeyConfigResponse,
        },
        utils::maybe_cached::{Expire, MaybeCached, RefreshStrategy},
    },
};
use crate::{
    error::TngError,
    tunnel::{
        ohttp::{
            key_config::KeyConfigExtend,
            protocol::{
                header::{
                    OhttpApi, OHTTP_CHUNKED_REQUEST_CONTENT_TYPE,
                    OHTTP_CHUNKED_RESPONSE_CONTENT_TYPE,
                },
                metadata::ServerKeyConfigHint,
            },
        },
        ra_context::RaContext,
    },
    AttestationResult, TokioRuntime,
};

const DEFAULT_KEY_CONFIG_REFRESH_SECOND: u64 = 5 * 60; // 5 minutes
const DEFAULT_KEY_REFRESH_BEFORE_EXPIRY_SECONDS: u64 = 0;

pub struct OHttpClient {
    inner: Arc<OHttpClientInner>,
    key_store_value: MaybeCached<KeyStoreValue, TngError>,
}

pub struct OHttpClientInner {
    ra_context: Arc<RaContext>,
    http_client: Arc<reqwest::Client>,
    forward_headers: reqwest::header::HeaderMap,
    base_url: Url,
    #[allow(unused)]
    runtime: TokioRuntime,
    /// How many seconds before the reported expiry to treat the cached key as
    /// expired, triggering an early background refresh.
    refresh_before_expiry: Duration,
}

struct KeyStoreValue {
    client_auth: ClientAuth,

    #[allow(unused)]
    client_key: Option<(
        <X25519HkdfSha256 as Kem>::PrivateKey,
        <X25519HkdfSha256 as Kem>::PublicKey,
    )>,

    /// A base64 encoded list of key configurations, each entry is a Individual key configuration entry. Defined in Section 3.1 of RFC 9458.
    server_key_config_list: Vec<KeyConfig>,

    /// Server attestation information. This is only represented if the server attestation is required.
    server_attestation_result: Option<AttestationResult>,
}

impl OHttpClient {
    pub async fn new(
        ra_context: Arc<RaContext>,
        http_client: Arc<reqwest::Client>,
        base_url: Url,
        forward_headers: reqwest::header::HeaderMap,
        key_refresh_before_expiry_seconds: Option<u64>,
        runtime: TokioRuntime,
    ) -> Result<Self> {
        let refresh_before_expiry = Duration::from_secs(
            key_refresh_before_expiry_seconds.unwrap_or(DEFAULT_KEY_REFRESH_BEFORE_EXPIRY_SECONDS),
        );

        let refresh_strategy = {
            #[cfg(unix)]
            if let Some(attest_ctx) = ra_context.attest_context() {
                attest_ctx.refresh_strategy()
            } else {
                RefreshStrategy::Periodically {
                    interval: DEFAULT_KEY_CONFIG_REFRESH_SECOND,
                }
            }
            #[cfg(not(unix))]
            {
                RefreshStrategy::Periodically {
                    interval: DEFAULT_KEY_CONFIG_REFRESH_SECOND,
                }
            }
        };

        let inner = Arc::new(OHttpClientInner {
            ra_context,
            http_client,
            forward_headers,
            base_url,
            runtime: runtime.clone(),
            refresh_before_expiry,
        });

        let key_store_value = MaybeCached::new(runtime.clone(), refresh_strategy, {
            let inner = inner.clone();
            move || {
                let inner = inner.clone();
                Box::pin(async move {
                    inner
                        .create_key_store_value()
                        .await
                        .map_err(TngError::GenServerHpkeConfigurationResponseFailed)
                }) as Pin<Box<_>>
            }
        })
        .await?;

        Ok(Self {
            inner,
            key_store_value,
        })
    }
}

impl OHttpClient {
    pub async fn forward_request(
        &self,
        request: axum::extract::Request,
    ) -> Result<(axum::response::Response, Option<AttestationResult>), TngError> {
        let key_store_value = self.key_store_value.get_latest().await?;

        match self
            .inner
            .send_encrypted_request(
                &key_store_value.server_key_config_list,
                &key_store_value.client_auth,
                request,
            )
            .await
        {
            Ok(response) => Ok((response, key_store_value.server_attestation_result.clone())),
            Err(error) => {
                // When the key config is expired, we should invalidate the key config cache. So that the next request will get the new key config.
                if matches!(
                    error,
                    TngError::ShouldRequestNewKeyConfigFromServerError(..)
                ) {
                    self.key_store_value.invalidate();
                }
                Err(error)
            }
        }
    }
}

impl OHttpClientInner {
    async fn create_key_store_value(&self) -> Result<(KeyStoreValue, Expire)> {
        // Handle metatdata for self
        let (client_key, client_auth, mut expire) = self.create_attested_client_key().await?;
        #[cfg(unix)]
        let attestation_attempt = self.ra_context.verify_set().map(|set| {
            set.attestation_metrics()
                .start(AttestationOperation::Verify, AttestationProtocol::Ohttp)
        });

        let (server_key_config, verified) = match self.ra_context.verify_set() {
            Some(verify_set) => {
                #[cfg(unix)]
                let proposals = verify_set
                    .make_proposals(|| {
                        Some(
                            verify_set
                                .attestation_metrics()
                                .start(AttestationOperation::Challenge, AttestationProtocol::Ohttp),
                        )
                    })
                    .await?;
                #[cfg(not(unix))]
                let proposals = verify_set.make_proposals(|| ()).await?;

                let request = KeyConfigRequest {
                    attest_request: AttestRequest { proposals },
                };
                let response = self.get_hpke_configuration(request.clone()).await?;
                let verified = check_response(
                    &request.attest_request,
                    &response.attest_response,
                    Some(verify_set),
                    |proposal| {
                        ServerUserData {
                            challenge_token: proposal.challenge_token().map(str::to_owned),
                            hpke_key_config: response.hpke_key_config.clone(),
                        }
                        .to_claims()
                    },
                )
                .await?;
                (response.hpke_key_config, verified)
            }
            None => {
                let request = KeyConfigRequest::default();
                let response = self.get_hpke_configuration(request.clone()).await?;
                check_response(
                    &request.attest_request,
                    &response.attest_response,
                    None,
                    |_| bail!("unexpected attestation output"),
                )
                .await?;
                (response.hpke_key_config, None)
            }
        };

        #[cfg(unix)]
        if let Some(attempt) = attestation_attempt {
            attempt.mark_succeeded();
        }

        expire = std::cmp::min(
            expire,
            Expire::from_timestamp(server_key_config.expire_timestamp)?,
        );

        let server_attestation_result = match verified {
            Some(result) => {
                expire = std::cmp::min(expire, Expire::from_timestamp(result.exp()?)?);
                Some(result)
            }
            None => None,
        };

        let expire = adjust_expire_for_early_refresh(expire, self.refresh_before_expiry);

        let server_key_config_list = KeyConfig::decode_list(
            BASE64_STANDARD
                .decode(server_key_config.encoded_key_config_list)?
                .as_ref(),
        )?;

        let result = (
            KeyStoreValue {
                client_auth,
                client_key, // TODO: ohttp hpke setup with the client key
                server_key_config_list,
                server_attestation_result,
            },
            expire,
        );
        Ok(result)
    }

    async fn create_attested_client_key(
        &self,
    ) -> Result<(
        Option<(
            <X25519HkdfSha256 as Kem>::PrivateKey,
            <X25519HkdfSha256 as Kem>::PublicKey,
        )>,
        ClientAuth,
        Expire,
    )> {
        #[cfg(unix)]
        if self.ra_context.attest_context().is_some() {
            bail!("client attestation over OHTTP is disabled");
        }
        Ok((None, ClientAuth::NoAuth(NoAuth {}), Expire::NoExpire))
    }

    /// Interface 1: Get HPKE Configuration
    /// x-tng-ohttp-api: /tng/key-config
    ///
    /// This method is used by TNG Clients to obtain the public key configuration needed
    /// to establish an encrypted channel and verify the server's identity.
    async fn get_hpke_configuration(
        &self,
        key_config_request: KeyConfigRequest,
    ) -> Result<KeyConfigResponse, TngError> {
        let url = self.base_url.clone();

        tracing::info!(
            ?url,
            ?key_config_request,
            "Getting HPKE configuration upstream"
        );

        let response = self
            .http_client
            .post(url)
            .headers(self.forward_headers.clone())
            .header(OhttpApi::HEADER_NAME, OhttpApi::KEY_CONFIG)
            .json(&key_config_request)
            .send()
            .await
            .map_err(|error| TngError::RequestKeyConfigFailed(error.into()))?
            .check_error_response()
            .await
            .map_err(TngError::RequestKeyConfigFailed)?;

        let response: KeyConfigResponse = response
            .json()
            .await
            .map_err(|error| TngError::RequestKeyConfigFailed(error.into()))?;

        tracing::debug!(?response, "Received HPKE key configuration");

        Ok(response)
    }

    /// Clients use the hpke_key_config obtained from Interface 1 to encrypt a standard HTTP request,
    /// and send the encrypted ciphertext as the request body to the server.
    async fn send_encrypted_request(
        &self,
        server_key_config_list: &[KeyConfig],
        client_auth: &ClientAuth,
        request: axum::extract::Request,
    ) -> Result<axum::response::Response, TngError> {
        // Encode the request to bhttp message
        let bhttp_encoder = BhttpEncoder::from_request(request);

        // Encrypt to get the ohttp message
        let mut key_config = server_key_config_list
            .first()
            .context("No key config found")
            .map_err(TngError::ClientSelectHpkeConfigurationFailed)?
            .clone();

        tracing::debug!(
            public_key = ?key_config.public_key_data(),
            "Encrypting request with HPKE key"
        );

        let client = ohttp::ClientRequest::from_config(&mut key_config)?;

        let (encrypted_request, client_response_decapsulator) = {
            #[cfg(wasm)]
            let mut encrypted_request = Vec::new();
            #[cfg(wasm)]
            let client_request =
                client.encapsulate_stream(futures::io::Cursor::new(&mut encrypted_request))?;

            #[cfg(unix)]
            let (encrypted_request, request_write) = tokio::io::duplex(4096);
            #[cfg(unix)]
            let client_request = client.encapsulate_stream(request_write.compat())?;

            let client_response_decapsulator = client_request.response_decapsulator()?;

            let encryption_task = async {
                async {
                    let mut client_request = client_request.compat_write();
                    tokio::io::copy(
                        &mut bhttp_encoder
                            .map_err(std::io::Error::other)
                            .into_async_read()
                            .compat(),
                        &mut client_request,
                    )
                    .await?;
                    let mut client_request = client_request.into_inner();
                    client_request.close().await?; // Remember to close the response stream

                    Ok::<_, anyhow::Error>(())
                }
                .await
                .unwrap_or_else(|error| tracing::error!(?error, "Error when encrypting request"))
            };

            // We have to avoid using spawn_supervised_task_current_span(), since it may randomly not got executed on wasm (web) and currently we have no idea why.
            //  streaming request is not supported, so we can just wait for the encryption task to finish here.
            #[cfg(wasm)]
            let _: () = encryption_task.await;

            #[cfg(unix)]
            self.runtime
                .spawn_supervised_task_current_span(encryption_task);

            (encrypted_request, client_response_decapsulator)
        };

        let ohttp_request_body = {
            let metadata_buf = {
                let metadata = Metadata {
                    client_auth: Some(client_auth.clone()), // TODO: optimize this clone
                    key_config_hint: Some(ServerKeyConfigHint {
                        public_key: key_config.public_key_data()?.into_vec(),
                    }),
                };

                let metadata_len = metadata.encoded_len();
                if metadata_len > METADATA_MAX_LEN {
                    return Err(TngError::MetadataTooLong);
                }
                let mut metadata_buf = BytesMut::new();
                metadata_buf
                    .put_u32(u32::try_from(metadata_len).map_err(|_| TngError::MetadataTooLong)?); // big-endian
                metadata_buf.reserve(metadata_len); // to prevent reallocations during encoding
                metadata
                    .encode(&mut metadata_buf)
                    .map_err(TngError::MetadataEncodeError)?;
                tracing::trace!("metadata length: {:?}", metadata_buf.len());
                metadata_buf
            };

            #[cfg(wasm)]
            {
                let mut body_bytes = metadata_buf;
                body_bytes.extend_from_slice(&encrypted_request);
                tracing::debug!("Encrypted request body length: {:?}", body_bytes.len());
                reqwest::Body::from(body_bytes.freeze())
            }
            #[cfg(unix)]
            {
                let body = std::io::Cursor::new(metadata_buf).chain(encrypted_request);
                reqwest::Body::wrap_stream(tokio_util::io::ReaderStream::new(body))
            }
        };

        // Forward the request to the upstream server
        let url = self.base_url.clone();

        tracing::debug!(?url, "Sending OHTTP request to upstream server");

        let response = self
            .http_client
            .post(url)
            .headers(self.forward_headers.clone())
            .header(OhttpApi::HEADER_NAME, OhttpApi::TUNNEL)
            .header(
                http::header::CONTENT_TYPE,
                OHTTP_CHUNKED_REQUEST_CONTENT_TYPE,
            )
            .body(ohttp_request_body)
            .send()
            .await
            .map_err(TngError::HttpCipherTextForwardError)?;

        #[cfg(unix)]
        tracing::debug!(
            status = ?response.status(),
            version = ?response.version(),
            "Received OHTTP response from upstream server"
        );
        #[cfg(wasm)]
        tracing::debug!(
            status = ?response.status(),
            "Received OHTTP response from upstream server"
        );

        // Check the response status code
        let status_code = response.status();
        let response = response.check_error_response().await.map_err(|error| {
            if status_code == StatusCode::UNPROCESSABLE_ENTITY {
                TngError::ShouldRequestNewKeyConfigFromServerError(error)
            } else {
                TngError::HttpCipherTextBadResponse(error)
            }
        })?;

        // Check content-type
        match response.headers().get(http::header::CONTENT_TYPE) {
            Some(value) => {
                if value != OHTTP_CHUNKED_RESPONSE_CONTENT_TYPE {
                    return Err(TngError::InvalidOHttpResponse(anyhow!(
                        "Wrong content-type header"
                    )));
                }
            }
            None => {
                return Err(TngError::InvalidOHttpResponse(anyhow!(
                    "Wrong content-type header"
                )));
            }
        }

        let response_body = response.bytes_stream();

        #[cfg(wasm)]
        // Create a new stream wrapper here since reqwest::Response is not Send, which is required by BhttpDecoder.
        // TODO: maybe we can check Send requirements in BhttpDecoder can be removed ?
        let response_body = {
            use futures::SinkExt;

            let (mut sender, receiver) = futures::channel::mpsc::unbounded();
            tokio_with_wasm::task::spawn(async move {
                let stream = response_body;
                sender.send_all(&mut stream.map(|item| Ok(item))).await
            });
            receiver
        };

        // Decrypt the ohttp response message
        let decrypted_response = client_response_decapsulator.decapsulate_response(
            StreamReader::new(response_body.map(|result| result.map_err(std::io::Error::other)))
                .compat(),
        )?;
        // Decode the bhttp binary message
        let decode_result = BhttpDecoder::new(decrypted_response)
            .decode_message()
            .await?;

        let HttpMessage::Response(response) = decode_result.into_full_message()? else {
            return Err(TngError::InvalidHttpResponse);
        };

        let response = {
            let (head, body) = response.into_parts();
            tracing::debug!(response = ?head, "Decrypted response head from upstream server");
            http::Response::from_parts(head, body)
        };

        Ok(axum::response::IntoResponse::into_response(response))
    }
}

/// Shift the expiry earlier by `refresh_before_expiry` so a background refresh
/// fires before the egress actually evicts the key. If the buffer exceeds the
/// key's remaining TTL (adjusted time would land in the past), the original
/// expiry is kept and a warning is logged to avoid a tight refetch loop.
fn adjust_expire_for_early_refresh(expire: Expire, refresh_before_expiry: Duration) -> Expire {
    match expire {
        Expire::ExpireAt(t) => match t.checked_sub(refresh_before_expiry) {
            Some(adjusted) if adjusted > SystemTime::now() => Expire::ExpireAt(adjusted),
            _ => {
                if !refresh_before_expiry.is_zero() {
                    tracing::warn!(
                        refresh_before_expiry = ?refresh_before_expiry,
                        "key_refresh_before_expiry_seconds exceeds key's remaining TTL; \
                         skipping early refresh",
                    );
                }
                Expire::ExpireAt(t)
            }
        },
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adjust_expire_no_expire_unchanged() {
        let result = adjust_expire_for_early_refresh(Expire::NoExpire, Duration::from_secs(30));
        assert!(matches!(result, Expire::NoExpire));
    }

    #[test]
    fn test_adjust_expire_zero_buffer_unchanged() {
        let original = SystemTime::now() + Duration::from_secs(300);
        let result =
            adjust_expire_for_early_refresh(Expire::ExpireAt(original), Duration::from_secs(0));
        assert_eq!(result, Expire::ExpireAt(original));
    }

    #[test]
    fn test_adjust_expire_shifts_earlier() {
        let buffer = Duration::from_secs(30);
        let original = SystemTime::now() + Duration::from_secs(300);
        let result = adjust_expire_for_early_refresh(Expire::ExpireAt(original), buffer);

        match result {
            Expire::ExpireAt(adjusted) => {
                let shift = original.duration_since(adjusted).unwrap();
                assert_eq!(shift, buffer);
            }
            _ => panic!("expected ExpireAt"),
        }
    }

    #[test]
    fn test_adjust_expire_buffer_exceeds_ttl_keeps_original() {
        let original = SystemTime::now() + Duration::from_secs(10);
        let buffer = Duration::from_secs(600);
        let result = adjust_expire_for_early_refresh(Expire::ExpireAt(original), buffer);
        assert_eq!(result, Expire::ExpireAt(original));
    }

    #[test]
    fn test_adjust_expire_buffer_equals_ttl_keeps_original() {
        // When the buffer exactly equals (or nearly equals) the remaining TTL,
        // the adjusted time would be ~now which is not strictly in the future,
        // so the original expiry should be preserved.
        let original = SystemTime::now() + Duration::from_secs(1);
        let buffer = Duration::from_secs(2);
        let result = adjust_expire_for_early_refresh(Expire::ExpireAt(original), buffer);
        assert_eq!(result, Expire::ExpireAt(original));
    }
}
