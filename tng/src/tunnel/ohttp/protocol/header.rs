pub const OHTTP_CHUNKED_REQUEST_CONTENT_TYPE: &str = "message/ohttp-chunked-req";

pub const OHTTP_CHUNKED_RESPONSE_CONTENT_TYPE: &str = "message/ohttp-chunked-res";

#[derive(Debug, Clone)]
#[allow(unused)]
pub enum OhttpApi {
    KeyConfig,
    Tunnel,
}

impl OhttpApi {
    pub const HEADER_NAME: &'static str = "x-tng-ohttp-api";
    /// - POST /tng/key-config: Get HPKE configuration
    pub const KEY_CONFIG: &'static str = "/tng/key-config";
    /// - POST /tng/tunnel: Process encrypted requests
    pub const TUNNEL: &'static str = "/tng/tunnel";
}
