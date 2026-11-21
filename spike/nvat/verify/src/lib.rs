//! Verify saved NVIDIA GPU evidence through libnvat the way Trustee's NvRemote / NvLocal
//! verifiers do (deps/verifier/src/nvidia/nvat.rs, upstream PR #1627), and return the
//! verdict and the claims with the per-request fields (timestamps, token ids) removed, so
//! runs on different builds and machines can be diffed.
//!
//! NVAT_SPIKE_TLS_CA_CERT, if set, is passed as the CA bundle for every HTTPS request, or
//! with `auto`, the first of the usual system bundle locations that exists. Trustee sets
//! none, so the bundle path libcurl's configure found on the build machine applies.

use std::sync::OnceLock;

use base64::Engine;
use nv_attestation_sdk::{
    EvidencePolicy, GpuEvidenceSource, GpuLocalVerifier, GpuNrasVerifier, HttpOptions, Nonce,
    NvatSdk, OcspClient, RimStore, SdkOptions,
};
use serde_json::{json, Map, Value};

// The same HTTP settings Trustee uses.
const CONNECTION_TIMEOUT_MS: i64 = 10_000;
const REQUEST_TIMEOUT_MS: i64 = 60_000;
const MAX_RETRY_COUNT: i64 = 5;

// Claims that differ on every request rather than with the evidence or the build.
const VOLATILE: &[&str] = &["iat", "exp", "nbf", "jti"];

/// Verify `report` (hex) with its PEM `certs` against `nonce_hex`, through NRAS (`remote`) or
/// in-process (`local`).
pub fn run(
    mode: &str,
    report: &str,
    certs: &str,
    nonce_hex: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let report = std::fs::read_to_string(report)?;
    let certs = std::fs::read_to_string(certs)?;

    init_sdk()?;

    // Trustee's devices_to_nvat_json: the hex report re-encoded as base64, the PEM chain
    // base64-encoded as the attester sends it.
    let evidence = json!([{
        "arch": "HOPPER",
        "nonce": nonce_hex,
        "evidence": b64.encode(hex::decode(report.trim())?),
        "certificate": b64.encode(&certs),
    }]);
    let nonce = Nonce::from_hex(nonce_hex)?;
    let source = GpuEvidenceSource::from_json_string(&evidence.to_string())?;
    let evidence = source.collect(&nonce)?;

    let mut http = HttpOptions::builder()
        .max_retry_count(MAX_RETRY_COUNT)
        .connection_timeout_ms(CONNECTION_TIMEOUT_MS)
        .request_timeout_ms(REQUEST_TIMEOUT_MS);
    if let Some(ca) = tls_ca_cert()? {
        http = http.tls_ca_cert(ca);
    }
    let http = http.build()?;

    let result = match mode {
        "remote" => {
            let verifier = GpuNrasVerifier::new(None, None, Some(&http))?;
            verifier.verify(&evidence, &EvidencePolicy::default_policy()?)?
        }
        "local" => {
            let rim_store = RimStore::create_remote(None, None, Some(&http))?;
            let ocsp = OcspClient::create_default(None, None, Some(&http))?;
            let policy = EvidencePolicy::builder()
                .verify_rim_signature(true)
                .verify_rim_cert_chain(true)
                .build()?;
            let verifier = GpuLocalVerifier::new(&rim_store, &ocsp)?;
            verifier.verify(&evidence, &policy)?
        }
        _ => return Err(format!("unknown mode {mode}").into()),
    };

    let eat: Value = serde_json::from_str(&result.eat_json()?)?;
    if std::env::var_os("NVAT_SPIKE_RAW").is_some() {
        eprintln!("raw EAT: {eat}");
        eprintln!("raw claims: {}", result.claims_json()?);
    }
    let out = json!({
        "mode": mode,
        "success": result.is_success(),
        "result_code": result.result_code,
        "message": result.result_message(),
        "eat": decode_eat(&eat)?,
    });
    Ok(out)
}

// Where Linux distributions and macOS keep the system CA bundle (the files openssl-probe and
// Go's crypto/x509 look for).
const CA_BUNDLES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt", // Debian, Ubuntu, Arch, Gentoo
    "/etc/pki/tls/certs/ca-bundle.crt",   // Fedora, RHEL, CentOS
    "/etc/ssl/ca-bundle.pem",             // openSUSE
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // RHEL 7+
    "/etc/ssl/cert.pem",                  // macOS, Alpine, FreeBSD
];

fn tls_ca_cert() -> Result<Option<String>, Box<dyn std::error::Error>> {
    match std::env::var("NVAT_SPIKE_TLS_CA_CERT").ok().as_deref() {
        None => Ok(None),
        Some("auto") => {
            let found = CA_BUNDLES
                .iter()
                .find(|p| std::path::Path::new(p).is_file())
                .ok_or("no system CA bundle found")?;
            eprintln!("CA bundle: {found}");
            Ok(Some(found.to_string()))
        }
        Some(path) => Ok(Some(path.to_string())),
    }
}

/// Once per process and never shut down, as Trustee does.
fn init_sdk() -> Result<(), Box<dyn std::error::Error>> {
    static INIT: OnceLock<Result<(), String>> = OnceLock::new();
    INIT.get_or_init(|| {
        let sdk = NvatSdk::init(SdkOptions::new().map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        eprintln!("libnvat {}", NvatSdk::version());
        std::mem::forget(sdk);
        Ok(())
    })
    .clone()
    .map_err(Into::into)
}

/// A detached EAT is `[["JWT", <overall token>], {"<device>": <device token>, ...}]`; return
/// the tokens' payloads, minus the per-request claims.
fn decode_eat(eat: &Value) -> Result<Value, Box<dyn std::error::Error>> {
    let overall = eat[0][1].as_str().ok_or("EAT: no overall token")?;
    let mut devices = Map::new();
    for (name, token) in eat[1].as_object().ok_or("EAT: no device tokens")? {
        devices.insert(
            name.clone(),
            jwt_claims(token.as_str().ok_or("EAT: bad token")?)?,
        );
    }
    let mut overall = jwt_claims(overall)?;
    // The overall token binds each device token by digest, which changes with the device
    // token's iat and jti.
    if let Some(submods) = overall.get_mut("submods").and_then(Value::as_object_mut) {
        for submod in submods.values_mut() {
            if submod[0] == "DIGEST" {
                submod[1][1] = json!("<digest of the device token>");
            }
        }
    }
    Ok(json!({"overall": overall, "devices": devices}))
}

fn jwt_claims(token: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let payload = token.split('.').nth(1).ok_or("not a JWT")?;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut claims: Value = serde_json::from_slice(&b64.decode(payload.trim_end_matches('='))?)?;
    if let Some(map) = claims.as_object_mut() {
        for key in VOLATILE {
            map.remove(*key);
        }
    }
    Ok(claims)
}
