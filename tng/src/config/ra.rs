use std::collections::HashMap;
use std::path::Path;

use anyhow::{anyhow, Context as _, Result};
use serde::de::Deserializer;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::TngError;
#[cfg(unix)]
use crate::tunnel::utils::maybe_cached::RefreshStrategy;

// ---------------------------------------------------------------------------
// Custom Deserialize on RaArgsUnchecked
// ---------------------------------------------------------------------------
// The JSON config format mixes an optional `model` tag with provider-specific
// keys (`aa_provider`, `as_provider`, `aa_type`, `as_type`) in one flat object.
// Serde has no built-in "default variant when tag is missing", so we inject
// defaults (`model`, provider tags, sub-type tags) into the raw JSON here
// before delegating to the serde-derived `AttestArgs` / `VerifyArgs`.
//
// Compared with the previous MaybeTagged-style split (tagged + untagged
// wrapper structs with TryFrom):
// 1. Provider enums (`AttesterArgs`, `ConverterArgs`, …) use plain serde
//    derives — no field duplication across extra layers.
// 2. `AttestArgs` / `VerifyArgs` are also serde-derived (`#[serde(tag, flatten)]`)
//    — no manual Serialize/Deserialize, so the structure is self-documenting.
// 3. Default injection lives in one place (here), keeping the downstream
//    types unaware of backward-compat defaulting.

/// Remote Attestation configuration parameters
#[derive(Debug, Clone, Serialize)]
pub struct RaArgsUnchecked {
    /// Whether to disable Remote Attestation functionality
    #[serde(default = "bool::default")]
    pub no_ra: bool,

    /// Attestation parameters configuration (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attest: Option<AttestArgs>,

    /// Verification parameters configuration (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify: Option<VerifyArgs>,
}

impl<'de> Deserialize<'de> for RaArgsUnchecked {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        /// Mirrors `RaArgsUnchecked` but keeps `attest`/`verify` as raw JSON
        /// so we can inject tag defaults before parsing.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            #[serde(default)]
            no_ra: bool,
            attest: Option<serde_json::Value>,
            verify: Option<serde_json::Value>,
        }

        let raw = Raw::deserialize(deserializer)?;

        let attest = raw
            .attest
            .map(|mut v| {
                if let Some(obj) = v.as_object_mut() {
                    inject_tag_defaults(obj);
                }
                serde_json::from_value::<AttestArgs>(v)
            })
            .transpose()
            .map_err(serde::de::Error::custom)?;

        let verify = raw
            .verify
            .map(|mut v| {
                if let Some(obj) = v.as_object_mut() {
                    inject_tag_defaults(obj);
                }
                serde_json::from_value::<VerifyArgs>(v)
            })
            .transpose()
            .map_err(serde::de::Error::custom)?;

        Ok(RaArgsUnchecked {
            no_ra: raw.no_ra,
            attest,
            verify,
        })
    }
}

#[derive(Debug, Clone)]
pub enum RaArgs {
    #[cfg(unix)]
    AttestOnly(AttestArgs),
    VerifyOnly(VerifyArgs),
    #[cfg(unix)]
    AttestAndVerify(AttestArgs, VerifyArgs),
    NoRa,
}

impl RaArgsUnchecked {
    pub fn into_checked(self) -> Result<RaArgs, TngError> {
        let ra_args = if self.no_ra {
            // Sanity check
            if self.verify.is_some() {
                return Err(TngError::InvalidParameter(anyhow!(
                    "The 'no_ra: true' flag should not be used with 'verify' field"
                )));
            }

            if self.attest.is_some() {
                return Err(TngError::InvalidParameter(anyhow!(
                    "The 'no_ra: true' flag should not be used with 'attest' field"
                )));
            }

            tracing::warn!("The 'no_ra: true' flag was set, please note that SHOULD NOT be used in production environment");

            RaArgs::NoRa
        } else {
            match (self.attest, self.verify) {
                (None, None) => {
                    return Err(TngError::InvalidParameter(anyhow!("At least one of 'attest' and 'verify' field and '\"no_ra\": true' should be set for 'add_egress'")));
                }
                (None, Some(verify)) => RaArgs::VerifyOnly(verify),
                #[cfg(unix)]
                (Some(attest), None) => RaArgs::AttestOnly(attest),
                #[cfg(unix)]
                (Some(attest), Some(verify)) => RaArgs::AttestAndVerify(attest, verify),
                #[cfg(wasm)]
                (Some(..), _) => {
                    return Err(TngError::InvalidParameter(anyhow!("`attest` option is not supported since attestation is not supported on this platform.")));
                }
            }
        };

        // Sanity check for the attest_args.
        #[cfg(unix)]
        if let RaArgs::AttestOnly(attest_args) | RaArgs::AttestAndVerify(attest_args, _) = &ra_args
        {
            match &attest_args {
                AttestArgs::Passport { attester, .. }
                | AttestArgs::BackgroundCheck { attester, .. } => match attester {
                    AttesterArgs::Coco(coco_attester) => match coco_attester {
                        CocoAttesterArgs::Uds { aa_addr } => {
                            let aa_sock_file = aa_addr
                                .strip_prefix("unix:///")
                                .context("AA address must start with unix:///")
                                .map_err(TngError::InvalidParameter)?;
                            let aa_sock_file = Path::new("/").join(aa_sock_file);
                            if !Path::new(&aa_sock_file).exists() {
                                return Err(TngError::InvalidParameter(anyhow!(
                                    "AA socket file {aa_sock_file:?} not found"
                                )));
                            }
                        }
                    },
                    AttesterArgs::Ita(ita) => {
                        let aa_sock_file = ita
                            .aa_addr
                            .strip_prefix("unix:///")
                            .context("AA address must start with unix:///")
                            .map_err(TngError::InvalidParameter)?;
                        let aa_sock_file = Path::new("/").join(aa_sock_file);
                        if !Path::new(&aa_sock_file).exists() {
                            return Err(TngError::InvalidParameter(anyhow!(
                                "AA socket file {aa_sock_file:?} not found"
                            )));
                        }
                    }
                    AttesterArgs::CocoAsr(args) => {
                        Url::parse(&args.asr_addr)
                            .with_context(|| format!("Invalid ASR address: {}", args.asr_addr))
                            .map_err(TngError::InvalidParameter)?;
                    }
                    AttesterArgs::ItaAsr(args) => {
                        Url::parse(&args.asr_addr)
                            .with_context(|| format!("Invalid ASR address: {}", args.asr_addr))
                            .map_err(TngError::InvalidParameter)?;
                    }
                },
            };

            if let AttestArgs::Passport {
                converter: ConverterArgs::Ita(ita),
                ..
            } = attest_args
            {
                Url::parse(&ita.as_addr)
                    .with_context(|| format!("Invalid ITA API address: {}", ita.as_addr))
                    .map_err(TngError::InvalidParameter)?;
                if ita.api_key.is_none() {
                    return Err(TngError::InvalidParameter(anyhow!(
                        "ITA api_key is required: set it in config or via ${} env var",
                        ITA_API_KEY_ENV
                    )));
                }
            }
        }

        // Sanity check for the verify_args.
        {
            let verify_args = match &ra_args {
                RaArgs::VerifyOnly(verify_args) => verify_args,
                #[cfg(unix)]
                RaArgs::AttestAndVerify(_, verify_args) => verify_args,
                _ => return Ok(ra_args),
            };

            // Check token_verify
            match verify_args {
                VerifyArgs::Passport { verifier }
                | VerifyArgs::BackgroundCheck { verifier, .. } => {
                    match verifier {
                        // This verifier only accepts tokens signed by the in-process service it was
                        // derived from, and in passport mode the token is minted by the peer's
                        // attestation service instead, which holds a different key. Every
                        // handshake would fail, so refuse the combination up front rather than at
                        // the first connection.
                        #[cfg(feature = "__coco-builtin-as")]
                        VerifierArgs::CocoBuiltin => {
                            if matches!(verify_args, VerifyArgs::Passport { .. }) {
                                return Err(TngError::InvalidParameter(anyhow!(
                                    "The 'coco_builtin' verifier cannot be used in passport mode, because it only accepts tokens minted by the builtin attestation service in this process, not ones the peer brings from its own. Use 'background_check' instead."
                                )));
                            }
                        }
                        VerifierArgs::Coco(coco_verifier) => match coco_verifier {
                            CocoVerifierArgs::Restful {
                                as_addr,
                                as_headers,
                                trusted_certs_paths,
                                ..
                            }
                            | CocoVerifierArgs::Grpc {
                                as_addr,
                                as_headers,
                                trusted_certs_paths,
                                ..
                            } => {
                                if as_addr.is_none() && !as_headers.is_empty() {
                                    return Err(TngError::InvalidParameter(anyhow!(
                                        "'as_headers' cannot be set without 'as_addr'"
                                    )));
                                }

                                // Additional checks for Passport mode
                                if matches!(verify_args, VerifyArgs::Passport { .. })
                                    && as_addr.is_none()
                                    && trusted_certs_paths.is_none()
                                {
                                    return Err(TngError::InvalidParameter(anyhow!("At least one of 'as_addr' or 'trusted_certs_paths' must be set to verify attestation token")));
                                }

                                if let Some(paths) = trusted_certs_paths {
                                    for path in paths {
                                        if !Path::new(path).exists() {
                                            return Err(TngError::InvalidParameter(anyhow!("Attestation service trusted certificate path does not exist: {}", path)));
                                        }
                                    }
                                }
                            }
                        },
                        VerifierArgs::Ita(_) => {
                            // ITA verifier fetches JWKS from the portal URL; no additional checks needed here
                        }
                    }
                }
            };

            // Check if as_addr is a valid URL (for Restful/Grpc types)
            if let VerifyArgs::BackgroundCheck {
                converter,
                verifier,
            } = verify_args
            {
                #[cfg(not(feature = "__coco-builtin-as"))]
                let _ = verifier;

                // The two halves of the builtin service are one unit: the verifier reads the
                // signing key and policy id out of the converter. Pairing it with anything else
                // would fail at the first handshake with an error about an unknown policy rather
                // than about the misconfiguration that caused it.
                #[cfg(feature = "__coco-builtin-as")]
                {
                    let converter_is_builtin =
                        matches!(converter, ConverterArgs::CocoBuiltin { .. });
                    let verifier_is_builtin = matches!(verifier, VerifierArgs::CocoBuiltin);

                    if converter_is_builtin != verifier_is_builtin {
                        return Err(TngError::InvalidParameter(anyhow!(
                            "'coco_builtin' must be set as the as_provider of both the converter and the verifier, or of neither"
                        )));
                    }
                }

                match converter {
                    #[cfg(feature = "__coco-builtin-as")]
                    ConverterArgs::CocoBuiltin {
                        policy_dir,
                        policy_ids,
                        ..
                    } => {
                        // No policy is compiled into the binary, so an ingress whose policy
                        // directory is missing could never verify anything.
                        if !Path::new(policy_dir).is_dir() {
                            return Err(TngError::InvalidParameter(anyhow!(
                                "Policy directory does not exist: {policy_dir}"
                            )));
                        }

                        // The EAR token broker enforces the first id and warns that it ignored the
                        // rest, so accepting a longer list would silently enforce less than asked.
                        if policy_ids.len() != 1 {
                            return Err(TngError::InvalidParameter(anyhow!(
                                "The 'coco_builtin' provider requires exactly one entry in 'policy_ids', naming the policies to read from {policy_dir} as {{policy_id}}_{{tee_class}}.rego, but {} were given",
                                policy_ids.len()
                            )));
                        }

                        // The id becomes both a filename and a storage key, and the attestation
                        // service rejects a key outside this set. Catching it here names the field
                        // at fault instead of failing later inside `set_policy`.
                        let id = &policy_ids[0];
                        if id.is_empty()
                            || !id
                                .chars()
                                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
                        {
                            return Err(TngError::InvalidParameter(anyhow!(
                                "Invalid policy id {id:?}: only ASCII letters, digits, '-', '_' and '.' are allowed"
                            )));
                        }
                    }
                    ConverterArgs::Coco(coco_converter) => match coco_converter {
                        CocoConverterArgs::Restful { as_addr, .. }
                        | CocoConverterArgs::Grpc { as_addr, .. } => {
                            Url::parse(as_addr)
                                .with_context(|| {
                                    format!("Invalid attestation service address: {}", as_addr)
                                })
                                .map_err(TngError::InvalidParameter)?;
                        }
                    },
                    ConverterArgs::Ita(ita) => {
                        Url::parse(&ita.as_addr)
                            .with_context(|| format!("Invalid ITA API address: {}", ita.as_addr))
                            .map_err(TngError::InvalidParameter)?;
                        if ita.api_key.is_none() {
                            return Err(TngError::InvalidParameter(anyhow!(
                                "ITA api_key is required: set it in config or via ${} env var",
                                ITA_API_KEY_ENV
                            )));
                        }
                    }
                }
            }
        }
        Ok(ra_args)
    }
}

// ---------------------------------------------------------------------------
// Provider-tagged config enums (serde-derived)
// ---------------------------------------------------------------------------

/// Provider-tagged attester config. Serde reads "aa_provider" from flat JSON.
/// Separate from as_provider because in Passport mode the attester and
/// converter can use different providers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "aa_provider", rename_all = "snake_case")]
pub enum AttesterArgs {
    Coco(CocoAttesterArgs),
    Ita(ItaAttesterArgs),
    CocoAsr(CocoAsrAttesterArgs),
    ItaAsr(ItaAsrAttesterArgs),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItaAttesterArgs {
    /// Attestation agent address (unix socket path). ITA reuses CoCo AA via ttrpc.
    pub aa_addr: String,
}

#[cfg(unix)]
impl ItaAttesterArgs {
    pub fn to_attester(&self) -> anyhow::Result<rats_cert::tee::ita::ItaAttester> {
        rats_cert::tee::ita::ItaAttester::new(&self.aa_addr).map_err(Into::into)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CocoAsrAttesterArgs {
    /// API Server Rest HTTP address (e.g. `"http://127.0.0.1:8006"`)
    pub asr_addr: String,
}

#[cfg(unix)]
impl CocoAsrAttesterArgs {
    pub fn to_attester(
        &self,
    ) -> anyhow::Result<rats_cert::tee::coco::asr_attester::CocoAsrAttester> {
        rats_cert::tee::coco::asr_attester::CocoAsrAttester::new(&self.asr_addr).map_err(Into::into)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItaAsrAttesterArgs {
    /// API Server Rest HTTP address (e.g. `"http://127.0.0.1:8006"`)
    pub asr_addr: String,
}

#[cfg(unix)]
impl ItaAsrAttesterArgs {
    pub fn to_attester(&self) -> anyhow::Result<rats_cert::tee::ita::ItaAsrAttester> {
        rats_cert::tee::ita::ItaAsrAttester::new(&self.asr_addr).map_err(Into::into)
    }
}

/// CoCo-internal attester variants. Serde reads "aa_type" from flat JSON.
/// Default is Uds when aa_type is omitted (injected by custom Deserialize).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "aa_type", rename_all = "snake_case")]
pub enum CocoAttesterArgs {
    /// Unix Domain Socket
    Uds {
        /// Attestation agent address (unix socket path)
        aa_addr: String,
    },
}

const DEFAULT_ITA_API_URL: &str = "https://api.trustauthority.intel.com";
const DEFAULT_ITA_PORTAL_URL: &str = "https://portal.trustauthority.intel.com";
const ITA_API_KEY_ENV: &str = "ITA_API_KEY";
fn default_ita_api_url() -> String {
    DEFAULT_ITA_API_URL.to_string()
}

fn default_ita_portal_url() -> String {
    DEFAULT_ITA_PORTAL_URL.to_string()
}

/// Where the builtin attestation service looks for its Rego policies.
///
/// Nothing is compiled into the binary, so this directory has to exist and hold a CPU policy
/// before an ingress using the builtin service will start.
#[cfg(feature = "__coco-builtin-as")]
const DEFAULT_POLICY_DIR: &str = "/etc/tng/policies";

#[cfg(feature = "__coco-builtin-as")]
fn default_policy_dir() -> String {
    DEFAULT_POLICY_DIR.to_string()
}

#[cfg(feature = "__coco-builtin-as")]
fn default_required_tee_classes() -> Vec<String> {
    vec![rats_cert::tee::coco::converter::policy::CPU_TEE_CLASS.to_owned()]
}

/// Provider-tagged converter config. Serde reads "as_provider" from flat JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "as_provider", rename_all = "snake_case")]
pub enum ConverterArgs {
    Coco(CocoConverterArgs),
    /// Upstream CoCo attestation service running in this process, with no remote AS involved.
    ///
    /// A provider of its own rather than an `as_type` under `coco`, because it shares no settings
    /// with the remote CoCo types: there is no address to reach, no headers to send and no
    /// certificates to trust.
    #[cfg(feature = "__coco-builtin-as")]
    CocoBuiltin {
        /// Directory the Rego policies are read from
        #[serde(default = "default_policy_dir")]
        policy_dir: String,
        /// Policy ID list, naming the policies in `policy_dir` to enforce
        ///
        /// A policy is read from `{policy_id}_{tee_class}.rego`, mirroring how the attestation
        /// service names a policy in its own storage, so one directory can hold several sets. A
        /// list to match the attestation service's request field and the other providers here,
        /// though its EAR token broker only ever honours one, so exactly one is required.
        policy_ids: Vec<String>,
        /// TEE classes a peer must attest, rejecting it if any is absent
        ///
        /// A policy cannot express this, because policies are only evaluated against the evidence
        /// that arrived: a peer that never offers its GPU is appraised on its CPU alone, and the
        /// `gpu` policy is never consulted no matter how strict it is.
        ///
        /// Defaults to `cpu`, because the class of a peer's primary evidence is whatever its agent
        /// reports it to be, and nothing else here ties that to a CPU. A peer presenting only
        /// device evidence would otherwise mint a token holding a single non-CPU appraisal and be
        /// accepted, so requiring the class is what makes "the peer runs in a confidential VM" a
        /// property this side checks rather than assumes. Add `gpu` to demand the device too, or
        /// set this to `[]` to accept whatever the peer presents.
        ///
        /// Always serialized, unlike the optional fields around it: with a non-empty default, an
        /// omitted field and an explicit `[]` mean different things, so a round trip through JSON
        /// has to preserve which one was written.
        #[serde(default = "default_required_tee_classes")]
        required_tee_classes: Vec<String>,
        /// Passed through to the attestation service's per-TEE verifier configuration
        #[serde(default, skip_serializing_if = "Option::is_none")]
        verifier_config: Option<serde_json::Value>,
    },
    Ita(ItaConverterArgs),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ItaConverterArgs {
    #[serde(default = "default_ita_api_url")]
    pub as_addr: String,
    /// Optional in config JSON -- if absent, `inject_ita_api_key_default()` fills
    /// it from the `$ITA_API_KEY` env var during deserialization.
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub policy_ids: Vec<String>,
    /// Max number of retries for ITA API calls (nonce + attest).
    /// When unset, uses the default from `ItaConverter`.
    pub ita_max_retries: Option<usize>,
    /// Initial delay between ITA API retries in milliseconds.
    /// When unset, uses the default from `ItaConverter`.
    pub ita_retry_initial_delay_ms: Option<u64>,
    /// Maximum delay between ITA API retries in milliseconds.
    /// When unset, uses the default from `ItaConverter`.
    pub ita_retry_max_delay_ms: Option<u64>,
}

/// Manual impl to redact `api_key` from debug/log output.
impl std::fmt::Debug for ItaConverterArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ItaConverterArgs")
            .field("as_addr", &self.as_addr)
            .field("api_key", &self.api_key.as_ref().map(|_| "[REDACTED]"))
            .field("policy_ids", &self.policy_ids)
            .field("ita_max_retries", &self.ita_max_retries)
            .field(
                "ita_retry_initial_delay_ms",
                &self.ita_retry_initial_delay_ms,
            )
            .field("ita_retry_max_delay_ms", &self.ita_retry_max_delay_ms)
            .finish()
    }
}

impl ItaConverterArgs {
    pub fn to_converter(&self) -> anyhow::Result<rats_cert::tee::ita::ItaConverter> {
        let api_key = self
            .api_key
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("ITA api_key is required but not set"))?;

        let mut converter =
            rats_cert::tee::ita::ItaConverter::new(api_key, &self.as_addr, &self.policy_ids)?;
        if let Some(n) = self.ita_max_retries {
            converter = converter.with_max_retries(n);
        }
        if let Some(ms) = self.ita_retry_initial_delay_ms {
            converter = converter.with_retry_initial_delay(std::time::Duration::from_millis(ms));
        }
        if let Some(ms) = self.ita_retry_max_delay_ms {
            converter = converter.with_retry_max_delay(std::time::Duration::from_millis(ms));
        }
        Ok(converter)
    }
}

/// CoCo-internal converter variants. Serde reads "as_type" from flat JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "as_type", rename_all = "snake_case")]
pub enum CocoConverterArgs {
    /// Restful API
    Restful {
        /// Attestation service address
        as_addr: String,
        /// Policy ID list
        #[serde(default)]
        policy_ids: Vec<String>,
        /// Custom headers to be sent with attestation service requests
        #[serde(default)]
        as_headers: HashMap<String, String>,
        /// CA certificate bundles used to authenticate the Attestation Service
        #[serde(default)]
        as_ca_certs: Vec<String>,
    },
    /// gRPC API
    Grpc {
        /// Attestation service address
        as_addr: String,
        /// Policy ID list
        #[serde(default)]
        policy_ids: Vec<String>,
        /// Custom headers to be sent with attestation service requests
        #[serde(default)]
        as_headers: HashMap<String, String>,
    },
}

/// Provider-tagged verifier config. Serde reads "as_provider" from flat JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "as_provider", rename_all = "snake_case")]
pub enum VerifierArgs {
    Coco(CocoVerifierArgs),
    /// Counterpart to [`ConverterArgs::CocoBuiltin`].
    ///
    /// Carries no settings of its own: the token it checks is signed with an ephemeral key held by
    /// the converter, so the key and the policy id it accepts both come from there rather than
    /// from configuration.
    #[cfg(feature = "__coco-builtin-as")]
    CocoBuiltin,
    Ita(ItaVerifierArgs),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItaVerifierArgs {
    #[serde(default = "default_ita_portal_url")]
    pub ita_jwks_addr: String,
    #[serde(default)]
    pub policy_ids: Vec<String>,
}

impl ItaVerifierArgs {
    pub fn to_verifier(&self) -> anyhow::Result<rats_cert::tee::ita::ItaVerifier> {
        rats_cert::tee::ita::ItaVerifier::new(&self.ita_jwks_addr, &self.policy_ids)
            .map_err(Into::into)
    }
}

/// CoCo-internal verifier variants. Serde reads "as_type" from flat JSON.
/// Mirrors CocoConverterArgs structure. as_addr is Optional because verifier
/// can work with just trusted_certs_paths (local cert trust) without AS.
/// Invariant: if as_addr is None, as_headers must be empty (checked in into_checked).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "as_type", rename_all = "snake_case")]
pub enum CocoVerifierArgs {
    /// Restful API
    Restful {
        /// Attestation service address, used for fetching AS certificate (optional)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        as_addr: Option<String>,
        /// Policy ID list
        policy_ids: Vec<String>,
        /// Custom headers to be sent with attestation service requests
        #[serde(default)]
        as_headers: HashMap<String, String>,
        /// Trusted certificate paths list (optional)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        trusted_certs_paths: Option<Vec<String>>,
    },
    /// gRPC API
    Grpc {
        /// Attestation service address, used for fetching AS certificate (optional)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        as_addr: Option<String>,
        /// Policy ID list
        policy_ids: Vec<String>,
        /// Custom headers to be sent with attestation service requests
        #[serde(default)]
        as_headers: HashMap<String, String>,
        /// Trusted certificate paths list (optional)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        trusted_certs_paths: Option<Vec<String>>,
    },
}

// ---------------------------------------------------------------------------
// AttestArgs / VerifyArgs (serde-derived)
// ---------------------------------------------------------------------------

#[cfg(unix)]
const EVIDENCE_REFRESH_INTERVAL_SECOND: u64 = 10 * 60; // 10 minutes

/// Attestation parameters configuration enum.
/// Note: refresh_interval lives here at the model level for consistency with
/// ConverterArgs/VerifierArgs (all plain enums). If desired, it could be moved
/// into AttesterArgs via a struct wrapper at the cost of one more level of
/// indirection and inconsistency with the ConverterArgs/VerifierArgs enums.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "model", rename_all = "snake_case")]
pub enum AttestArgs {
    /// Passport mode attestation parameters
    Passport {
        #[serde(flatten)]
        attester: AttesterArgs,
        #[serde(flatten)]
        converter: ConverterArgs,
        /// Evidence refresh interval (seconds), optional
        refresh_interval: Option<u64>,
        /// Max attestation attempts (evidence generation + optional passport conversion).
        /// Defaults to 3.
        max_retries: Option<usize>,
    },
    /// Background check mode attestation parameters
    BackgroundCheck {
        #[serde(flatten)]
        attester: AttesterArgs,
        /// Evidence refresh interval (seconds), optional
        refresh_interval: Option<u64>,
        /// Max attestation attempts (evidence generation). Defaults to 3.
        max_retries: Option<usize>,
    },
}

#[cfg(unix)]
impl AttestArgs {
    pub fn refresh_strategy(&self) -> RefreshStrategy {
        let interval = match self {
            Self::Passport {
                refresh_interval, ..
            }
            | Self::BackgroundCheck {
                refresh_interval, ..
            } => refresh_interval.unwrap_or(EVIDENCE_REFRESH_INTERVAL_SECOND),
        };
        if interval == 0 {
            RefreshStrategy::Always
        } else {
            RefreshStrategy::Periodically { interval }
        }
    }

    pub fn max_retries(&self) -> usize {
        match self {
            Self::Passport { max_retries, .. } | Self::BackgroundCheck { max_retries, .. } => {
                max_retries.unwrap_or(3)
            }
        }
    }
}

/// Verification parameters configuration enum.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "model", rename_all = "snake_case")]
pub enum VerifyArgs {
    /// Passport mode verification parameters
    Passport {
        #[serde(flatten)]
        verifier: VerifierArgs,
    },
    /// Background check mode verification parameters
    BackgroundCheck {
        #[serde(flatten)]
        converter: ConverterArgs,
        #[serde(flatten)]
        verifier: VerifierArgs,
    },
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Inject default tag values into raw JSON before delegation to serde-derived
/// deserializers. Covers the `model` discriminator, provider tags
/// (`aa_provider`/`as_provider`), and CoCo-specific sub-type tags
/// (`aa_type`/`as_type`) so that omitting any of them gives
/// backward-compatible defaults.
fn inject_tag_defaults(obj: &mut serde_json::Map<String, serde_json::Value>) {
    obj.entry("model").or_insert("background_check".into());
    obj.entry("aa_provider").or_insert("coco".into());
    obj.entry("as_provider").or_insert("coco".into());

    // CoCo-specific sub-type defaults
    if obj.get("aa_provider").and_then(|v| v.as_str()) == Some("coco") {
        obj.entry("aa_type").or_insert("uds".into());
    }
    if obj.get("as_provider").and_then(|v| v.as_str()) == Some("coco") {
        obj.entry("as_type").or_insert("restful".into());
    }

    // ITA: inject api_key from environment variable if not present in config
    if obj.get("as_provider").and_then(|v| v.as_str()) == Some("ita") {
        inject_ita_api_key_default(obj);
    }
}

/// Fill `api_key` from `$ITA_API_KEY` env var if it's absent or null in the config.
fn inject_ita_api_key_default(obj: &mut serde_json::Map<String, serde_json::Value>) {
    let has_key = obj
        .get("api_key")
        .map(|v| !v.is_null() && v.as_str() != Some(""))
        .unwrap_or(false);
    if !has_key {
        if let Ok(env_key) = std::env::var(ITA_API_KEY_ENV) {
            if !env_key.is_empty() {
                obj.insert("api_key".into(), serde_json::Value::String(env_key));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn test_background_check_attest_without_model() {
        let json = json!(
            {
                "attest": {
                    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
                    "refresh_interval": 3600
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.attest {
            Some(AttestArgs::BackgroundCheck {
                attester,
                refresh_interval,
                ..
            }) => {
                match attester {
                    AttesterArgs::Coco(CocoAttesterArgs::Uds { aa_addr }) => {
                        assert_eq!(
                            aa_addr,
                            "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                        );
                    }
                    _ => panic!("Expected Coco/Uds variant"),
                }
                assert_eq!(*refresh_interval, Some(3600));
            }
            _ => panic!("Expected BackgroundCheck variant"),
        }

        // Test serialization
        let serialized = serde_json::to_string(&ra_args).expect("Failed to serialize");
        assert!(serialized.contains(r#""aa_type":"uds""#));
        assert!(serialized.contains(r#""aa_addr":"unix:///run/confidential-containers/attestation-agent/attestation-agent.sock""#));
        assert!(serialized.contains(r#""refresh_interval":3600"#));
    }

    #[test]
    fn test_background_check_attest_with_model() {
        let json = json!(
            {
                "attest": {
                    "model": "background_check",
                    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
                    "refresh_interval": 3600
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.attest {
            Some(AttestArgs::BackgroundCheck {
                attester,
                refresh_interval,
                ..
            }) => {
                match attester {
                    AttesterArgs::Coco(CocoAttesterArgs::Uds { aa_addr }) => {
                        assert_eq!(
                            aa_addr,
                            "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                        );
                    }
                    _ => panic!("Expected Coco/Uds variant"),
                }
                assert_eq!(*refresh_interval, Some(3600));
            }
            _ => panic!("Expected BackgroundCheck variant"),
        }
    }

    #[test]
    fn test_passport_attest() {
        let json = json!(
            {
                "attest": {
                    "model": "passport",
                    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
                    "refresh_interval": 3600,
                    "as_addr": "localhost:8081",
                    "policy_ids": ["policy1", "policy2"]
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.attest {
            Some(AttestArgs::Passport {
                attester,
                converter,
                refresh_interval,
                ..
            }) => {
                match attester {
                    AttesterArgs::Coco(CocoAttesterArgs::Uds { aa_addr }) => {
                        assert_eq!(
                            aa_addr,
                            "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                        );
                    }
                    _ => panic!("Expected Coco/Uds variant"),
                }
                assert_eq!(*refresh_interval, Some(3600));
                match converter {
                    ConverterArgs::Coco(CocoConverterArgs::Restful {
                        as_addr,
                        policy_ids,
                        ..
                    }) => {
                        assert_eq!(as_addr, "localhost:8081");
                        assert_eq!(policy_ids, &vec!["policy1", "policy2"]);
                    }
                    _ => panic!("Expected Coco/Restful converter"),
                }
            }
            _ => panic!("Expected Passport variant"),
        }

        // Test serialization
        let serialized = serde_json::to_string(&ra_args).expect("Failed to serialize");
        assert!(serialized.contains(r#""model":"passport""#));
        assert!(serialized.contains(r#""aa_type":"uds""#));
        assert!(serialized.contains(r#""aa_addr":"unix:///run/confidential-containers/attestation-agent/attestation-agent.sock""#));
        assert!(serialized.contains(r#""as_type":"restful""#));
        assert!(serialized.contains(r#""as_addr":"localhost:8081""#));
        assert!(serialized.contains(r#""policy_ids":["policy1","policy2"]"#));
    }

    #[test]
    #[should_panic]
    fn test_attest_bad_model() {
        let json = json!(
            {
                "attest": {
                    "model": "foobar",
                    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                }
            }
        );

        serde_json::from_value::<RaArgsUnchecked>(json).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_passport_attest_missing_fields() {
        let json = json!(
            {
                "attest": {
                    "model": "passport",
                    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                }
            }
        );

        serde_json::from_value::<RaArgsUnchecked>(json).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_verify_bad_model() {
        let json = json!(
            {
                "verify": {
                    "model": "foobar",
                    "as_addr": "localhost:8081",
                    "policy_ids": ["policy1", "policy2"]
                }
            }
        );

        serde_json::from_value::<RaArgsUnchecked>(json).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_passport_verify_missing_fields() {
        let json = json!(
            {
                "verify": {
                    "model": "passport",
                    "as_addr": "localhost:8081"
                }
            }
        );

        serde_json::from_value::<RaArgsUnchecked>(json).unwrap();
    }
    #[test]
    fn test_background_check_verify_without_model() {
        let json = json!(
            {
                "verify": {
                    "as_addr": "localhost:8081",
                    "policy_ids": ["policy1", "policy2"]
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.verify {
            Some(VerifyArgs::BackgroundCheck { converter, .. }) => match converter {
                ConverterArgs::Coco(CocoConverterArgs::Restful {
                    as_addr,
                    policy_ids,
                    ..
                }) => {
                    assert_eq!(as_addr, "localhost:8081");
                    assert_eq!(policy_ids, &vec!["policy1", "policy2"]);
                }
                _ => panic!("Expected Coco/Restful converter"),
            },
            _ => panic!("Expected BackgroundCheck variant"),
        }
    }

    #[test]
    fn test_background_check_verify_with_model() {
        let json = json!(
            {
                "verify": {
                    "model": "background_check",
                    "as_addr": "localhost:8081",
                    "policy_ids": ["policy1", "policy2"]
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.verify {
            Some(VerifyArgs::BackgroundCheck { converter, .. }) => match converter {
                ConverterArgs::Coco(CocoConverterArgs::Restful {
                    as_addr,
                    policy_ids,
                    ..
                }) => {
                    assert_eq!(as_addr, "localhost:8081");
                    assert_eq!(policy_ids, &vec!["policy1", "policy2"]);
                }
                _ => panic!("Expected Coco/Restful converter"),
            },
            _ => panic!("Expected BackgroundCheck variant"),
        }
    }

    #[test]
    fn test_passport_verify() {
        let json = json!(
            {
                "verify": {
                    "model": "passport",
                    "policy_ids": ["policy1", "policy2"]
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.verify {
            Some(VerifyArgs::Passport { verifier }) => match verifier {
                VerifierArgs::Coco(CocoVerifierArgs::Restful { policy_ids, .. }) => {
                    assert_eq!(policy_ids, &vec!["policy1", "policy2"]);
                }
                _ => panic!("Expected Coco/Restful verifier"),
            },
            _ => panic!("Expected Passport variant"),
        }

        // Test serialization
        let serialized = serde_json::to_string(&ra_args).expect("Failed to serialize");
        assert!(serialized.contains(r#""model":"passport""#));
        assert!(serialized.contains(r#""policy_ids":["policy1","policy2"]"#));
    }

    #[test]
    fn test_passport_verify_with_invalid_cert_path() {
        let json = json!(
            {
                "verify": {
                    "model": "passport",
                    "policy_ids": ["policy1"],
                    "trusted_certs_paths": ["/path/that/does/not/exist/cert.pem"]
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");
        let result = ra_args.into_checked();
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(
            format!("{error:?}").contains("trusted certificate path does not exist"),
            "{error:?}"
        );
    }

    #[test]
    fn test_background_check_verify_with_invalid_cert_path() {
        let json = json!(
            {
                "verify": {
                    "model": "background_check",
                    "as_addr": "http://localhost:8080",
                    "policy_ids": ["policy1"],
                    "trusted_certs_paths": ["/path/that/does/not/exist/cert.pem"]
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");
        let result = ra_args.into_checked();
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(
            format!("{error:?}").contains("trusted certificate path does not exist"),
            "{error:?}"
        );
    }

    #[test]
    fn test_background_check_verify_with_invalid_as_addr() {
        let json = json!(
            {
                "verify": {
                    "model": "background_check",
                    "as_addr": "not-a-valid-url",
                    "policy_ids": ["policy1"]
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");
        let result = ra_args.into_checked();
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(
            format!("{error:?}").contains("Invalid attestation service address"),
            "{error:?}"
        );
    }

    #[test]
    fn test_background_check_verify_with_valid_as_addr() {
        let json = json!(
            {
                "verify": {
                    "model": "background_check",
                    "as_addr": "<should-be-a-url>:<should-be-a-port-number>",
                    "policy_ids": ["policy1"]
                }
            }
        );

        let ra_args: RaArgsUnchecked =
            serde_json::from_value::<RaArgsUnchecked>(json).expect("Failed to deserialize");
        let result = ra_args.into_checked();
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(
            format!("{error:?}").contains("Invalid attestation service address"),
            "{error:?}"
        );
    }

    #[test]
    fn test_new_format_attest_with_aa_type_uds() {
        // New format: explicit aa_type="uds"
        let json = json!(
            {
                "attest": {
                    "aa_type": "uds",
                    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock",
                    "refresh_interval": 3600
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.attest {
            Some(AttestArgs::BackgroundCheck {
                attester,
                refresh_interval,
                ..
            }) => {
                match attester {
                    AttesterArgs::Coco(CocoAttesterArgs::Uds { aa_addr }) => {
                        assert_eq!(
                            aa_addr,
                            "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                        );
                    }
                    _ => panic!("Expected Coco/Uds variant"),
                }
                assert_eq!(*refresh_interval, Some(3600));
            }
            _ => panic!("Expected BackgroundCheck variant"),
        }

        // Test serialization
        let serialized = serde_json::to_string(&ra_args).expect("Failed to serialize");
        assert!(serialized.contains(r#""aa_type":"uds""#));
    }

    #[test]
    fn test_new_format_verify_with_as_type_restful() {
        // New format: explicit as_type="restful"
        let json = json!(
            {
                "verify": {
                    "as_type": "restful",
                    "as_addr": "http://localhost:8080",
                    "policy_ids": ["policy1"]
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.verify {
            Some(VerifyArgs::BackgroundCheck { converter, .. }) => match converter {
                ConverterArgs::Coco(CocoConverterArgs::Restful {
                    as_addr,
                    policy_ids,
                    ..
                }) => {
                    assert_eq!(as_addr, "http://localhost:8080");
                    assert_eq!(policy_ids, &vec!["policy1"]);
                }
                _ => panic!("Expected Coco/Restful converter"),
            },
            _ => panic!("Expected BackgroundCheck variant"),
        }

        // Test serialization
        let serialized = serde_json::to_string(&ra_args).expect("Failed to serialize");
        assert!(serialized.contains(r#""as_type":"restful""#));
    }

    #[test]
    fn test_new_format_verify_with_as_type_grpc() {
        // New format: explicit as_type="grpc"
        let json = json!(
            {
                "verify": {
                    "as_type": "grpc",
                    "as_addr": "http://localhost:5000",
                    "policy_ids": ["policy1"]
                }
            }
        );

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.verify {
            Some(VerifyArgs::BackgroundCheck { converter, .. }) => match converter {
                ConverterArgs::Coco(CocoConverterArgs::Grpc { as_addr, .. }) => {
                    assert_eq!(as_addr, "http://localhost:5000");
                }
                _ => panic!("Expected Coco/Grpc converter"),
            },
            _ => panic!("Expected BackgroundCheck variant"),
        }

        // Test serialization
        let serialized = serde_json::to_string(&ra_args).expect("Failed to serialize");
        assert!(serialized.contains(r#""as_type":"grpc""#));
    }

    /// The builtin service is selected with `as_provider` rather than an `as_type` under `coco`,
    /// because it shares no settings with the remote CoCo types. Both halves of a background_check
    /// verifier flatten from that one tag, so naming it once configures the pair.
    #[cfg(feature = "__coco-builtin-as")]
    #[test]
    fn test_coco_builtin_is_selected_by_as_provider() {
        let json = json!({
            "verify": {
                "as_provider": "coco_builtin",
                "policy_dir": "/etc/tng/policies",
                "policy_ids": ["myorg"]
            }
        });

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.verify {
            Some(VerifyArgs::BackgroundCheck {
                converter,
                verifier,
            }) => {
                match converter {
                    ConverterArgs::CocoBuiltin {
                        policy_dir,
                        policy_ids,
                        ..
                    } => {
                        assert_eq!(policy_dir, "/etc/tng/policies");
                        assert_eq!(policy_ids, &vec!["myorg"]);
                    }
                    _ => panic!("Expected CocoBuiltin converter"),
                }
                assert!(matches!(verifier, VerifierArgs::CocoBuiltin));
            }
            _ => panic!("Expected BackgroundCheck variant"),
        }

        let serialized = serde_json::to_string(&ra_args).expect("Failed to serialize");
        assert!(serialized.contains(r#""as_provider":"coco_builtin""#));
        // No sub-type tag should be injected for a provider that has no sub-types.
        assert!(!serialized.contains(r#""as_type""#));
    }

    /// A list of any length but one would enforce something other than what was asked for, since
    /// the broker takes the first id and only warns about the rest; and an id outside the storage
    /// key charset would fail later inside `set_policy` instead.
    #[cfg(feature = "__coco-builtin-as")]
    #[test]
    fn test_coco_builtin_rejects_unusable_policy_ids() {
        for policy_ids in [json!([]), json!(["one", "two"]), json!(["my policy!"])] {
            let json = json!({
                "verify": {
                    "as_provider": "coco_builtin",
                    "policy_dir": "/tmp",
                    "policy_ids": policy_ids
                }
            });

            let ra_args: RaArgsUnchecked =
                serde_json::from_value(json).expect("Failed to deserialize");

            ra_args
                .into_checked()
                .expect_err(&format!("{policy_ids} should be rejected"));
        }
    }

    /// Omitting `policy_dir` has to be allowed, since a deployment installing policies at the
    /// default location should not have to name it.
    #[cfg(feature = "__coco-builtin-as")]
    #[test]
    fn test_coco_builtin_policy_dir_defaults() {
        let json = json!({"verify": {"as_provider": "coco_builtin", "policy_ids": ["myorg"]}});

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.verify {
            Some(VerifyArgs::BackgroundCheck {
                converter: ConverterArgs::CocoBuiltin { policy_dir, .. },
                ..
            }) => assert_eq!(policy_dir, DEFAULT_POLICY_DIR),
            _ => panic!("Expected a CocoBuiltin converter"),
        }
    }

    // =====================================================================
    // ITA mode tests
    // =====================================================================

    #[test]
    fn test_ita_passport_attest_config() {
        let aa_addr = "unix:///tmp/ita-aa.sock";
        let as_addr = "https://api.trustauthority.intel.com";
        let api_key = "test-key";
        let json = json!({
            "attest": {
                "model": "passport",
                "aa_provider": "ita",
                "aa_addr": aa_addr,
                "as_provider": "ita",
                "as_addr": as_addr,
                "api_key": api_key,
                "max_retries": 5,
                "ita_max_retries": 2,
                "ita_retry_initial_delay_ms": 200,
                "ita_retry_max_delay_ms": 2000
            }
        });

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.attest {
            Some(AttestArgs::Passport {
                attester,
                converter,
                max_retries,
                ..
            }) => {
                assert_eq!(*max_retries, Some(5));
                match attester {
                    AttesterArgs::Ita(ita) => {
                        assert_eq!(ita.aa_addr, aa_addr);
                    }
                    _ => panic!("Expected Ita attester"),
                }
                match converter {
                    ConverterArgs::Ita(ita) => {
                        assert_eq!(ita.as_addr, as_addr);
                        assert_eq!(ita.api_key, Some(api_key.to_string()));
                        assert_eq!(ita.ita_max_retries, Some(2));
                        assert_eq!(ita.ita_retry_initial_delay_ms, Some(200));
                        assert_eq!(ita.ita_retry_max_delay_ms, Some(2000));
                    }
                    _ => panic!("Expected Ita converter"),
                }
            }
            _ => panic!("Expected Passport attest variant"),
        }
    }

    #[test]
    fn test_ita_background_check_attest_config() {
        let aa_addr = "unix:///tmp/ita-aa.sock";
        let json = json!({
            "attest": {
                "aa_provider": "ita",
                "aa_addr": aa_addr
            }
        });

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.attest {
            Some(AttestArgs::BackgroundCheck {
                attester,
                max_retries,
                ..
            }) => {
                assert_eq!(*max_retries, None);
                match attester {
                    AttesterArgs::Ita(ita) => {
                        assert_eq!(ita.aa_addr, aa_addr);
                    }
                    _ => panic!("Expected Ita attester"),
                }
            }
            _ => panic!("Expected BackgroundCheck attest variant"),
        }
    }

    #[test]
    fn test_ita_background_check_verify_config() {
        let as_addr = "https://api.trustauthority.intel.com";
        let api_key = "test-key-123";
        let policy_ids = vec!["policy-1"];
        let json = json!({
            "verify": {
                "model": "background_check",
                "as_provider": "ita",
                "as_addr": as_addr,
                "api_key": api_key,
                "policy_ids": policy_ids
            }
        });

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.verify {
            Some(VerifyArgs::BackgroundCheck {
                converter,
                verifier,
            }) => {
                match converter {
                    ConverterArgs::Ita(ita) => {
                        assert_eq!(ita.as_addr, as_addr);
                        assert_eq!(ita.api_key, Some(api_key.to_string()));
                        assert_eq!(ita.policy_ids, policy_ids);
                    }
                    _ => panic!("Expected Ita converter"),
                }
                match verifier {
                    VerifierArgs::Ita(ita) => {
                        assert_eq!(ita.ita_jwks_addr, DEFAULT_ITA_PORTAL_URL);
                        assert_eq!(ita.policy_ids, policy_ids);
                    }
                    _ => panic!("Expected Ita verifier"),
                }
            }
            _ => panic!("Expected BackgroundCheck variant"),
        }
    }

    #[test]
    fn test_ita_passport_verify_config() {
        let jwks_addr = "https://portal.custom.intel.com";
        let policy_ids = vec!["my-policy"];
        let json = json!({
            "verify": {
                "model": "passport",
                "as_provider": "ita",
                "ita_jwks_addr": jwks_addr,
                "policy_ids": policy_ids
            }
        });

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");

        match &ra_args.verify {
            Some(VerifyArgs::Passport { verifier }) => match verifier {
                VerifierArgs::Ita(ita) => {
                    assert_eq!(ita.ita_jwks_addr, jwks_addr);
                    assert_eq!(ita.policy_ids, policy_ids);
                }
                _ => panic!("Expected Ita verifier"),
            },
            _ => panic!("Expected Passport variant"),
        }
    }

    #[test]
    fn test_ita_api_key_defaults_from_env() {
        let env_key = "env-key-456";
        let json = json!({
            "verify": {
                "model": "background_check",
                "as_provider": "ita"
            }
        });

        std::env::set_var(ITA_API_KEY_ENV, env_key);
        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");
        std::env::remove_var(ITA_API_KEY_ENV);

        match &ra_args.verify {
            Some(VerifyArgs::BackgroundCheck { converter, .. }) => match converter {
                ConverterArgs::Ita(ita) => {
                    assert_eq!(ita.as_addr, DEFAULT_ITA_API_URL);
                    assert_eq!(ita.api_key, Some(env_key.to_string()));
                }
                _ => panic!("Expected Ita converter"),
            },
            _ => panic!("Expected BackgroundCheck variant"),
        }
    }

    #[test]
    fn test_ita_config_serde_round_trip() {
        let as_addr = "https://api.trustauthority.intel.com";
        let api_key = "test-key";
        let policy_ids = vec!["p1"];
        let json = json!({
            "verify": {
                "model": "background_check",
                "as_provider": "ita",
                "as_addr": as_addr,
                "api_key": api_key,
                "policy_ids": policy_ids
            }
        });

        let ra_args: RaArgsUnchecked = serde_json::from_value(json).expect("Failed to deserialize");
        let serialized = serde_json::to_string(&ra_args).expect("Failed to serialize");
        let back: RaArgsUnchecked =
            serde_json::from_str(&serialized).expect("Failed to re-deserialize");

        match &back.verify {
            Some(VerifyArgs::BackgroundCheck { converter, .. }) => match converter {
                ConverterArgs::Ita(ita) => {
                    assert_eq!(ita.as_addr, as_addr);
                    assert_eq!(ita.api_key, Some(api_key.to_string()));
                    assert_eq!(ita.policy_ids, policy_ids);
                }
                _ => panic!("Expected Ita converter after round-trip"),
            },
            _ => panic!("Expected BackgroundCheck after round-trip"),
        }
    }

    #[test]
    fn test_ita_background_check_verify_into_checked_rejects_missing_api_key() {
        std::env::remove_var(ITA_API_KEY_ENV);
        let json = json!({
            "verify": {
                "model": "background_check",
                "as_provider": "ita"
            }
        });
        let ra: RaArgsUnchecked = serde_json::from_value(json).unwrap();
        ra.into_checked()
            .expect_err("should reject missing api_key");
    }

    #[test]
    fn test_ita_background_check_verify_into_checked_rejects_invalid_as_addr() {
        let json = json!({
            "verify": {
                "model": "background_check",
                "as_provider": "ita",
                "as_addr": "not a url",
                "api_key": "key"
            }
        });
        let ra: RaArgsUnchecked = serde_json::from_value(json).unwrap();
        assert!(ra.into_checked().is_err());
    }

    #[test]
    fn test_ita_passport_attest_into_checked_rejects_missing_api_key() {
        std::env::remove_var(ITA_API_KEY_ENV);
        let json = json!({
            "attest": {
                "model": "passport",
                "aa_provider": "ita",
                "aa_addr": "unix:///dev/null",
                "as_provider": "ita"
            }
        });
        let ra: RaArgsUnchecked = serde_json::from_value(json).unwrap();
        ra.into_checked()
            .expect_err("should reject missing api_key");
    }

    #[test]
    fn test_ita_passport_attest_into_checked_rejects_invalid_as_addr() {
        let json = json!({
            "attest": {
                "model": "passport",
                "aa_provider": "ita",
                "aa_addr": "unix:///dev/null",
                "as_provider": "ita",
                "as_addr": "not a url",
                "api_key": "key"
            }
        });
        let ra: RaArgsUnchecked = serde_json::from_value(json).unwrap();
        assert!(ra.into_checked().is_err());
    }

    #[test]
    fn test_ita_passport_verify_into_checked_succeeds() {
        let json = json!({
            "verify": {
                "model": "passport",
                "as_provider": "ita",
                "ita_jwks_addr": "https://portal.trustauthority.intel.com",
                "policy_ids": ["test-policy"]
            }
        });
        let ra: RaArgsUnchecked = serde_json::from_value(json).unwrap();
        let checked = ra.into_checked();
        assert!(
            checked.is_ok(),
            "valid ITA verify config should pass into_checked: {checked:?}"
        );
    }

    #[test]
    fn test_ita_background_check_verify_into_checked_succeeds() {
        let json = json!({
            "verify": {
                "model": "background_check",
                "as_provider": "ita",
                "as_addr": "https://api.trustauthority.intel.com",
                "api_key": "test-key-123",
                "ita_jwks_addr": "https://portal.trustauthority.intel.com",
                "policy_ids": ["test-policy"]
            }
        });
        let ra: RaArgsUnchecked = serde_json::from_value(json).unwrap();
        let checked = ra.into_checked();
        assert!(
            checked.is_ok(),
            "valid ITA background_check verify config should pass into_checked: {checked:?}"
        );
    }

    #[test]
    fn test_ita_converter_args_debug_redacts_api_key() {
        let secret = "super-secret-key-12345";
        let args = ItaConverterArgs {
            as_addr: "https://api.trustauthority.intel.com".to_string(),
            api_key: Some(secret.to_string()),
            policy_ids: vec![],
            ita_max_retries: None,
            ita_retry_initial_delay_ms: None,
            ita_retry_max_delay_ms: None,
        };
        let debug_output = format!("{:?}", args);
        assert!(
            !debug_output.contains(secret),
            "Debug output must not contain the raw API key"
        );
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug output should show [REDACTED] for api_key"
        );
    }
}
