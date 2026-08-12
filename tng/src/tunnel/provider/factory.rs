#[cfg(feature = "__coco-builtin-as")]
use std::path::Path;

use anyhow::Result;
#[cfg(unix)]
use rats_cert::tee::coco::attester::CocoAttester;
#[cfg(feature = "__coco-builtin-as")]
use rats_cert::tee::coco::converter::coco_builtin::CocoBuiltinConverter;
use rats_cert::tee::coco::converter::grpc::CocoGrpcConverter;
use rats_cert::tee::coco::converter::restful::CocoRestfulConverter;
use rats_cert::tee::coco::converter::CocoConverter;
use rats_cert::tee::coco::verifier::remote::CocoRemoteVerifier;
use rats_cert::tee::coco::verifier::CocoVerifier;

#[cfg(unix)]
use crate::config::ra::{AttesterArgs, CocoAttesterArgs};
use crate::config::ra::{CocoConverterArgs, CocoVerifierArgs, ConverterArgs, VerifierArgs};

#[cfg(unix)]
use super::attester::TngAttester;
use super::converter::TngConverter;
use super::verifier::TngVerifier;

/// Instantiate a `TngAttester` from config. Dispatches on provider, then sub-type.
#[cfg(unix)]
pub fn create_attester(config: &AttesterArgs) -> Result<TngAttester> {
    match config {
        AttesterArgs::Coco(coco) => match coco {
            CocoAttesterArgs::Uds { aa_addr } => Ok(TngAttester::Coco(CocoAttester::new(aa_addr)?)),
        },
        AttesterArgs::Ita(args) => Ok(TngAttester::Ita(args.to_attester()?)),
        AttesterArgs::CocoAsr(args) => Ok(TngAttester::CocoAsr(args.to_attester()?)),
        AttesterArgs::ItaAsr(args) => Ok(TngAttester::ItaAsr(args.to_attester()?)),
    }
}

/// Instantiate a `TngConverter` from config. Dispatches on provider, then sub-type.
pub async fn create_converter(config: &ConverterArgs) -> Result<TngConverter> {
    match config {
        #[cfg(feature = "__coco-builtin-as")]
        ConverterArgs::CocoBuiltin {
            policy_dir,
            required_tee_classes,
            verifier_config,
        } => {
            // Read here rather than lazily: an ingress with no usable policy can verify nothing,
            // so failing now surfaces the problem at startup instead of on the first handshake.
            let policies =
                rats_cert::tee::coco::converter::policy::load_from_dir(Path::new(policy_dir))
                    .await?;

            Ok(TngConverter::Coco(CocoConverter::CocoBuiltin(
                CocoBuiltinConverter::new(&policies, verifier_config.clone(), required_tee_classes)
                    .await?,
            )))
        }
        ConverterArgs::Coco(coco) => match coco {
            CocoConverterArgs::Restful {
                as_addr,
                policy_ids,
                as_headers,
                as_ca_certs,
            } => Ok(TngConverter::Coco(CocoConverter::Restful(
                CocoRestfulConverter::new(as_addr, policy_ids, as_headers, as_ca_certs)?,
            ))),
            CocoConverterArgs::Grpc {
                as_addr,
                policy_ids,
                as_headers,
            } => Ok(TngConverter::Coco(CocoConverter::Grpc(
                CocoGrpcConverter::new(as_addr, policy_ids, as_headers)?,
            ))),
        },
        ConverterArgs::Ita(args) => Ok(TngConverter::Ita(args.to_converter()?)),
    }
}

/// Instantiate a `TngVerifier` from config. Dispatches on provider, then sub-type.
pub async fn create_verifier(config: &VerifierArgs) -> Result<TngVerifier> {
    match config {
        // Built by `VerifyContext::from_verify_args` from the converter that owns the in-process
        // service, since the signing key and policy id it needs exist only there.
        #[cfg(feature = "__coco-builtin-as")]
        VerifierArgs::CocoBuiltin => anyhow::bail!(
            "The `coco_builtin` verifier requires a `coco_builtin` converter in the same background_check verifier"
        ),
        VerifierArgs::Coco(coco) => match coco {
            CocoVerifierArgs::Restful {
                as_addr,
                policy_ids,
                as_headers,
                trusted_certs_paths,
            } => {
                let as_addr_config = as_addr.as_ref().map(|addr| {
                    rats_cert::cert::verify::AttestationServiceAddrArgs {
                        as_addr: addr.clone(),
                        as_is_grpc: false,
                        as_headers: as_headers.clone(),
                    }
                });
                Ok(TngVerifier::Coco(CocoVerifier::Remote(
                    CocoRemoteVerifier::new(&as_addr_config, trusted_certs_paths, policy_ids)
                        .await?,
                )))
            }
            CocoVerifierArgs::Grpc {
                as_addr,
                policy_ids,
                as_headers,
                trusted_certs_paths,
            } => {
                let as_addr_config = as_addr.as_ref().map(|addr| {
                    rats_cert::cert::verify::AttestationServiceAddrArgs {
                        as_addr: addr.clone(),
                        as_is_grpc: true,
                        as_headers: as_headers.clone(),
                    }
                });
                Ok(TngVerifier::Coco(CocoVerifier::Remote(
                    CocoRemoteVerifier::new(&as_addr_config, trusted_certs_paths, policy_ids)
                        .await?,
                )))
            }
        },
        VerifierArgs::Ita(args) => Ok(TngVerifier::Ita(args.to_verifier()?)),
    }
}
