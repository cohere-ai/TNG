//! Verifies a TDX quote offline against saved collateral, the way Trustee's TDX verifier calls
//! the QVL (`deps/verifier/src/intel_dcap/mod.rs`), and prints the outcome as JSON.
//!
//! Usage: qvl-spike-verify <quote> <collateral.json> <unix-time>
//!
//! The raw supplemental data is printed in full so that two builds can be compared byte for
//! byte, not just by verdict.

use intel_tee_quote_verification_rs::{
    sgx_ql_qv_supplemental_t, tee_get_supplemental_data_version_and_size,
    tee_supp_data_descriptor_t, tee_verify_quote, QuoteCollateral,
};
use serde_json::{json, Value};
use std::ffi::CStr;
use std::os::raw::c_char;

fn c_str(bytes: &[u8]) -> Vec<c_char> {
    bytes
        .iter()
        .map(|&b| b as c_char)
        .chain(std::iter::once(0))
        .collect()
}

fn field<'a>(collateral: &'a Value, name: &str) -> &'a str {
    collateral[name]
        .as_str()
        .unwrap_or_else(|| panic!("collateral has no {name}"))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, quote_path, collateral_path, time] = args.as_slice() else {
        eprintln!("usage: {} <quote> <collateral.json> <unix-time>", args[0]);
        std::process::exit(2);
    };
    let quote = std::fs::read(quote_path).expect("read quote");
    let collateral: Value =
        serde_json::from_slice(&std::fs::read(collateral_path).expect("read collateral"))
            .expect("parse collateral");
    let time: i64 = time.parse().expect("unix time");

    let collateral = QuoteCollateral {
        major_version: 3,
        minor_version: 1,
        tee_type: 0x81,
        tcb_info: c_str(field(&collateral, "tcb_info").as_bytes()),
        tcb_info_issuer_chain: c_str(field(&collateral, "tcb_info_issuer_chain").as_bytes()),
        qe_identity: c_str(field(&collateral, "qe_identity").as_bytes()),
        qe_identity_issuer_chain: c_str(field(&collateral, "qe_identity_issuer_chain").as_bytes()),
        pck_crl: c_str(&hex::decode(field(&collateral, "pck_crl_hex")).unwrap()),
        pck_crl_issuer_chain: c_str(field(&collateral, "pck_crl_issuer_chain").as_bytes()),
        root_ca_crl: c_str(&hex::decode(field(&collateral, "root_ca_crl_hex")).unwrap()),
    };

    let out = match tee_get_supplemental_data_version_and_size(&quote) {
        Err(e) => {
            json!({"error": "tee_get_supplemental_data_version_and_size", "code": format!("{:#x}", e.0)})
        }
        Ok((version, size)) => {
            let mut supp = sgx_ql_qv_supplemental_t::default();
            let mut desc = tee_supp_data_descriptor_t {
                major_version: 0,
                data_size: size,
                p_data: std::ptr::from_mut(&mut supp).cast(),
            };
            // Safety: `desc` points at a live `sgx_ql_qv_supplemental_t`, and `size` is what
            // the library reported for it, as in Trustee's caller.
            match unsafe {
                tee_verify_quote(&quote, Some(&collateral), time, None, Some(&mut desc))
            } {
                Err(e) => json!({"error": "tee_verify_quote", "code": format!("{:#x}", e.0)}),
                Ok((expiration, result)) => {
                    // Safety: the struct is plain old data, read only up to `size` bytes.
                    let raw = unsafe {
                        std::slice::from_raw_parts(
                            std::ptr::from_ref(&supp).cast::<u8>(),
                            size as usize,
                        )
                    };
                    let sa = unsafe { CStr::from_ptr(supp.sa_list.as_ptr()) };
                    json!({
                        "verification_result": format!("{:#x}", result.0),
                        "collateral_expiration_status": expiration,
                        "supplemental_version": format!("{version:#x}"),
                        "supplemental_size": size,
                        "tcb_level_date_tag": supp.tcb_level_date_tag,
                        "earliest_expiration_date": supp.earliest_expiration_date,
                        "tcb_eval_ref_num": supp.tcb_eval_ref_num,
                        "advisory_ids": sa.to_string_lossy(),
                        "supplemental_hex": hex::encode(raw),
                    })
                }
            }
        }
    };
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
