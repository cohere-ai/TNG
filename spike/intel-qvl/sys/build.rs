//! Builds Intel's `libsgx_dcap_quoteverify` from the DCAP source tree and links it statically,
//! instead of linking the system library Intel only packages for x86-64 Linux.
//!
//! The source set mirrors `QuoteVerification/dcap_quoteverify/linux/Makefile` at `DCAP_1.27`:
//! the QVL attestation and parser libraries, the `tee_verify_quote` front end, and the QvE
//! verification logic compiled untrusted, which is what fills the supplemental data. Left out
//! is the QAL appraisal engine (and the WAMR runtime it embeds), which only backs
//! `tee_appraise_verification_token` and friends.
//!
//! Inputs, both checkouts:
//! - `DCAP_SRC_DIR`: intel/confidential-computing.tee.dcap at `DCAP_1.27`, with the
//!   `QuoteVerification/QVL` and `external/jwt-cpp` submodules.
//! - `SGX_SDK_INCLUDE_DIR`: `common/inc` of intel/confidential-computing.sgx.sdk.
//!
//! `QVL_USE_SYSTEM_LIB=1` links the installed library instead, as the crates.io crate does,
//! which is the baseline the source build is compared against.
//!
//! `QVL_BINDINGS_FILE` skips bindgen, and so libclang, and uses that file as the bindings.
//! `bindings/linux-glibc.rs` is the one for glibc targets.

use std::env;
use std::path::{Path, PathBuf};

fn env_path(name: &str) -> PathBuf {
    println!("cargo:rerun-if-env-changed={name}");
    let value = env::var(name).unwrap_or_else(|_| panic!("{name} must be set"));
    let path = PathBuf::from(value);
    assert!(
        path.is_dir(),
        "{name}={} is not a directory",
        path.display()
    );
    path
}

fn sorted_glob(dir: &Path, depth: usize, ext: &str) -> Vec<PathBuf> {
    fn walk(dir: &Path, depth: usize, ext: &str, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if depth > 0 {
                    walk(&path, depth - 1, ext, out);
                }
            } else if path.extension().is_some_and(|e| e == ext) {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, depth, ext, &mut out);
    out.sort();
    out
}

fn base_build(cpp: bool) -> cc::Build {
    let mut build = cc::Build::new();
    build
        .cpp(cpp)
        .warnings(false)
        .define("NDEBUG", None)
        .flag("-USGX_TRUSTED")
        .flag_if_supported("-Wno-attributes")
        .flag_if_supported("-ffunction-sections")
        .flag_if_supported("-fdata-sections");
    if cpp {
        build.std("c++17");
    }
    build
}

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    println!("cargo:rerun-if-changed=bindings.h");
    println!("cargo:rerun-if-changed=generated");
    println!("cargo:rerun-if-changed=shim");
    println!("cargo:rerun-if-env-changed=QVL_USE_SYSTEM_LIB");

    let mut bindgen_includes: Vec<PathBuf> = Vec::new();

    if env::var("QVL_USE_SYSTEM_LIB").is_ok_and(|v| v == "1") {
        println!("cargo:rustc-link-lib=sgx_dcap_quoteverify");
    } else {
        let dcap = env_path("DCAP_SRC_DIR");
        let sgx_inc = env_path("SGX_SDK_INCLUDE_DIR");
        let openssl_inc = PathBuf::from(
            env::var("DEP_OPENSSL_INCLUDE").expect("openssl-sys did not report its include dir"),
        );

        let qv = dcap.join("QuoteVerification");
        let qg = dcap.join("QuoteGeneration");
        let qvl = qv.join("QVL/Src");
        let lib = qvl.join("AttestationLibrary");
        let par = qvl.join("AttestationParsers");
        let com = qvl.join("AttestationCommons");
        let qve = dcap.join("ae/QvE");
        let generated = manifest.join("generated");

        let lib_inc = vec![
            com.join("include"),
            com.join("include/Utils"),
            lib.join("include"),
            lib.join("src"),
            par.join("include"),
            qvl.join("ThirdParty/rapidjson/include"),
            dcap.join("external/jwt-cpp/include"),
            qve.join("Include"),
            openssl_inc.clone(),
        ];
        let par_inc = vec![
            com.join("include"),
            com.join("include/Utils"),
            qvl.clone(),
            par.join("include"),
            par.join("src"),
            lib.join("include"),
            qvl.join("ThirdParty/rapidjson/include"),
            openssl_inc.clone(),
        ];
        let mut ver_inc = vec![
            qve.join("Include"),
            qv.join("dcap_quoteverify/inc"),
            qg.join("quote_wrapper/common/inc"),
            sgx_inc.clone(),
            qg.join("common/inc/internal"),
            qg.join("common/inc/internal/linux"),
        ];
        ver_inc.extend(lib_inc.iter().cloned());
        ver_inc.extend([
            qg.join("qpl/inc"),
            qv.join("appraisal/common"),
            qv.join("appraisal/qal"),
            generated.clone(),
            generated.join("linux"),
        ]);

        let mut lib_srcs = sorted_glob(&lib.join("src"), 2, "cpp");
        lib_srcs.extend(sorted_glob(&com.join("src/Utils"), 0, "cpp"));
        let par_srcs = sorted_glob(&par.join("src"), 1, "cpp");
        let mut ver_srcs = sorted_glob(&qv.join("dcap_quoteverify"), 0, "cpp");
        ver_srcs.extend(sorted_glob(&qv.join("dcap_quoteverify/linux"), 0, "cpp"));
        ver_srcs.extend([
            qve.join("qve/qve.cpp"),
            qve.join("qve/qve_logic.cpp"),
            qg.join("qpl/sgx_base64.cpp"),
            qv.join("appraisal/common/ec_key.cpp"),
            manifest.join("shim/sgxssl_ocalls.cpp"),
        ]);
        let c_srcs = [
            qg.join("common/src/se_trace.c"),
            qg.join("common/src/se_thread.c"),
            generated.join("linux/qve_u.c"),
        ];

        let mut objects = Vec::new();
        for (srcs, incs, cpp) in [
            (&lib_srcs, &lib_inc, true),
            (&par_srcs, &par_inc, true),
            (&ver_srcs, &ver_inc, true),
            (&c_srcs.to_vec(), &ver_inc, false),
        ] {
            let mut build = base_build(cpp);
            if !cpp && env::var("CARGO_CFG_TARGET_OS").is_ok_and(|os| os == "macos") {
                // se_thread.c's se_get_threadid() calls syscall(__NR_gettid), Linux's
                // number. Nothing in the library calls that function, but it has to
                // compile; Darwin's equivalent comes from the <sys/syscall.h> it includes.
                build.define("__NR_gettid", "SYS_thread_selfid");
            }
            objects.extend(build.includes(incs).files(srcs).compile_intermediates());
        }
        // One archive, so the circular references between the QVL pieces need no link-order
        // games. `cpp(true)` makes cc emit the C++ runtime link for the target (libstdc++ or
        // libc++).
        base_build(true)
            .objects(objects)
            .compile("sgx_dcap_quoteverify");

        bindgen_includes = vec![
            qv.join("dcap_quoteverify/inc"),
            qg.join("quote_wrapper/common/inc"),
            qve.join("Include"),
            sgx_inc,
        ];
    }

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Where libclang is not available, as in the manylinux images the wheels are built in,
    // take bindings generated elsewhere. They carry the C library's own typedefs, so a file
    // generated against glibc is only good for glibc targets.
    println!("cargo:rerun-if-env-changed=QVL_BINDINGS_FILE");
    if let Ok(file) = env::var("QVL_BINDINGS_FILE") {
        println!("cargo:rerun-if-changed={file}");
        std::fs::copy(&file, out_path.join("bindings.rs"))
            .unwrap_or_else(|e| panic!("QVL_BINDINGS_FILE={file}: {e}"));
        return;
    }

    let mut builder = bindgen::Builder::default();
    if let Ok(val) = env::var("SGX_SDK") {
        builder = builder.clang_arg(format!("-I{val}/include/"));
    }
    for inc in &bindgen_includes {
        builder = builder.clang_arg(format!("-I{}", inc.display()));
    }

    // The crates.io crate's bindgen configuration, plus the formatter: bindgen otherwise
    // formats with whatever rustfmt binary is installed, and leaves the output on one line
    // where there is none, so the committed bindings could not be compared across machines.
    let bindings = builder
        .formatter(bindgen::Formatter::Prettyplease)
        .header("bindings.h")
        .newtype_enum("_quote3_error_t")
        .newtype_enum("_sgx_ql_qv_result_t")
        .rustified_enum("_sgx_ql_request_policy")
        .rustified_enum("sgx_qv_path_type_t")
        .no_debug("_quote_t")
        .no_debug("_sgx_ql_auth_data_t")
        .no_debug("_sgx_ql_certification_data_t")
        .no_debug("_sgx_ql_ecdsa_sig_data_t")
        .no_debug("_sgx_quote3_t")
        .no_debug("_sgx_ql_att_key_id_param_t")
        .derive_default(true)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
