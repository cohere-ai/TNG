# syntax=docker/dockerfile:1
# Cohere TNG images. Use `--target egress` or `--target ingress`.

# Verifiers for the in-process attestation service, one argument each because each one brings its
# own system dependencies. Each takes a boolean: 1, true, yes or on to build it, and 0, false, no,
# off or empty to leave it out. Anything else is an error rather than a guess, since a value read
# the wrong way would either skip a package and fail deep in the build or silently ship a verifier
# that was meant to be off. So:
#
#   --build-arg BUILTIN_AS_TDX=0 --build-arg BUILTIN_AS_AZSNP=0 --build-arg BUILTIN_AS_NVIDIA=0
#
# builds a plain TNG with none of it: no Intel DCAP, no TPM libraries, and no verifier code. The
# feature list handed to cargo is assembled below from these, so the packages and the features
# cannot drift apart, and a name this file does not know about cannot be passed in. The three RUNs
# that read them each repeat the same parse, there being no way to normalise a build argument once
# and share it across layers.
#
# TNG has verifier features for raw SEV-SNP, SGX and Azure TDX as well. They are deliberately not
# wired up here; adding one means adding its packages too, since SGX and Azure TDX need the DCAP
# library and Azure TDX needs the TPM libraries on top of it.
#
# Azure SEV-SNP subsumes the raw SEV-SNP verifier upstream, so a peer reporting through
# /dev/sev-guest rather than a paravisor's vTPM is covered without naming that feature.
#
# These decide what a peer's evidence can be appraised against, not what this image can prove about
# itself, and they are only reachable through `as_provider: coco_builtin` in background-check mode.
#
# Compiling the NVIDIA verifier has a configuration consequence: a peer that presents GPU evidence
# is appraised under a `gpu` class policy, and if the policy directory has none, the handshake fails
# closed rather than ignoring the GPU. Deployments attesting GPU peers must ship a GPU policy.
ARG BUILTIN_AS_TDX=1
ARG BUILTIN_AS_AZSNP=1
ARG BUILTIN_AS_NVIDIA=1

# Ubuntu rather than the official Rust image, which is Debian based: Intel publishes the DCAP
# quote verification library for Ubuntu only, and matching the runtime stage keeps the glibc that
# library was built against consistent across both stages. Rust comes from rustup, pinned by
# rust-toolchain.toml.
FROM ubuntu:24.04 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    libprotobuf-dev \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

ARG BUILTIN_AS_TDX
ARG BUILTIN_AS_AZSNP
ARG BUILTIN_AS_NVIDIA

# Build dependencies of the verifiers, installed only for the ones being built.
#
# clang and perl go in for any of them rather than being tracked per verifier: bindgen and a
# vendored OpenSSL both arrive through the attestation service's dependency graph, and which crate
# pulls them shifts with upstream. Nothing links libssl at runtime.
#
# libtss2-dev is for the Azure SEV-SNP verifier. Verifying an Azure CVM is entirely offline, since
# the attester ships the VCEK inside the evidence, but the verifier still reaches tss-esapi through
# az-cvm-vtpm and so needs the TPM libraries at build time. tss-esapi-sys locates them with
# pkg-config, which is not part of build-essential.
#
# The Intel DCAP quote verification library is for the TDX verifier. The armored key is dropped in
# as-is so this needs no gnupg, and only the quote verification library is needed, not the quote
# provider: the verifier fetches DCAP collateral itself over HTTPS from Intel's PCS. It is x86_64
# only, since Intel publishes no arm64 packages, so an arm64 image has to turn TDX off.
RUN set -eu; \
    bool() { case "$(echo "${2-}" | tr 'A-Z' 'a-z')" in \
        1|true|yes|on) echo 1 ;; \
        ""|0|false|no|off) ;; \
        *) echo "$1: expected a boolean, got '$2'" >&2; exit 1 ;; \
    esac; }; \
    tdx=$(bool BUILTIN_AS_TDX "$BUILTIN_AS_TDX"); \
    azsnp=$(bool BUILTIN_AS_AZSNP "$BUILTIN_AS_AZSNP"); \
    nvidia=$(bool BUILTIN_AS_NVIDIA "$BUILTIN_AS_NVIDIA"); \
    [ -n "$tdx$azsnp$nvidia" ] || exit 0; \
    apt-get update; \
    apt-get install -y --no-install-recommends clang perl; \
    [ -z "$azsnp" ] || apt-get install -y --no-install-recommends libtss2-dev pkg-config; \
    if [ -n "$tdx" ]; then \
        curl --proto '=https' --tlsv1.2 -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key \
            -o /etc/apt/keyrings/intel-sgx.asc; \
        echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/intel-sgx.asc] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main" \
            > /etc/apt/sources.list.d/intel-sgx.list; \
        apt-get update; \
        apt-get install -y --no-install-recommends libsgx-dcap-quote-verify-dev; \
    fi; \
    rm -rf /var/lib/apt/lists/*

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --no-modify-path --default-toolchain none

WORKDIR /src

COPY rust-toolchain.toml .
RUN rustup show

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    set -eu; \
    bool() { case "$(echo "${2-}" | tr 'A-Z' 'a-z')" in \
        1|true|yes|on) echo 1 ;; \
        ""|0|false|no|off) ;; \
        *) echo "$1: expected a boolean, got '$2'" >&2; exit 1 ;; \
    esac; }; \
    tdx=$(bool BUILTIN_AS_TDX "$BUILTIN_AS_TDX"); \
    azsnp=$(bool BUILTIN_AS_AZSNP "$BUILTIN_AS_AZSNP"); \
    nvidia=$(bool BUILTIN_AS_NVIDIA "$BUILTIN_AS_NVIDIA"); \
    features=""; \
    [ -z "$tdx" ] || features="$features,coco-builtin-as-tdx"; \
    [ -z "$azsnp" ] || features="$features,coco-builtin-as-azsnp"; \
    [ -z "$nvidia" ] || features="$features,coco-builtin-as-nvidia"; \
    env RUSTFLAGS="--cfg tokio_unstable" \
    cargo install --locked \
    ${features:+--features "${features#,}"} \
    --path ./tng/ --root /out

FROM ubuntu:24.04 AS runtime-base

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    jq \
    python3-minimal \
    && rm -rf /var/lib/apt/lists/*

ARG BUILTIN_AS_TDX
ARG BUILTIN_AS_AZSNP

# Runtime halves of the build dependencies above: the tss2 libraries for Azure SEV-SNP, and
# libsgx_dcap_quoteverify.so.1 for TDX. NVIDIA needs nothing here, being pure Rust that checks the
# GPU's SPDM report against the certificate chain in the evidence.
RUN set -eu; \
    bool() { case "$(echo "${2-}" | tr 'A-Z' 'a-z')" in \
        1|true|yes|on) echo 1 ;; \
        ""|0|false|no|off) ;; \
        *) echo "$1: expected a boolean, got '$2'" >&2; exit 1 ;; \
    esac; }; \
    tdx=$(bool BUILTIN_AS_TDX "$BUILTIN_AS_TDX"); \
    azsnp=$(bool BUILTIN_AS_AZSNP "$BUILTIN_AS_AZSNP"); \
    if [ -n "$azsnp" ]; then \
        apt-get update; \
        apt-get install -y --no-install-recommends \
            libtss2-esys-3.0.2-0t64 \
            libtss2-mu-4.0.1-0t64 \
            libtss2-tctildr0t64; \
    fi; \
    if [ -n "$tdx" ]; then \
        curl --proto '=https' --tlsv1.2 -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key \
            -o /etc/apt/keyrings/intel-sgx.asc; \
        echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/intel-sgx.asc] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main" \
            > /etc/apt/sources.list.d/intel-sgx.list; \
        apt-get update; \
        apt-get install -y --no-install-recommends libsgx-dcap-quote-verify; \
    fi; \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/bin/tng /usr/local/bin/tng

FROM runtime-base AS egress
COPY cohere/docker/egress/tng-conf.json /etc/tng/conf.default.json
COPY cohere/docker/egress/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
CMD ["docker-entrypoint.sh"]

FROM runtime-base AS ingress
RUN apt-get update && apt-get install -y --no-install-recommends \
    gettext-base \
    && rm -rf /var/lib/apt/lists/*
COPY cohere/docker/ingress/tng-conf.json /etc/tng/conf.template.json
COPY cohere/docker/ingress/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
CMD ["docker-entrypoint.sh"]
