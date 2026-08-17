# syntax=docker/dockerfile:1
# Cohere TNG images — use `--target egress` or `--target ingress`.

# Ubuntu rather than the official Rust image, which is Debian based: Intel publishes the DCAP
# quote verification library for Ubuntu only, and matching the runtime stage keeps the glibc that
# library was built against consistent across both stages. Rust comes from rustup, pinned by
# rust-toolchain.toml.
FROM ubuntu:24.04 AS builder

# clang is for bindgen in intel-tee-quote-verification-sys. The attestation service pulls in
# OpenSSL, which builds from vendored source and so needs perl and a C toolchain rather than
# libssl-dev; nothing here links libssl at runtime.
#
# libtss2-dev is for the Azure SEV-SNP verifier. Verifying an Azure CVM is entirely offline, since
# the attester ships the VCEK inside the evidence, but the verifier still reaches tss-esapi through
# az-cvm-vtpm and so needs the TPM libraries at build time. tss-esapi-sys locates them with
# pkg-config, which is not part of build-essential.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    clang \
    curl \
    libprotobuf-dev \
    libtss2-dev \
    perl \
    pkg-config \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Intel DCAP quote verification library, required by the TDX verifier in the in-process
# attestation service. The armored key is dropped in as-is so this needs no gnupg. Only the quote
# verification library is needed, not the quote provider: the verifier fetches DCAP collateral
# itself over HTTPS from Intel's PCS.
#
# x86_64 only. Intel publishes no arm64 packages, so building this image for arm64 means dropping
# the coco-builtin-as-tdx feature below.
RUN curl --proto '=https' --tlsv1.2 -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key \
        -o /etc/apt/keyrings/intel-sgx.asc \
    && echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/intel-sgx.asc] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main" \
        > /etc/apt/sources.list.d/intel-sgx.list \
    && apt-get update && apt-get install -y --no-install-recommends \
    libsgx-dcap-quote-verify-dev \
    && rm -rf /var/lib/apt/lists/*

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --no-modify-path --default-toolchain none

WORKDIR /src

COPY rust-toolchain.toml .
RUN rustup show

COPY . .

# Each verifier is its own feature because each brings its own dependencies: TDX needs the Intel
# DCAP library above, Azure SEV-SNP needs the TPM libraries, and NVIDIA needs neither, being pure
# Rust that checks the GPU's SPDM report against the certificate chain in the evidence.
#
# Azure SEV-SNP subsumes the plain SEV-SNP verifier upstream, so a peer reporting through
# /dev/sev-guest rather than a paravisor's vTPM is covered as well, without naming that feature.
#
# These decide what a peer's evidence can be appraised against, not what this image can prove about
# itself, and they are only reachable through `as_provider: coco_builtin` in background-check mode.
#
# Compiling the NVIDIA verifier has a configuration consequence: a peer that presents GPU evidence
# is appraised under a `gpu` class policy, and if the policy directory has none, the handshake fails
# closed rather than ignoring the GPU. Deployments attesting GPU peers must ship a GPU policy.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    env RUSTFLAGS="--cfg tokio_unstable" \
    cargo install --locked \
    --features 'coco-builtin-as-tdx,coco-builtin-as-azsnp,coco-builtin-as-nvidia' \
    --path ./tng/ --root /out

FROM ubuntu:24.04 AS runtime-base

# The tss2 libraries are the runtime half of libtss2-dev above.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    jq \
    libtss2-esys-3.0.2-0t64 \
    libtss2-mu-4.0.1-0t64 \
    libtss2-tctildr0t64 \
    python3-minimal \
    && rm -rf /var/lib/apt/lists/*

# Runtime half of the DCAP dependency above: the binary links libsgx_dcap_quoteverify.so.1.
RUN curl --proto '=https' --tlsv1.2 -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key \
        -o /etc/apt/keyrings/intel-sgx.asc \
    && echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/intel-sgx.asc] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main" \
        > /etc/apt/sources.list.d/intel-sgx.list \
    && apt-get update && apt-get install -y --no-install-recommends \
    libsgx-dcap-quote-verify \
    && rm -rf /var/lib/apt/lists/*

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
