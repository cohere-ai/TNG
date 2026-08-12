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
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    clang \
    curl \
    libprotobuf-dev \
    perl \
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

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    env RUSTFLAGS="--cfg tokio_unstable" \
    cargo install --locked --features 'coco-builtin-as-tdx' --path ./tng/ --root /out

FROM ubuntu:24.04 AS runtime-base

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    jq \
    python3-minimal \
    && rm -rf /var/lib/apt/lists/*

# Runtime half of the DCAP dependency above: the binary links libsgx_dcap_quoteverify.so.1. Both
# images need it, because the single binary is built with the verifier compiled in and would fail
# to load without it, even on the egress side that only attests.
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
