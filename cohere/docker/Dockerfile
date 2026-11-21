# syntax=docker/dockerfile:1
# Cohere TNG images. Use `--target tng` (no baked-in config), `--target egress-ita`,
# `--target egress-trustee`, or `--target ingress`.

# Verifiers for the in-process attestation service, one argument each because each one brings its
# own system dependencies. Each takes a boolean: 1, true, yes or on to build it, and 0, false, no,
# off or empty to leave it out. Anything else is an error rather than a guess, since a value read
# the wrong way would either skip a package and fail deep in the build or silently ship a verifier
# that was meant to be off. So:
#
#   --build-arg BUILTIN_AS_TDX=0 --build-arg BUILTIN_AS_AZSNP=0 --build-arg BUILTIN_AS_NVIDIA=0
#
# builds a plain TNG with none of it: no verifier code and none of their build tools. The
# feature list handed to cargo is assembled below from these, so the packages and the features
# cannot drift apart, and a name this file does not know about cannot be passed in. The three RUNs
# that read them each repeat the same parse, there being no way to normalise a build argument once
# and share it across layers.
#
# TNG has verifier features for raw SEV-SNP, SGX and Azure TDX as well. They are deliberately not
# wired up here; adding one means checking its system dependencies too, since Azure TDX reaches
# the TPM libraries.
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

# The official Rust image at the version rust-toolchain.toml pins, which already carries git and a
# C/C++ toolchain. Bookworm, not trixie: its glibc (2.36) is older than the Ubuntu 24.04 runtime's
# (2.39), and a binary only runs on a glibc at least as new as the one it was built against.
FROM rust:1.95.0-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
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
# None of the verifiers links a system library, at build or run time: their OpenSSL is vendored and
# linked statically, and TDX compiles Intel's quote verification library from source into the
# binary (deps/intel-tee-quote-verification-sys). Azure SEV-SNP is also entirely offline, since the
# attester ships the VCEK inside the evidence.
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
    rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY rust-toolchain.toml .
RUN rustup show

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
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
    env RUSTFLAGS="--cfg tokio_unstable" CARGO_NET_GIT_FETCH_WITH_CLI=true \
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

COPY --from=builder /out/bin/tng /usr/local/bin/tng
# Notices for the third-party code the TDX verifier compiles into tng. Copied whether or not TDX
# is built, as a COPY cannot depend on a build argument.
COPY deps/intel-tee-quote-verification-sys/generated/licenses/ /usr/share/licenses/tng/intel-tee-quote-verification-sys/

FROM runtime-base AS tng

# Each egress variant is the shared tng-conf.json plus its own attest.json, used for both the
# tunnel and the OHTTP key, and verify.json for the gossip peers.
FROM runtime-base AS egress-conf
COPY cohere/docker/egress/ /src/
RUN set -eu; \
    for variant in ita trustee; do \
        jq --slurpfile attest "/src/$variant/attest.json" --slurpfile verify "/src/$variant/verify.json" \
            '.add_egress |= map(.attest = $attest[0] | .ohttp.key.attest = $attest[0] | .ohttp.key.verify = $verify[0])' \
            /src/tng-conf.json > "/src/$variant/conf.json"; \
    done

FROM runtime-base AS egress-base
COPY cohere/docker/egress/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
CMD ["docker-entrypoint.sh"]

FROM egress-base AS egress-ita
COPY --from=egress-conf /src/ita/conf.json /etc/tng/conf.default.json

FROM egress-base AS egress-trustee
COPY --from=egress-conf /src/trustee/conf.json /etc/tng/conf.default.json

FROM runtime-base AS ingress
RUN apt-get update && apt-get install -y --no-install-recommends \
    gettext-base \
    && rm -rf /var/lib/apt/lists/*
COPY cohere/docker/ingress/tng-conf.json /etc/tng/conf.template.json
COPY cohere/docker/ingress/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
CMD ["docker-entrypoint.sh"]
