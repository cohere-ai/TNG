# syntax=docker/dockerfile:1
# Cohere TNG images — use `--target egress` or `--target ingress`.

FROM rust:1.89-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler \
    libprotobuf-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    env RUSTFLAGS="--cfg tokio_unstable" \
    cargo install --locked --path ./tng/ --root /out

FROM ubuntu:24.04 AS runtime-base

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    jq \
    python3-minimal \
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
