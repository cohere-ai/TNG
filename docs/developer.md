# Developer Guide

This guide is intended for developers who need to modify the TNG source code or debug/run tests locally. It introduces the project structure, how to build TNG and its images, how to run the test suites, and how releases are made.

## Project Structure Overview

- **tng/**: Core service implementation, including command-line entry, configuration parsing, tunnel (Ingress/Egress), remote attestation, observability, and other main logic.
- **tng/src/tunnel/provider/**: Pluggable remote-attestation provider layer (evidence, token, attester, converter, and verifier wiring) to support multiple providers for attestation-agent and attestation-service, such as CoCo and Intel Trust Authority (ITA).
- **rats-cert/**: Remote attestation library used by `tng`: evidence collection and verification for the CoCo and ITA providers, the in-process attestation service (`coco-builtin-as-*` features), and fetching signed policies.
- **tng-testsuite/**: Integration test suite, providing orchestratable "scenario tasks" covering typical usage such as HTTP proxy, transparent proxy, Socks5, OHTTP, and unidirectional/bidirectional remote attestation.
- **tng-wasm/**: Browser-side JavaScript SDK, providing interfaces like `tng_fetch`, used in conjunction with OHTTP and remote attestation. For specific usage, see `tng-wasm/README.md`.
- **cohere/docker/**: The Dockerfile for the published container images, plus the default configuration and entrypoints of the ingress and egress images.
- **cohere/python/cohere-tng/**: The `cohere-tng` Python package, an `httpx` transport built as a native Rust extension with PyO3 and maturin.
- **cohere/python/conseel/**: The `conseel` Python package, a drop-in encrypted transport for AI SDKs built on `cohere-tng`.
- **docs/**: User and development documentation, including the configuration manual (`configuration.md`) and this developer guide.

If you only want to compile and run TNG locally, you can focus on the `tng/` directory. If you need to debug a complete end-to-end scenario (e.g., "HTTP proxy + unidirectional remote attestation"), it is recommended to prioritize running the corresponding `tng-testsuite` case for reproduction.

## Minimum Supported Rust Version (MSRV)

This project requires two versions of the Rust toolchain:

- `1.95.0`: The toolchain used to build TNG from source. It is pinned in [rust-toolchain.toml](../rust-toolchain.toml), so `rustup` selects it automatically inside the repository.
- `nightly-2025-07-07`: The toolchain required for building the TNG JavaScript SDK. For details, see [tng-wasm/README.md](../tng-wasm/README.md).

## Setting Up the Development Environment

1. Clone the source code:

```sh
git clone https://github.com/cohere-ai/TNG.git
cd TNG
```

The default branch is `cohere`. Release tags are named `vX.Y.Z`.

2. Install [rustup](https://rustup.rs). The first `cargo` command run in the repository installs the toolchain from `rust-toolchain.toml`.

3. Install the build dependencies. On Ubuntu, at minimum:

```sh
sudo apt-get install -y build-essential protobuf-compiler libprotobuf-dev libssl-dev pkg-config clang
```

`protoc` is required: `rats-cert` generates gRPC code at build time. The test-runner image, [.github/test-deps/Dockerfile.test-runner](../.github/test-deps/Dockerfile.test-runner), carries the full set of dependencies used in CI, including the Intel DCAP quote verification library needed by the `coco-builtin-as-tdx` feature and the network tools the integration tests use (`iptables`, `iproute2`, `ipset`, `socat` and others).

4. Build TNG:

```sh
make bin-build   # RUSTFLAGS="--cfg tokio_unstable" cargo build --release
```

The binary is written to `target/release/tng`.

The in-process attestation service (`as_provider: coco_builtin`) is not built by default. Enable it with one or more of the `coco-builtin-as-*` features in [tng/Cargo.toml](../tng/Cargo.toml), for example `--features tng/coco-builtin-as-tdx`. Some of them need extra system libraries; [cohere/docker/Dockerfile](../cohere/docker/Dockerfile) lists them.

### Checks Before Committing

CI runs these on every pull request (`co-clippy.yml` and `co-fmt.yml`):

```sh
make clippy        # cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

## Running Tests

Tests run in CI through [.github/workflows/co-test.yml](../.github/workflows/co-test.yml), which creates a GCP `c3-standard-8` Confidential VM with Intel TDX, starts the attestation services, and runs every suite inside the test-runner image. The steps below follow that workflow.

> [!IMPORTANT]
> Many tests collect real TDX evidence, so they must run on a TDX guest (`/dev/tdx_guest` must exist). The ITA tests also need an Intel Trust Authority API key in the `ITA_API_KEY` environment variable, and are skipped when it is not set.

In this repository, integration tests are mainly concentrated in the `tng-testsuite` crate, covering common scenarios through different test files, such as:

- **`tcp_two_way_ra.rs`**: Verifies TCP scenarios where both the client and server have remote attestation enabled (mutual RA).
- **`http_encapulation_with_ingress_httpproxy.rs`**: Verifies encrypted HTTP scenarios where the client accesses via HTTP proxy and the server uses netfilter.
- **`python_sdk.rs`**: Verifies the `cohere-tng` Python SDK against a TNG egress.
- **`js_sdk_http.rs`**: Verifies scenarios using the browser-side JavaScript SDK (`tng-wasm`) with OHTTP and remote attestation.

### Starting the Attestation Services

The test dependencies are defined in [.github/test-deps/docker-compose.yml](../.github/test-deps/docker-compose.yml):

- **keygen**: Generates the attestation service's token-signing certificate chain into `.github/test-deps/.keys/`.
- **as**: The CoCo attestation service (`restful-as`), on port `8081`.
- **cert-proxy**: Serves the token-signing certificate at `GET /certificate` and forwards all other requests to the attestation service, on port `8080`. This is the attestation service address the tests use.
- **aa**: The CoCo attestation agent, built for TDX. It listens on `/run/confidential-containers/attestation-agent/attestation-agent.sock`.
- **asr**: The CoCo [API Server Rest](https://github.com/confidential-containers/guest-components/tree/main/api-server-rest) (ASR), which proxies HTTP requests to the attestation agent, on `127.0.0.1:8006`.

Start them and copy the certificates to the paths the tests read:

```sh
cd .github/test-deps
docker compose up -d --build --wait --wait-timeout 120
./setup_test_certs.sh   # copies .keys/ to /tmp/as-full.pem and /tmp/as-ca.pem
curl -sf http://127.0.0.1:8080/certificate | head -c 200
```

> [!NOTE]
> The upstream ASR is missing two interface features needed by TNG: an `encoding` parameter on `/aa/evidence` for hex-encoded runtime data, and an `/aa/additional_evidence` endpoint for fetching additional evidence (for devices such as GPU). These are implemented in the [Cohere fork](https://github.com/cohere-ai/guest-components/tree/cohere) ([PR](https://github.com/cohere-ai/guest-components/pull/2)), which is what [Dockerfile.asr](../.github/test-deps/Dockerfile.asr) installs.

> [!IMPORTANT]
> The ASR rejects any request whose source IP is not loopback (`127.0.0.1`), returning `403 Forbidden`. The tests and the ASR must therefore run on the same host, which is why the `asr` service uses host networking.

### Building the Test Runner

```sh
docker build -t test-runner -f .github/test-deps/Dockerfile.test-runner .github/test-deps
```

The commands below run inside it, with the repository mounted at `/workspace`. Run them from the repository root:

```sh
docker run --rm -it --privileged --network host \
  -e RUST_LOG=warn \
  -e ITA_API_KEY \
  -v "$PWD":/workspace \
  -v /run/confidential-containers/attestation-agent:/run/confidential-containers/attestation-agent \
  -v /tmp/as-full.pem:/tmp/as-full.pem:ro \
  -v /tmp/as-ca.pem:/tmp/as-ca.pem:ro \
  test-runner bash
```

The integration tests create network namespaces and iptables rules, so the container must be privileged and use host networking.

### Skipped Tests

[.github/test-skip-list.txt](../.github/test-skip-list.txt) lists tests CI skips, one per line, each with a comment saying why. CI passes each entry to `cargo test` as `--skip <name>`. The commands below build these flags inline.

### Unit Tests

```sh
cargo test --workspace --bins --lib --features tng/coco-builtin-as-tdx -- --nocapture \
  $(sed 's/#.*//' .github/test-skip-list.txt | xargs -n1 printf -- '--skip %s ')
```

### Integration Tests

```sh
cargo test --no-default-features --features on-source-code --package tng-testsuite -- --nocapture \
  $(sed 's/#.*//' .github/test-skip-list.txt | xargs -n1 printf -- '--skip %s ')
```

To run a single scenario, add `--test <name>`, for example `--test tcp_two_way_ra`.

### Python SDK Tests

```sh
apt-get update && apt-get install -y --no-install-recommends python3-venv
python3 -m venv /workspace/.venv
/workspace/.venv/bin/pip install maturin httpx pytest
(cd cohere/python/cohere-tng && /workspace/.venv/bin/maturin develop)
/workspace/.venv/bin/pip install -e cohere/python/conseel

# Unit tests, no network needed
/workspace/.venv/bin/pytest cohere/python/cohere-tng/tests/ -v

# Integration tests against a TNG egress
cargo test --no-default-features --features on-source-code,python-sdk \
  --package tng-testsuite --test python_sdk -- --nocapture
```

## Building the Container Images

All published images are built from [cohere/docker/Dockerfile](../cohere/docker/Dockerfile), with the repository root as the build context. Pick the image with `--target`:

| Target | Published as | Description |
| --- | --- | --- |
| `tng` | `ghcr.io/cohere-ai/tng` | Plain TNG with no baked-in configuration. |
| `ingress` | `ghcr.io/cohere-ai/tng-ingress` | Pre-configured ingress. See [cohere/docker/ingress/README.md](../cohere/docker/ingress/README.md). |
| `egress-ita` | `ghcr.io/cohere-ai/tng-ita` | Pre-configured OHTTP egress using Intel Trust Authority. |
| `egress-trustee` | `ghcr.io/cohere-ai/tng-trustee` | Pre-configured OHTTP egress for the background check model. |

```sh
docker build -f cohere/docker/Dockerfile --target tng -t tng:latest .
docker run -it --rm --privileged --network host --cgroupns=host tng:latest tng launch --config-content='<your config json string>'
```

The in-process attestation service verifiers are controlled by the `BUILTIN_AS_TDX`, `BUILTIN_AS_AZSNP` and `BUILTIN_AS_NVIDIA` build arguments, all on by default. Each takes `1`/`true`/`yes`/`on` or `0`/`false`/`no`/`off`. Turning all three off builds TNG with no verifier code and none of their system libraries:

```sh
docker build -f cohere/docker/Dockerfile --target tng \
  --build-arg BUILTIN_AS_TDX=0 --build-arg BUILTIN_AS_AZSNP=0 --build-arg BUILTIN_AS_NVIDIA=0 \
  -t tng:minimal .
```

The TDX verifier depends on Intel's DCAP library, which is x86_64 only, so an arm64 build must set `BUILTIN_AS_TDX=0`. The comments at the top of the Dockerfile explain each verifier's dependencies.

CI builds all four images on every push to `cohere` (`co-build-docker.yml`), tags them `cohere` and `sha-<commit>`, and attaches build provenance and SBOM attestations.

## Release Process

Releases are driven by the version in the workspace [Cargo.toml](../Cargo.toml):

1. Run the **Cohere Bump Version** workflow (`co-bump-version.yml`) manually. It computes the next version from the conventional commits since the last tag with `git-cliff`, updates `Cargo.toml` and `Cargo.lock`, and pushes a `release/vX.Y.Z` branch. Open a pull request from that branch into `cohere`.
2. Merging the pull request changes `Cargo.toml` on `cohere`, which triggers **Cohere Auto Release Check** (`co-auto-release-check.yml`). If the version has no tag yet, it dispatches **Cohere Release** (`co-release.yml`).
3. `co-release.yml` waits for every other workflow on the commit to succeed, then:
   - publishes the `cohere-tng` and `conseel` wheels that `co-build-python.yml` built for that commit to PyPI,
   - tags the four images built for that commit with the version and `latest`,
   - creates the `vX.Y.Z` tag and GitHub release.

PyPI uploads cannot be undone. If a release job fails after publishing, use "Re-run failed jobs" on the same run rather than dispatching a new one.
