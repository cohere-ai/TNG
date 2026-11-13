.PHONY: help
help:
	@echo "Read README.md first"

# The test targets expect their dependencies to be present already, as they are in
# the test-runner image (.github/test-deps/Dockerfile.test-runner).
.PHONY: run-test
run-test:
	./tng-testsuite/run-test.sh

.PHONY: run-test-on-bin
run-test-on-bin:
	cargo test --no-default-features --features on-bin --package tng-testsuite --tests -- --nocapture


.PHONY: run-test-on-podman
run-test-on-podman:
	cargo test --no-default-features --features on-podman --package tng-testsuite --tests -- --nocapture


VERSION 	:= $(shell grep '^version' ./Cargo.toml | awk -F' = ' '{print $$2}' | tr -d '"')

.PHONY: bin-build
bin-build:
	RUSTFLAGS="--cfg tokio_unstable" cargo build --release

.PHONY: docker-build
docker-build:
	docker build -f cohere/docker/Dockerfile --target tng -t tng:${VERSION} .

.PHONY: install-wasm-build-dependencies
install-wasm-build-dependencies:
	if ! command -v wasm-pack >/dev/null; then \
		cargo +nightly-2025-07-07 install wasm-pack --locked ; \
	fi
	if ! rustup component list --toolchain nightly-2025-07-07 | grep rust-src | grep installed >/dev/null; then \
		rustup component add rust-src --toolchain nightly-2025-07-07 ; \
	fi

.PHONY: wasm-build-release
wasm-build-release: install-wasm-build-dependencies
	RUSTUP_TOOLCHAIN=nightly-2025-07-07 RUSTFLAGS='--cfg getrandom_backend="wasm_js" -C target-feature=+atomics,+bulk-memory,+mutable-globals' wasm-pack build --release --target web ./tng-wasm -Z build-std=std,panic_abort

.PHONY: wasm-build-debug
wasm-build-debug: install-wasm-build-dependencies
	RUSTUP_TOOLCHAIN=nightly-2025-07-07 RUSTFLAGS='--cfg getrandom_backend="wasm_js" -C target-feature=+atomics,+bulk-memory,+mutable-globals' wasm-pack build --dev --target web ./tng-wasm -Z build-std=std,panic_abort

.PHONY: wasm-pack-release
wasm-pack-release: wasm-build-release
	wasm-pack pack ./tng-wasm
	@echo 'Now you can install with "npm install <.tgz path>"'

.PHONY: wasm-pack-debug
wasm-pack-debug: wasm-build-debug
	wasm-pack pack ./tng-wasm
	@echo 'Now you can install with "npm install <.tgz path>"'

.PHONY: wasm-unit-test
wasm-unit-test: wasm-unit-test-chrome
	RUSTUP_TOOLCHAIN=nightly-2025-07-07 RUSTFLAGS='--cfg getrandom_backend="wasm_js" -C target-feature=+atomics,+bulk-memory,+mutable-globals' wasm-pack test --headless --chrome ./tng-wasm -Z build-std=std,panic_abort

.PHONY: wasm-unit-test-chrome
wasm-unit-test-chrome: install-wasm-build-dependencies
	@command -v google-chrome >/dev/null || { echo 'google-chrome is required for wasm unit tests' >&2; exit 1; }
	RUSTUP_TOOLCHAIN=nightly-2025-07-07 RUSTFLAGS='--cfg getrandom_backend="wasm_js" -C target-feature=+atomics,+bulk-memory,+mutable-globals' wasm-pack test --headless --chrome ./tng-wasm -Z build-std=std,panic_abort -- --nocapture

.PHONY: wasm-unit-test-firefox
wasm-unit-test-firefox: install-wasm-build-dependencies
	@command -v firefox >/dev/null || { echo 'firefox is required for wasm unit tests' >&2; exit 1; }
	RUSTUP_TOOLCHAIN=nightly-2025-07-07 RUSTFLAGS='--cfg getrandom_backend="wasm_js" -C target-feature=+atomics,+bulk-memory,+mutable-globals' wasm-pack test --headless --firefox ./tng-wasm -Z build-std=std,panic_abort -- --nocapture

.PHONY: wasm-integration-test
wasm-integration-test: wasm-build-debug
	RUSTUP_TOOLCHAIN=nightly-2025-07-07 cargo test --no-default-features --features on-source-code,js-sdk --package tng-testsuite --test 'js_sdk*' -- --nocapture

.PHONY: clippy
clippy:
	cargo clippy --all-targets -- -D warnings
