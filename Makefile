.PHONE: help
help:
	@echo "Read README.md first"

# The test targets expect their dependencies to be present already, as they are in
# the test-runner image (.github/test-deps/Dockerfile.test-runner).
.PHONE: run-test
run-test:
	./tng-testsuite/run-test.sh

.PHONE: run-test-coverage
run-test-coverage:
	./tng-testsuite/run-test.sh --coverage

.PHONE: run-test-on-bin
run-test-on-bin:
	cargo test --no-default-features --features on-bin --package tng-testsuite --tests -- --nocapture


.PHONE: run-test-on-podman
run-test-on-podman:
	cargo test --no-default-features --features on-podman --package tng-testsuite --tests -- --nocapture


VERSION 	:= $(shell grep '^version' ./Cargo.toml | awk -F' = ' '{print $$2}' | tr -d '"')

# Version components for bumping
MAJOR := $(shell echo $(VERSION) | awk -F. '{print $$1}')
MINOR := $(shell echo $(VERSION) | awk -F. '{print $$2}')
PATCH := $(shell echo $(VERSION) | awk -F. '{print $$3}')

# Calculate new versions
NEW_VERSION_MAJOR := $(shell echo $$(( $(MAJOR) + 1 ))).0.0
NEW_VERSION_MINOR := $(MAJOR).$(shell echo $$(( $(MINOR) + 1 ))).0
NEW_VERSION_PATCH := $(MAJOR).$(MINOR).$(shell echo $$(( $(PATCH) + 1 )))

# Function to update Cargo.toml version
define update-cargo-toml
	@sed -i 's/^version = "$(VERSION)"/version = "$(1)"/' Cargo.toml
endef

# Function to update buildspec.yml version
define update-buildspec-yml
	@sed -i -E 's/(tags: \[\[)[0-9]+\.[0-9]+\.[0-9]+(, latest\]\])/\1$(1)\2/' APPLICATION/tng/buildspec.yml
endef

# Function to update Cargo.lock
define update-cargo-lock
	@cargo update --workspace --offline 2>/dev/null || cargo update --workspace
endef

# Main bump version function
# $(1) = version type (major/minor/patch)
# $(2) = new version number
define bump-version-internal
	@echo "Bumping $(1) version: $(VERSION) -> $(2)"
	$(call update-cargo-toml,$(2))
	@echo "New version: $(2)"
	$(call update-cargo-lock)
	$(call update-buildspec-yml,$(2))
	@echo "Updated APPLICATION/tng/buildspec.yml"
	@echo "Version bump complete. New version: $(2)"
	@echo "Changes made:"
	@echo "  - Updated Cargo.toml"
	@echo "  - Updated Cargo.lock"
	@echo "  - Updated APPLICATION/tng/buildspec.yml"
	@echo ""
	@echo "If it is ok to commit, run the following commands:"
	@echo "  git add ."
	@echo "  git commit -m \"Bump $(1) version to $(2)\""
	@echo "  git tag -a v$(2) -m \"Bump $(1) version to $(2)\""
	@echo "  git push origin v$(2)"
endef

# Bump major version (2.4.0 -> 3.0.0)
.PHONY: bump-version-major
bump-version-major:
	$(call bump-version-internal,major,$(NEW_VERSION_MAJOR))

# Bump minor version (2.4.0 -> 2.5.0)
.PHONY: bump-version-minor
bump-version-minor:
	$(call bump-version-internal,minor,$(NEW_VERSION_MINOR))

# Bump patch version (2.4.0 -> 2.4.1)
.PHONY: bump-version-patch
bump-version-patch:
	$(call bump-version-internal,patch,$(NEW_VERSION_PATCH))

.PHONE: bin-build
bin-build:
	RUSTFLAGS="--cfg tokio_unstable" cargo build --release

.PHONE: docker-build
docker-build:
	docker build -t tng:${VERSION} .

.PHONE: install-wasm-build-dependencies
install-wasm-build-dependencies:
	if ! command -v wasm-pack >/dev/null; then \
		cargo +nightly-2025-07-07 install wasm-pack --locked ; \
	fi
	if ! rustup component list --toolchain nightly-2025-07-07-x86_64-unknown-linux-gnu | grep rust-src | grep installed >/dev/null; then \
		rustup component add rust-src --toolchain nightly-2025-07-07-x86_64-unknown-linux-gnu ; \
	fi

define WASM_PATCH_PACKAGE_JSON =
	@echo "Patching package.json ..."
	if ! command -v jq >/dev/null; then yum install -y jq ; fi
	rm -f tng-wasm/pkg/package.json.bak && \
		cp tng-wasm/pkg/package.json tng-wasm/pkg/package.json.bak && \
		jq '.name = "@inclavare-containers/tng" | .publishConfig = { "registry": "https://npm.pkg.github.com/", "access": "public" }' tng-wasm/pkg/package.json.bak > tng-wasm/pkg/package.json
endef

.PHONE: wasm-build-release
wasm-build-release: install-wasm-build-dependencies
	RUSTUP_TOOLCHAIN=nightly-2025-07-07 RUSTFLAGS='--cfg getrandom_backend="wasm_js" -C target-feature=+atomics,+bulk-memory,+mutable-globals' wasm-pack build --release --target web ./tng-wasm -Z build-std=std,panic_abort
	$(WASM_PATCH_PACKAGE_JSON)

.PHONE: wasm-build-debug
wasm-build-debug: install-wasm-build-dependencies
	RUSTUP_TOOLCHAIN=nightly-2025-07-07 RUSTFLAGS='--cfg getrandom_backend="wasm_js" -C target-feature=+atomics,+bulk-memory,+mutable-globals' wasm-pack build --dev --target web ./tng-wasm -Z build-std=std,panic_abort
	$(WASM_PATCH_PACKAGE_JSON)

.PHONE: wasm-pack-release
wasm-pack-release: wasm-build-release
	wasm-pack pack
	@echo 'Now you can install with "npm install <tar.gz path>"'

.PHONE: wasm-pack-debug
wasm-pack-debug: wasm-build-debug
	wasm-pack pack
	@echo 'Now you can install with "npm install <tar.gz path>"'

.PHONE: wasm-unit-test
wasm-unit-test: wasm-unit-test-chrome
	RUSTUP_TOOLCHAIN=nightly-2025-07-07 RUSTFLAGS='--cfg getrandom_backend="wasm_js" -C target-feature=+atomics,+bulk-memory,+mutable-globals' wasm-pack test --headless --chrome ./tng-wasm -Z build-std=std,panic_abort

.PHONE: wasm-unit-test-chrome
wasm-unit-test-chrome: install-wasm-build-dependencies
	if ! command -v google-chrome; then echo -e '[google-chrome]\nname=google-chrome\nbaseurl=https://dl.google.com/linux/chrome/rpm/stable/x86_64\nenabled=1\ngpgcheck=1\ngpgkey=https://dl.google.com/linux/linux_signing_key.pub' | tee /etc/yum.repos.d/google-chrome.repo; yum install google-chrome-stable -y ; fi
	RUSTUP_TOOLCHAIN=nightly-2025-07-07 RUSTFLAGS='--cfg getrandom_backend="wasm_js" -C target-feature=+atomics,+bulk-memory,+mutable-globals' wasm-pack test --headless --chrome ./tng-wasm -Z build-std=std,panic_abort -- --nocapture

.PHONE: wasm-unit-test-firefox
wasm-unit-test-firefox: install-wasm-build-dependencies
	if ! command -v firefox; then yum install -y firefox ; fi
	RUSTUP_TOOLCHAIN=nightly-2025-07-07 RUSTFLAGS='--cfg getrandom_backend="wasm_js" -C target-feature=+atomics,+bulk-memory,+mutable-globals' wasm-pack test --headless --firefox ./tng-wasm -Z build-std=std,panic_abort -- --nocapture

.PHONE: wasm-integration-test
wasm-integration-test: wasm-build-debug
	RUSTUP_TOOLCHAIN=nightly-2025-07-07 cargo test --no-default-features --features on-source-code,js-sdk --package tng-testsuite --test 'js_sdk*' -- --nocapture

.PHONE: www-demo
www-demo:
	cd tng-wasm/www && npm run start

.PHONE: mac-cross-build
mac-cross-build:
	RUSTFLAGS="-L native=/usr/lib/" cargo zigbuild --target aarch64-apple-darwin

.PHONE: clippy
clippy:
	cargo clippy --all-targets -- -D warnings

# Test dependencies: Attestation Agent
.PHONY: test-dep-aa
test-dep-aa:
	@echo "=== Starting Attestation Agent ==="
	@if ! command -v attestation-agent > /dev/null; then \
		yum install -y attestation-agent; \
	fi
	RUST_LOG=debug attestation-agent --attestation_sock unix:///run/confidential-containers/attestation-agent/attestation-agent.sock

# Test dependencies: Attestation Service (with SLSA provenance and Rekor)
.PHONY: test-dep-as
test-dep-as:
	@set -e; \
	echo "=== Starting OCI Registry ==="; \
	if ! command -v crane > /dev/null; then \
		curl -sSL https://github.com/google/go-containerregistry/releases/latest/download/go-containerregistry_Linux_x86_64.tar.gz | tar -xzf - -C /usr/local/bin crane; \
		chmod +x /usr/local/bin/crane; \
	fi; \
	pkill -x crane 2>/dev/null || true; \
	crane registry serve --address=:5000 & \
	for i in $$(seq 1 10); do \
		if curl -s http://127.0.0.1:5000/v2/ > /dev/null; then \
			echo "OCI registry is ready"; \
			break; \
		fi; \
		echo "Waiting for OCI registry..."; \
		sleep 1; \
	done; \
	echo "=== Installing SLSA Tools ==="; \
	if ! command -v cosign > /dev/null; then \
		curl -sSL -o /usr/local/bin/cosign https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64; \
		chmod +x /usr/local/bin/cosign; \
	fi; \
	if ! command -v rekor-cli > /dev/null; then \
		curl -sSL -o /usr/local/bin/rekor-cli https://github.com/sigstore/rekor/releases/latest/download/rekor-cli-linux-amd64; \
		chmod +x /usr/local/bin/rekor-cli; \
	fi; \
	if ! command -v slsa-generator > /dev/null; then \
		curl -sSL -o /usr/local/bin/slsa-generator https://github.com/openanolis/trustee/raw/refs/heads/main/tools/slsa/slsa-generator; \
		chmod +x /usr/local/bin/slsa-generator; \
	fi; \
	echo "=== Generating SLSA Provenance and Uploading to Rekor ==="; \
	mkdir -p /tmp/slsa-test; \
	echo "Working directory: /tmp/slsa-test"; \
	cd /tmp/slsa-test && \
		echo '#!/bin/bash' > demo-app.sh && \
		echo 'echo "Hello, SLSA Provenance Test!"' >> demo-app.sh && \
		echo 'echo "This is a test binary for reference value generation"' >> demo-app.sh && \
		echo 'echo "Timestamp: $$(date)"' >> demo-app.sh && \
		echo 'exit 0' >> demo-app.sh && \
		chmod +x demo-app.sh && \
		echo "Artifact SHA256: $$(sha256sum demo-app.sh | awk '{print $$1}')" && \
		export COSIGN_PASSWORD="" && \
		rm -f slsa-test.key slsa-test.pub && \
		cosign generate-key-pair --output-key-prefix slsa-test && \
		/usr/local/bin/slsa-generator \
			--artifact-type binary \
			--artifact ./demo-app.sh \
			--artifact-id test-artifact \
			--artifact-version 1.0.0 \
			--sign-key ./slsa-test.key \
			--rekor-url https://log2025-1.rekor.sigstore.dev \
			--rekor-api-version 2 \
			--provenance-store-protocol oci \
			--provenance-store-uri oci://127.0.0.1:5000/trustee/provenance:test-artifact-1.0.0 \
			--provenance-store-artifact bundle; \
	echo "=== Verifying OCI Registry Upload ==="; \
	curl -s http://127.0.0.1:5000/v2/trustee/provenance/tags/list | jq .; \
	curl -s -H "Accept: application/vnd.oci.image.manifest.v1+json" \
		http://127.0.0.1:5000/v2/trustee/provenance/manifests/test-artifact-1.0.0 | jq .; \
	echo "=== Starting Attestation Service ==="; \
	if ! command -v restful-as > /dev/null; then \
		systemctl mask trustee || true; \
		yum install -y trustee; \
	fi; \
	systemctl stop trustee || true; \
	if ! command -v jq > /dev/null; then yum install -y jq; fi; \
	if ! command -v openssl > /dev/null; then yum install -y openssl; fi; \
	openssl ecparam -genkey -name prime256v1 -out /tmp/as-ca.key; \
	openssl req -x509 -sha256 -nodes -days 365 -key /tmp/as-ca.key -out /tmp/as-ca.pem -subj "/O=Trustee CA" \
		-addext keyUsage=critical,cRLSign,keyCertSign,digitalSignature; \
	openssl ecparam -genkey -name prime256v1 -out /tmp/as.key; \
	openssl req -new -key /tmp/as.key -out /tmp/as.csr -subj "/CN=Trustee/O=Trustee CA"; \
	echo '[v3_req]' > /tmp/as-ext.cnf; \
	echo 'subjectKeyIdentifier = hash' >> /tmp/as-ext.cnf; \
	openssl x509 -req -in /tmp/as.csr -CA /tmp/as-ca.pem -CAkey /tmp/as-ca.key -CAcreateserial \
		-out /tmp/as.pem -days 365 -extensions v3_req -extfile /tmp/as-ext.cnf -sha256; \
	cat /tmp/as.pem /tmp/as-ca.pem > /tmp/as-full.pem; \
	mkdir -p /opt/trustee/attestation-service/policies/opa; \
	echo 'package policy' > /opt/trustee/attestation-service/policies/opa/default.rego; \
	echo '' >> /opt/trustee/attestation-service/policies/opa/default.rego; \
	echo 'default executables := 3' >> /opt/trustee/attestation-service/policies/opa/default.rego; \
	echo 'default hardware := 2' >> /opt/trustee/attestation-service/policies/opa/default.rego; \
	echo 'default configuration := 2' >> /opt/trustee/attestation-service/policies/opa/default.rego; \
	echo 'default file_system := 2' >> /opt/trustee/attestation-service/policies/opa/default.rego; \
	cat /etc/trustee/as-config.json | jq '.attestation_token_broker.signer.cert_path="/tmp/as-full.pem" | .attestation_token_broker.signer.key_path="/tmp/as.key" | .rvps_config={"type":"BuiltIn","storage":{"type":"LocalFs"}}' > /tmp/config_with_cert.json; \
	RUST_LOG=debug restful-as --socket 0.0.0.0:8080 --config-file /tmp/config_with_cert.json
