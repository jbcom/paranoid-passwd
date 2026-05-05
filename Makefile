.PHONY: help build build-cli build-gui test lint test-cli-contract test-tui-e2e test-gui-e2e test-gui-e2e-emulate test-vault-e2e verify-security verify-assurance verify-human-review verify-branch-protection verify-published-release docs-build docs-linkcheck docs-check ci builder-image ci-emulate package-release smoke-release release-validate release-emulate clean

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
RELEASE_VERSION ?= $(shell sed -n 's/^version = "\(.*\)"$$/\1/p' Cargo.toml | head -n 1)
DIST_DIR ?= dist/release
BUILDER_CONTEXT_HASH := $(shell if command -v shasum >/dev/null 2>&1; then cat .github/actions/builder/Dockerfile .github/actions/builder/entrypoint.sh | shasum -a 256 | awk '{print substr($$1,1,12)}'; else cat .github/actions/builder/Dockerfile .github/actions/builder/entrypoint.sh | sha256sum | awk '{print substr($$1,1,12)}'; fi)
BUILDER_IMAGE ?= paranoid-passwd-builder:$(BUILDER_CONTEXT_HASH)
HOST_OS := $(shell uname -s | tr '[:upper:]' '[:lower:]')
HOST_ARCH := $(shell uname -m | sed -e 's/^x86_64$$/amd64/' -e 's/^aarch64$$/arm64/')
HOST_EXT := $(if $(filter windows,$(HOST_OS)),.exe,)
HOST_ARCHIVE := $(if $(filter windows,$(HOST_OS)),zip,tar.gz)
HOST_ARTIFACT := $(DIST_DIR)/paranoid-passwd-$(RELEASE_VERSION)-$(HOST_OS)-$(HOST_ARCH).$(HOST_ARCHIVE)
HOST_GUI_ARTIFACT := $(DIST_DIR)/paranoid-passwd-gui-$(RELEASE_VERSION)-$(HOST_OS)-$(HOST_ARCH).$(HOST_ARCHIVE)
HOST_GUI_DMG_ARTIFACT := $(DIST_DIR)/paranoid-passwd-gui-$(RELEASE_VERSION)-$(HOST_OS)-$(HOST_ARCH).dmg
HOST_DEB_ARTIFACT := $(DIST_DIR)/paranoid-passwd_$(RELEASE_VERSION)_$(HOST_ARCH).deb
HOST_GUI_DEB_ARTIFACT := $(DIST_DIR)/paranoid-passwd-gui_$(RELEASE_VERSION)_$(HOST_ARCH).deb
GUI_E2E_SCREENSHOT ?= $(DIST_DIR)/gui-e2e.png
CI_GUI_E2E_TARGET := $(if $(filter linux,$(HOST_OS)),test-gui-e2e)

help: ## Show available targets
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

build: ## Build every Rust crate in debug mode
	cargo build --workspace --locked --frozen --offline

build-cli: ## Build the paranoid-passwd CLI in release mode
	PARANOID_CLI_BUILD_COMMIT="$(COMMIT)" PARANOID_CLI_BUILD_DATE="$(DATE)" cargo build -p paranoid-cli --release --locked --frozen --offline

build-gui: ## Build the GUI app in release mode
	PARANOID_GUI_BUILD_COMMIT="$(COMMIT)" PARANOID_GUI_BUILD_DATE="$(DATE)" cargo build -p paranoid-gui --release --locked --frozen --offline

test: ## Run the Rust test suites
	bash scripts/cargo_test.sh --workspace --locked --frozen --offline

lint: ## Run formatting and clippy gates
	cargo fmt --check
	cargo clippy --workspace --all-targets --locked --frozen --offline -- -D warnings

test-cli-contract: ## Run the generator CLI contract script against the debug CLI binary
	cargo build -p paranoid-cli --locked --frozen --offline
	bash tests/test_cli.sh target/debug/paranoid-passwd

test-tui-e2e: ## Run the real PTY-driven TUI binary workflow harness
	cargo build -p paranoid-cli --locked --frozen --offline
	python3 tests/test_tui_e2e.py target/debug/paranoid-passwd

test-gui-e2e: ## Run the real GUI workflow harness under Xvfb and capture a screenshot artifact
	cargo build -p paranoid-cli -p paranoid-gui --locked --frozen --offline
	bash tests/test_gui_e2e.sh target/debug/paranoid-passwd target/debug/paranoid-passwd-gui "$(GUI_E2E_SCREENSHOT)"

test-gui-e2e-emulate: builder-image ## Run the Linux GUI workflow harness through the custom builder image
	mkdir -p "$(DIST_DIR)"
	docker run --rm --entrypoint bash -v "$$(pwd)":/github/workspace -w /github/workspace \
		-e CARGO_TARGET_DIR=/tmp/cargo-target \
		"$(BUILDER_IMAGE)" \
		-lc "cargo build -p paranoid-cli -p paranoid-gui --locked --frozen --offline && bash tests/test_gui_e2e.sh /tmp/cargo-target/debug/paranoid-passwd /tmp/cargo-target/debug/paranoid-passwd-gui \"$(GUI_E2E_SCREENSHOT)\""

test-vault-e2e: ## Run the headless vault CLI end-to-end suite against the debug CLI binary
	cargo build -p paranoid-cli --locked --frozen --offline
	bash tests/test_vault_cli.sh target/debug/paranoid-passwd

verify-security: ## Run repository security and supply-chain verification scripts
	$(MAKE) verify-assurance

verify-assurance: ## Run deterministic security assurance protocol gates
	bash scripts/hallucination_check.sh
	bash scripts/supply_chain_verify.sh
	bash scripts/verify_human_review_inventory.sh
	python3 scripts/security_assurance_gate.py

verify-human-review: ## Verify the tracked HUMAN_REVIEW inventory matches the source tree
	bash scripts/verify_human_review_inventory.sh

verify-branch-protection: ## Verify main branch protection matches the Rust-native required checks
	bash scripts/verify_branch_protection.sh

verify-published-release: ## Verify a published GitHub release asset set, attestation, checksums, and host smoke path (TAG=paranoid-passwd-vX.Y.Z)
	@if [ -z "$(TAG)" ]; then echo "TAG is required, for example: make verify-published-release TAG=paranoid-passwd-v3.5.2"; exit 2; fi
	bash scripts/verify_published_release.sh "$(TAG)"

docs-build: ## Build the Sphinx docs site
	python3 -m tox -e docs

docs-linkcheck: ## Validate outbound documentation links
	python3 -m tox -e docs-linkcheck

docs-check: ## Validate the docs site, generated API docs, and external links
	python3 -m tox -e docs,docs-linkcheck

ci: ## Run the local equivalent of the repository CI gates
	cargo fmt --check
	cargo clippy --workspace --all-targets --locked --frozen --offline -- -D warnings
	bash scripts/cargo_test.sh --workspace --locked --frozen --offline
	$(MAKE) test-cli-contract
	$(MAKE) test-tui-e2e
	$(if $(CI_GUI_E2E_TARGET),$(MAKE) $(CI_GUI_E2E_TARGET))
	$(MAKE) test-vault-e2e
	$(MAKE) verify-assurance
	python3 -m tox -e docs,docs-linkcheck

builder-image: ## Build or reuse the local builder image keyed to the builder context hash
	@docker image inspect "$(BUILDER_IMAGE)" >/dev/null 2>&1 || docker build -t "$(BUILDER_IMAGE)" .github/actions/builder

ci-emulate: builder-image ## Run the CI target through the custom builder image
	docker run --rm --entrypoint bash -v "$$(pwd)":/github/workspace -w /github/workspace \
		-e CARGO_TARGET_DIR=/tmp/cargo-target \
		"$(BUILDER_IMAGE)" \
		-lc "make ci"

package-release: ## Build and package the host-native CLI and GUI release archives into $(DIST_DIR)
	mkdir -p "$(DIST_DIR)"
	PARANOID_CLI_BUILD_COMMIT="$(COMMIT)" PARANOID_CLI_BUILD_DATE="$(DATE)" \
		bash scripts/build_release_artifact.sh "$(RELEASE_VERSION)" "$(HOST_OS)" "$(HOST_ARCH)" "$(HOST_EXT)" "$(HOST_ARCHIVE)" "$(DIST_DIR)"
	PARANOID_GUI_BUILD_COMMIT="$(COMMIT)" PARANOID_GUI_BUILD_DATE="$(DATE)" \
		bash scripts/build_release_artifact.sh "$(RELEASE_VERSION)" "$(HOST_OS)" "$(HOST_ARCH)" "$(HOST_EXT)" "$(HOST_ARCHIVE)" "$(DIST_DIR)" paranoid-passwd-gui paranoid-gui
ifeq ($(HOST_OS),linux)
	PARANOID_CLI_BUILD_COMMIT="$(COMMIT)" PARANOID_CLI_BUILD_DATE="$(DATE)" \
		bash scripts/build_release_artifact.sh "$(RELEASE_VERSION)" "$(HOST_OS)" "$(HOST_ARCH)" "$(HOST_EXT)" deb "$(DIST_DIR)"
	PARANOID_GUI_BUILD_COMMIT="$(COMMIT)" PARANOID_GUI_BUILD_DATE="$(DATE)" \
		bash scripts/build_release_artifact.sh "$(RELEASE_VERSION)" "$(HOST_OS)" "$(HOST_ARCH)" "$(HOST_EXT)" deb "$(DIST_DIR)" paranoid-passwd-gui paranoid-gui
endif
ifeq ($(HOST_OS),darwin)
	PARANOID_GUI_BUILD_COMMIT="$(COMMIT)" PARANOID_GUI_BUILD_DATE="$(DATE)" \
		bash scripts/build_release_artifact.sh "$(RELEASE_VERSION)" "$(HOST_OS)" "$(HOST_ARCH)" "$(HOST_EXT)" dmg "$(DIST_DIR)" paranoid-passwd-gui paranoid-gui
endif

smoke-release: package-release ## Smoke-test the host-native CLI and GUI release archives
	bash scripts/smoke_test_release_artifact.sh "$(RELEASE_VERSION)" "$(HOST_OS)" "$(HOST_ARCH)" "$(HOST_ARTIFACT)"
	bash scripts/smoke_test_release_artifact.sh "$(RELEASE_VERSION)" "$(HOST_OS)" "$(HOST_ARCH)" "$(HOST_GUI_ARTIFACT)" paranoid-passwd-gui
ifeq ($(HOST_OS),linux)
	bash scripts/smoke_test_release_artifact.sh "$(RELEASE_VERSION)" "$(HOST_OS)" "$(HOST_ARCH)" "$(HOST_DEB_ARTIFACT)"
	bash scripts/smoke_test_release_artifact.sh "$(RELEASE_VERSION)" "$(HOST_OS)" "$(HOST_ARCH)" "$(HOST_GUI_DEB_ARTIFACT)" paranoid-passwd-gui
endif
ifeq ($(HOST_OS),darwin)
	bash scripts/smoke_test_release_artifact.sh "$(RELEASE_VERSION)" "$(HOST_OS)" "$(HOST_ARCH)" "$(HOST_GUI_DMG_ARTIFACT)" paranoid-passwd-gui
endif

release-validate: ## Validate a populated release dist dir, generate package manifests, and smoke-test install.sh
	bash scripts/release_validate.sh "$(RELEASE_VERSION)" "$(DIST_DIR)"

release-emulate: builder-image ## Build and smoke-test the linux-amd64 CLI and GUI release paths through the custom builder image
	mkdir -p "$(DIST_DIR)"
	docker run --rm --entrypoint bash -v "$$(pwd)":/github/workspace -w /github/workspace \
		-e PARANOID_CLI_BUILD_COMMIT="$(COMMIT)" \
		-e PARANOID_CLI_BUILD_DATE="$(DATE)" \
		-e PARANOID_GUI_BUILD_COMMIT="$(COMMIT)" \
		-e PARANOID_GUI_BUILD_DATE="$(DATE)" \
		-e CARGO_TARGET_DIR=/tmp/cargo-target \
		"$(BUILDER_IMAGE)" \
		-lc "bash scripts/build_release_artifact.sh \"$(RELEASE_VERSION)\" linux amd64 \"\" tar.gz \"$(DIST_DIR)\" && bash scripts/smoke_test_release_artifact.sh \"$(RELEASE_VERSION)\" linux amd64 \"$(DIST_DIR)/paranoid-passwd-$(RELEASE_VERSION)-linux-amd64.tar.gz\" && bash scripts/build_release_artifact.sh \"$(RELEASE_VERSION)\" linux amd64 \"\" deb \"$(DIST_DIR)\" && bash scripts/smoke_test_release_artifact.sh \"$(RELEASE_VERSION)\" linux amd64 \"$(DIST_DIR)/paranoid-passwd_$(RELEASE_VERSION)_amd64.deb\" && bash scripts/build_release_artifact.sh \"$(RELEASE_VERSION)\" linux amd64 \"\" tar.gz \"$(DIST_DIR)\" paranoid-passwd-gui paranoid-gui && bash scripts/smoke_test_release_artifact.sh \"$(RELEASE_VERSION)\" linux amd64 \"$(DIST_DIR)/paranoid-passwd-gui-$(RELEASE_VERSION)-linux-amd64.tar.gz\" paranoid-passwd-gui && bash scripts/build_release_artifact.sh \"$(RELEASE_VERSION)\" linux amd64 \"\" deb \"$(DIST_DIR)\" paranoid-passwd-gui paranoid-gui && bash scripts/smoke_test_release_artifact.sh \"$(RELEASE_VERSION)\" linux amd64 \"$(DIST_DIR)/paranoid-passwd-gui_$(RELEASE_VERSION)_amd64.deb\" paranoid-passwd-gui"

clean: ## Remove Rust and docs build artifacts
	rm -rf target docs/_build .tox dist
