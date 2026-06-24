.PHONY: help configure bootstrap-local show-config build build-cli build-gui test lint test-cli-contract test-tui-e2e test-gui-host-check test-gui-android-check _test-gui-android-check test-gui-wasm-check _test-gui-wasm-check test-gui-targets test-gui-e2e test-gui-visual-regression test-gui-e2e-emulate test-gui-visual-regression-emulate _test-gui-e2e-emulate test-vault-e2e verify-security verify-assurance verify-deep verify-ai-review verify-branch-protection verify-published-release docs-build docs-linkcheck docs-check ci quality builder-image _builder-image ci-emulate _ci-emulate package-release smoke-release release-validate release-emulate _release-emulate clean

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LOCAL_CONFIG_DIR ?= .config
LOCAL_CONFIG_MK ?= $(LOCAL_CONFIG_DIR)/paranoid-local.mk
LOCAL_CONFIG_ENV ?= $(LOCAL_CONFIG_DIR)/paranoid-local.env
-include $(LOCAL_CONFIG_MK)
DOCKER ?= docker
DOCKER_BIN_DIR ?=
RELEASE_VERSION ?= $(shell sed -n 's/^version = "\(.*\)"$$/\1/p' Cargo.toml | head -n 1)
DIST_DIR ?= dist/release
BUILDER_CONTEXT_HASH := $(shell if command -v shasum >/dev/null 2>&1; then cat .github/actions/builder/Dockerfile .github/actions/builder/entrypoint.sh | shasum -a 256 | awk '{print substr($$1,1,12)}'; else cat .github/actions/builder/Dockerfile .github/actions/builder/entrypoint.sh | sha256sum | awk '{print substr($$1,1,12)}'; fi)
HOST_OS := $(shell uname -s | tr '[:upper:]' '[:lower:]')
HOST_ARCH := $(shell uname -m | sed -e 's/^x86_64$$/amd64/' -e 's/^aarch64$$/arm64/')
BUILDER_PLATFORM ?= linux/$(HOST_ARCH)
BUILDER_PLATFORM_TAG := $(subst /,-,$(BUILDER_PLATFORM))
BUILDER_TARGET_ARCH := $(lastword $(subst /, ,$(BUILDER_PLATFORM)))
BUILDER_IMAGE ?= paranoid-passwd-builder:$(BUILDER_CONTEXT_HASH)-$(BUILDER_PLATFORM_TAG)
RELEASE_EMULATE_ARCH ?= $(BUILDER_TARGET_ARCH)
HOST_EXT := $(if $(filter windows,$(HOST_OS)),.exe,)
HOST_ARCHIVE := $(if $(filter windows,$(HOST_OS)),zip,tar.gz)
HOST_ARTIFACT := $(DIST_DIR)/paranoid-passwd-$(RELEASE_VERSION)-$(HOST_OS)-$(HOST_ARCH).$(HOST_ARCHIVE)
HOST_GUI_ARTIFACT := $(DIST_DIR)/paranoid-passwd-gui-$(RELEASE_VERSION)-$(HOST_OS)-$(HOST_ARCH).$(HOST_ARCHIVE)
HOST_GUI_DMG_ARTIFACT := $(DIST_DIR)/paranoid-passwd-gui-$(RELEASE_VERSION)-$(HOST_OS)-$(HOST_ARCH).dmg
HOST_DEB_ARTIFACT := $(DIST_DIR)/paranoid-passwd_$(RELEASE_VERSION)_$(HOST_ARCH).deb
HOST_GUI_DEB_ARTIFACT := $(DIST_DIR)/paranoid-passwd-gui_$(RELEASE_VERSION)_$(HOST_ARCH).deb
GUI_E2E_SCREENSHOT ?= $(DIST_DIR)/gui-e2e.png
GUI_E2E_VIEWPORTS ?= desktop=1280x1024
GUI_E2E_VISUAL_VIEWPORTS ?= desktop=1280x1024 tablet=900x700 mobile=420x800
GUI_E2E_TARGET_VOLUME ?= paranoid-passwd-cargo-target-gui-e2e
GUI_E2E_CLEAN ?= 0
CI_EMULATE_TARGET_VOLUME ?= paranoid-passwd-cargo-target-ci-emulate
RELEASE_EMULATE_TARGET_VOLUME ?= paranoid-passwd-cargo-target-release-emulate
CI_GUI_E2E_TARGET := $(if $(filter linux,$(HOST_OS)),test-gui-e2e)
LOCAL_GUI_E2E_TARGET := $(if $(filter darwin,$(HOST_OS)),test-gui-e2e-emulate,$(if $(filter linux,$(HOST_OS)),test-gui-e2e))
LOCAL_GUI_VISUAL_TARGET := $(if $(filter darwin,$(HOST_OS)),test-gui-visual-regression-emulate,$(if $(filter linux,$(HOST_OS)),test-gui-visual-regression))
CARGO_TARGET_DIR ?= target
CARGO_DEBUG_DIR := $(CARGO_TARGET_DIR)/debug
CLI_DEBUG_BIN := $(CARGO_DEBUG_DIR)/paranoid-passwd
GUI_DEBUG_BIN := $(CARGO_DEBUG_DIR)/paranoid-passwd-gui

help: ## Show available targets
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

configure: ## Detect the local Rust, Android, WASM, Docker, and GUI test build chain
	bash scripts/configure_local_toolchain.sh

bootstrap-local: ## Install Rust GUI targets and regenerate the local build-chain config
	rustup target add aarch64-linux-android wasm32-unknown-unknown
	$(MAKE) configure

show-config: ## Print the generated local build-chain summary
	@bash scripts/configure_local_toolchain.sh --quiet
	@cat "$(LOCAL_CONFIG_DIR)/paranoid-local.summary"

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
	bash tests/test_cli.sh "$(CLI_DEBUG_BIN)"

test-tui-e2e: ## Run the real PTY-driven TUI binary workflow harness
	cargo build -p paranoid-cli --locked --frozen --offline
	python3 tests/test_tui_e2e.py "$(CLI_DEBUG_BIN)"

test-gui-host-check: ## Compile-check the host Slint GUI surface
	cargo check -p paranoid-gui --locked --frozen --offline

test-gui-android-check: ## Compile-check the Slint GUI library for Android using the configured NDK
	@bash scripts/configure_local_toolchain.sh --quiet
	$(MAKE) _test-gui-android-check

_test-gui-android-check:
	@if [ "$(ANDROID_TOOLCHAIN_READY)" != "1" ]; then cat "$(LOCAL_CONFIG_DIR)/paranoid-local.summary"; echo "Android toolchain is incomplete; run make bootstrap-local and install Android SDK/NDK if needed."; exit 2; fi
	ANDROID_HOME="$(ANDROID_HOME)" ANDROID_SDK_ROOT="$(ANDROID_SDK_ROOT)" ANDROID_NDK_HOME="$(ANDROID_NDK_HOME)" ANDROID_NDK_ROOT="$(ANDROID_NDK_ROOT)" CC_aarch64_linux_android="$(ANDROID_CC_AARCH64)" AR_aarch64_linux_android="$(ANDROID_AR)" RANLIB_aarch64_linux_android="$(ANDROID_RANLIB)" CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$(ANDROID_LINKER_AARCH64)" cargo check -p paranoid-gui --lib --target "$(ANDROID_TARGET)" --locked --frozen --offline

test-gui-wasm-check: ## Compile-check the Slint GUI library for WASM
	@bash scripts/configure_local_toolchain.sh --quiet
	$(MAKE) _test-gui-wasm-check

_test-gui-wasm-check:
	@if [ "$(WASM_TOOLCHAIN_READY)" != "1" ]; then cat "$(LOCAL_CONFIG_DIR)/paranoid-local.summary"; echo "WASM Rust target is incomplete; run make bootstrap-local and install wasm-pack if packaging is needed."; exit 2; fi
	cargo check -p paranoid-gui --lib --target "$(WASM_TARGET)" --locked --frozen --offline

test-gui-targets: test-gui-host-check test-gui-android-check test-gui-wasm-check ## Compile-check host, Android, and WASM GUI targets

test-gui-e2e: ## Run the real GUI workflow harness under Xvfb and capture a screenshot artifact
	cargo build -p paranoid-cli -p paranoid-gui --locked --frozen --offline
	bash tests/test_gui_e2e.sh "$(CLI_DEBUG_BIN)" "$(GUI_DEBUG_BIN)" "$(GUI_E2E_SCREENSHOT)"

test-gui-visual-regression: ## Run GUI workflow screenshots across desktop, tablet, and narrow viewport classes
	cargo build -p paranoid-cli -p paranoid-gui --locked --frozen --offline
	bash tests/test_gui_e2e.sh "$(CLI_DEBUG_BIN)" "$(GUI_DEBUG_BIN)" "$(GUI_E2E_SCREENSHOT)" "$(GUI_E2E_VISUAL_VIEWPORTS)"

test-gui-e2e-emulate: ## Run the Linux GUI workflow harness through the custom builder image
	@bash scripts/configure_local_toolchain.sh --quiet
	@$(MAKE) _test-gui-e2e-emulate

test-gui-visual-regression-emulate: ## Run the multi-viewport GUI screenshot harness through the custom builder image
	@bash scripts/configure_local_toolchain.sh --quiet
	@$(MAKE) _test-gui-e2e-emulate GUI_E2E_VIEWPORTS="$(GUI_E2E_VISUAL_VIEWPORTS)"

_test-gui-e2e-emulate: _builder-image
	mkdir -p "$(DIST_DIR)"
	@if [ "$(GUI_E2E_CLEAN)" = "1" ]; then PATH="$(DOCKER_BIN_DIR):$$PATH" "$(DOCKER)" volume rm -f "$(GUI_E2E_TARGET_VOLUME)" >/dev/null 2>&1 || true; fi
	PATH="$(DOCKER_BIN_DIR):$$PATH" "$(DOCKER)" run --rm --platform "$(BUILDER_PLATFORM)" --user root --entrypoint bash \
		-v "$$(pwd)":/github/workspace \
		--mount type=volume,source="$(GUI_E2E_TARGET_VOLUME)",target=/cargo-target \
		-w /github/workspace \
		"$(BUILDER_IMAGE)" \
		-lc "chown -R builder:builder /cargo-target && su builder -s /bin/bash -c 'export CARGO_TARGET_DIR=/cargo-target CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0; cargo build -p paranoid-cli -p paranoid-gui --locked --frozen --offline && bash tests/test_gui_e2e.sh /cargo-target/debug/paranoid-passwd /cargo-target/debug/paranoid-passwd-gui \"$(GUI_E2E_SCREENSHOT)\" \"$(GUI_E2E_VIEWPORTS)\"'"
	@if [ "$(GUI_E2E_CLEAN)" = "1" ]; then PATH="$(DOCKER_BIN_DIR):$$PATH" "$(DOCKER)" volume rm -f "$(GUI_E2E_TARGET_VOLUME)" >/dev/null 2>&1 || true; fi

test-vault-e2e: ## Run the headless vault CLI end-to-end suite against the debug CLI binary
	cargo build -p paranoid-cli --locked --frozen --offline
	bash tests/test_vault_cli.sh "$(CLI_DEBUG_BIN)"

verify-security: ## Run repository security and supply-chain verification scripts
	$(MAKE) verify-assurance

verify-assurance: ## Run deterministic security assurance protocol gates
	bash scripts/hallucination_check.sh
	bash scripts/supply_chain_verify.sh
	bash scripts/verify_ai_review_inventory.sh
	python3 scripts/security_assurance_gate.py

verify-deep: ## Run local-only static/dependency/secret quality checks before pushing
	cargo run -p xtask --locked --frozen --offline -- verify-deep

verify-ai-review: ## Verify the tracked AI_REVIEW inventory matches the source tree
	bash scripts/verify_ai_review_inventory.sh

verify-branch-protection: ## Verify main branch protection matches the Rust-native required checks
	bash scripts/verify_branch_protection.sh

verify-published-release: ## Verify a published GitHub release asset set, attestation, checksums, and host smoke path (TAG=paranoid-passwd-vX.Y.Z)
	@if [ -z "$(TAG)" ]; then echo "TAG is required, for example: make verify-published-release TAG=paranoid-passwd-v3.7.0"; exit 2; fi
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

quality: ## Run local release-candidate quality gates, including GUI e2e when supported
	PARANOID_STRICT_EXTERNAL_TOOLS=1 PARANOID_RUN_LOCAL_SCANNERS=1 $(MAKE) verify-deep
	$(MAKE) ci
	$(MAKE) test-gui-targets
	$(if $(LOCAL_GUI_VISUAL_TARGET),$(MAKE) $(LOCAL_GUI_VISUAL_TARGET))


builder-image: ## Build or reuse the local builder image keyed to the builder context hash
	@bash scripts/configure_local_toolchain.sh --quiet
	@$(MAKE) _builder-image

_builder-image:
	@if [ -z "$(DOCKER)" ] || [ "$(DOCKER_READY)" != "1" ]; then cat "$(LOCAL_CONFIG_DIR)/paranoid-local.summary"; echo "Docker is not ready; start Docker Desktop or install a Docker-compatible runtime, then run make configure."; exit 2; fi
	@PATH="$(DOCKER_BIN_DIR):$$PATH" "$(DOCKER)" image inspect "$(BUILDER_IMAGE)" >/dev/null 2>&1 || PATH="$(DOCKER_BIN_DIR):$$PATH" "$(DOCKER)" build --platform "$(BUILDER_PLATFORM)" -t "$(BUILDER_IMAGE)" .github/actions/builder

ci-emulate: ## Run the CI target through the custom builder image
	@bash scripts/configure_local_toolchain.sh --quiet
	@$(MAKE) _ci-emulate

_ci-emulate: _builder-image
	PATH="$(DOCKER_BIN_DIR):$$PATH" "$(DOCKER)" volume rm -f "$(CI_EMULATE_TARGET_VOLUME)" >/dev/null 2>&1 || true
	PATH="$(DOCKER_BIN_DIR):$$PATH" "$(DOCKER)" run --rm --platform "$(BUILDER_PLATFORM)" --user root --entrypoint bash \
		-v "$$(pwd)":/github/workspace \
		--mount type=volume,source="$(CI_EMULATE_TARGET_VOLUME)",target=/cargo-target \
		-w /github/workspace \
		"$(BUILDER_IMAGE)" \
		-lc "chown -R builder:builder /cargo-target && su builder -s /bin/bash -c 'export CARGO_TARGET_DIR=/cargo-target CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0; make ci'"
	PATH="$(DOCKER_BIN_DIR):$$PATH" "$(DOCKER)" volume rm -f "$(CI_EMULATE_TARGET_VOLUME)" >/dev/null 2>&1 || true

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

release-emulate: ## Build and smoke-test the Linux CLI and GUI release paths through the custom builder image
	@bash scripts/configure_local_toolchain.sh --quiet
	@$(MAKE) _release-emulate

_release-emulate: _builder-image
	mkdir -p "$(DIST_DIR)"
	PATH="$(DOCKER_BIN_DIR):$$PATH" "$(DOCKER)" volume rm -f "$(RELEASE_EMULATE_TARGET_VOLUME)" >/dev/null 2>&1 || true
	PATH="$(DOCKER_BIN_DIR):$$PATH" "$(DOCKER)" run --rm --platform "$(BUILDER_PLATFORM)" --user root --entrypoint bash \
		-v "$$(pwd)":/github/workspace \
		--mount type=volume,source="$(RELEASE_EMULATE_TARGET_VOLUME)",target=/cargo-target \
		-w /github/workspace \
		-e PARANOID_CLI_BUILD_COMMIT="$(COMMIT)" \
		-e PARANOID_CLI_BUILD_DATE="$(DATE)" \
		-e PARANOID_GUI_BUILD_COMMIT="$(COMMIT)" \
		-e PARANOID_GUI_BUILD_DATE="$(DATE)" \
		"$(BUILDER_IMAGE)" \
		-lc "chown -R builder:builder /cargo-target && su builder -s /bin/bash -c 'export CARGO_TARGET_DIR=/cargo-target CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0; bash scripts/build_release_artifact.sh \"$(RELEASE_VERSION)\" linux \"$(RELEASE_EMULATE_ARCH)\" \"\" tar.gz \"$(DIST_DIR)\" && bash scripts/smoke_test_release_artifact.sh \"$(RELEASE_VERSION)\" linux \"$(RELEASE_EMULATE_ARCH)\" \"$(DIST_DIR)/paranoid-passwd-$(RELEASE_VERSION)-linux-$(RELEASE_EMULATE_ARCH).tar.gz\" && bash scripts/build_release_artifact.sh \"$(RELEASE_VERSION)\" linux \"$(RELEASE_EMULATE_ARCH)\" \"\" deb \"$(DIST_DIR)\" && bash scripts/smoke_test_release_artifact.sh \"$(RELEASE_VERSION)\" linux \"$(RELEASE_EMULATE_ARCH)\" \"$(DIST_DIR)/paranoid-passwd_$(RELEASE_VERSION)_$(RELEASE_EMULATE_ARCH).deb\" && bash scripts/build_release_artifact.sh \"$(RELEASE_VERSION)\" linux \"$(RELEASE_EMULATE_ARCH)\" \"\" tar.gz \"$(DIST_DIR)\" paranoid-passwd-gui paranoid-gui && bash scripts/smoke_test_release_artifact.sh \"$(RELEASE_VERSION)\" linux \"$(RELEASE_EMULATE_ARCH)\" \"$(DIST_DIR)/paranoid-passwd-gui-$(RELEASE_VERSION)-linux-$(RELEASE_EMULATE_ARCH).tar.gz\" paranoid-passwd-gui && bash scripts/build_release_artifact.sh \"$(RELEASE_VERSION)\" linux \"$(RELEASE_EMULATE_ARCH)\" \"\" deb \"$(DIST_DIR)\" paranoid-passwd-gui paranoid-gui && bash scripts/smoke_test_release_artifact.sh \"$(RELEASE_VERSION)\" linux \"$(RELEASE_EMULATE_ARCH)\" \"$(DIST_DIR)/paranoid-passwd-gui_$(RELEASE_VERSION)_$(RELEASE_EMULATE_ARCH).deb\" paranoid-passwd-gui'"
	PATH="$(DOCKER_BIN_DIR):$$PATH" "$(DOCKER)" volume rm -f "$(RELEASE_EMULATE_TARGET_VOLUME)" >/dev/null 2>&1 || true

clean: ## Remove Rust and docs build artifacts
	rm -rf target docs/_build .tox dist
