.PHONY: help build build-cli build-gui test lint verify-security verify-human-review verify-branch-protection verify-published-release docs-build docs-linkcheck docs-check ci ci-emulate package-release smoke-release release-validate release-emulate clean

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
RELEASE_VERSION ?= $(shell sed -n 's/^version = "\(.*\)"$$/\1/p' Cargo.toml | head -n 1)
DIST_DIR ?= dist/release
HOST_OS := $(shell uname -s | tr '[:upper:]' '[:lower:]')
HOST_ARCH := $(shell uname -m | sed -e 's/^x86_64$$/amd64/' -e 's/^aarch64$$/arm64/')
HOST_EXT := $(if $(filter windows,$(HOST_OS)),.exe,)
HOST_ARCHIVE := $(if $(filter windows,$(HOST_OS)),zip,tar.gz)
HOST_ARTIFACT := $(DIST_DIR)/paranoid-passwd-$(RELEASE_VERSION)-$(HOST_OS)-$(HOST_ARCH).$(HOST_ARCHIVE)
HOST_GUI_ARTIFACT := $(DIST_DIR)/paranoid-passwd-gui-$(RELEASE_VERSION)-$(HOST_OS)-$(HOST_ARCH).$(HOST_ARCHIVE)
HOST_GUI_DMG_ARTIFACT := $(DIST_DIR)/paranoid-passwd-gui-$(RELEASE_VERSION)-$(HOST_OS)-$(HOST_ARCH).dmg
HOST_DEB_ARTIFACT := $(DIST_DIR)/paranoid-passwd_$(RELEASE_VERSION)_$(HOST_ARCH).deb
HOST_GUI_DEB_ARTIFACT := $(DIST_DIR)/paranoid-passwd-gui_$(RELEASE_VERSION)_$(HOST_ARCH).deb

help: ## Show available targets
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

build: ## Build every Rust crate in debug mode
	cargo build --workspace --locked --frozen --offline

build-cli: ## Build the paranoid-passwd CLI in release mode
	PARANOID_CLI_BUILD_COMMIT="$(COMMIT)" PARANOID_CLI_BUILD_DATE="$(DATE)" cargo build -p paranoid-cli --release --locked --frozen --offline

build-gui: ## Build the GUI app in release mode
	PARANOID_GUI_BUILD_COMMIT="$(COMMIT)" PARANOID_GUI_BUILD_DATE="$(DATE)" cargo build -p paranoid-gui --release --locked --frozen --offline

test: ## Run the Rust test suites
	cargo test --workspace --locked --frozen --offline

lint: ## Run formatting and clippy gates
	cargo fmt --check
	cargo clippy --workspace --all-targets --locked --frozen --offline -- -D warnings

verify-security: ## Run repository security and supply-chain verification scripts
	bash scripts/hallucination_check.sh
	bash scripts/supply_chain_verify.sh
	bash scripts/verify_human_review_inventory.sh

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
	cargo test --workspace --locked --frozen --offline
	cargo build -p paranoid-cli --locked --frozen --offline
	bash tests/test_cli.sh target/debug/paranoid-passwd
	bash scripts/hallucination_check.sh
	bash scripts/supply_chain_verify.sh
	bash scripts/verify_human_review_inventory.sh
	python3 -m tox -e docs,docs-linkcheck

ci-emulate: ## Build the custom builder image and run the CI target from the repository root
	docker build -t paranoid-passwd-builder .github/actions/builder
	docker run --rm -v "$$(pwd)":/github/workspace -w /github/workspace paranoid-passwd-builder bash -lc "make ci"

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

release-emulate: ## Build and smoke-test the linux-amd64 CLI and GUI release paths through the custom builder image
	docker build -t paranoid-passwd-builder .github/actions/builder
	mkdir -p "$(DIST_DIR)"
	docker run --rm -v "$$(pwd)":/github/workspace -w /github/workspace \
		-e PARANOID_CLI_BUILD_COMMIT="$(COMMIT)" \
		-e PARANOID_CLI_BUILD_DATE="$(DATE)" \
		-e PARANOID_GUI_BUILD_COMMIT="$(COMMIT)" \
		-e PARANOID_GUI_BUILD_DATE="$(DATE)" \
		paranoid-passwd-builder \
		bash -lc "bash scripts/build_release_artifact.sh \"$(RELEASE_VERSION)\" linux amd64 \"\" tar.gz \"$(DIST_DIR)\" && bash scripts/smoke_test_release_artifact.sh \"$(RELEASE_VERSION)\" linux amd64 \"$(DIST_DIR)/paranoid-passwd-$(RELEASE_VERSION)-linux-amd64.tar.gz\" && bash scripts/build_release_artifact.sh \"$(RELEASE_VERSION)\" linux amd64 \"\" deb \"$(DIST_DIR)\" && bash scripts/smoke_test_release_artifact.sh \"$(RELEASE_VERSION)\" linux amd64 \"$(DIST_DIR)/paranoid-passwd_$(RELEASE_VERSION)_amd64.deb\" && bash scripts/build_release_artifact.sh \"$(RELEASE_VERSION)\" linux amd64 \"\" tar.gz \"$(DIST_DIR)\" paranoid-passwd-gui paranoid-gui && bash scripts/smoke_test_release_artifact.sh \"$(RELEASE_VERSION)\" linux amd64 \"$(DIST_DIR)/paranoid-passwd-gui-$(RELEASE_VERSION)-linux-amd64.tar.gz\" paranoid-passwd-gui && bash scripts/build_release_artifact.sh \"$(RELEASE_VERSION)\" linux amd64 \"\" deb \"$(DIST_DIR)\" paranoid-passwd-gui paranoid-gui && bash scripts/smoke_test_release_artifact.sh \"$(RELEASE_VERSION)\" linux amd64 \"$(DIST_DIR)/paranoid-passwd-gui_$(RELEASE_VERSION)_amd64.deb\" paranoid-passwd-gui"

clean: ## Remove Rust and docs build artifacts
	rm -rf target docs/_build .tox dist
