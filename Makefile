# ═══════════════════════════════════════════════════════════════
# paranoid — Makefile
#
# This is a C project that compiles to WASM and deploys to a browser.
#
# RECOMMENDED: Use Docker for builds (handles all dependencies):
#   docker build -t paranoid-artifact .
#   docker create --name temp paranoid-artifact
#   docker cp temp:/artifact ./artifact
#   docker rm temp
#
# PROVENANCE:
#   OpenSSL is compiled FROM SOURCE inside Docker using our patches.
#   No precompiled binaries from third parties.
#   See scripts/build_openssl_wasm.sh for the full build process.
#
# LOCAL BUILDS (CI/Docker only):
#   Local builds require vendor/openssl and vendor/acutest.
#   These are built/cloned automatically inside Docker.
#   For local development, use Docker or manually build OpenSSL.
# ═══════════════════════════════════════════════════════════════

# ── Configuration ──────────────────────────────────────────

PROJECT      := paranoid
VERSION      := 2.0.0

# OpenSSL for WASM — built from source (not precompiled!)
# In Docker: compiled by scripts/build_openssl_wasm.sh
# Locally: must be built manually or extracted from Docker
OPENSSL_DIR  := vendor/openssl
OPENSSL_INC  := $(OPENSSL_DIR)/include
OPENSSL_LIB  := $(OPENSSL_DIR)/lib/libcrypto.a

# Test framework
ACUTEST_DIR  := vendor/acutest

# Native OpenSSL for test compilation (system package, NOT the WASM vendor lib)
# The vendor libcrypto.a is compiled for wasm32 — it cannot be linked by native cc.
# In Docker: `apk add openssl-dev` provides native headers + libcrypto
# On macOS:  `brew install openssl` (may need PKG_CONFIG_PATH override)
NATIVE_OPENSSL_CFLAGS ?= $(shell pkg-config --cflags libcrypto 2>/dev/null)
NATIVE_OPENSSL_LIBS   ?= $(shell pkg-config --libs libcrypto 2>/dev/null || echo "-lcrypto")

# Source
SRC_DIR      := src
INC_DIR      := include
SRC          := $(SRC_DIR)/paranoid.c
WASM_ENTRY   := $(SRC_DIR)/wasm_entry.c
HDR          := $(INC_DIR)/paranoid.h

# Web assets (separate files for CodeQL/SAST scanning)
WWW_DIR      := www
HTML         := $(WWW_DIR)/index.html
CSS          := $(WWW_DIR)/style.css
JS           := $(WWW_DIR)/app.js

# Output
BUILD_DIR    := build
WASM         := $(BUILD_DIR)/paranoid.wasm
SITE_DIR     := $(BUILD_DIR)/site

# ── Toolchain ──────────────────────────────────────────────

CC           := zig cc
TARGET       := wasm32-wasi
CFLAGS       := -O2 -fdata-sections -ffunction-sections \
                -I$(INC_DIR) -I$(OPENSSL_INC) \
                -DPARANOID_VERSION_STRING=\"$(VERSION)\"
# -Wl,--no-entry: tell wasm-ld this is a reactor/library, not a command
# -lwasi-emulated-getpid: provide getpid shim needed by OpenSSL internals
# -s: strip debug symbols from WASM binary
# -Wl,--gc-sections: garbage-collect unreferenced sections
# Note: wasm_entry.c provides a stub main() for Zig's WASI libc
LDFLAGS      := -s -lwasi-emulated-getpid -Wl,--no-entry -Wl,--gc-sections

# Hash tools (detect what's available)
SHA256       := $(shell command -v sha256sum 2>/dev/null || \
                        echo "shasum -a 256")
OPENSSL_BIN  := $(shell command -v openssl 2>/dev/null)

# Reproducible timestamp: honour SOURCE_DATE_EPOCH if set, else current time
BUILD_TIME   := $(shell if [ -n "$$SOURCE_DATE_EPOCH" ]; then \
                    date -u -d "@$$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || \
                    date -u -r "$$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || \
                    date -u +%Y-%m-%dT%H:%M:%SZ; \
                else \
                    date -u +%Y-%m-%dT%H:%M:%SZ; \
                fi)

# WASM introspection
WASM_OBJDUMP := $(shell command -v wasm-objdump 2>/dev/null)

# Binaryen optimizer — fixes Zig WASM codegen issues and optimizes size
WASM_OPT     := $(shell command -v wasm-opt 2>/dev/null)

# ── Exported WASM functions ────────────────────────────────
# Every public API function from paranoid.h

EXPORTS := \
    paranoid_version \
    paranoid_generate \
    paranoid_run_audit \
    paranoid_get_result_ptr \
    paranoid_get_result_size \
    paranoid_offset_password_length \
    paranoid_offset_chi2_statistic \
    paranoid_offset_current_stage \
    paranoid_offset_all_pass \
    paranoid_sha256 \
    paranoid_sha256_hex \
    paranoid_chi_squared \
    paranoid_serial_correlation \
    paranoid_count_collisions \
    malloc \
    free

EXPORT_FLAGS := $(foreach fn,$(EXPORTS),-Wl,--export=$(fn))

# ── ANSI colors ────────────────────────────────────────────

_G := \033[0;32m
_R := \033[0;31m
_D := \033[0;90m
_B := \033[1m
_N := \033[0m

# ═══════════════════════════════════════════════════════════
# TARGETS
# ═══════════════════════════════════════════════════════════

.PHONY: all build site clean verify hash deploy check \
        check-deps info help test test-native integration hallucination supply-chain \
        docker-build docker-extract docker-e2e docker-all

## Default: build everything
all: site

## Show project info
info:
	@echo ""
	@printf "$(_B)$(PROJECT)$(_N) v$(VERSION)\n"
	@echo "────────────────────────────────────"
	@printf "  Compiler:   $(_D)$(CC) --target=$(TARGET)$(_N)\n"
	@printf "  OpenSSL:    $(_D)$(OPENSSL_DIR) (from source)$(_N)\n"
	@printf "  Source:     $(_D)$(SRC)$(_N)\n"
	@printf "  WASM stub:  $(_D)$(WASM_ENTRY)$(_N)\n"
	@printf "  Header:     $(_D)$(HDR)$(_N)\n"
	@printf "  Web:        $(_D)$(WWW_DIR)/{index.html,style.css,app.js}$(_N)\n"
	@printf "  Output:     $(_D)$(SITE_DIR)/$(_N)\n"
	@echo ""

# ── Dependencies ───────────────────────────────────────────
# OpenSSL is compiled FROM SOURCE inside Docker via build_openssl_wasm.sh.
# Acutest is cloned inside Docker at a SHA-pinned commit.
#
# SHA-pinned dependency versions (must match Dockerfile ARGs):
OPENSSL_TAG      := openssl-3.4.0
ACUTEST_SHA      := 31751b4089c93b46a9fd8a8183a695f772de66de

## Check if vendor dependencies exist
check-deps:
	@if [ ! -f $(OPENSSL_LIB) ]; then \
		printf "$(_R)✗$(_N) vendor/openssl not found\n"; \
		printf "  Use Docker build (recommended) or build OpenSSL from source:\n"; \
		printf "    git clone --depth=1 --branch $(OPENSSL_TAG) https://github.com/openssl/openssl.git /tmp/openssl-src\n"; \
		printf "    ./scripts/build_openssl_wasm.sh /tmp/openssl-src vendor/openssl patches\n"; \
		exit 1; \
	fi
	@if [ ! -f $(ACUTEST_DIR)/include/acutest.h ]; then \
		printf "$(_R)✗$(_N) vendor/acutest not found\n"; \
		printf "  Use Docker build (recommended) or manually clone at pinned SHA:\n"; \
		printf "    git clone https://github.com/mity/acutest.git vendor/acutest\n"; \
		printf "    cd vendor/acutest && git checkout $(ACUTEST_SHA)\n"; \
		exit 1; \
	fi
	@printf "$(_G)✓$(_N) Dependencies found\n"

# ── Compile ────────────────────────────────────────────────

## Build the WASM binary
build: $(WASM)

$(BUILD_DIR):
	@mkdir -p $@

WASM_STRIP   := $(shell command -v wasm-strip 2>/dev/null)

$(WASM): $(SRC) $(HDR) $(WASM_ENTRY) $(OPENSSL_LIB)
	@mkdir -p $(BUILD_DIR)
	@printf "$(_G)▸$(_N) Compiling $(SRC) + $(WASM_ENTRY) → $@\n"
	$(CC) --target=$(TARGET) $(CFLAGS) \
	    $(SRC) $(WASM_ENTRY) $(OPENSSL_LIB) \
	    $(LDFLAGS) $(EXPORT_FLAGS) \
	    -o $@
ifdef WASM_OPT
	@printf "$(_G)▸$(_N) Post-processing with wasm-opt (fixes Zig codegen + optimizes size)\n"
	$(WASM_OPT) -O2 --enable-bulk-memory -o $@ $@
endif
ifdef WASM_STRIP
	@printf "$(_G)▸$(_N) Stripping WASM binary\n"
	$(WASM_STRIP) $@
endif
	@printf "$(_G)✓$(_N) $@ ($$(du -h $@ | cut -f1))\n"

# ── Assemble site ──────────────────────────────────────────

## Build site: WASM + web assets with SRI injection
site: $(WASM) $(HTML) $(CSS) $(JS)
	@printf "$(_G)▸$(_N) Assembling site → $(SITE_DIR)/\n"
	@mkdir -p $(SITE_DIR)
	@cp $(CSS) $(SITE_DIR)/style.css
	@cp $(JS) $(SITE_DIR)/app.js
	@# Compute SRI hashes for WASM, CSS, JS
	$(eval WASM_SRI := sha384-$(shell $(OPENSSL_BIN) dgst -sha384 -binary $(WASM) | $(OPENSSL_BIN) base64 -A))
	$(eval WASM_SHA := $(shell $(SHA256) $(WASM) | cut -d' ' -f1))
	$(eval CSS_SRI  := sha384-$(shell $(OPENSSL_BIN) dgst -sha384 -binary $(CSS) | $(OPENSSL_BIN) base64 -A))
	$(eval JS_SRI   := sha384-$(shell $(OPENSSL_BIN) dgst -sha384 -binary $(JS) | $(OPENSSL_BIN) base64 -A))
	@# Inject hashes into HTML
	@sed \
	    -e 's|__WASM_SRI__|$(WASM_SRI)|g' \
	    -e 's|__WASM_SHA256__|$(WASM_SHA)|g' \
	    -e 's|__CSS_SRI__|$(CSS_SRI)|g' \
	    -e 's|__JS_SRI__|$(JS_SRI)|g' \
	    -e 's|__VERSION__|$(VERSION)|g' \
	    -e 's|__BUILD_TIME__|$(BUILD_TIME)|g' \
	    $(HTML) > $(SITE_DIR)/index.html
	@cp $(WASM) $(SITE_DIR)/paranoid.wasm
	@# Build manifest
	@printf '{\n' > $(SITE_DIR)/BUILD_MANIFEST.json
	@printf '  "project": "$(PROJECT)",\n' >> $(SITE_DIR)/BUILD_MANIFEST.json
	@printf '  "version": "$(VERSION)",\n' >> $(SITE_DIR)/BUILD_MANIFEST.json
	@printf '  "build_time": "$(BUILD_TIME)",\n' >> $(SITE_DIR)/BUILD_MANIFEST.json
	@printf '  "zig_version": "$(shell zig version 2>/dev/null || echo unknown)",\n' >> $(SITE_DIR)/BUILD_MANIFEST.json
	@printf '  "openssl_tag": "$(OPENSSL_TAG)",\n' >> $(SITE_DIR)/BUILD_MANIFEST.json
	@printf '  "openssl_provenance": "from-source",\n' >> $(SITE_DIR)/BUILD_MANIFEST.json
	@printf '  "source_sha256": "$(shell $(SHA256) $(SRC) | cut -d" " -f1)",\n' >> $(SITE_DIR)/BUILD_MANIFEST.json
	@printf '  "wasm_sha256": "$(WASM_SHA)",\n' >> $(SITE_DIR)/BUILD_MANIFEST.json
	@printf '  "wasm_sri": "$(WASM_SRI)",\n' >> $(SITE_DIR)/BUILD_MANIFEST.json
	@printf '  "css_sri": "$(CSS_SRI)",\n' >> $(SITE_DIR)/BUILD_MANIFEST.json
	@printf '  "js_sri": "$(JS_SRI)"\n' >> $(SITE_DIR)/BUILD_MANIFEST.json
	@printf '}\n' >> $(SITE_DIR)/BUILD_MANIFEST.json
	@printf "$(_G)✓$(_N) Site ready: $(SITE_DIR)/\n"
	@printf "    index.html  paranoid.wasm  style.css  app.js  BUILD_MANIFEST.json\n"

# ── Verify ─────────────────────────────────────────────────

## Verify WASM exports and imports
verify: $(WASM)
ifdef WASM_OBJDUMP
	@printf "\n$(_B)WASM Verification$(_N)\n"
	@printf "────────────────────────────────────\n"
	@printf "\n$(_G)▸$(_N) Required exports:\n"
	@$(foreach fn,$(EXPORTS), \
	    if $(WASM_OBJDUMP) -x $(WASM) 2>/dev/null | grep -q "$(fn)"; then \
	        printf "  $(_G)✓$(_N) $(fn)\n"; \
	    else \
	        printf "  $(_R)✗$(_N) $(fn) — MISSING\n"; \
	        exit 1; \
	    fi; \
	)
	@printf "\n$(_G)▸$(_N) Import namespaces:\n"
	@UNEXPECTED=0; \
	for ns in $$($(WASM_OBJDUMP) -x $(WASM) 2>/dev/null | \
	    grep ' <- ' | \
	    sed 's/.*<- \([^.]*\)\..*/\1/' | \
	    sort -u); do \
	    if [ "$$ns" = "wasi_snapshot_preview1" ]; then \
	        printf "  $(_G)✓$(_N) $$ns (expected)\n"; \
	    else \
	        printf "  $(_R)✗$(_N) $$ns (UNEXPECTED — review required)\n"; \
	        UNEXPECTED=1; \
	    fi; \
	done; \
	if [ "$$UNEXPECTED" -eq 1 ]; then \
	    printf "  $(_R)✗$(_N) Unexpected import namespaces detected\n"; \
	    exit 1; \
	fi
	@printf "\n$(_G)▸$(_N) Binary size: $$(du -h $(WASM) | cut -f1)\n"
else
	@printf "$(_R)✗$(_N) wasm-objdump not found (install wabt)\n"
endif

## Print SHA-256 and SRI hashes
hash: $(WASM)
	@printf "\n$(_B)Hashes$(_N)\n"
	@printf "────────────────────────────────────\n"
	@printf "  SHA-256: $$($(SHA256) $(WASM) | cut -d' ' -f1)\n"
ifdef OPENSSL_BIN
	@printf "  SRI:     sha384-$$($(OPENSSL_BIN) dgst -sha384 -binary $(WASM) | $(OPENSSL_BIN) base64 -A)\n"
endif
	@echo ""

# ── Deploy (local preview) ─────────────────────────────────

## Serve site locally for testing
serve: site
	@printf "$(_G)▸$(_N) Serving $(SITE_DIR) on http://localhost:8080\n"
	@printf "    (Ctrl+C to stop)\n"
	@cd $(SITE_DIR) && python3 -m http.server 8080

# ── Testing ────────────────────────────────────────────────

# Native test binary configuration
TEST_SRC        := tests/test_native.c
TEST_BIN        := $(BUILD_DIR)/test_native

# Native compiler (system CC for running tests locally)
# Uses system OpenSSL (openssl-dev), NOT the WASM vendor library
NATIVE_CC       := cc
NATIVE_CFLAGS   := -O2 -Wall -Wextra -I$(INC_DIR) $(NATIVE_OPENSSL_CFLAGS) -I$(ACUTEST_DIR)/include \
                   -DPARANOID_VERSION_STRING=\"$(VERSION)\"

## Run all tests (native C tests first, then integration)
test: test-native integration hallucination supply-chain
	@printf "$(_G)✓$(_N) All tests passed\n"

## Run native C unit tests (acutest framework)
test-native: $(TEST_BIN)
	@printf "$(_G)▸$(_N) Running native C unit tests (acutest)\n"
	@$(TEST_BIN)

## Build native test binary (acutest is header-only — no extra .c file needed)
## Links against system OpenSSL (openssl-dev), NOT the WASM vendor libcrypto.a
## Note: wasm_entry.c is NOT included here — it's only for WASM builds
$(TEST_BIN): $(TEST_SRC) $(SRC)
	@mkdir -p $(BUILD_DIR)
	@printf "$(_G)▸$(_N) Compiling native test binary (acutest)\n"
	$(NATIVE_CC) $(NATIVE_CFLAGS) \
	    $(TEST_SRC) $(SRC) \
	    $(NATIVE_OPENSSL_LIBS) \
	    -lm -lpthread -ldl \
	    -o $(TEST_BIN)
	@printf "$(_G)✓$(_N) Native test binary ready: $(TEST_BIN)\n"

## Run integration tests
integration: site
	@printf "$(_G)▸$(_N) Running integration tests\n"
	@./scripts/integration_test.sh

## Run hallucination detection
hallucination:
	@printf "$(_G)▸$(_N) Running hallucination detection\n"
	@./scripts/hallucination_check.sh

## Run supply chain verification
supply-chain:
	@printf "$(_G)▸$(_N) Running supply chain verification\n"
	@./scripts/supply_chain_verify.sh

# ── Docker Targets ─────────────────────────────────────────

.PHONY: docker-build docker-extract docker-e2e docker-all

## Build Docker image with all tests (RECOMMENDED)
docker-build:
	@printf "$(_G)▸$(_N) Building Docker image with SBOM and provenance\n"
	DOCKER_BUILDKIT=1 docker build \
		--sbom=true \
		--provenance=mode=max \
		-t paranoid-artifact .

## Extract artifacts from Docker image
docker-extract:
	@printf "$(_G)▸$(_N) Extracting verified artifacts from Docker image\n"
	@docker rm -f temp-paranoid 2>/dev/null || true
	@docker create --name temp-paranoid paranoid-artifact || { printf "$(_R)✗$(_N) Failed to create container. Run 'make docker-build' first.\n"; exit 1; }
	@mkdir -p artifact
	@docker cp temp-paranoid:/artifact/. ./artifact/
	@docker rm temp-paranoid
	@printf "$(_G)✓$(_N) Artifacts extracted to ./artifact/\n"
	@ls -la artifact/

## Run E2E tests with Docker Compose + Playwright
docker-e2e:
	@printf "$(_G)▸$(_N) Running E2E tests with Docker Compose + Playwright\n"
	@docker compose up --abort-on-container-exit paranoid-server playwright

## Full Docker workflow: build → extract → E2E test
docker-all: docker-build docker-extract docker-e2e
	@printf "$(_G)✓$(_N) Full Docker workflow complete\n"

# ── Clean ──────────────────────────────────────────────────

## Remove all build artifacts
clean:
	@printf "$(_G)▸$(_N) Cleaning build artifacts\n"
	rm -rf $(BUILD_DIR)
	rm -rf artifact/
	rm -rf test-results/
	rm -rf playwright-report/
	@printf "$(_G)✓$(_N) Clean\n"

# ── Help ───────────────────────────────────────────────────

## Show available targets
help:
	@echo ""
	@printf "$(_B)$(PROJECT)$(_N) v$(VERSION) — build targets\n"
	@echo "────────────────────────────────────"
	@echo ""
	@echo "  RECOMMENDED: Docker-based workflow"
	@echo "  make docker-build   Build image with tests + attestation"
	@echo "  make docker-extract Extract verified artifacts"
	@echo "  make docker-e2e     Run E2E tests with Playwright"
	@echo "  make docker-all     Full workflow: build → extract → E2E"
	@echo ""
	@echo "  Or manually:"
	@echo "    docker build -t paranoid-artifact ."
	@echo "    docker create --name temp paranoid-artifact"
	@echo "    docker cp temp:/artifact ./artifact"
	@echo "    docker rm temp"
	@echo ""
	@echo "  Local (requires vendor/):"
	@echo "  make              Build site (WASM + HTML/CSS/JS)"
	@echo "  make build        Compile WASM binary only"
	@echo "  make site         Assemble site with SRI hashes"
	@echo "  make verify       Verify WASM exports/imports"
	@echo "  make hash         Print WASM hashes"
	@echo "  make serve        Local dev server (port 8080)"
	@echo "  make clean        Remove build artifacts"
	@echo "  make info         Show project configuration"
	@echo "  make check-deps   Check if vendor dependencies exist"
	@echo ""
	@echo "  Testing:"
	@echo "  make test         Run all tests (native + integration)"
	@echo "  make test-native  Run native C unit tests (acutest)"
	@echo "  make integration  Run integration tests"
	@echo "  make hallucination  Run LLM hallucination detection"
	@echo "  make supply-chain Run supply chain verification"
	@echo ""
