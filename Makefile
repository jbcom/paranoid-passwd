# ═══════════════════════════════════════════════════════════════
# paranoid — Makefile
#
# This is a C project that compiles to WASM and deploys to a browser.
# Treat it like one: make, make test, make clean, make deploy.
# ═══════════════════════════════════════════════════════════════

# ── Configuration ──────────────────────────────────────────

PROJECT      := paranoid
VERSION      := 2.0.0

# Submodule paths
OPENSSL_SUB  := vendor/openssl-wasm
OPENSSL_INC  := $(OPENSSL_SUB)/precompiled/include
OPENSSL_LIB  := $(OPENSSL_SUB)/precompiled/lib/libcrypto.a

# Source
SRC_DIR      := src
INC_DIR      := include
SRC          := $(SRC_DIR)/paranoid.c
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
CFLAGS       := -Ofast -I$(INC_DIR) -I$(OPENSSL_INC) \
                -DPARANOID_VERSION_STRING=\"$(VERSION)\"
LDFLAGS      := -lwasi-emulated-getpid -rdynamic

# Hash tools (detect what's available)
SHA256       := $(shell command -v sha256sum 2>/dev/null || \
                        echo "shasum -a 256")
OPENSSL_BIN  := $(shell command -v openssl 2>/dev/null)

# WASM introspection
WASM_OBJDUMP := $(shell command -v wasm-objdump 2>/dev/null)

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

EXPORT_FLAGS := $(foreach fn,$(EXPORTS),--export=$(fn))

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
        submodule info help

## Default: build everything
all: site

## Show project info
info:
	@echo ""
	@printf "$(_B)$(PROJECT)$(_N) v$(VERSION)\n"
	@echo "────────────────────────────────────"
	@printf "  Compiler:   $(_D)$(CC) --target=$(TARGET)$(_N)\n"
	@printf "  OpenSSL:    $(_D)$(OPENSSL_SUB)$(_N)\n"
	@printf "  Source:     $(_D)$(SRC)$(_N)\n"
	@printf "  Header:     $(_D)$(HDR)$(_N)\n"
	@printf "  Web:        $(_D)$(WWW_DIR)/{index.html,style.css,app.js}$(_N)\n"
	@printf "  Output:     $(_D)$(SITE_DIR)/$(_N)\n"
	@echo ""

# ── Submodule ──────────────────────────────────────────────

## Ensure OpenSSL submodule is checked out
submodule: $(OPENSSL_LIB)

$(OPENSSL_LIB):
	@printf "$(_G)▸$(_N) Initializing OpenSSL submodule...\n"
	git submodule update --init --recursive --depth=1
	@test -f $@ || { printf "$(_R)✗$(_N) libcrypto.a not found\n"; exit 1; }
	@printf "$(_G)✓$(_N) OpenSSL ready: $@\n"

# ── Compile ────────────────────────────────────────────────

## Build the WASM binary
build: $(WASM)

$(BUILD_DIR):
	@mkdir -p $@

$(WASM): $(SRC) $(HDR) $(OPENSSL_LIB) | $(BUILD_DIR)
	@printf "$(_G)▸$(_N) Compiling $(SRC) → $@\n"
	$(CC) --target=$(TARGET) $(CFLAGS) \
	    $(SRC) $(OPENSSL_LIB) \
	    $(LDFLAGS) $(EXPORT_FLAGS) \
	    -o $@
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
	    -e 's|__BUILD_TIME__|$(shell date -u +%Y-%m-%dT%H:%M:%SZ)|g' \
	    $(HTML) > $(SITE_DIR)/index.html
	@cp $(WASM) $(SITE_DIR)/paranoid.wasm
	@# Build manifest
	@printf '{\n' > $(SITE_DIR)/BUILD_MANIFEST.json
	@printf '  "project": "$(PROJECT)",\n' >> $(SITE_DIR)/BUILD_MANIFEST.json
	@printf '  "version": "$(VERSION)",\n' >> $(SITE_DIR)/BUILD_MANIFEST.json
	@printf '  "build_time": "$(shell date -u +%Y-%m-%dT%H:%M:%SZ)",\n' >> $(SITE_DIR)/BUILD_MANIFEST.json
	@printf '  "zig_version": "$(shell zig version 2>/dev/null || echo unknown)",\n' >> $(SITE_DIR)/BUILD_MANIFEST.json
	@printf '  "openssl_commit": "$(shell git -C $(OPENSSL_SUB) rev-parse HEAD 2>/dev/null || echo unknown)",\n' >> $(SITE_DIR)/BUILD_MANIFEST.json
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
	@$(WASM_OBJDUMP) -x $(WASM) 2>/dev/null | \
	    grep "import" | \
	    sed 's/.*<\(.*\)\..*/\1/' | \
	    sort -u | \
	    while read ns; do \
	        if [ "$$ns" = "wasi_snapshot_preview1" ]; then \
	            printf "  $(_G)✓$(_N) $$ns (expected)\n"; \
	        else \
	            printf "  $(_R)✗$(_N) $$ns (UNEXPECTED — review required)\n"; \
	        fi; \
	    done
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

# ── Clean ──────────────────────────────────────────────────

## Remove all build artifacts
clean:
	@printf "$(_G)▸$(_N) Cleaning build artifacts\n"
	rm -rf $(BUILD_DIR)
	@printf "$(_G)✓$(_N) Clean\n"

# ── Help ───────────────────────────────────────────────────

## Show available targets
help:
	@echo ""
	@printf "$(_B)$(PROJECT)$(_N) v$(VERSION) — build targets\n"
	@echo "────────────────────────────────────"
	@echo ""
	@echo "  make              Build site (WASM + HTML/CSS/JS)"
	@echo "  make build        Compile WASM binary only"
	@echo "  make site         Assemble site with SRI hashes"
	@echo "  make verify       Verify WASM exports/imports"
	@echo "  make hash         Print WASM hashes"
	@echo "  make serve        Local dev server (port 8080)"
	@echo "  make clean        Remove build artifacts"
	@echo "  make info         Show project configuration"
	@echo "  make submodule    Initialize OpenSSL submodule"
	@echo ""
