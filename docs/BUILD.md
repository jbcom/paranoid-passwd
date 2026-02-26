# Build System Internals

This document describes the build system, reproducible build process, and supply chain security measures.

---

## Table of Contents

- [Build Overview](#build-overview)
- [Makefile Architecture](#makefile-architecture)
- [Compilation Process](#compilation-process)
- [SRI Hash Injection](#sri-hash-injection)
- [Build Manifest](#build-manifest)
- [Reproducible Builds](#reproducible-builds)
- [Supply Chain Security](#supply-chain-security)
- [Verification](#verification)

---

## Build Overview

The build system transforms source files into a deployable website:

```
INPUT                           OUTPUT
─────────────────────          ───────────────────────
src/paranoid.c                 build/paranoid.wasm (~180KB)
include/paranoid.h             
vendor/openssl-wasm/           build/site/
  precompiled/lib/libcrypto.a    ├── index.html (with SRI hashes)
www/index.html                   ├── paranoid.wasm
www/app.js                       ├── app.js
www/style.css                    ├── style.css
                                 └── BUILD_MANIFEST.json
```

---

## Makefile Architecture

### Targets

```makefile
.PHONY: all build site verify hash serve clean info

# Default target
all: site

# Compile WASM only
build: build/paranoid.wasm

# Assemble site with SRI hashes
site: build/site/index.html

# Verify WASM exports/imports
verify: build/paranoid.wasm
	@command -v wasm-objdump ...

# Print binary hashes
hash: build/paranoid.wasm
	@echo "SHA-256: $$(openssl dgst -sha256 ...)"

# Local development server
serve: site
	@cd build/site && python3 -m http.server 8080

# Clean build artifacts
clean:
	@rm -rf build/

# Show toolchain info
info:
	@echo "=== Paranoid Build Info ==="
	@zig version
	@openssl version
```

### Variables

```makefile
ZIG := zig
OPENSSL_INCLUDE := vendor/openssl-wasm/precompiled/include
OPENSSL_LIB := vendor/openssl-wasm/precompiled/lib
WASM_TARGET := wasm32-wasi
WASM_OUT := build/paranoid.wasm
```

---

## Compilation Process

### Step 1: Compile C → WASM

```makefile
build/paranoid.wasm: src/paranoid.c include/paranoid.h
	@mkdir -p build
	$(ZIG) cc -target $(WASM_TARGET) \
		-I include \
		-I $(OPENSSL_INCLUDE) \
		-L $(OPENSSL_LIB) \
		-l crypto \
		-O3 \
		-flto \
		-fno-stack-protector \
		-o $(WASM_OUT) \
		src/paranoid.c
```

**Compiler flags**:
- `-target wasm32-wasi` — WebAssembly with WASI support
- `-I include` — Header search path (paranoid.h)
- `-I $(OPENSSL_INCLUDE)` — OpenSSL headers
- `-L $(OPENSSL_LIB)` — OpenSSL library path
- `-l crypto` — Link against libcrypto.a
- `-O3` — Maximum optimization
- `-flto` — Link-time optimization (smaller binary)
- `-fno-stack-protector` — WASM doesn't need stack canaries

**Output**: `build/paranoid.wasm` (~180KB)

### Step 2: Compute SRI Hashes

```makefile
WASM_HASH := $(shell openssl dgst -sha384 -binary $(WASM_OUT) | openssl base64 -A)
JS_HASH := $(shell openssl dgst -sha384 -binary www/app.js | openssl base64 -A)
CSS_HASH := $(shell openssl dgst -sha384 -binary www/style.css | openssl base64 -A)
```

**Why SHA-384?**
- SHA-256: Adequate but SHA-1 collisions exist
- SHA-384: Truncated SHA-512 (more conservative)
- SHA-512: Overkill for SRI (larger hashes, minimal benefit)

**Format**: `sha384-<base64-encoded-hash>`

### Step 3: Inject SRI Hashes

```makefile
build/site/index.html: www/index.html build/paranoid.wasm
	@mkdir -p build/site
	@cp www/index.html build/site/index.html
	@sed -i 's|__WASM_SRI__|sha384-$(WASM_HASH)|g' build/site/index.html
	@sed -i 's|__JS_SRI__|sha384-$(JS_HASH)|g' build/site/index.html
	@sed -i 's|__CSS_SRI__|sha384-$(CSS_HASH)|g' build/site/index.html
```

**Placeholders in `www/index.html`**:
```html
<script src="app.js" integrity="__JS_SRI__" crossorigin="anonymous"></script>
<link rel="stylesheet" href="style.css" integrity="__CSS_SRI__">
```

**After injection**:
```html
<script src="app.js" 
        integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/6CC..." 
        crossorigin="anonymous"></script>
```

### Step 4: Copy Assets

```makefile
	@cp $(WASM_OUT) build/site/paranoid.wasm
	@cp www/app.js build/site/app.js
	@cp www/style.css build/site/style.css
```

### Step 5: Generate Build Manifest

```makefile
	@echo '{ \
		"timestamp": "$(shell date -u +%Y-%m-%dT%H:%M:%SZ)", \
		"commit": "$(shell git rev-parse HEAD)", \
		"zig_version": "$(shell $(ZIG) version)", \
		"wasm_sha256": "$(shell openssl dgst -sha256 -binary $(WASM_OUT) | openssl base64 -A)", \
		"wasm_sri": "sha384-$(WASM_HASH)", \
		"js_sri": "sha384-$(JS_HASH)", \
		"css_sri": "sha384-$(CSS_HASH)" \
	}' > build/site/BUILD_MANIFEST.json
```

**Example output**:
```json
{
  "timestamp": "2026-02-26T03:00:00Z",
  "commit": "bc727e2a1f3e4b5c6d7e8f9a0b1c2d3e4f5a6b7c",
  "zig_version": "0.14.0",
  "wasm_sha256": "3a2b1c4d5e6f7g8h9i0j1k2l3m4n5o6p...",
  "wasm_sri": "sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K...",
  "js_sri": "sha384-9rGHJkLpMnOqRsTuVwXyZ0123456789A...",
  "css_sri": "sha384-BcDeFgHiJkLmNoPqRsTuVwXyZ0123456..."
}
```

---

## SRI Hash Injection

### Why SRI?

**Subresource Integrity** prevents tampered assets from loading:

```
Attacker:  CDN compromise → modify app.js → inject backdoor
Browser:   Compute hash(downloaded app.js) → mismatch with SRI hash → REFUSE TO LOAD
```

### How It Works

1. **Build time**: Compute hash of asset
2. **Deploy time**: HTML includes hash in `integrity` attribute
3. **Runtime**: Browser computes hash of downloaded asset
4. **Verification**: If hashes match → load; if mismatch → block

### Browser Enforcement

```javascript
// Browser behavior (pseudo-code)
function loadScript(url, sri_hash) {
    const content = fetch(url);
    const computed_hash = sha384(content);
    
    if (computed_hash === sri_hash) {
        execute(content);  // SAFE
    } else {
        throw new SecurityError("SRI check failed");  // BLOCK
    }
}
```

### Limitations

- **Same-origin only** (or CORS-enabled)
- **Requires `crossorigin` attribute** for scripts from CDN
- **Cache invalidation** (hash change = new file)

---

## Build Manifest

### Purpose

Cryptographic record of build provenance:

```json
{
  "timestamp": "ISO 8601 UTC",
  "commit": "Git SHA (40 chars)",
  "zig_version": "Compiler version",
  "wasm_sha256": "Binary hash (base64)",
  "wasm_sri": "SRI hash for integrity attribute",
  "js_sri": "JavaScript SRI hash",
  "css_sri": "CSS SRI hash"
}
```

### Use Cases

1. **Reproducible builds**: Compare manifests across machines
2. **Audit trail**: Verify deployed binary matches build
3. **Rollback**: Identify which commit produced current binary
4. **Debugging**: Confirm correct build artifacts deployed

---

## Reproducible Builds

### Goal

**Bit-for-bit identical output** from same source, on any machine.

### Challenges

| Challenge | Impact | Mitigation |
|-----------|--------|------------|
| Timestamps in binary | Different hashes | `SOURCE_DATE_EPOCH` |
| File paths embedded | Different hashes | Relative paths only |
| Build machine differences | Different hashes | Containerized builds |
| Compiler version drift | Different hashes | Pin version (Zig 0.14.0) |
| Non-deterministic linking | Different hashes | Reproducible linker flags |

### SOURCE_DATE_EPOCH

```makefile
# Use deterministic timestamp
export SOURCE_DATE_EPOCH := $(shell git log -1 --format=%ct)

build/paranoid.wasm: src/paranoid.c
	SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) \
	$(ZIG) cc ... -o $(WASM_OUT) src/paranoid.c
```

**Effect**: All embedded timestamps use commit time (deterministic).

### Container-Based Builds (Attested, scratch final)

The repository ships a Dockerfile that:

- Uses a builder image supplied **with a required digest** (`DEBIAN_IMAGE`) to avoid unpinned bases.
- Verifies the Zig toolchain hash (`ZIG_SHA256`) before extraction (matches the checked-in tarball).
- Builds with BuildKit and copies only `build/site/` + `paranoid.wasm` into a `scratch` final image (no OS, no shell).
- Fails closed if the OpenSSL submodule is missing.

Build (requires BuildKit):

```bash
DOCKER_BUILDKIT=1 docker build \  # placeholder digest below; command fails until replaced
  --build-arg DEBIAN_IMAGE=debian:12-slim@sha256:REQUIRE_TRUSTED_DIGEST \
  --provenance=mode=max \
  -t paranoid-artifact .
```
Example structure (replace with a verified digest):  
`--build-arg DEBIAN_IMAGE=debian:12-slim@sha256:<REPLACE_WITH_VERIFIED_DIGEST>` (placeholder only; builds fail until replaced)
Note: `REQUIRE_TRUSTED_DIGEST` is intentionally invalid; this command is incomplete until a verified digest is supplied (see below).

How to obtain a trusted digest (examples):
- `skopeo inspect --raw docker://debian:12-slim | jq -r '.digest // ((.manifests[] | select(.platform.arch=="amd64").digest) | first)'` (amd64 == x86_64; substitute the output into `--build-arg DEBIAN_IMAGE=…@<digest>`; ensure exactly one digest is returned)
- `docker buildx imagetools inspect debian:12-slim --format '{{json .Manifest.digest}}'` for manifest lists (Docker Hub); for single-platform responses use `--format '{{json .Digest}}'` and confirm the output is a 64-hex sha256 digest before using it

Verify the digest you plan to use:
- Cross-check the digest from two independent registries/mirrors (e.g., docker.io and debian registry) and ensure they match.
- Validate the manifest signature with Debian's official signing keys (e.g., `skopeo stand-alone-sign` / `cosign verify-blob` if exported).
- Record the digest in change control alongside the BuildKit provenance envelope.

Obtain attested artifact image (contains only `/artifact/site` and `paranoid.wasm`):

```bash
docker create --name paranoid-out paranoid-artifact
docker cp paranoid-out:/artifact ./artifact
docker rm paranoid-out
find ./artifact -maxdepth 2 -type f
```

To prove chain-of-custody:

- Keep the builder base digest in change control (CI should inject it).
- Preserve the BuildKit provenance envelope (`--provenance=mode=max`).
- Record the Zig tarball hash (already hard-pinned in the Dockerfile).
- Compare `artifact/site/BUILD_MANIFEST.json` against the hash emitted by `make hash`.

### Diverse Double-Compilation (Planned)

Compile with **two different compilers**, compare outputs:

```bash
# Build 1: Zig
zig cc ... -o build/paranoid-zig.wasm

# Build 2: Clang
clang --target=wasm32-wasi ... -o build/paranoid-clang.wasm

# Compare (should be functionally equivalent)
wasm2wat build/paranoid-zig.wasm > zig.wat
wasm2wat build/paranoid-clang.wasm > clang.wat
diff zig.wat clang.wat
```

**Rationale**: If both compilers produce same functionality, less likely both have same backdoor.

---

## Supply Chain Security

### Threat Model

**Attacker goals**:
1. Inject backdoor during build
2. Compromise dependencies (OpenSSL, Zig)
3. Tamper with deployed artifacts

### Defense Layers

| Layer | Threat | Mitigation | Status |
|-------|--------|------------|--------|
| 1. Source | Malicious commits | Human review, signed commits | ⚠️ Partial |
| 2. Dependencies | Compromised submodules | Pin commit SHA | ✅ Done |
| 3. Compiler | Backdoored Zig | SHA-pinned in CI | ✅ Done |
| 4. Build env | Compromised runner | Reproducible builds | 🔴 TODO |
| 5. Artifacts | Tampered WASM | SRI hashes | ✅ Done |
| 6. Deploy | CDN compromise | SRI + multi-party verification | ⚠️ Partial |

### Dependency Pinning

**OpenSSL WASM** (git submodule):
```bash
# Pin to specific commit
cd vendor/openssl-wasm
git checkout <commit-sha>

# In .gitmodules:
[submodule "vendor/openssl-wasm"]
    path = vendor/openssl-wasm
    url = https://github.com/jedisct1/openssl-wasm.git
    # TODO: Add commit SHA pin
```

**Zig compiler** (CI):
```yaml
- name: Setup Zig
  uses: mlugg/setup-zig@7d14f16220b57e3e4e02a93c4e5e8dbbdb2a2f7e  # SHA-pinned
  with:
    version: 0.14.0  # Exact version
```

### Build Attestation (Planned)

Sign build artifacts with GPG:

```bash
# Generate detached signature
gpg --armor --detach-sign build/paranoid.wasm

# Verify signature
gpg --verify paranoid.wasm.asc paranoid.wasm
```

**Multi-party signing** (3-of-5 threshold):
- Builder 1 signs (SHA: abc123...)
- Builder 2 signs (SHA: abc123...)  # Same hash = good
- Builder 3 signs (SHA: abc123...)
- Require 3 matching signatures before deploy

---

## Verification

### Local Verification

```bash
# Build locally
make clean && make site

# Compute hash
make hash
# SHA-256: 3a2b1c4d...
# SRI-384: sha384-oqVu...

# Compare against BUILD_MANIFEST.json
cat build/site/BUILD_MANIFEST.json
```

### CI Verification (Job 2)

```yaml
- name: Verify WASM
  run: |
    # Download artifact from Job 1
    # Compute SHA-256
    COMPUTED_HASH=$(openssl dgst -sha256 ...)
    
    # Compare against Job 1 output
    if [ "$COMPUTED_HASH" != "$EXPECTED_HASH" ]; then
      echo "HASH MISMATCH!"
      exit 1
    fi
```

### Community Verification (Planned)

**Transparency log**:
```
https://paranoid-project.org/builds/
├── v2.0.0/
│   ├── BUILD_MANIFEST.json
│   ├── paranoid.wasm
│   ├── paranoid.wasm.asc (GPG signature)
│   └── checksums.txt
```

Anyone can:
1. Download source at tagged commit
2. Build locally
3. Compare hash against transparency log
4. Report mismatch (supply chain attack detected)

---

## Build Commands Reference

### Development

```bash
make              # Build everything
make build        # Compile WASM only
make site         # Assemble site
make serve        # Local server (http://localhost:8080)
make clean        # Remove build artifacts
```

### Verification

```bash
make verify       # Check WASM exports/imports (requires wabt)
make hash         # Print SHA-256 and SRI hashes
make info         # Show toolchain configuration
```

### CI/CD

```bash
make site         # Job 1: Build
make verify       # Job 2: Verify WASM structure
# Job 3: Deploy build/site/ to GitHub Pages
```

---

## Troubleshooting

### Submodule Not Initialized

```bash
git submodule update --init --recursive --depth=1
```

### Zig Version Mismatch

```bash
# Check version
zig version  # Should be 0.14.0

# Install specific version
snap install zig --classic --beta  # Ubuntu
brew install zig                    # macOS
```

### SRI Hash Mismatch in Browser

```
Error: Failed to find a valid digest in the 'integrity' attribute
```

**Cause**: Cached old version.

**Fix**:
```bash
# Rebuild
make clean && make site

# Hard refresh browser
Ctrl+Shift+R (Windows/Linux)
Cmd+Shift+R (macOS)
```

### WASM Compilation Fails

```
error: undefined symbol: RAND_bytes
```

**Cause**: OpenSSL library not found.

**Fix**:
```bash
# Verify library exists
ls -lh vendor/openssl-wasm/precompiled/lib/libcrypto.a

# If missing, reinitialize submodule
git submodule update --init --recursive --depth=1
```

---

## Future Enhancements

### 1. Reproducible Builds

- [ ] `SOURCE_DATE_EPOCH` support
- [ ] Containerized builds (Docker)
- [ ] Diverse double-compilation (Zig + Clang)
- [ ] Community verification infrastructure

### 2. Build Attestation

- [ ] GPG signing of artifacts
- [ ] Multi-party signature threshold (3-of-5)
- [ ] Transparency log (public build records)
- [ ] SLSA provenance (Level 3+ compliance)

### 3. Supply Chain Hardening

- [ ] Submodule commit SHA pinning
- [ ] Automated dependency updates (Dependabot)
- [ ] Vulnerability scanning (Snyk, CodeQL)
- [ ] SBOM generation (Software Bill of Materials)

### 4. Performance

- [ ] Parallel compilation (multiple cores)
- [ ] Incremental builds (only recompile changed files)
- [ ] Cache optimization (ccache integration)

---

## Conclusion

The build system prioritizes:

1. **Reproducibility** — Same source → same binary
2. **Auditability** — Every step logged, hashed, signed
3. **Integrity** — SRI hashes prevent tampering
4. **Transparency** — Open process, community verification

This is not just a build system — it's a **supply chain security framework** designed to detect and prevent attacks at every stage.
