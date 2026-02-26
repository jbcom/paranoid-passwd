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

### Container-Based Builds (Liquibase-Style Supply Chain Security)

The repository implements the supply chain security practices from [Liquibase's Docker Security Blog](https://www.liquibase.com/blog/docker-supply-chain-security):

**Build Philosophy — All Testing Inside Docker:**

The Dockerfile runs **all tests as a condition of successful build**. If ANY test fails, the Docker build fails — no artifacts are produced.

```
╔════════════════════════════════════════════════════════════════════════╗
║                    DOCKER MULTI-STAGE BUILD PIPELINE                   ║
╠════════════════════════════════════════════════════════════════════════╣
║                                                                        ║
║  STAGE 1: BASE                                                         ║
║    └── Alpine 3.21 + build tools (gcc, make, git, wabt)               ║
║                                                                        ║
║  STAGE 2: DEPS                                                         ║
║    ├── git clone openssl-wasm @ SHA-pinned commit                     ║
║    └── git clone munit @ SHA-pinned commit                            ║
║    (NO SUBMODULES NEEDED!)                                            ║
║                                                                        ║
║  STAGE 3: TEST-NATIVE                                                  ║
║    └── Run munit C tests → MUST PASS or build fails                   ║
║                                                                        ║
║  STAGE 4: BUILD-ZIG                                                    ║
║    └── Compile WASM with Zig                                          ║
║                                                                        ║
║  STAGE 5: VERIFY                                                       ║
║    ├── WASM export/import verification                                ║
║    ├── Hallucination detection                                        ║
║    ├── Binary size verification                                       ║
║    └── Site asset verification                                        ║
║                                                                        ║
║  STAGE 6: ARTIFACT                                                     ║
║    └── Collect verified artifacts                                     ║
║                                                                        ║
║  FINAL: SCRATCH IMAGE (zero attack surface)                           ║
║                                                                        ║
╚════════════════════════════════════════════════════════════════════════╝
```

**No Submodules Required:**

The Dockerfile clones dependencies directly at SHA-pinned commits:
- **openssl-wasm**: `fe926b5006593ad2825243f97e363823cd56599f`
- **munit**: `fbbdf1467eb0d04a6ee465def2e529e4c87f2118`

This makes container builds **fully self-contained** and reproducible without any vendor/ directory or .gitmodules file.

**Base Image Rationale — Alpine Linux:**

We use **Alpine Linux** as the base image for minimal attack surface:

| Metric | Alpine | Debian slim |
|--------|--------|-------------|
| Compressed size | ~3.5MB | ~29MB |
| Base libraries | musl + BusyBox | glibc |
| Attack surface | Minimal | Larger |
| Package manager | apk | apt |

Why Alpine over Debian?
- **~8x smaller** base image (3.5MB vs 29MB compressed)
- **Minimal footprint** with musl-libc and BusyBox
- **All required build dependencies available** via apk (make, git, curl, openssl, wabt)
- **Zig static binary** works on musl-libc without glibc compatibility shims

Note: The Liquibase container itself is Java-based for database migrations. We adopt Liquibase's **security practices** (SHA pinning, SBOM, Cosign signing, SLSA provenance) rather than their runtime image.

**Features:**
- **SHA256-pinned base image** — `alpine:3.21@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659`
- **SHA-pinned openssl-wasm** — Commit `fe926b5006593ad2825243f97e363823cd56599f`
- **SHA-pinned munit** — Commit `fbbdf1467eb0d04a6ee465def2e529e4c87f2118`
- **All tests run inside Docker** — Build fails if any test fails
- **SBOM generation** — Software Bill of Materials attached to every image (`--sbom=true`)
- **SLSA Level 3 provenance** — Non-falsifiable build attestation (`--provenance=mode=max`)
- **Cosign keyless signing** — Ephemeral certificates via GitHub OIDC, recorded in Sigstore's Rekor transparency log
- **Scratch final image** — Zero attack surface (no OS, no shell)
- **Zig toolchain hash verification** — Tarball hash verified before extraction

**Build (with full attestation):**

```bash
DOCKER_BUILDKIT=1 docker build \
  --sbom=true \
  --provenance=mode=max \
  -t paranoid-artifact .
```

**Verify signature (after push to registry):**

```bash
cosign verify ghcr.io/jbcom/paranoid-passwd:latest \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity-regexp="https://github.com/jbcom/paranoid-passwd/.*"
```

**View SBOM:**

```bash
docker buildx imagetools inspect ghcr.io/jbcom/paranoid-passwd:latest \
  --format '{{ json .SBOM }}'
```

**View SLSA Provenance:**

```bash
docker buildx imagetools inspect ghcr.io/jbcom/paranoid-passwd:latest \
  --format '{{ json .Provenance }}'
```

**Extract artifacts from scratch image:**

```bash
docker create --name paranoid-out paranoid-artifact
docker cp paranoid-out:/artifact ./artifact
docker rm paranoid-out
find ./artifact -maxdepth 2 -type f
```

**Chain-of-custody verification:**

1. Verify Cosign signature against GitHub OIDC issuer
2. Inspect SBOM for complete dependency inventory
3. Verify SLSA provenance matches expected source commit
4. Compare `artifact/site/BUILD_MANIFEST.json` against `make hash` output
5. Check Rekor transparency log for signature record

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

**OpenSSL WASM** (cloned directly in Dockerfile, no submodule):
```dockerfile
# In Dockerfile
ARG OPENSSL_WASM_COMMIT=fe926b5006593ad2825243f97e363823cd56599f
RUN git clone --filter=blob:none --no-checkout ${OPENSSL_WASM_REPO} openssl-wasm && \
    cd openssl-wasm && \
    git checkout ${OPENSSL_WASM_COMMIT}
```

**munit testing framework** (cloned directly in Dockerfile):
```dockerfile
# In Dockerfile
ARG MUNIT_COMMIT=fbbdf1467eb0d04a6ee465def2e529e4c87f2118
RUN git clone --filter=blob:none --no-checkout ${MUNIT_REPO} munit && \
    cd munit && \
    git checkout ${MUNIT_COMMIT}
```

**Zig compiler** (CI):
```yaml
- name: Setup Zig
  uses: mlugg/setup-zig@7d14f16220b57e3e4e02a93c4e5e8dbbdb2a2f7e  # SHA-pinned
  with:
    version: 0.14.0  # Exact version
```

**Note**: The vendor/ directory and .gitmodules are **only for local development** convenience. Docker builds are fully self-contained and clone dependencies directly.

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

## Testing

### Overview

The project uses a comprehensive testing strategy:

1. **Native C Unit Tests** (munit framework) — Run BEFORE WASM compilation
2. **Integration Tests** — Verify complete WASM module in browser environment
3. **Hallucination Detection** — Automated checks for LLM-introduced bugs
4. **Supply Chain Verification** — Dependency and build integrity checks

### µnit (munit) Testing Framework

We use [µnit](https://nemequ.github.io/munit/) for native C unit testing:

**Why munit?**
- **Single file** — Just `munit.c` and `munit.h` (trivial to integrate)
- **Portable** — Works on any C89+ compiler
- **Powerful CLI** — Reproducible tests with `--seed`, iterations, filtering
- **Rich assertions** — Type-specific assertions with value display on failure
- **Nested suites** — Organize tests hierarchically

**Test Coverage:**

| Suite | Coverage |
|-------|----------|
| `/sha256` | NIST FIPS 180-4 known-answer vectors |
| `/rejection` | Boundary verification: `(256/N)*N - 1` |
| `/generate` | Length, charset, uniqueness, error handling |
| `/chi_squared` | Uniform/biased distribution, df = N-1 |
| `/serial` | Correlation tests (constant, alternating) |
| `/collision` | Duplicate detection |
| `/struct` | WASM/JS struct offset verification |
| `/audit` | Full pipeline integration |
| `/stress` | High-volume distribution verification |

**Run Tests:**

```bash
# Run all native C tests
make test-native

# Run with munit options
./build/test_munit --help
./build/test_munit --seed 12345        # Reproducible PRNG seed
./build/test_munit /paranoid/sha256    # Run only SHA-256 tests
./build/test_munit --iterations 100    # Stress test (run each test 100x)
```

**Example Output:**

```
Running test suite with seed 0x1a2b3c4d...
/paranoid/sha256/empty                         [ OK    ]
/paranoid/sha256/abc                           [ OK    ]
/paranoid/rejection/boundary_94                [ OK    ]
/paranoid/stress/distribution                  [ OK    ]

30 of 30 (100%) tests successful, 0 (0%) test skipped.
```

### Test Before WASM Compilation

The testing strategy ensures correctness at the **native C level** before compiling to WASM:

```
                    TESTING STAGES
┌──────────────────────────────────────────────────────┐
│                                                      │
│  src/paranoid.c  ──► [make test-native] ──► PASS?   │
│       │                                     │        │
│       │                                     ▼        │
│       │                               [make build]  │
│       │                                     │        │
│       ▼                                     ▼        │
│  paranoid.wasm  ◄────────────────────────────       │
│       │                                              │
│       ▼                                              │
│  [make integration] ──► Browser/WASM tests          │
│                                                      │
└──────────────────────────────────────────────────────┘
```

This catches:
- Rejection sampling bugs (`max_valid = (256/N)*N - 1`)
- Statistical formula errors (df = N-1, p-value interpretation)
- Memory safety issues (before they become WASM traps)
- Entropy calculation errors

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

### Testing

```bash
make test         # Run ALL tests (native + integration + checks)
make test-native  # Run native C unit tests (munit)
make integration  # Run browser/WASM integration tests
make hallucination # LLM hallucination detection
make supply-chain # Supply chain verification
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
make test-native  # Job 1.5: Native C tests
make verify       # Job 2: Verify WASM structure
# Job 3: Deploy build/site/ to GitHub Pages
```

---

## Troubleshooting

### Local Development Setup (Optional)

For local development without Docker, you may optionally set up the vendor directory:

```bash
# Clone dependencies for local development
mkdir -p vendor
git clone https://github.com/jedisct1/openssl-wasm.git vendor/openssl-wasm
cd vendor/openssl-wasm && git checkout fe926b5006593ad2825243f97e363823cd56599f
cd ../..
git clone https://github.com/nemequ/munit.git vendor/munit
cd vendor/munit && git checkout fbbdf1467eb0d04a6ee465def2e529e4c87f2118
```

**Note**: For production builds, always use Docker — it clones dependencies automatically at SHA-pinned commits.

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

**Fix** (local development):
```bash
# Verify library exists
ls -lh vendor/openssl-wasm/precompiled/lib/libcrypto.a

# If missing, clone the dependency
mkdir -p vendor
git clone https://github.com/jedisct1/openssl-wasm.git vendor/openssl-wasm
cd vendor/openssl-wasm && git checkout fe926b5006593ad2825243f97e363823cd56599f
```

**Fix** (production): Use Docker — it handles all dependencies automatically.

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
