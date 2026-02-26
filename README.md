<div align="center">

# paranoid-passwd

### The Password Generator That Trusts No One — Not Even Its Own Creator

**A self-auditing cryptographic password generator that treats the LLM that built it as an adversary.**

<!-- CI/CD Status -->
[![CI](https://img.shields.io/github/actions/workflow/status/jbcom/paranoid-passwd/ci.yml?branch=main&label=CI&logo=github&style=flat-square)](https://github.com/jbcom/paranoid-passwd/actions/workflows/ci.yml)
[![CD](https://img.shields.io/github/actions/workflow/status/jbcom/paranoid-passwd/cd.yml?branch=main&label=CD&logo=github&style=flat-square)](https://github.com/jbcom/paranoid-passwd/actions/workflows/cd.yml)
[![Release](https://img.shields.io/github/actions/workflow/status/jbcom/paranoid-passwd/release.yml?label=Release&logo=github&style=flat-square)](https://github.com/jbcom/paranoid-passwd/actions/workflows/release.yml)

<!-- Supply Chain Security -->
[![SLSA Level 3](https://img.shields.io/badge/SLSA-Level%203-green?style=flat-square&logo=slsa)](https://slsa.dev)
[![Sigstore](https://img.shields.io/badge/Sigstore-Cosign%20Signed-blueviolet?style=flat-square&logo=sigstore)](https://www.sigstore.dev/)
[![SBOM](https://img.shields.io/badge/SBOM-CycloneDX-blue?style=flat-square&logo=linuxfoundation)](https://cyclonedx.org/)

<!-- Code Quality -->
[![OpenSSF Scorecard](https://img.shields.io/ossf-scorecard/github.com/jbcom/paranoid-passwd?style=flat-square&label=OpenSSF%20Scorecard)](https://securityscorecards.dev/viewer/?uri=github.com/jbcom/paranoid-passwd)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/jbcom/paranoid-passwd/codeql.yml?label=CodeQL&logo=github&style=flat-square)](https://github.com/jbcom/paranoid-passwd/security/code-scanning)

<!-- Project Info -->
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)
[![GitHub release](https://img.shields.io/github/v/release/jbcom/paranoid-passwd?style=flat-square&logo=github)](https://github.com/jbcom/paranoid-passwd/releases)
[![GitHub stars](https://img.shields.io/github/stars/jbcom/paranoid-passwd?style=flat-square&logo=github)](https://github.com/jbcom/paranoid-passwd/stargazers)

<!-- Tech Stack -->
[![C](https://img.shields.io/badge/C-00599C?style=flat-square&logo=c&logoColor=white)](src/paranoid.c)
[![WebAssembly](https://img.shields.io/badge/WebAssembly-654FF0?style=flat-square&logo=webassembly&logoColor=white)](https://webassembly.org/)
[![Zig](https://img.shields.io/badge/Zig-F7A41D?style=flat-square&logo=zig&logoColor=white)](https://ziglang.org/)
[![OpenSSL](https://img.shields.io/badge/OpenSSL-721412?style=flat-square&logo=openssl&logoColor=white)](https://www.openssl.org/)
[![Wolfi](https://img.shields.io/badge/Wolfi-4A4A55?style=flat-square&logo=linux&logoColor=white)](https://wolfi.dev/)

[**Live Demo**](https://paranoid-passwd.com) · [**Documentation**](#-documentation) · [**Security**](SECURITY.md) · [**Report Bug**](https://github.com/jbcom/paranoid-passwd/issues)

</div>

---

## What's New in v3

> **Zero-Trust Password Generation with Wolfi Supply Chain Security**

v3 is a complete rearchitecture: Docker multi-stage builds are replaced by [melange](https://github.com/chainguard-dev/melange) + [apko](https://github.com/chainguard-dev/apko) on [Wolfi](https://wolfi.dev/), the 1.5MB OpenSSL WASM dependency is eliminated in favor of a compact FIPS 180-4 SHA-256 implementation + WASI `random_get`, and the build system moves from Makefile to CMake with Zig cross-compilation.

| Feature | Description |
|---------|-------------|
| **Wolfi + melange/apko** | Declarative, reproducible package builds and OCI images — no Dockerfile, no shell-in-shell |
| **<100KB WASM** | Compact FIPS 180-4 SHA-256 + WASI `random_get` replaces the 1.5MB OpenSSL WASM link |
| **Platform abstraction** | `paranoid_platform.h` separates native (OpenSSL) and WASM (compact SHA-256 + WASI) backends |
| **CMake build system** | Native tests via CTest, WASM via Zig cross-compilation toolchain (`cmake/wasm32-wasi.cmake`) |
| **SBOM + SLSA L3** | Software Bill of Materials + non-falsifiable build provenance on every release |
| **Cosign signing** | Keyless signatures via GitHub OIDC, recorded in Sigstore's Rekor transparency log |
| **Playwright E2E** | Browser tests verify the full HTML/CSS/JS/WASM path |
| **acutest C tests** | Native unit tests with NIST FIPS 180-4 known-answer vectors run before WASM compilation |
| **release-please** | Automated, attested releases with signed artifacts |
| **Double compilation** | Ken Thompson defense — Zig and Clang must produce matching WASM binaries |

**Every artifact is:**
- Built in a Wolfi environment via melange (declarative, auditable recipe)
- Tested at the C level (CTest) AND in the browser (Playwright)
- Attested with SBOM + SLSA provenance
- Signed with Cosign (keyless)
- Deployed only from verified releases

```bash
# Verify any release
cosign verify ghcr.io/jbcom/paranoid-passwd:latest \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity-regexp="https://github.com/jbcom/paranoid-passwd/.*"
```

---

## What is paranoid-passwd?

`paranoid-passwd` is a C program compiled to WebAssembly that generates cryptographic passwords inside a WASM sandbox. It runs a comprehensive 7-layer statistical audit entirely in C, using a platform abstraction layer: OpenSSL RAND_bytes for native builds, WASI `random_get` (backed by Web Crypto `getRandomValues`) for WASM builds. The browser never touches the random bytes — JavaScript only reads the results from WASM linear memory.

**Key Features:**
- **CSPRNG delegation** — WASI `random_get` in browser (backed by OS CSPRNG), OpenSSL RAND_bytes native
- **Rejection sampling** — Uniform distribution with no modulo bias
- **7-layer statistical audit** — Chi-squared, serial correlation, collision detection, entropy proofs, birthday paradox, pattern checks, NIST conformance
- **WASM sandbox isolation** — JavaScript cannot modify random bytes
- **Fail-closed design** — No JavaScript fallback (intentional)
- **<100KB WASM binary** — No OpenSSL in WASM; compact FIPS 180-4 SHA-256 implementation
- **Full transparency** — All code auditable, complete threat model disclosed

---

## Live Demo

**[Try it now](https://paranoid-passwd.com)** — Deployed from signed releases to GitHub Pages

Generate a 32-character password using 94 printable ASCII characters with **209.75 bits of entropy**. The tool will:
1. Generate the password using the platform CSPRNG
2. Run 7 statistical tests to verify randomness
3. Display detailed audit results with visual indicators
4. Show brute-force resistance calculations

---

## Why v3?

v1 was a monolithic HTML file with 350 lines of JavaScript doing crypto math. v2 moved everything to C + OpenSSL compiled to WASM via Zig. v3 eliminates the OpenSSL WASM dependency entirely and replaces Docker with Wolfi-based tooling.

| Problem | v2 Approach | v3 Solution |
|---------|-------------|-------------|
| **1.5MB WASM binary** | Full OpenSSL `libcrypto.a` compiled to `wasm32-wasi` | Compact FIPS 180-4 SHA-256 (~300 lines of C) + WASI `random_get` produces <100KB |
| **Docker trust model** | Multi-stage Dockerfile with shell-in-shell builds | melange (declarative Wolfi package) + apko (OCI image from packages) — no shell, fully auditable |
| **Makefile complexity** | Hand-maintained Makefile with many targets | CMake with native and WASM toolchain files |
| **OpenSSL WASM patching** | Custom `scripts/build_openssl_wasm.sh` | Eliminated — WASM needs only `sha256_compact.c` and WASI syscalls |
| **Alpine base image** | Alpine 3.21 (musl libc, limited SBOM tooling) | Wolfi (glibc, built-in SBOM generation, Chainguard supply chain) |

v3 treats this as what it is: **a C project that happens to render in a browser**, with purpose-built supply chain security from [Chainguard](https://www.chainguard.dev/).

---

## Quick Start

### Option 1: Use the Live Demo (Recommended)

Visit **[paranoid-passwd.com](https://paranoid-passwd.com)** — no installation needed.

### Option 2: Local Build with CMake

```bash
# Clone repository
git clone https://github.com/jbcom/paranoid-passwd.git
cd paranoid-passwd

# --- Native build (tests) ---
# Prerequisites: CMake >= 3.20, OpenSSL dev libraries
cmake -B build/native -DCMAKE_BUILD_TYPE=Debug
cmake --build build/native
ctest --test-dir build/native --output-on-failure

# --- WASM build ---
# Prerequisites: Zig >= 0.13.0, wabt (optional, for wasm-validate)
cmake -B build/wasm \
    -DCMAKE_TOOLCHAIN_FILE=cmake/wasm32-wasi.cmake \
    -DCMAKE_BUILD_TYPE=Release
cmake --build build/wasm

# --- Serve locally ---
mkdir -p build/site
cp www/index.html www/style.css www/app.js build/site/
cp build/wasm/paranoid.wasm build/site/
cp build/wasm/BUILD_MANIFEST.json build/site/
python3 -m http.server 8080 --directory build/site
# Open http://localhost:8080
```

### Option 3: melange/apko (Production Build)

```bash
# Prerequisites: melange v0.43.3, apko v1.1.11

# Build Wolfi package
melange keygen
melange build melange.yaml \
  --signing-key melange.rsa \
  --arch x86_64 \
  --out-dir packages/

# Build OCI image
apko build apko.yaml \
  paranoid-passwd:latest \
  paranoid-passwd.tar \
  --keyring-append melange.rsa.pub \
  --repository-append packages/

# Extract artifacts
docker load < paranoid-passwd.tar
docker create --name tmp paranoid-passwd:latest
docker cp tmp:/usr/share/paranoid-passwd/site ./site
docker rm tmp

# Serve
cd site && python3 -m http.server 8080
```

---

## Architecture

```
paranoid-passwd/
├── src/
│   ├── paranoid.c            # Core crypto logic (~600 lines)
│   ├── platform_native.c     # Native: OpenSSL RAND_bytes + EVP SHA-256
│   ├── platform_wasm.c       # WASM: WASI random_get
│   └── sha256_compact.c      # FIPS 180-4 SHA-256 (WASM only, no OpenSSL)
├── include/
│   ├── paranoid.h            # Public API + struct definitions
│   ├── paranoid_platform.h   # Platform abstraction interface
│   └── paranoid_frama.h      # Frama-C annotations
├── www/
│   ├── index.html            # Structure (CSS-only wizard state machine)
│   ├── style.css             # Dark theme (navy + emerald)
│   └── app.js                # WASM bridge (display-only)
├── tests/
│   ├── test_native.c         # CTest native unit tests
│   ├── test_paranoid.c       # Core API tests
│   ├── test_sha256.c         # NIST CAVP vectors
│   ├── test_statistics.c     # Statistical test KATs
│   └── e2e/                  # Playwright browser tests
├── CMakeLists.txt            # Build system (native + WASM)
├── cmake/wasm32-wasi.cmake   # Zig cross-compilation toolchain
├── melange.yaml              # Wolfi package recipe
├── apko.yaml                 # OCI image assembly
├── scripts/
│   ├── double_compile.sh     # Ken Thompson defense (Zig + Clang)
│   ├── hallucination_check.sh
│   ├── supply_chain_verify.sh
│   ├── multiparty_verify.sh
│   └── integration_test.sh
└── .github/workflows/
    ├── ci.yml                # PR verification
    ├── cd.yml                # Build + sign + release-please
    ├── release.yml           # Pages deploy from releases
    ├── codeql.yml            # Static analysis
    └── scorecard.yml         # OpenSSF Scorecard
```

### The Trust Boundary

There is exactly **ONE** trust boundary in the entire system — 3 lines of JavaScript:

```javascript
// WASI shim — the ONLY security-critical JavaScript
random_get(ptr, len) {
  crypto.getRandomValues(new Uint8Array(mem.buffer, ptr, len));
  return 0;
}
```

Everything above this runs in WASM linear memory. Everything below is the OS kernel.

### Entropy Chain

```
paranoid.c: paranoid_platform_random(buf, n)
    |
Platform abstraction (paranoid_platform.h):
  Native: OpenSSL RAND_bytes -> OS CSPRNG
  WASM:   WASI random_get(ptr, len)
    |
Browser polyfill: crypto.getRandomValues(buf)    <- 3 lines of JS
    |
OS CSPRNG: /dev/urandom / CryptGenRandom / SecRandomCopyBytes
    |
Hardware: RDRAND / RDSEED / interrupt timing
```

---

## Supply Chain Security

This project implements supply chain security using [Chainguard](https://www.chainguard.dev/)'s toolchain: melange for reproducible package builds and apko for minimal OCI images, both on [Wolfi](https://wolfi.dev/).

| Layer | Implementation | Status |
|-------|---------------|--------|
| **Base OS** | Wolfi (glibc, Chainguard-maintained, built-in SBOM) | Done |
| **Package Build** | melange v0.43.3 (declarative YAML recipe, signing key) | Done |
| **Image Assembly** | apko v1.1.11 (OCI image from packages, automatic SBOM) | Done |
| **Cross-Compilation** | Zig 0.13.0 via `cmake/wasm32-wasi.cmake` toolchain | Done |
| **Testing** | acutest C tests (CTest) + Playwright E2E | Done |
| **SBOM** | Software Bill of Materials (apko automatic generation) | Done |
| **Provenance** | SLSA Level 3 (`actions/attest-build-provenance`) | Done |
| **Signing** | Cosign keyless via GitHub OIDC | Done |
| **Actions** | All SHA-pinned (no tags) | Done |
| **Reproducibility** | Diverse double-compilation (Zig + Clang) | Done |
| **Releases** | release-please with attested artifacts | Done |

### CI/CD Pipeline

```
+------------------------------------------------------------------------+
|                       PULL REQUEST (ci.yml)                             |
+------------------------------------------------------------------------+
|  Native CTest      WASM Build+Validate     CodeQL        SonarCloud   |
|      |                    |                   |               |        |
|   acutest C         Zig cross-compile     C + JS scan    Quality gate  |
|   NIST vectors      wasm-validate                                      |
|                           |                                            |
|                     Playwright E2E                                      |
|                           |                                            |
|  ShellCheck        Hallucination Check     Supply Chain Verify          |
|                                                                        |
|  ALL CHECKS MUST PASS TO MERGE                                         |
+------------------------------------------------------------------------+
                                |
                                v
+------------------------------------------------------------------------+
|                       PUSH TO MAIN (cd.yml)                             |
+------------------------------------------------------------------------+
|  melange build -> apko image -> Cosign sign -> release-please           |
|      |                |              |               |                  |
|   Wolfi pkg       OCI image      Keyless         Creates PR            |
|   signed APK      with SBOM      Rekor log       for release           |
|                                                                        |
|  Double Compilation (Zig + Clang must match)                            |
+------------------------------------------------------------------------+
                                |
                                v
+------------------------------------------------------------------------+
|                       RELEASE (release.yml)                             |
+------------------------------------------------------------------------+
|  Build from tag -> Attest -> Sign -> Upload Assets -> Deploy to Pages   |
|      |               |        |           |               |             |
|   melange/apko    SLSA     Cosign    WASM + ZIP      GitHub Pages       |
|   from tag       provenance         checksums        paranoid-passwd.com|
+------------------------------------------------------------------------+
```

### Verification Commands

```bash
# Verify Cosign signature
cosign verify ghcr.io/jbcom/paranoid-passwd:latest \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity-regexp="https://github.com/jbcom/paranoid-passwd/.*"

# Run double compilation check locally
./scripts/double_compile.sh

# Run supply chain verification
./scripts/supply_chain_verify.sh
```

---

## Threat Model

`paranoid-passwd` treats the LLM that built it as an adversary. Six primary threats:

| ID | Threat | Status |
|----|--------|--------|
| **T1** | Training data leakage (passwords biased toward breach dumps) | Mitigated via CSPRNG delegation |
| **T2** | Token distribution bias (softmax non-uniformity) | Mitigated via rejection sampling |
| **T3** | Deterministic reproduction (same prompt -> same password) | Mitigated via hardware entropy |
| **T4** | Prompt injection steering | Residual (code is LLM-authored) |
| **T5** | Hallucinated security claims | **CRITICAL** — verify the math yourself |
| **T6** | Screen/conversation exposure | Advisory (clear clipboard) |

**T5 is the most dangerous** because it makes all other threats invisible. If the chi-squared implementation has a bug, the audit will still "pass."

Read the full threat model: [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)

---

## Security

### Entropy Specifications

| Metric | Value |
|--------|-------|
| **Password length** | 32 characters |
| **Character set** | 94 printable ASCII |
| **Entropy** | 209.75 bits |
| **Search space** | 94^32 ~ 1.38 x 10^63 |
| **Brute-force resistance** | 2.19 x 10^43 years @ 10^12 hash/s |
| **Birthday paradox** | ~4.37 x 10^31 passwords for 50% collision |

> **Note**: These calculations assume the default 32-char, 94-symbol charset. Verify independently: entropy = log2(94) x 32 ≈ 209.75 bits. See [Honest Limitations](#honest-limitations) — this code was written by an LLM.

### Statistical Audit (7 Layers)

| Layer | Test | Purpose |
|-------|------|---------|
| 1 | **Chi-Squared** | Verifies character frequency matches expected uniform distribution |
| 2 | **Serial Correlation** | Checks for positional dependencies (lag-1 autocorrelation) |
| 3 | **Collision Detection** | Generates 500-password batch, verifies uniqueness via SHA-256 |
| 4 | **Entropy Proofs** | Calculates log2(N) x L, validates against NIST standards |
| 5 | **Birthday Paradox** | Computes collision probability for given batch size |
| 6 | **Pattern Checks** | Detects runs, cycles, and trivial sequences |
| 7 | **NIST Conformance** | Validates against SP 800-63B entropy requirements |

### Reporting Security Issues

See [SECURITY.md](SECURITY.md) for our security policy and disclosure process.

---

## Honest Limitations

> **We believe in radical transparency about what this tool can and cannot guarantee.**

1. **This code was written by an LLM.** The CSPRNG primitives (WASI `random_get`, OpenSSL `RAND_bytes`) are sound, but the glue code (rejection sampling, chi-squared approximations, struct offsets) could contain subtle errors.

2. **Statistical tests are necessary but not sufficient.** Passing chi-squared proves consistency with randomness, not randomness itself.

3. **Struct offset assumptions.** The JavaScript reader relies on hardcoded byte offsets. Runtime verification catches compiler mismatches, but if verification itself is wrong, JS reads garbage.

4. **The WASI shim is 3 lines of JS that are not WASM-isolated.** A sufficiently motivated attacker controlling the browser could replace `crypto.getRandomValues`.

5. **This threat model is not peer-reviewed.** The 6-threat taxonomy is LLM-derived, not from published research.

Read all limitations: [AGENTS.md](AGENTS.md#honest-limitations)

---

## Documentation

| Document | Purpose |
|----------|---------|
| [AGENTS.md](AGENTS.md) | Complete project documentation, LLM clean room protocols, verification checklists |
| [SECURITY.md](SECURITY.md) | Security policy, disclosure process, LLM threat model |
| [DEVELOPMENT.md](DEVELOPMENT.md) | Development setup, testing, contributing guidelines |
| [CHANGELOG.md](CHANGELOG.md) | Version history and release notes |
| [docs/BUILD.md](docs/BUILD.md) | Build system, CMake pipeline, acutest testing |
| [docs/SUPPLY-CHAIN.md](docs/SUPPLY-CHAIN.md) | SLSA Level 3 attestation, Cosign, SBOM, melange/apko |
| [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) | Comprehensive threat analysis (18 threats) |
| [docs/AUDIT.md](docs/AUDIT.md) | Statistical audit methodology (7 layers) |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System architecture diagrams |
| [docs/DESIGN.md](docs/DESIGN.md) | Design decisions and rationale |

---

## Contributing

We welcome:

- **Cryptographer review** of `src/paranoid.c` (especially rejection sampling and chi-squared)
- **Struct layout verification** (compare offsets against `wasm-objdump` output)
- **Additional statistical tests** (NIST SP 800-22, Dieharder)
- **New LLM threat vectors** as the field evolves
- **Accessibility improvements** to the web frontend

See [DEVELOPMENT.md](DEVELOPMENT.md) for development setup and guidelines.

### Security Policy

Contributions that weaken the security posture will be rejected:
- Removing fail-closed behavior
- Replacing CSPRNG with PRNG
- Removing/weakening statistical tests
- Suppressing threat model warnings
- Unpinning GitHub Actions from commit SHAs

---

## License

MIT License — see [LICENSE](LICENSE) for details.

**However**, read the [Honest Limitations](#honest-limitations) section before production use. This tool demonstrates a verifiable generation pipeline and formalizes the LLM threat model, but should be reviewed by a human cryptographer before relying on it for production secrets.

---

## FAQ

<details>
<summary><strong>Q: Why not just use a password manager?</strong></summary>

A: You should! This tool demonstrates what a verifiable generation pipeline looks like and provides an auditable reference implementation. It's designed to be educational and to formalize the LLM threat model.
</details>

<details>
<summary><strong>Q: Can I use this in production?</strong></summary>

A: The generation algorithm (platform-abstracted CSPRNG + rejection sampling) is production-grade. The implementation should be reviewed by a human cryptographer first. The supply chain security (SBOM, SLSA, Cosign) provides enterprise-grade verification.
</details>

<details>
<summary><strong>Q: Why C instead of Rust?</strong></summary>

A: Originally for OpenSSL — we compiled official OpenSSL source to `wasm32-wasi`. In v3, the WASM build no longer depends on OpenSSL: a compact FIPS 180-4 SHA-256 implementation (`src/sha256_compact.c`, ~300 lines) replaces `libcrypto.a`, and WASI `random_get` replaces `RAND_bytes`. C remains the language for Zig cross-compilation compatibility and Frama-C formal verification. The platform abstraction layer (`include/paranoid_platform.h`) cleanly separates native and WASM backends. A Rust port using `ring` or `rustls` would be viable but would require a different crypto library.
</details>

<details>
<summary><strong>Q: Why no JavaScript fallback?</strong></summary>

A: The fail-closed design is intentional. JavaScript fallbacks violate the threat model by exposing crypto operations to prototype pollution, GC memory retention, and browser extension attacks.
</details>

<details>
<summary><strong>Q: How do I verify the build?</strong></summary>

A: Multiple options:
```bash
# Verify Cosign signature
cosign verify ghcr.io/jbcom/paranoid-passwd:latest \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity-regexp="https://github.com/jbcom/paranoid-passwd/.*"

# Run double compilation check (Zig + Clang must match)
./scripts/double_compile.sh

# Run supply chain verification
./scripts/supply_chain_verify.sh
```
</details>

<details>
<summary><strong>Q: Why melange/apko instead of Docker?</strong></summary>

A: Supply chain security with better guarantees. melange builds are:
- **Declarative** — YAML recipe, no shell-in-shell scripting
- **Reproducible** — same inputs produce identical packages
- **Signed** — built packages are cryptographically signed
- **Auditable** — every build step is explicit and visible in `melange.yaml`

apko produces minimal OCI images from those packages with automatic SBOM generation. The entire build chain (Wolfi base OS, melange package, apko image) is maintained by [Chainguard](https://www.chainguard.dev/) with a focus on supply chain security. Docker multi-stage builds mix build logic with shell scripting in ways that are difficult to audit and reproduce.
</details>

<details>
<summary><strong>Q: What happened to OpenSSL in WASM?</strong></summary>

A: Eliminated in v3. Compiling OpenSSL to `wasm32-wasi` produced a 1.5MB binary and required custom patches (`scripts/build_openssl_wasm.sh`). The WASM build only needs two things: random bytes (WASI `random_get`, 3 lines) and SHA-256 (compact FIPS 180-4 implementation, ~300 lines of C). Native builds still use OpenSSL via the platform abstraction layer (`include/paranoid_platform.h`).
</details>

---

## Acknowledgments

- **[Zig](https://ziglang.org/)** — Cross-compiles C to `wasm32-wasi` via `cmake/wasm32-wasi.cmake` toolchain
- **[Wolfi](https://wolfi.dev/)** — Undistro base OS with built-in SBOM and supply chain focus
- **[melange](https://github.com/chainguard-dev/melange)** — Declarative Wolfi package builder
- **[apko](https://github.com/chainguard-dev/apko)** — Minimal OCI image assembler with automatic SBOM
- **[OpenSSL](https://github.com/openssl/openssl)** — RAND_bytes + EVP SHA-256 for native builds
- **[acutest](https://github.com/mity/acutest)** — Header-only C unit test framework
- **NIST SP 800-90A** — DRBG specification
- **NIST SP 800-63B** — Digital identity guidelines (entropy requirements)
- **NIST FIPS 180-4** — Secure Hash Standard (SHA-256 implementation reference)

---

**Built with transparency. Audited with paranoia.**
