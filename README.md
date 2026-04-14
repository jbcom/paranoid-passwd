---
title: paranoid-passwd
updated: 2026-04-09
status: current
domain: product
---

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

[**Live Demo**](https://paranoid-passwd.com) · [**Documentation**](#documentation) · [**Security**](SECURITY.md) · [**Report Bug**](https://github.com/jbcom/paranoid-passwd/issues)

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

## Quick Start

### Option 1: Use the Live Demo (Recommended)

Visit **[paranoid-passwd.com](https://paranoid-passwd.com)** — no installation needed.

### Option 2: CLI — verified install from attested GitHub Releases

```bash
# Download tarball + checksums for your platform (example: darwin-arm64)
gh release download paranoid-passwd-v3.2.0 --repo jbcom/paranoid-passwd \
    -p 'paranoid-passwd-3.2.0-darwin-arm64.tar.gz' -p 'checksums.txt'

# Verify sigstore-signed provenance — fails if not built by our release workflow
gh attestation verify paranoid-passwd-3.2.0-darwin-arm64.tar.gz --owner jbcom

# Run it
tar xzf paranoid-passwd-3.2.0-darwin-arm64.tar.gz
./paranoid-passwd-3.2.0-darwin-arm64/paranoid-passwd --length 32
```

No `curl | bash`. The attestation chain walks from the GitHub Release
tarball → sigstore → Rekor transparency log → the exact workflow run
that produced the binary. See **[docs/CLI.md](docs/CLI.md)** for full
CLI usage, flag reference, exit codes, and the Homebrew tap / Wolfi apk
install paths.

### Option 3: Local Build with CMake

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

---

## Architecture

For the full file map and component diagram, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

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

For the complete entropy chain and supply chain security details, see
[docs/SUPPLY-CHAIN.md](docs/SUPPLY-CHAIN.md) and [docs/BUILD.md](docs/BUILD.md).

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
| [AGENTS.md](AGENTS.md) | LLM clean room protocols, hallucination patterns, verification checklists |
| [STANDARDS.md](STANDARDS.md) | Code quality rules, style conventions |
| [SECURITY.md](SECURITY.md) | Security policy, disclosure process, LLM threat model |
| [CHANGELOG.md](CHANGELOG.md) | Version history and release notes |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System architecture diagrams and data flow |
| [docs/DESIGN.md](docs/DESIGN.md) | Design decisions and rationale |
| [docs/TESTING.md](docs/TESTING.md) | Test strategy, coverage, how to run |
| [docs/BUILD.md](docs/BUILD.md) | CMake pipeline, SRI injection, reproducible builds |
| [docs/SUPPLY-CHAIN.md](docs/SUPPLY-CHAIN.md) | SLSA Level 3 attestation, Cosign, SBOM, melange/apko |
| [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) | Comprehensive threat analysis (18 threats) |
| [docs/AUDIT.md](docs/AUDIT.md) | Statistical audit methodology (7 layers) |
| [docs/STATE.md](docs/STATE.md) | Current development state and planned work |

---

## Contributing

We welcome:

- **Cryptographer review** of `src/paranoid.c` (especially rejection sampling and chi-squared)
- **Struct layout verification** (compare offsets against `wasm-objdump` output)
- **Additional statistical tests** (NIST SP 800-22, Dieharder)
- **New LLM threat vectors** as the field evolves
- **Accessibility improvements** to the web frontend

See [docs/TESTING.md](docs/TESTING.md) for development setup, build commands, and contributing guidelines.

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

Read the full honest limitations in [AGENTS.md](AGENTS.md).

---

**Built with transparency. Audited with paranoia.**
