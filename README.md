<div align="center">

# 🔐 paranoid-passwd

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
[![OpenSSL](https://img.shields.io/badge/OpenSSL-721412?style=flat-square&logo=openssl&logoColor=white)](https://www.openssl.org/)
[![Docker](https://img.shields.io/badge/Docker-2496ED?style=flat-square&logo=docker&logoColor=white)](Dockerfile)
[![Alpine Linux](https://img.shields.io/badge/Alpine-0D597F?style=flat-square&logo=alpinelinux&logoColor=white)](https://alpinelinux.org/)

[**🚀 Live Demo**](https://jonbogaty.com/paranoid-passwd) · [**📖 Documentation**](#-documentation) · [**🔒 Security**](SECURITY.md) · [**🐛 Report Bug**](https://github.com/jbcom/paranoid-passwd/issues)

</div>

---

## 🎉 What's New in v2

> **Zero-Trust Password Generation with Full Supply Chain Security**

This release represents a complete architectural overhaul implementing [Liquibase-style supply chain security](https://www.liquibase.com/blog/docker-supply-chain-security):

| Feature | Description |
|---------|-------------|
| **🐳 Docker-First CI/CD** | All builds run inside verified Docker containers — no local toolchain trust required |
| **📦 SBOM + SLSA L3** | Software Bill of Materials + non-falsifiable build provenance on every release |
| **✍️ Cosign Signing** | Keyless signatures via GitHub OIDC, recorded in Sigstore's Rekor transparency log |
| **🧪 E2E Testing** | Playwright browser tests in isolated containers verify the full HTML→CSS→JS→WASM path |
| **🏔️ Alpine Base** | 8x smaller attack surface than Debian (~3.5MB vs ~29MB) |
| **🔬 munit C Tests** | Native unit tests with NIST FIPS 180-4 known-answer vectors run before WASM compilation |
| **📝 release-please** | Automated, attested releases with signed artifacts |

**Every artifact is:**
- ✅ Built in a SHA-pinned Alpine container
- ✅ Tested at the C level AND in the browser
- ✅ Attested with SBOM + SLSA provenance
- ✅ Signed with Cosign (keyless)
- ✅ Deployed only from verified releases

```bash
# Verify any release
cosign verify ghcr.io/jbcom/paranoid-passwd:latest \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity-regexp="https://github.com/jbcom/paranoid-passwd/.*"
```

---

## What is paranoid-passwd?

`paranoid-passwd` is a C program compiled to WebAssembly that generates cryptographic passwords inside a WASM sandbox. It runs a comprehensive 7-layer statistical audit entirely in C, using OpenSSL's CSPRNG (Cryptographically Secure Pseudo-Random Number Generator). The browser never touches the random bytes — JavaScript only reads the results from WASM linear memory.

**Key Features:**
- ✅ **OpenSSL CSPRNG** — AES-256-CTR DRBG, NIST SP 800-90A compliant
- ✅ **Rejection sampling** — Uniform distribution with no modulo bias
- ✅ **7-layer statistical audit** — Chi-squared, serial correlation, collision detection, entropy proofs, birthday paradox, pattern checks, NIST conformance
- ✅ **WASM sandbox isolation** — JavaScript cannot modify random bytes
- ✅ **Fail-closed design** — No JavaScript fallback (intentional)
- ✅ **Full transparency** — All code auditable, complete threat model disclosed

---

## 🚀 Live Demo

🔗 **[Try it now](https://jonbogaty.com/paranoid-passwd)** — Deployed from signed releases

Generate a 32-character password using 94 printable ASCII characters with **209.75 bits of entropy**. The tool will:
1. Generate the password using OpenSSL's CSPRNG
2. Run 7 statistical tests to verify randomness
3. Display detailed audit results with visual indicators
4. Show brute-force resistance calculations

---

## 💡 Why v2?

v1 was a monolithic HTML file with 350 lines of JavaScript doing crypto math. That created problems:

| Problem | Impact | v2 Solution |
|---------|--------|-------------|
| **CodeQL couldn't classify** | Security-critical logic mixed with DOM manipulation | Separate C/JS/CSS files |
| **JavaScript is hostile** | Prototype pollution, GC memory retention, extension attacks | All crypto in WASM |
| **Fallbacks masked failures** | Users thought they had WASM isolation when they didn't | Fail-closed (no JS fallback) |
| **No supply chain verification** | No way to verify binary provenance | SBOM + SLSA + Cosign |

v2 treats this as what it is: **a C project that happens to render in a browser**, with enterprise-grade supply chain security.

---

## 🛠️ Quick Start

### Option 1: Use the Live Demo (Recommended)

Visit **[jonbogaty.com/paranoid-passwd](https://jonbogaty.com/paranoid-passwd)** — no installation needed.

### Option 2: Docker (Verified Build)

```bash
# Build with full supply chain attestation
docker build -t paranoid-passwd .

# Extract verified artifacts
docker create --name temp paranoid-passwd
docker cp temp:/artifact ./artifact
docker rm temp

# Serve locally
cd artifact/site && python3 -m http.server 8080
# Open http://localhost:8080
```

### Option 3: Full Docker Workflow with E2E Tests

```bash
# Clone repository
git clone https://github.com/jbcom/paranoid-passwd.git
cd paranoid-passwd

# Run full E2E test suite (builds + tests in Docker)
docker compose up --build --abort-on-container-exit

# Or use Makefile targets
make docker-all  # Build → Extract → E2E Test
```

### Option 4: Local Development (Advanced)

<details>
<summary>Click to expand local development setup</summary>

**Prerequisites:**
- Zig ≥ 0.14.0
- OpenSSL (for hash computation)
- wabt (optional, for WASM verification)

```bash
# Clone dependencies manually (for local builds only)
mkdir -p vendor
git clone https://github.com/jedisct1/openssl-wasm.git vendor/openssl-wasm
cd vendor/openssl-wasm && git checkout fe926b5006593ad2825243f97e363823cd56599f && cd ../..
git clone https://github.com/nemequ/munit.git vendor/munit
cd vendor/munit && git checkout fbbdf1467eb0d04a6ee465def2e529e4c87f2118 && cd ../..

# Build and serve
make site
make serve  # http://localhost:8080
```

**Note:** Local builds are for development only. Production artifacts should always come from verified Docker builds.

</details>

---

## 🏗️ Architecture

```
paranoid/
├── src/paranoid.c           # ALL crypto computation (400 lines of C)
├── include/paranoid.h       # Public C API + struct definitions
├── www/
│   ├── index.html           # Structure only (no inline JS/CSS)
│   ├── style.css            # CSS-only wizard + animations
│   └── app.js               # Display-only WASM bridge (reads struct, sets textContent)
├── tests/
│   ├── munit/               # Native C unit tests (NIST vectors, rejection sampling)
│   └── e2e/                 # Playwright browser tests
├── Dockerfile               # Multi-stage build with all verification gates
├── docker-compose.yml       # E2E testing with Playwright
└── .github/workflows/
    ├── ci.yml               # PR verification (Docker build + E2E tests)
    ├── cd.yml               # Push to main (SBOM + Cosign + release-please)
    └── release.yml          # Deploy from signed releases
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

---

## 🔗 Supply Chain Security

This project implements **Liquibase-style supply chain security** with full artifact attestation:

| Layer | Implementation | Status |
|-------|---------------|--------|
| **Base Image** | Alpine 3.21 (SHA256-pinned digest) | ✅ |
| **Dependencies** | SHA-pinned commits (cloned in Dockerfile) | ✅ |
| **Testing** | munit C tests + Playwright E2E in Docker | ✅ |
| **SBOM** | Software Bill of Materials (`--sbom=true`) | ✅ |
| **Provenance** | SLSA Level 3 (`--provenance=mode=max`) | ✅ |
| **Signing** | Cosign keyless via GitHub OIDC | ✅ |
| **Actions** | All SHA-pinned (no tags) | ✅ |
| **Releases** | release-please with attested artifacts | ✅ |

### CI/CD Pipeline

```
┌────────────────────────────────────────────────────────────────────────┐
│                           PULL REQUEST (ci.yml)                        │
├────────────────────────────────────────────────────────────────────────┤
│  Docker Build (all tests inside) → E2E Tests → WASM Verification       │
│      ↓                                ↓              ↓                 │
│   munit C tests                 Playwright      wasm-objdump           │
│   NIST vectors                  screenshots     exports check          │
│                                                                        │
│  ✓ ALL CHECKS MUST PASS TO MERGE                                       │
└────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                           PUSH TO MAIN (cd.yml)                        │
├────────────────────────────────────────────────────────────────────────┤
│  Docker Build → SBOM → Provenance → Cosign Sign → release-please       │
│      ↓            ↓         ↓            ↓              ↓              │
│   Verified    Deps list   SLSA L3    Keyless      Creates PR           │
│   WASM                               Rekor log    for release          │
└────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                           RELEASE (release.yml)                        │
├────────────────────────────────────────────────────────────────────────┤
│  Build from tag → Attest → Sign → Upload Assets → Deploy to Pages      │
│      ↓             ↓        ↓          ↓              ↓                │
│   Verified      SLSA    Cosign    WASM + ZIP     GitHub Pages          │
│   image        provenance        checksums       from release          │
└────────────────────────────────────────────────────────────────────────┘
```

### Verification Commands

```bash
# Verify Cosign signature
cosign verify ghcr.io/jbcom/paranoid-passwd:latest \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity-regexp="https://github.com/jbcom/paranoid-passwd/.*"

# View SBOM
docker buildx imagetools inspect ghcr.io/jbcom/paranoid-passwd:latest \
  --format '{{ json .SBOM }}'

# View SLSA Provenance
docker buildx imagetools inspect ghcr.io/jbcom/paranoid-passwd:latest \
  --format '{{ json .Provenance }}'
```

---

## 🛡️ Threat Model

`paranoid-passwd` treats the LLM that built it as an adversary. Six primary threats:

| ID | Threat | Status |
|----|--------|--------|
| **T1** | Training data leakage (passwords biased toward breach dumps) | ✅ Mitigated via CSPRNG delegation |
| **T2** | Token distribution bias (softmax non-uniformity) | ✅ Mitigated via rejection sampling |
| **T3** | Deterministic reproduction (same prompt → same password) | ✅ Mitigated via hardware entropy |
| **T4** | Prompt injection steering | ⚠️ Residual (code is LLM-authored) |
| **T5** | Hallucinated security claims | ⚠️ **CRITICAL** — verify the math yourself |
| **T6** | Screen/conversation exposure | ⚠️ Advisory (clear clipboard) |

**T5 is the most dangerous** because it makes all other threats invisible. If the chi-squared implementation has a bug, the audit will still "pass."

👉 **Read the full threat model**: [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)

---

## 🔒 Security

### Entropy Specifications

| Metric | Value |
|--------|-------|
| **Password length** | 32 characters |
| **Character set** | 94 printable ASCII |
| **Entropy** | 209.75 bits |
| **Search space** | 94³² ≈ 1.38 × 10⁶³ |
| **Brute-force resistance** | 2.19 × 10⁴³ years @ 10¹² hash/s |
| **Birthday paradox** | ~4.37 × 10³¹ passwords for 50% collision |

### Statistical Audit (7 Layers)

| Layer | Test | Purpose |
|-------|------|---------|
| 1 | **Chi-Squared** | Verifies character frequency matches expected uniform distribution |
| 2 | **Serial Correlation** | Checks for positional dependencies (lag-1 autocorrelation) |
| 3 | **Collision Detection** | Generates 500-password batch, verifies uniqueness via SHA-256 |
| 4 | **Entropy Proofs** | Calculates log₂(N) × L, validates against NIST standards |
| 5 | **Birthday Paradox** | Computes collision probability for given batch size |
| 6 | **Pattern Checks** | Detects runs, cycles, and trivial sequences |
| 7 | **NIST Conformance** | Validates against SP 800-63B entropy requirements |

### Reporting Security Issues

See [SECURITY.md](SECURITY.md) for our security policy and disclosure process.

---

## ⚠️ Honest Limitations

> **We believe in radical transparency about what this tool can and cannot guarantee.**

1. **This code was written by an LLM.** The OpenSSL primitives are sound, but the glue code (rejection sampling, chi-squared approximations, struct offsets) could contain subtle errors.

2. **Statistical tests are necessary but not sufficient.** Passing χ² proves consistency with randomness, not randomness itself.

3. **Struct offset assumptions.** The JavaScript reader relies on hardcoded byte offsets. Runtime verification catches compiler mismatches, but if verification itself is wrong, JS reads garbage.

4. **The WASI shim is 3 lines of JS that are not WASM-isolated.** A sufficiently motivated attacker controlling the browser could replace `crypto.getRandomValues`.

5. **This threat model is not peer-reviewed.** The 6-threat taxonomy is LLM-derived, not from published research.

👉 **Read all limitations**: [AGENTS.md](AGENTS.md#honest-limitations)

---

## 📖 Documentation

| Document | Purpose |
|----------|---------|
| [AGENTS.md](AGENTS.md) | Complete project documentation, LLM clean room protocols, verification checklists |
| [SECURITY.md](SECURITY.md) | Security policy, disclosure process, LLM threat model |
| [DEVELOPMENT.md](DEVELOPMENT.md) | Development setup, testing, contributing guidelines |
| [CHANGELOG.md](CHANGELOG.md) | Version history and release notes |
| [docs/BUILD.md](docs/BUILD.md) | Build system, Docker pipeline, munit testing |
| [docs/SUPPLY-CHAIN.md](docs/SUPPLY-CHAIN.md) | SLSA Level 3 attestation, Cosign, SBOM |
| [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) | Comprehensive threat analysis (18 threats) |
| [docs/AUDIT.md](docs/AUDIT.md) | Statistical audit methodology (7 layers) |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System architecture diagrams |
| [docs/DESIGN.md](docs/DESIGN.md) | Design decisions and rationale |

---

## 🤝 Contributing

We welcome:

- **🔬 Cryptographer review** of `src/paranoid.c` (especially rejection sampling and chi-squared)
- **📐 Struct layout verification** (compare offsets against `wasm-objdump` output)
- **📊 Additional statistical tests** (NIST SP 800-22, Dieharder)
- **🛡️ New LLM threat vectors** as the field evolves
- **♿ Accessibility improvements** to the web frontend

See [DEVELOPMENT.md](DEVELOPMENT.md) for development setup and guidelines.

### Security Policy

Contributions that weaken the security posture will be rejected:
- ❌ Removing fail-closed behavior
- ❌ Replacing CSPRNG with PRNG
- ❌ Removing/weakening statistical tests
- ❌ Suppressing threat model warnings
- ❌ Unpinning GitHub Actions from commit SHAs

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

**However**, read the [Honest Limitations](#️-honest-limitations) section before production use. This tool demonstrates a verifiable generation pipeline and formalizes the LLM threat model, but should be reviewed by a human cryptographer before relying on it for production secrets.

---

## ❓ FAQ

<details>
<summary><strong>Q: Why not just use a password manager?</strong></summary>

A: You should! This tool demonstrates what a verifiable generation pipeline looks like and provides an auditable reference implementation. It's designed to be educational and to formalize the LLM threat model.
</details>

<details>
<summary><strong>Q: Can I use this in production?</strong></summary>

A: The generation algorithm (OpenSSL CSPRNG + rejection sampling) is production-grade. The implementation should be reviewed by a human cryptographer first. The supply chain security (SBOM, SLSA, Cosign) provides enterprise-grade verification.
</details>

<details>
<summary><strong>Q: Why C instead of Rust?</strong></summary>

A: OpenSSL. `jedisct1/openssl-wasm` provides a maintained, pre-compiled `libcrypto.a` for `wasm32-wasi`. Zig's `cc` can link against it with zero configuration. A Rust port is possible but would require building the crypto library from scratch.
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

# Local verification
make verify   # Check WASM exports
make hash     # Print SHA-256 and SRI hashes
```
</details>

<details>
<summary><strong>Q: Why Docker for everything?</strong></summary>

A: Supply chain security. Docker builds are:
- Reproducible (same inputs → same outputs)
- Isolated (no local toolchain trust)
- Attestable (SBOM + provenance attached)
- Verifiable (Cosign signatures)
</details>

---

## Acknowledgments

- **OpenSSL WASM** by [jedisct1](https://github.com/jedisct1/openssl-wasm) — Precompiled OpenSSL for WebAssembly
- **Zig** — Modern C/C++ compiler with excellent WebAssembly support
- **NIST SP 800-90A** — DRBG specification
- **NIST SP 800-63B** — Digital identity guidelines (entropy requirements)

---

**Built with transparency. Audited with paranoia. 🔒**
