# paranoid

**A self-auditing cryptographic password generator that treats the LLM that built it as an adversary.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-audited-green.svg)](SECURITY.md)
[![CI Status](https://github.com/jbcom/paranoid-passwd/workflows/Deploy/badge.svg)](https://github.com/jbcom/paranoid-passwd/actions)

---

## What is this?

`paranoid` is a C program compiled to WebAssembly that generates cryptographic passwords inside a WASM sandbox. It runs a comprehensive 7-layer statistical audit entirely in C, using OpenSSL's CSPRNG (Cryptographically Secure Pseudo-Random Number Generator). The browser never touches the random bytes — JavaScript only reads the results from WASM linear memory.

**Key Features:**
- ✅ OpenSSL CSPRNG (AES-256-CTR DRBG, NIST SP 800-90A compliant)
- ✅ Rejection sampling for uniform distribution (no modulo bias)
- ✅ 7-layer statistical audit (chi-squared, serial correlation, collision detection, entropy proofs, birthday paradox, pattern checks, NIST conformance)
- ✅ WASM sandbox isolation (JavaScript cannot modify random bytes)
- ✅ Fail-closed design (no JavaScript fallback)
- ✅ Full transparency (all code auditable, complete threat model disclosure)

---

## Live Demo

🔗 **[Try it now](https://jbcom.github.io/paranoid-passwd)** (GitHub Pages)

Generate a 32-character password using 94 printable ASCII characters with 209.75 bits of entropy. The tool will:
1. Generate the password using OpenSSL's CSPRNG
2. Run 7 statistical tests to verify randomness
3. Display detailed audit results with visual indicators
4. Show brute-force resistance calculations

---

## Why v2?

v1 was a monolithic HTML file with 350 lines of JavaScript doing crypto math. That created problems:

1. **CodeQL couldn't classify the code** — security-critical logic mixed with DOM manipulation
2. **JavaScript is hostile to crypto** — prototype pollution, GC memory retention, extension monkey-patching
3. **Fallbacks masked failures** — users thought they had WASM isolation when they didn't

v2 treats this as what it is: **a C project that happens to render in a browser**.

---

## Quick Start

### Prerequisites

- **Zig ≥ 0.14.0** (for WebAssembly compilation)
- **OpenSSL** (for hash computation during build)
- **wabt** (optional, for WASM verification)

### Installation

```bash
# Clone with submodules
git clone --recursive https://github.com/jbcom/paranoid-passwd.git
cd paranoid-passwd

# Build the site (compiles WASM + assembles HTML/CSS/JS with SRI hashes)
make site

# Run local development server
make serve
# Open http://localhost:8080
```

### Build Commands

```bash
make              # Build everything (same as 'make site')
make build        # Compile WASM only
make verify       # Verify WASM exports/imports (requires wabt)
make hash         # Print SHA-256 and SRI hashes
make site         # Assemble build/site/ with SRI injection
make serve        # Start local HTTP server on port 8080
make clean        # Remove build artifacts
make info         # Show toolchain configuration
```

---

## Architecture

```
paranoid/
├── src/paranoid.c        # ALL computation (400 lines of C)
├── include/paranoid.h    # Public C API
├── www/
│   ├── index.html        # Structure only (no inline JS/CSS)
│   ├── style.css         # CSS-only wizard + animations
│   └── app.js            # Display-only WASM bridge
├── vendor/openssl-wasm/  # OpenSSL compiled to WASM (submodule)
├── Makefile              # Build system
└── .github/workflows/    # CI/CD with SHA-pinned actions
```

### The Trust Boundary

There is exactly **ONE** trust boundary in the entire system:

```javascript
// WASI shim (3 lines) — the ONLY security-critical JavaScript
random_get(ptr, len) {
  crypto.getRandomValues(new Uint8Array(mem.buffer, ptr, len));
  return 0;
}
```

Everything above this runs in WASM. Everything below is the OS kernel.

---

## Documentation

| Document | Purpose |
|----------|---------|
| [AGENTS.md](AGENTS.md) | Complete project documentation (threat model, math proofs, architecture) |
| [SECURITY.md](SECURITY.md) | Security policy, disclosure process, LLM threat model, audit trail |
| [CHANGELOG.md](CHANGELOG.md) | Version history and release notes |
| [DEVELOPMENT.md](DEVELOPMENT.md) | Development setup, testing, contributing guidelines |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System architecture and component interaction |
| [docs/DESIGN.md](docs/DESIGN.md) | Design decisions and rationale |
| [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) | Comprehensive threat analysis |
| [docs/AUDIT.md](docs/AUDIT.md) | Statistical audit methodology |
| [docs/BUILD.md](docs/BUILD.md) | Build system internals |

---

## Threat Model

`paranoid` treats the LLM that built it as an adversary. Six primary threats:

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

## Security

### Entropy Specifications

- **32-char password from 94-char charset**: 209.75 bits of entropy
- **Search space**: 94³² ≈ 1.38 × 10⁶³
- **Brute-force resistance**: 2.19 × 10⁴³ years at 10¹² hash/s (10³³× age of universe)
- **Birthday paradox**: Need ~4.37 × 10³¹ passwords for 50% collision chance

### Statistical Audit (7 Layers)

1. **Chi-Squared Test** — Verifies character frequency matches expected uniform distribution
2. **Serial Correlation** — Checks for positional dependencies (lag-1 autocorrelation)
3. **Collision Detection** — Generates 500-password batch, verifies uniqueness via SHA-256
4. **Entropy Proofs** — Calculates log₂(N) × L, validates against NIST standards
5. **Birthday Paradox** — Computes collision probability for given batch size
6. **Pattern Checks** — Detects runs, cycles, and trivial sequences
7. **NIST Conformance** — Validates against SP 800-63B entropy requirements

### Reporting Security Issues

See [SECURITY.md](SECURITY.md) for our security policy and disclosure process.

---

## Honest Limitations

1. **This code was written by an LLM.** The OpenSSL primitives are sound, but the glue code (rejection sampling, chi-squared approximations, struct offsets) could contain subtle errors.

2. **Statistical tests are necessary but not sufficient.** Passing χ² proves consistency with randomness, not randomness itself.

3. **Struct offset assumptions.** The JavaScript reader relies on hardcoded byte offsets. Runtime verification catches compiler mismatches, but if verification itself is wrong, JS reads garbage.

4. **The WASI shim is 3 lines of JS that are not WASM-isolated.** A sufficiently motivated attacker controlling the browser could replace `crypto.getRandomValues`.

5. **This threat model is not peer-reviewed.** The 6-threat taxonomy is LLM-derived, not from published research.

👉 **Read all limitations**: [AGENTS.md](AGENTS.md#honest-limitations)

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
- ❌ Removing fail-closed behavior
- ❌ Replacing CSPRNG with PRNG
- ❌ Removing/weakening statistical tests
- ❌ Suppressing threat model warnings
- ❌ Unpinning GitHub Actions from commit SHAs

---

## License

MIT License — see [LICENSE](LICENSE) for details.

**However**, read the [Honest Limitations](#honest-limitations) section before production use. This tool demonstrates a verifiable generation pipeline and formalizes the LLM threat model, but should be reviewed by a human cryptographer before relying on it for production secrets.

---

## FAQ

**Q: Why not just use a password manager?**  
A: You should. This tool demonstrates what a verifiable generation pipeline looks like and provides an auditable reference implementation.

**Q: Can I use this in production?**  
A: The generation algorithm (OpenSSL CSPRNG + rejection sampling) is production-grade. The implementation should be reviewed by a human cryptographer first.

**Q: Why C instead of Rust?**  
A: OpenSSL. `jedisct1/openssl-wasm` provides a maintained, pre-compiled `libcrypto.a` for `wasm32-wasi`. Zig's `cc` can link against it with zero configuration.

**Q: Why no JavaScript fallback?**  
A: The fail-closed design is intentional. JavaScript fallbacks violate the threat model by exposing crypto operations to prototype pollution and GC memory retention.

**Q: How do I verify the build?**  
A: Run `make verify` to check WASM exports, `make hash` to print binary hashes. Compare against CI logs. All GitHub Actions are SHA-pinned to prevent supply chain attacks.

---

## Acknowledgments

- **OpenSSL WASM** by [jedisct1](https://github.com/jedisct1/openssl-wasm) — Precompiled OpenSSL for WebAssembly
- **Zig** — Modern C/C++ compiler with excellent WebAssembly support
- **NIST SP 800-90A** — DRBG specification
- **NIST SP 800-63B** — Digital identity guidelines (entropy requirements)

---

**Built with transparency. Audited with paranoia. 🔒**
