# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [3.1.0](https://github.com/jbcom/paranoid-passwd/compare/paranoid-passwd-v3.0.0...paranoid-passwd-v3.1.0) (2026-02-26)


### Features

* v3.0 — Wolfi migration, platform abstraction, full UX overhaul ([#1](https://github.com/jbcom/paranoid-passwd/issues/1)) ([ba451af](https://github.com/jbcom/paranoid-passwd/commit/ba451afcc15f627026c1d64b6bb60d6d4d5a6859))


### Bug Fixes

* CD pipeline — correct melange/apko versions, add reactor flag, use CI_GITHUB_TOKEN ([a43ddc3](https://github.com/jbcom/paranoid-passwd/commit/a43ddc3b3923b10be0325095c2f9dc67b4eb8f2c))
* melange build — add --runner docker for GitHub Actions ([bd30a95](https://github.com/jbcom/paranoid-passwd/commit/bd30a95b924c3326990bacfd8670e78a12abb370))
* melange/apko tar extraction — strip subdirectory from tarballs ([428a4e0](https://github.com/jbcom/paranoid-passwd/commit/428a4e0d3d4a3c9d0db3c954cb087f2d7532e26e))
* release-please — use config file, fix version tracking ([bc46bd3](https://github.com/jbcom/paranoid-passwd/commit/bc46bd3f5ddd55df6a8f483a5524c260d822ac40))
* restrict melange/apko to x86_64 only ([a5db163](https://github.com/jbcom/paranoid-passwd/commit/a5db163ecb26d0dbcbb5df25f4ad6be363c01302))

## [Unreleased]

### Planned
- NIST SP 800-22 statistical test suite integration
- Dieharder test battery integration
- Reproducible builds (deterministic WASM output)
- Third-party security audit
- Formal verification of rejection sampling
- Unit test suite for C code
- Integration tests for full audit pipeline

---

## [2.0.0] - 2026-02-26

### 🎉 Major Rewrite — Complete Architectural Overhaul

This is a complete rewrite from v1, treating `paranoid` as what it is: a C project that happens to render in a browser.

### Added

#### Core Architecture
- **C-based implementation** (`src/paranoid.c`, 400 lines)
  - ALL cryptographic logic moved from JavaScript to C
  - OpenSSL CSPRNG (AES-256-CTR DRBG, NIST SP 800-90A)
  - Rejection sampling for uniform distribution
  - 7-layer statistical audit pipeline
  
- **WASM compilation** via Zig toolchain
  - Compiled to `wasm32-wasi` target
  - OpenSSL compiled from official source (`vendor/openssl/`, built from tag `openssl-3.4.0` with WASI patches)
  - ~180KB binary size
  
- **Proper file structure**
  - `include/paranoid.h` — Public C API (249 lines)
  - `src/paranoid.c` — All computation (400 lines)
  - `www/index.html` — Structure only, no inline JS/CSS (213 lines)
  - `www/style.css` — CSS-only wizard + animations (834 lines)
  - `www/app.js` — Display-only WASM bridge (436 lines)

#### Security Features
- **Fail-closed design** — No JavaScript fallback (intentional)
- **WASM sandbox isolation** — Browser cannot modify random bytes
- **SRI hash injection** — All assets (WASM, JS, CSS) have integrity hashes
- **Struct offset verification** — JS verifies WASM memory layout at runtime
- **SHA-pinned GitHub Actions** — All CI/CD actions pinned to commit SHAs

#### Statistical Audit (7 Layers)
1. **Chi-Squared Test** — Uniform distribution verification
2. **Serial Correlation** — Independence check (lag-1 autocorrelation)
3. **Collision Detection** — 500-password batch uniqueness via SHA-256
4. **Entropy Proofs** — NIST SP 800-63B conformance
5. **Birthday Paradox** — Collision probability calculations
6. **Pattern Detection** — Heuristic checks for runs/sequences
7. **NIST Conformance** — AAL1/AAL2/AAL3 entropy thresholds

#### Build System
- **Makefile** with comprehensive targets:
  - `make build` — Compile WASM only
  - `make site` — Assemble deployable site with SRI hashes
  - `make verify` — Verify WASM exports/imports (requires wabt)
  - `make hash` — Print SHA-256 and SRI hashes
  - `make serve` — Local development server
  - `make clean` — Remove build artifacts
  - `make info` — Show toolchain configuration

#### CI/CD Pipeline
- **Split workflows** (`.github/workflows/`):
  - `ci.yml` — PR verification (Docker build + acutest C tests + E2E tests)
  - `cd.yml` — Push to main (SBOM + Cosign signing + release-please)
  - `release.yml` — Deploy from signed, attested releases
- **SHA-pinned actions** — All third-party actions pinned to commit SHAs
- **Build manifest** — `BUILD_MANIFEST.json` records all hashes, versions, commit SHA

#### Documentation
- **AGENTS.md** — Complete project documentation (21KB)
  - Architecture diagrams
  - Mathematical proofs
  - Honest limitations
  - File map with line counts
- **README.md** — Comprehensive project overview
- **SECURITY.md** — Security policy, threat model, audit trail
- **CHANGELOG.md** — Version history (this file)
- **DEVELOPMENT.md** — Development setup and contributing guidelines
- **docs/** directory:
  - `ARCHITECTURE.md` — System architecture
  - `DESIGN.md` — Design decisions
  - `THREAT-MODEL.md` — Threat analysis
  - `AUDIT.md` — Statistical methodology
  - `BUILD.md` — Build system internals

#### LLM Threat Model
- **6-threat taxonomy**:
  - T1: Training data leakage (mitigated via CSPRNG)
  - T2: Token distribution bias (mitigated via rejection sampling)
  - T3: Deterministic reproduction (mitigated via hardware entropy)
  - T4: Prompt injection steering (residual, code is LLM-authored)
  - T5: Hallucinated security claims (CRITICAL, verify math yourself)
  - T6: Screen/conversation exposure (advisory)

### Changed

- **Language**: JavaScript → C (with minimal JS bridge)
- **Crypto source**: JS `Math.random()` → OpenSSL CSPRNG
- **Distribution**: Modulo bias → Rejection sampling
- **Architecture**: Monolithic HTML → Separated concerns (C/JS/CSS/HTML)
- **Audit**: 3 basic checks → 7-layer comprehensive audit
- **Failure mode**: Silent fallback → Fail-closed (refuse to run)

### Removed

- **v1 monolithic HTML** (350+ lines, mixed JS/CSS/HTML)
- **JavaScript crypto fallback** (intentionally removed for security)
- **Modulo-based character selection** (replaced with rejection sampling)
- **Inline styles and scripts** (violated CodeQL analysis)

### Fixed

- **CodeQL classification** — Now scans C, JS, CSS separately
- **Prototype pollution vulnerability** — Crypto logic no longer in JS
- **Modulo bias** — Rejection sampling eliminates 50% character bias
- **Memory retention** — Random bytes never in JS heap (WASM linear memory)
- **Supply chain attacks** — SHA-pinned actions prevent mutable tag exploits

### Security

- **CVE-NONE-2025-001** (internal): Modulo bias in v1 reduced effective entropy by 1.75 bits
  - **Impact**: HIGH — 50% bias toward first 68 characters
  - **Fixed in**: v2.0.0 via rejection sampling
  - **Workaround**: Upgrade to v2.0.0 (no safe workaround for v1)

### Breaking Changes

- **v1 URLs deprecated** — v1 was a single HTML file; v2 requires WASM support
- **No JavaScript fallback** — Browsers without WASM support cannot use v2
- **Build system required** — Cannot be edited as a single file (must run `make`)
- **Docker-first builds** — OpenSSL built from official source inside Docker; test dependencies cloned at SHA-pinned commits (no submodules)

### Migration Guide (v1 → v2)

**v1 users**:
```html
<!-- Old (v1) -->
<script src="https://example.com/paranoid-v1.html"></script>
```

**v2 users**:
```bash
# Clone and build (Docker handles dependencies automatically)
git clone https://github.com/jbcom/paranoid-passwd.git
cd paranoid-passwd
docker build -t paranoid-passwd .

# Deploy build/site/ to your hosting
```

**Or use GitHub Pages**:
https://jbcom.github.io/paranoid-passwd

---

## [1.0.0] - 2025-XX-XX [DEPRECATED]

### Initial Release (Monolithic HTML)

- Single HTML file with embedded JavaScript
- Basic password generation via `crypto.getRandomValues()`
- 3 statistical tests (chi-squared, collision, entropy)
- Modulo-based character selection (**biased**, see CVE-NONE-2025-001)
- JavaScript fallback (masked failures)

### Known Issues (Unfixed in v1)

- **Modulo bias**: 50% bias toward first 68 characters
- **CodeQL classification failure**: Mixed HTML/JS/CSS confused SAST scanners
- **Silent fallback**: WASM failures fell back to weaker JS implementation
- **Prototype pollution risk**: Crypto logic exposed to JS runtime attacks
- **Memory retention**: Intermediate buffers retained by GC

**v1 is deprecated. All users should upgrade to v2.**

---

## Version History Summary

| Version | Date | Status | Key Feature |
|---------|------|--------|-------------|
| 2.0.0 | 2026-02-26 | ✅ **Current** | C/WASM rewrite, 7-layer audit, fail-closed |
| 1.0.0 | 2025-XX-XX | ❌ **Deprecated** | Monolithic HTML, modulo bias, silent fallback |

---

## Versioning Policy

- **Major version** (X.0.0): Breaking changes, architectural rewrites
- **Minor version** (2.X.0): New features, non-breaking API additions
- **Patch version** (2.0.X): Bug fixes, documentation updates, security patches

**Stability guarantees**:
- C API (`include/paranoid.h`) — Stable within major version
- WASM exports — Stable within major version
- Build system — May change in minor versions (documented)
- CI/CD pipeline — May change in minor versions (documented)

---

## Security Advisories

All security advisories are tracked in [SECURITY.md](SECURITY.md).

**Critical advisories**:
- **CVE-NONE-2025-001**: Modulo bias in v1 (fixed in v2.0.0)

---

## Links

- **GitHub Repository**: https://github.com/jbcom/paranoid-passwd
- **Live Demo**: https://jbcom.github.io/paranoid-passwd
- **Documentation**: See [AGENTS.md](AGENTS.md)
- **Security Policy**: See [SECURITY.md](SECURITY.md)
- **Development Guide**: See [DEVELOPMENT.md](DEVELOPMENT.md)

---

[Unreleased]: https://github.com/jbcom/paranoid-passwd/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/jbcom/paranoid-passwd/releases/tag/v2.0.0
[1.0.0]: https://github.com/jbcom/paranoid-passwd/releases/tag/v1.0.0
