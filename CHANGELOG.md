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
- Third-party security audit
- Formal verification of rejection sampling

---

## [3.0.0] - 2026-02-26

### 🎉 Major Rewrite — Complete Architectural Overhaul

This is a complete rewrite from v1, treating `paranoid-passwd` as what it is: a C project that happens to render in a browser.

### Added

#### Core Architecture
- **C-based implementation** (`src/paranoid.c`)
  - ALL cryptographic logic moved from JavaScript to C
  - Platform abstraction: OpenSSL CSPRNG (native), WASI random_get (WASM)
  - Compact FIPS 180-4 SHA-256 for WASM (no OpenSSL dependency)
  - Rejection sampling for uniform distribution
  - 7-layer statistical audit pipeline

- **WASM compilation** via CMake + Zig toolchain
  - Compiled to `wasm32-wasi` target
  - <100KB binary size (no OpenSSL in WASM)
  
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
- **CMake** build system (replaces Makefile):
  - Native build + CTest for unit testing
  - WASM cross-compilation via `cmake/wasm32-wasi.cmake` Zig toolchain
- **melange/apko** (Wolfi ecosystem, replaces Docker):
  - `melange.yaml` — Declarative package recipe
  - `apko.yaml` — OCI image assembly
  - Bitwise-reproducible builds with SBOM

#### CI/CD Pipeline
- **Split workflows** (`.github/workflows/`):
  - `ci.yml` — PR verification (native CTest + WASM build + E2E tests + CodeQL + ShellCheck)
  - `cd.yml` — Push to main (melange/apko build + Cosign signing + release-please + double compilation)
  - `release.yml` — Deploy from signed, attested releases to GitHub Pages
  - `codeql.yml` — CodeQL static analysis
  - `scorecard.yml` — OpenSSF Scorecard
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
- **Crypto source**: JS `Math.random()` → CSPRNG (OpenSSL native, WASI random_get WASM)
- **Distribution**: Modulo bias → Rejection sampling
- **Architecture**: Monolithic HTML → Separated concerns (C/JS/CSS/HTML)
- **Build system**: Makefile → CMake; Docker → melange/apko (Wolfi)
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
- **WASM binary size** — <100KB (removed OpenSSL dependency from WASM)

### Security

- **CVE-NONE-2025-001** (internal): Modulo bias in v1 reduced effective entropy by 1.75 bits
  - **Impact**: HIGH — 50% bias toward first 68 characters
  - **Fixed in**: v3.0.0 via rejection sampling
  - **Workaround**: Upgrade to v3.0.0 (no safe workaround for v1)

### Breaking Changes

- **v1 URLs deprecated** — v1 was a single HTML file; v3 requires WASM support
- **No JavaScript fallback** — Browsers without WASM support cannot use v3
- **Build system required** — Cannot be edited as a single file (must use CMake)
- **melange/apko builds** — Production builds use Wolfi ecosystem (no Docker required)

### Migration Guide (v1 → v3)

**v3 users**:
```bash
# Clone and build with CMake
git clone https://github.com/jbcom/paranoid-passwd.git
cd paranoid-passwd
cmake -B build/wasm -DCMAKE_TOOLCHAIN_FILE=cmake/wasm32-wasi.cmake -DCMAKE_BUILD_TYPE=Release
cmake --build build/wasm
```

**Or use the live site**:
https://paranoid-passwd.com

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

**v1 is deprecated. All users should upgrade to v3.**

---

## Version History Summary

| Version | Date | Status | Key Feature |
|---------|------|--------|-------------|
| 3.1.0 | 2026-02-26 | ✅ **Current** | CD pipeline fixes, first GitHub Pages deploy |
| 3.0.0 | 2026-02-26 | ✅ **Stable** | Wolfi migration, platform abstraction, UX overhaul |
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
- **Live Demo**: https://paranoid-passwd.com
- **Documentation**: See [AGENTS.md](AGENTS.md)
- **Security Policy**: See [SECURITY.md](SECURITY.md)
- **Development Guide**: See [DEVELOPMENT.md](DEVELOPMENT.md)

---

[Unreleased]: https://github.com/jbcom/paranoid-passwd/compare/paranoid-passwd-v3.1.0...HEAD
[3.0.0]: https://github.com/jbcom/paranoid-passwd/releases/tag/paranoid-passwd-v3.1.0
[1.0.0]: https://github.com/jbcom/paranoid-passwd/releases/tag/v1.0.0
