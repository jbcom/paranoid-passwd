# Design: v3.0 Wolfi Migration + UX Overhaul

**Date:** 2026-02-26
**Status:** Approved
**Version:** 2.0.0 → 3.0.0

## Summary

Migrate paranoid-passwd from Alpine+precompiled Zig+OpenSSL-in-WASM to Wolfi-native builds with melange/apko, refactor C architecture to use platform abstraction (removing OpenSSL from WASM), complete UX overhaul with compliance framework selection and full charset control, and establish production CI/CD with CodeQL, SonarCloud, and OpenSSF Scorecard.

## Problem Statement

1. **OpenSSL in WASM is wrong.** paranoid.c was never refactored to separate platform-specific code. The entire 1.5MB WASM binary includes ~1.2MB of unused OpenSSL. Only 6 OpenSSL calls are used: RAND_bytes + 5 EVP SHA-256 calls.

2. **Zig tarball is precompiled.** The 45MB `zig-linux-x86_64-0.13.0.tar.xz` is the only unattested binary in the supply chain. Wolfi builds Zig from source with LLVM 20.

3. **No proper C build system.** Raw Makefile with manual flags. No CMake, no configure, no cross-compilation toolchain files.

4. **UX is confusing.** "Configure Audit" doesn't explain password generation. Generated password disappears on Results page. No multi-password support. Charset options are prescriptive. Only partial NIST compliance. No regulatory framework selection.

5. **CI/CD gaps.** CodeQL badge broken (no workflow). SonarCloud configured but not wired. Scripts exist but aren't integrated.

## Architecture

### Platform Abstraction Layer

```
include/paranoid_platform.h
├── paranoid_platform_random(buf, len)  → int
└── paranoid_platform_sha256(in, len, out) → int

src/platform_native.c          src/platform_wasm.c
├── OpenSSL RAND_bytes()       ├── WASI random_get()
└── OpenSSL EVP SHA-256        └── sha256_compact.c (FIPS 180-4)
```

### Build Pipeline

```
CMakeLists.txt
├── Native target: links OpenSSL, builds tests
└── WASM target: cmake/wasm32-wasi.cmake toolchain
    └── Zig cc --target=wasm32-wasi (no OpenSSL)

melange.yaml → builds .apk (native test + WASM build + wasm-validate)
apko.yaml → assembles OCI image with SBOM
cosign → signs with Sigstore OIDC
```

### Static Asset Model

HTML/CSS/JS are source files that ship unmodified. No `__PLACEHOLDER__` injection.
- `www/index.html` — clean HTML, no build-time substitution
- `www/style.css` — clean CSS
- `www/app.js` — loads `BUILD_MANIFEST.json` at runtime for version/hashes
- `BUILD_MANIFEST.json` — generated at build time with SRI hashes, SHA-256, version

### CI/CD Pipeline

- `ci.yml` — PR: unsigned melange build + native tests + E2E + hallucination check + supply chain verify + CodeQL + SonarCloud + shellcheck
- `cd.yml` — Push to main: signed melange build + apko + cosign + release-please + double-compile + multiparty verify
- `release.yml` — On release: deploy artifact to GitHub Pages

## Pillars

### A: Build & Infrastructure (13 items)
Replace Docker+Makefile with CMake+melange+apko. Delete Dockerfile, Makefile, zig tarball, OpenSSL WASM build script, WASI entry stub, OpenSSL patches.

### B: C Architecture Refactor (9 items)
Create platform abstraction. Implement compact FIPS 180-4 SHA-256. Refactor paranoid.c to use abstraction. WASM target <100KB.

### C: CI/CD Pipeline (12 items)
Rewrite three workflows. Add CodeQL, SonarCloud, OpenSSF Scorecard, Dependabot. Wire double_compile.sh and multiparty_verify.sh. Fix broken badges and version manifest.

### D: UX/UI Overhaul (16 items)
- Hero section explaining what the tool does
- Password visible on Results page with copy button
- Multi-password generation (1-10)
- Regulatory compliance multi-select (NIST SP 800-63B, PCI DSS 4.0, HIPAA, SOC 2, GDPR/ENISA, ISO 27001)
- Full charset control (checkboxes + custom input)
- Exclude ambiguous characters toggle
- Minimum character-type requirements
- Wizard step renaming for clarity
- Real-time entropy preview
- Password strength meter
- Accessibility (ARIA labels, semantic HTML)
- Favicon

### E: Code Quality (8 items)
Frama-C optional CI stage, NIST CAVP SHA-256 test vectors, NIST SP 800-22 statistical vectors, shellcheck, doc updates, wasm-validate gate.

### F: New C API (5 items)
- `paranoid_generate_multiple()` — N passwords
- `paranoid_validate_charset()` — validate custom charset
- Min char-type enforcement (config struct)
- `paranoid_compliance_t` — framework thresholds
- Extended `paranoid_audit_result_t` — multi-password + compliance fields

## Implementation Order

Phase 1 (parallel, no deps): Platform abstraction + CMake + manifest loading
Phase 2 (needs Phase 1): paranoid.c refactor + new C API + tests
Phase 3 (needs Phase 2): Full UX overhaul
Phase 4 (needs all): melange/apko + CI/CD + quality gates

## Decisions

- **CMake over Meson:** Better Zig integration, wider CI support, Wolfi uses CMake for its own Zig build
- **Compact SHA-256 over alternative hashes:** FIPS 180-4 is the standard, ~150 lines C, verifiable against NIST CAVP
- **melange+apko over Docker:** Bitwise-reproducible, auto-SBOM, matches Wolfi's own attestation rigor
- **Runtime manifest loading over placeholder injection:** HTML stays clean source file, auditable without build artifacts
- **Major version bump (3.0.0):** Breaking API changes in paranoid_audit_result_t, new C API surface
