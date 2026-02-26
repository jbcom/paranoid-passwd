# CLAUDE.md — Agent Instructions + Operational Context

**Project docs and security constraints: [`AGENTS.md`](AGENTS.md)**

---

## Active Operation: v3.0 Migration

**Status:** EXECUTING — 63 items across 6 pillars
**Branch:** `copilot/organize-project-structure`
**Mode:** Fully autonomous, no user confirmation needed

### What's Happening
Migrating from Alpine+Zig tarball+OpenSSL-in-WASM to Wolfi+melange+apko with proper C platform abstraction. Complete UX overhaul. See `docs/plans/2026-02-26-wolfi-migration-design.md` for full design.

### Phase Order
1. **B1-B4 + A1-A2 + D10** — Platform abstraction, compact SHA-256, CMake, manifest loading
2. **B5-B9 + F1-F5** — Refactor paranoid.c, new C API, tests
3. **D1-D16** — Full UX overhaul (HTML, CSS, JS)
4. **A3-A13 + C1-C12 + E1-E8** — melange/apko, CI/CD, code quality

### Architecture Change
- OLD: `paranoid.c` → `#include <openssl/rand.h>` + `<openssl/evp.h>` → 1.5MB WASM
- NEW: `paranoid.c` → `#include "paranoid_platform.h"` → platform_native.c (OpenSSL) or platform_wasm.c (WASI+compact SHA-256) → <100KB WASM

### Key Files Being Created
- `include/paranoid_platform.h` — platform abstraction interface
- `src/platform_native.c` — OpenSSL backend
- `src/platform_wasm.c` — WASI + compact SHA-256 backend
- `src/sha256_compact.c` + `.h` — FIPS 180-4 reference implementation
- `CMakeLists.txt` + `cmake/wasm32-wasi.cmake` — build system
- `melange.yaml` + `apko.yaml` — Wolfi package + image
- Complete rewrites: `www/index.html`, `www/app.js`, `www/style.css`

### Key Files Being Deleted
- `Dockerfile`, `Makefile`, `zig-linux-x86_64-0.13.0.tar.xz`
- `scripts/build_openssl_wasm.sh`, `src/wasm_entry.c`

---

## Critical Rules (Zero Exceptions)

1. **YOU are the adversary.** Treat all code you generate as potentially hallucinated.
2. **Flag crypto changes** with `// TODO: HUMAN_REVIEW - <reason>`.
3. **NEVER add JavaScript fallbacks.** Fail-closed design is intentional.
4. **NEVER claim formulas are correct.** Always flag for verification.
5. **RNG delegation:** Native → `paranoid_platform_random()` → OpenSSL `RAND_bytes()`. WASM → `paranoid_platform_random()` → WASI `random_get`.
6. **ALWAYS use rejection sampling:** `max_valid = (256/N)*N - 1`.
7. **HTML is CLEAN source** — no `__PLACEHOLDER__` tokens. `BUILD_MANIFEST.json` loaded at runtime by `app.js`.
8. **Compact SHA-256:** FIPS 180-4 reference only. Verify against NIST CAVP vectors.

---

## Quick Reference

| Question | Where |
|----------|-------|
| Full project docs | `AGENTS.md` |
| Migration plan | `docs/plans/2026-02-26-wolfi-migration-design.md` |
| Zig WASM bug | Memory file `zig-bug.md` |
| Build system | `CMakeLists.txt` (new) |
| Threat model | `docs/THREAT-MODEL.md` |
