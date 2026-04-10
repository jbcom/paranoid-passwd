---
title: CLAUDE.md — Agent Entry Point
updated: 2026-04-09
status: current
domain: technical
---

# paranoid-passwd — Agent Entry Point

A self-auditing cryptographic password generator. All computation is in C compiled
to WebAssembly. JavaScript is a display-only bridge. The LLM that built this code
is part of the threat model.

## Project Identity

- **Language**: C (core), JavaScript (bridge), CSS (UI state machine)
- **Build**: CMake + Zig cross-compilation to `wasm32-wasi`
- **Package**: melange + apko (Wolfi ecosystem)
- **Live site**: https://paranoid-passwd.com
- **Current version**: 3.1.0

## Quick Command Reference

```bash
# WASM build (release)
cmake -B build/wasm -DCMAKE_TOOLCHAIN_FILE=cmake/wasm32-wasi.cmake -DCMAKE_BUILD_TYPE=Release
cmake --build build/wasm

# Native build + tests
cmake -B build/native -DCMAKE_BUILD_TYPE=Debug
cmake --build build/native
ctest --test-dir build/native --output-on-failure

# Local dev server
cp build/wasm/paranoid.wasm www/ && cp build/wasm/BUILD_MANIFEST.json www/
cd www && python3 -m http.server 8080

# E2E tests
cd tests/e2e && npm install && npx playwright test

# Production build (Wolfi)
melange build melange.yaml --arch x86_64 --runner docker
```

## File Map

```
src/paranoid.c            — ALL cryptographic computation
src/platform_wasm.c       — WASM backend: WASI random_get
src/platform_native.c     — Native backend: OpenSSL RAND_bytes
src/sha256_compact.c      — FIPS 180-4 SHA-256 (WASM only)
include/paranoid.h        — Public C API
include/paranoid_platform.h — Platform abstraction interface
www/index.html            — HTML structure only (no inline JS/CSS)
www/app.js                — WASM bridge, display-only
www/style.css             — CSS-only wizard navigation
cmake/wasm32-wasi.cmake   — Zig WASM toolchain file
melange.yaml              — Wolfi package recipe
apko.yaml                 — OCI image assembly
```

## Security-Critical Rules (Zero Exceptions)

1. `src/paranoid.c` and `include/paranoid.h` require human cryptographer review before
   any change — flag all crypto modifications with `// TODO: HUMAN_REVIEW - <reason>`.
2. Rejection sampling: `max_valid = (256/N)*N - 1` (the `-1` is critical).
3. P-value pass condition: `p > 0.01` (not `<`). Degrees of freedom: `N - 1` (not `N`).
4. Never add JavaScript fallbacks. Fail-closed design is intentional.
5. Never inline JS or CSS into HTML — CodeQL depends on file separation.
6. Never unpin GitHub Actions from commit SHAs.
7. RNG: WASM → WASI `random_get`. Native → OpenSSL `RAND_bytes`. Never `rand()`.

## Key Documentation

| Need | Location |
|------|----------|
| Architecture | `docs/ARCHITECTURE.md` |
| Design decisions | `docs/DESIGN.md` |
| Threat model | `docs/THREAT-MODEL.md` |
| Statistical audit | `docs/AUDIT.md` |
| Build internals | `docs/BUILD.md` |
| Supply chain | `docs/SUPPLY-CHAIN.md` |
| Testing strategy | `docs/TESTING.md` |
| Current state | `docs/STATE.md` |
| Code standards | `STANDARDS.md` |
| Agent protocols | `AGENTS.md` |
| Security policy | `SECURITY.md` |
