---
title: AGENTS.md — Extended Agent Protocols
updated: 2026-04-09
status: current
domain: technical
---

# AGENTS.md — Extended Agent Protocols for paranoid-passwd

This document is the mandatory read for any AI agent working on this codebase.
The project's threat model designates the LLM as an adversary by design.

## LLM Clean Room Protocol

Before making ANY change, complete this self-audit:

- [ ] I acknowledge that my training data includes password breach dumps
- [ ] I will not generate random numbers directly (only delegate to RAND_bytes or WASI)
- [ ] I will not implement custom crypto primitives
- [ ] I will not claim formulas are correct without textbook citation
- [ ] I will not modify `src/paranoid.c` or `include/paranoid.h` without flagging for human review
- [ ] I will not add JavaScript fallbacks (fail-closed design is intentional)
- [ ] Rejection sampling uses `max_valid = (256/N)*N - 1` (the `-1` is critical)
- [ ] I will flag statistical code with `// TODO: HUMAN_REVIEW - <reason>`

If you cannot check all boxes, stop and request human guidance.

## Zero-Exception Rules

### Never:
1. Use `rand()`, `srand()`, or any LLM-generated randomness — use `RAND_bytes()` or WASI
2. Implement crypto primitives — use OpenSSL EVP or the vendored sha256_compact
3. Use modulo without rejection sampling — the correct boundary is `(256/N)*N - 1`
4. Claim a formula is correct — always flag for human verification
5. Add JavaScript fallbacks — WASM unavailability must be a visible failure, not silent downgrade
6. Unpin GitHub Actions from commit SHAs — tags are mutable, SHAs are not
7. Inline JS or CSS into HTML — CodeQL file-type classification depends on file separation
8. Remove statistical test layers — defense in depth requires all 7

### Always:
1. Delegate RNG to platform: `paranoid_platform_random()` → OpenSSL (native) or WASI (WASM)
2. Apply rejection sampling: `do { RAND_bytes(&b,1); } while (b > max_valid);`
3. Flag crypto changes: `// TODO: HUMAN_REVIEW - <reason>`
4. Cite textbooks, not memory: "Knuth vol 2 §3.4.1" not "I believe this is standard"
5. Add known-answer tests against NIST vectors when touching statistical code
6. Verify struct offsets: `paranoid_offset_*()` return values must match JS reads

## Common Hallucination Patterns

These bugs appear correct but are cryptographically wrong:

```c
// Off-by-one in rejection sampling
int max_valid = (256 / N) * N;     // WRONG — biases first character
int max_valid = (256 / N) * N - 1; // CORRECT

// Inverted p-value logic
int pass = (p_value < 0.01);  // WRONG — rejects correct randomness
int pass = (p_value > 0.01);  // CORRECT — fail to reject H0

// Wrong degrees of freedom
int df = N;     // WRONG — inflates chi2 statistic
int df = N - 1; // CORRECT (Pearson 1900)
```

## Change Verification Checklist

Before committing:

### Source Code
- [ ] No `rand()` or `srand()` anywhere in new code
- [ ] Rejection sampling uses `(256/N)*N - 1`
- [ ] P-value pass logic: `p > 0.01` (not `<`)
- [ ] Chi-squared degrees of freedom: `df = N - 1` (not `N`)
- [ ] All crypto changes flagged `TODO: HUMAN_REVIEW`

### Build
- [ ] `cmake --build build/wasm` succeeds with zero warnings
- [ ] WASM binary size remains under 250KB
- [ ] `wasm-objdump -x build/wasm/paranoid.wasm` shows only `wasi_snapshot_preview1` imports
- [ ] Native tests pass: `ctest --test-dir build/native --output-on-failure`

### Documentation
- [ ] `README.md` updated for user-facing changes
- [ ] `CHANGELOG.md` updated with change description
- [ ] `docs/ARCHITECTURE.md` updated if architecture changed
- [ ] `docs/THREAT-MODEL.md` updated if new threats identified

### E2E
- [ ] `cd tests/e2e && npx playwright test` passes
- [ ] Browser console shows zero errors
- [ ] All 7 audit stages complete with correct results

## Architecture Patterns

### Platform Abstraction

The `paranoid_platform.h` interface has two implementations:

| File | Platform | RNG | SHA-256 |
|------|----------|-----|---------|
| `src/platform_native.c` | CMake native build | `OpenSSL RAND_bytes` | OpenSSL EVP |
| `src/platform_wasm.c` | CMake WASM build | WASI `random_get` | sha256_compact |

Never call OpenSSL from WASM targets. Never call WASI from native targets.

### WASM–JS Boundary

`www/app.js` is a bridge, not a library. The three-line WASI shim is the
only security-critical JavaScript:

```javascript
// This is the ONLY place browser entropy enters the WASM sandbox
random_get(ptr, len) {
    crypto.getRandomValues(new Uint8Array(mem.buffer, ptr, len));
    return 0;
}
```

Everything else in `app.js` reads from the static result struct via offset
constants and calls `textContent` to display values. It never computes,
hashes, samples, or holds random bytes.

### Struct Layout

`paranoid_audit_result_t` is a static global in WASM linear memory. The
pointer returned by `paranoid_get_result_ptr()` never changes. JavaScript
reads it via `DataView` using offsets computed by `paranoid_offset_*()` C
functions. `verifyOffsets()` in `app.js` compares cached JS constants
against live C offsets at startup — mismatch halts execution.

### CSS State Machine

`www/style.css` manages the wizard page navigation via hidden radio buttons
and CSS `:checked` combinators. There is no JavaScript for navigation. This
reduces JS surface area and keeps state transitions auditable as CSS rules.

## For Human Cryptographers

Focus areas requiring expert review:

1. `src/paranoid.c` — rejection sampling boundary, chi-squared formula,
   Wilson-Hilferty p-value approximation, serial correlation computation
2. `src/sha256_compact.c` — FIPS 180-4 reference implementation; verify
   against NIST CAVP test vectors in `tests/test_sha256.c`
3. `src/platform_wasm.c` — WASI `random_get` delegation chain
4. `www/app.js` lines 15–17 — WASI shim calling `crypto.getRandomValues`

Report findings to: security@paranoid-project.org

## Documentation Map

All extended documentation lives in `docs/`:

| Document | Content |
|----------|---------|
| `docs/ARCHITECTURE.md` | System design, data flow, memory model, trust boundaries |
| `docs/DESIGN.md` | Design decisions with rationale (why C+WASM, why no fallback, etc.) |
| `docs/THREAT-MODEL.md` | 18-threat taxonomy including LLM-specific threats T1–T6 |
| `docs/AUDIT.md` | 7-layer statistical audit methodology with formulas and limitations |
| `docs/BUILD.md` | CMake, melange/apko, SRI injection, reproducible builds |
| `docs/SUPPLY-CHAIN.md` | Zero-trust build model, attestation, multi-party verification |
| `docs/TESTING.md` | Test strategy, coverage, how to run each test suite |
| `docs/STATE.md` | Current development state and planned work |
| `STANDARDS.md` | Code quality rules, style conventions, enforcement |
