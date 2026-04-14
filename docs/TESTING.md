---
title: Testing
updated: 2026-04-09
status: current
domain: quality
---

# Testing Strategy

## Overview

Testing runs in three phases: native C unit tests, WASM build verification, then
browser E2E tests. The sequence is enforced in CI via job dependencies —
`wasm-build needs: native-test` and `e2e-test needs: wasm-build`.

```
src/*.c  →  cmake native build  →  CTest  →  cmake WASM build  →  Playwright E2E
                                  (pass)
```

## Native C Unit Tests

The native build compiles `paranoid.c` with the `platform_native.c` backend
(OpenSSL) and links against the `acutest` test framework via the `vendor/` directory.

### Run

```bash
cmake -B build/native -DCMAKE_BUILD_TYPE=Debug
cmake --build build/native
ctest --test-dir build/native --output-on-failure
```

### Test Binaries

| Binary | Purpose |
|--------|---------|
| `test_native` | Comprehensive acutest-based C tests |
| `test_sha256` | NIST FIPS 180-4 known-answer vectors |
| `test_statistics` | Chi-squared and serial correlation KATs |
| `test_paranoid` | Standalone integration test framework |

### Run Individual Suites

```bash
./build/native/test_native --list        # List all test cases
./build/native/test_native sha256        # Run only SHA-256 tests
./build/native/test_native -v            # Verbose output
./build/native/test_sha256               # NIST CAVP vectors
./build/native/test_statistics           # Statistical KATs
```

### Test Coverage Areas

| Suite | What It Verifies |
|-------|-----------------|
| `sha256/*` | NIST FIPS 180-4 known-answer vectors (empty string, "abc", 448-bit) |
| `rejection/*` | Boundary formula: `max_valid = (256/N)*N - 1` for N=1..256 |
| `generate/*` | Length, charset, uniqueness, error handling |
| `chi_squared/*` | Uniform input passes, biased input fails, df = N-1 |
| `serial/*` | Constant string fails, alternating string passes |
| `collision/*` | Duplicate detection in 500-password batch |
| `struct/*` | WASM/JS struct offset consistency |
| `audit/*` | Full 7-layer pipeline integration |
| `stress/*` | High-volume distribution uniformity |

## WASM Build Verification

After native tests pass, build and verify the WASM binary:

```bash
cmake -B build/wasm -DCMAKE_TOOLCHAIN_FILE=cmake/wasm32-wasi.cmake -DCMAKE_BUILD_TYPE=Release
cmake --build build/wasm

# Verify exports (requires wabt)
wasm-objdump -x build/wasm/paranoid.wasm | grep "export name"

# Verify no OpenSSL imports
wasm-objdump -x build/wasm/paranoid.wasm | grep "import"
# Expected: ONLY wasi_snapshot_preview1 imports

# Verify binary size
ls -lh build/wasm/paranoid.wasm
# Expected: under 250KB
```

## E2E Browser Tests

Playwright tests exercise the full HTML/CSS/JS/WASM path in a real browser.

### Run

```bash
cd tests/e2e
npm install
npx playwright test
```

### Manual Verification

```bash
# 1. Build WASM and copy artifacts
cmake -B build/wasm -DCMAKE_TOOLCHAIN_FILE=cmake/wasm32-wasi.cmake -DCMAKE_BUILD_TYPE=Release
cmake --build build/wasm
cp build/wasm/paranoid.wasm www/
cp build/wasm/BUILD_MANIFEST.json www/

# 2. Start local server
cd www && python3 -m http.server 8080

# 3. Open http://localhost:8080 in browser and verify:
#    - Status indicator shows green (WASM loaded)
#    - Click "Generate + Run 7-Layer Audit"
#    - All 7 stages complete with passing results
#    - Browser console shows zero errors
#    - Network tab shows paranoid.wasm loads with 200 status
```

## Verification Scripts

```bash
./scripts/hallucination_check.sh      # LLM hallucination pattern detection
./scripts/supply_chain_verify.sh      # Dependency and build integrity
./scripts/double_compile.sh           # Zig vs Clang output comparison
./scripts/multiparty_verify.sh check  # Multi-party hash threshold
./scripts/integration_test.sh         # End-to-end smoke test
```

## CI Pipeline

The full test sequence in CI (`.github/workflows/ci.yml`):

1. Native C build + CTest
2. WASM cross-compilation + `wasm-validate`
3. WASM export verification via `wasm-objdump`
4. Playwright E2E tests
5. CodeQL static analysis (C/C++ and JavaScript)
6. ShellCheck on all shell scripts
7. Hallucination detection script
8. Supply chain verification script

All checks must pass before a PR may be merged.

## Known Limitations

- Chi-squared Wilson-Hilferty p-value approximation is conservative for small
  samples. For L=32 passwords against a charset of N=94 the expected per-bucket
  count is E_i ≈ 0.34, well below the conventional ≥5 rule. The audit
  detects only catastrophic bias at single-password length; longer passwords
  or batched audits give the test meaningful power. See `docs/AUDIT.md` for
  full discussion.
- Serial correlation only tests lag-1. Longer-range patterns are not tested.
- Collision test batch size (500) is too small to catch near-misses. It only
  catches catastrophic PRNG failures.
- Pattern detection is heuristic and QWERTY-specific.

## Adding Tests

When adding a new C export:

1. Add known-answer tests to `tests/test_native.c` using `acutest`.
2. Add at least one biased/incorrect-input test that must fail.
3. Add struct offset export and corresponding test in `tests/test_native.c struct/*`.
4. If the export is visible in browser, add a Playwright assertion.
