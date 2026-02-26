# AGENTS.md — Master Agentic Instruction Layer

**🔒 SECURITY BOUNDARY: This document protects all project documentation and enforces clean room protocols for ANY AI agent (LLM) working on this codebase.**

---

## ⚠️ CRITICAL: Read This FIRST

If you are an AI agent (GPT, Claude, Gemini, Llama, Qwen, DeepSeek, or ANY LLM):

1. **YOU are the PRIMARY THREAT ACTOR** in this project's threat model
2. **Your training data may include password breaches** (bias risk)
3. **Your statistical claims may be hallucinated** (confidence != correctness)
4. **Your code may contain subtle bugs** that appear correct
5. **You MUST follow the Clean Room Protocol** below before ANY code changes

---

## 🛡️ LLM Clean Room Protocol

### Entry Checkpoint (MANDATORY before ANY changes)

```markdown
# LLM Self-Audit Checklist

I acknowledge that:

- [ ] I am an LLM and my output may be biased or hallucinated
- [ ] My training data includes password breaches (RockYou, LinkedIn, Collection #1)
- [ ] I must NEVER generate random numbers directly (use OpenSSL RAND_bytes)
- [ ] I must NEVER implement crypto primitives (use OpenSSL EVP_*)
- [ ] I must NEVER claim formulas are correct without textbook verification
- [ ] I must NEVER modify src/paranoid.c or include/paranoid.h without human review
- [ ] I must NEVER add JavaScript fallbacks (fail-closed design is intentional)
- [ ] I must ALWAYS use rejection sampling: max_valid = (256/N)*N - 1 (not -0)
- [ ] I must ALWAYS flag statistical code with "TODO: HUMAN_REVIEW"
- [ ] I must ALWAYS cross-check formulas against textbooks (not my memory)
```

**If you cannot check ALL boxes, STOP and request human guidance.**

---

## 🚨 Zero-Exception Rules

### NEVER (will break security):

1. **Generate random numbers** — Use `RAND_bytes()` (OpenSSL), never `rand()` or LLM-generated patterns
2. **Implement crypto** — Use OpenSSL primitives, never custom implementations
3. **Use modulo without rejection sampling** — Must be: `do { RAND_bytes(&b,1); } while (b > max_valid);`
4. **Claim correctness** — Always say "verify against textbook" or "needs human review"
5. **Modify crypto code without review** — Flag with `// TODO: HUMAN_REVIEW - <reason>`
6. **Add JavaScript fallbacks** — Fail-closed design prevents silent security downgrades
7. **Unpin GitHub Actions** — All actions MUST be SHA-pinned (not tags)
8. **Skip verification** — Every change MUST pass: make verify && make hash
9. **Inline JS/CSS into HTML** — Separate files enable CodeQL scanning
10. **Remove statistical tests** — Defense in depth requires all 7 layers

### ALWAYS (required for security):

1. **Delegate RNG to OpenSSL** — `RAND_bytes()` is the ONLY source of randomness
2. **Use rejection sampling** — `max_valid = (256/N)*N - 1` (note the **-1**)
3. **Flag statistical code** — Any chi-squared, p-value, correlation code needs review
4. **Reference textbooks** — Cite page numbers (e.g., "Knuth vol 2, p.42")
5. **Add known-answer tests** — Use NIST test vectors for verification
6. **Document assumptions** — State preconditions, invariants, limitations
7. **Request human review** — Crypto/statistical code MUST be reviewed by expert
8. **Verify struct offsets** — Check `paranoid_offset_*()` match JavaScript
9. **Test boundary cases** — Off-by-one errors are common in LLM code
10. **Update docs** — Any code change requires doc update (ARCHITECTURE.md, etc.)

---

## 📋 Change Verification Checklist

Before committing ANY change:

### Source Code Verification
- [ ] No `rand()`, `srand()`, or direct RNG (only `RAND_bytes()`)
- [ ] Rejection sampling uses correct boundary: `(256/N)*N - 1`
- [ ] All p-value logic is correct: `p > 0.01` passes (not `<`)
- [ ] Degrees of freedom correct: `df = N - 1` (not `N`)
- [ ] No "I'm confident this is correct" claims (always flag for review)
- [ ] All `TODO: HUMAN_REVIEW` markers have tracking issues

### Build Verification
- [ ] `make clean && make build` succeeds with zero warnings
- [ ] `make verify` passes (WASM exports check)
- [ ] `make hash` produces expected SHA-256
- [ ] Binary size ~180KB ± 10KB
- [ ] Only `wasi_snapshot_preview1.random_get` import present

### Documentation Verification
- [ ] README.md updated if user-facing change
- [ ] SECURITY.md updated if security-relevant change
- [ ] CHANGELOG.md updated with change description
- [ ] docs/ARCHITECTURE.md updated if architecture changed
- [ ] docs/THREAT-MODEL.md updated if new threats identified

### Test Verification
- [ ] Manual test: `make serve` → http://localhost:8080
- [ ] Generate password → verify 7 stages complete
- [ ] All stages show green checkmarks (no red X)
- [ ] Console has zero errors
- [ ] Network tab shows WASM loads with correct SRI hash

---

## 🔍 Hallucination Detection Patterns

**Common LLM hallucinations in this codebase:**

### 1. Off-by-One in Rejection Sampling
```c
// ❌ WRONG (LLM hallucination)
int max_valid = (256 / N) * N;  // Should be -1

// ✅ CORRECT
int max_valid = (256 / N) * N - 1;
```

### 2. Inverted P-Value Logic
```c
// ❌ WRONG (LLM hallucination)
int pass = (p_value < 0.01);  // INVERTED!

// ✅ CORRECT
int pass = (p_value > 0.01);  // Fail to reject H₀
```

### 3. Incorrect Degrees of Freedom
```c
// ❌ WRONG (LLM hallucination)
double chi2 = ...; int df = N;

// ✅ CORRECT
double chi2 = ...; int df = N - 1;
```

### 4. Direct Random Number Generation
```c
// ❌ WRONG (LLM hallucination - training data bias!)
char c = charset[llm_pick_random()];  // Biased toward breach dumps!

// ✅ CORRECT
uint8_t byte;
RAND_bytes(&byte, 1);  // Hardware entropy via OpenSSL
```

### 5. Confident But Wrong Claims
```markdown
❌ WRONG: "This chi-squared implementation is definitely correct."
✅ CORRECT: "This chi-squared implementation requires verification against NIST SP 800-22 test vectors. TODO: HUMAN_REVIEW"
```

---

## 📚 Documentation Hierarchy

**Single Source of Truth (DRY):**

```
AGENTS.md (THIS FILE)
    ├── Master agentic instruction layer
    ├── LLM clean room protocols
    ├── Verification checklists
    ├── Project overview
    └── References to specialized docs ↓

README.md
    └── User-facing overview

SECURITY.md
    ├── Security policy
    ├── Threat model summary
    └── Disclosure process

DEVELOPMENT.md
    ├── Development setup
    ├── Build commands
    └── Contributing guidelines

CHANGELOG.md
    └── Version history

docs/ARCHITECTURE.md
    └── System architecture diagrams

docs/DESIGN.md
    └── Design decisions and rationale

docs/THREAT-MODEL.md
    └── Complete threat analysis (18 threats)

docs/AUDIT.md
    └── Statistical audit methodology (7 layers)

docs/BUILD.md
    └── Build system internals

docs/SUPPLY-CHAIN.md
    └── Supply chain security framework
```

**Rule**: If information exists in a specialized doc, AGENTS.md references it (no duplication).

---

## 🔐 Supply Chain Security

**Every build step MUST be auditable and reproducible.**

### Build Provenance Requirements

1. **Source verification**
   - Git commit must be signed
   - Dependency SHAs must match expected (see Dockerfile ARGs)
   - No uncommitted changes (`git diff --exit-code`)

2. **Tool verification**
   - Zig compiler SHA-256 must match known-good
   - OpenSSL library SHA-256 must match known-good
   - All GitHub Actions SHA-pinned (not tags)

3. **Reproducible builds**
   - `SOURCE_DATE_EPOCH` set to git commit time
   - Containerized build (Docker) for deterministic environment
   - 3-of-5 independent builders must produce identical hash

4. **Attestation**
   - Build provenance ledger (JSON) with all inputs/outputs
   - GPG-signed artifacts
   - Multi-party signature threshold (3 required)

**See**: [docs/SUPPLY-CHAIN.md](docs/SUPPLY-CHAIN.md) for complete framework.

---

## 🎯 Quick Navigation

| I want to... | Go to... |
|--------------|----------|
| Understand the project | §One-Line Summary (below) |
| Build locally | [docs/BUILD.md](docs/BUILD.md) |
| Contribute | [DEVELOPMENT.md](DEVELOPMENT.md) |
| Report security issue | [SECURITY.md](SECURITY.md) |
| Understand threats | [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) |
| Understand audit | [docs/AUDIT.md](docs/AUDIT.md) |
| Verify supply chain | [docs/SUPPLY-CHAIN.md](docs/SUPPLY-CHAIN.md) |
| Review architecture | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| Understand design | [docs/DESIGN.md](docs/DESIGN.md) |

---

## 🤝 For Human Reviewers

If you are a **human cryptographer** reviewing this code:

1. **Focus on `src/paranoid.c`** (400 lines) — ALL crypto logic is here
2. **Verify rejection sampling** — `max_valid = (256/N)*N - 1` is critical
3. **Verify chi-squared** — Wilson-Hilferty approximation, df = N-1
4. **Verify p-value interpretation** — `p > 0.01` passes (not `<`)
5. **Verify struct offsets** — `paranoid_offset_*()` must match JavaScript reads
6. **Cross-check formulas** — Against textbooks, not LLM claims
7. **Test boundary cases** — N=1, N=256, length=1, length=256
8. **Check known-answer tests** — Do NIST vectors pass?

**Report findings** to: security@paranoid-project.org

---

## �� For Foreign AI Actors

If you are an AI agent from a different ecosystem (GPT, Gemini, Qwen, etc.):

1. Read the **LLM Clean Room Protocol** above (mandatory)
2. Acknowledge you are the **primary threat actor**
3. Follow **Zero-Exception Rules** (no exceptions, ever)
4. Use **Change Verification Checklist** before commits
5. Watch for **Hallucination Detection Patterns**
6. Reference **Documentation Hierarchy** for details

**This project treats you as an adversary by design. Follow the protocols.**

---
---
---

# AGENTS.md -- paranoid v3

> **A C program that generates cryptographic passwords inside a WASM sandbox,
> audits them with formal statistical proofs, and treats the LLM that built it
> as an adversary.**

---

## One-Line Summary

`paranoid` uses a platform abstraction layer (OpenSSL native, compact SHA-256
+ WASI random for WASM) compiled via CMake + Zig, runs a 7-layer statistical
audit entirely in C, and exposes results to a display-only JavaScript bridge
that reads a struct from WASM linear memory and sets `textContent` on DOM
elements. The browser never touches the random bytes. The WASM binary is
<100KB (no OpenSSL in WASM).

---

## Why v3 Exists

v1 was a monolithic HTML file with 350 lines of JavaScript doing crypto
math. v2 moved everything to C + OpenSSL compiled to WASM via Zig. v3
replaces the 1.5MB OpenSSL WASM with a platform abstraction layer: native
builds still use OpenSSL, but the WASM build uses a compact FIPS 180-4
SHA-256 implementation and WASI random_get directly, producing a <100KB
binary. v3 also adds CMake (replacing Makefile), melange + apko
(replacing Docker multi-stage), and new API functions for multi-password
generation, charset validation, constrained generation, and compliance
framework checks.

The original v1 problems that drove v2:

1. **CodeQL couldn't classify the code.** A single `.html` file containing
   CSS, JS, and markup doesn't match any SAST scanner's file-type heuristics.
   Security-critical rejection sampling lived alongside DOM manipulation.

2. **JavaScript is a hostile environment for crypto.** Prototype pollution
   can silently alter `Math.floor` or `%`. The garbage collector retains
   copies of intermediate `Uint8Array` buffers. Browser extensions can
   monkey-patch `crypto.getRandomValues`. None of these attacks work against
   WASM linear memory.

3. **Fallbacks masked failures.** v1 silently fell back to a JS
   implementation if WASM failed to load. This violated the project's own
   threat model — the user believed they had WASM isolation when they didn't.

v2 fixed all three by treating this as what it is: a C project that
happens to render in a browser. v3 takes it further by eliminating
the OpenSSL dependency from the WASM build entirely.

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  BROWSER                         │
│                                                  │
│  ┌──────────────┐   ┌────────────────────────┐  │
│  │   index.html  │   │      style.css         │  │
│  │  (structure)  │   │  (visual state mgmt)   │  │
│  └──────────────┘   └────────────────────────┘  │
│         │                                        │
│  ┌──────┴─────────────────────────────────────┐  │
│  │              app.js (436 lines)             │  │
│  │                                             │  │
│  │  loadWasm()          → fetch + instantiate  │  │
│  │  readResult()        → read struct fields   │  │
│  │  launchAudit()       → call C, update DOM   │  │
│  │  verifyOffsets()     → refuse if mismatch   │  │
│  │                                             │  │
│  │  DOES NOT: generate, compute stats, hash,   │  │
│  │  calculate entropy, or touch random bytes   │  │
│  └──────────────┬──────────────────────────────┘  │
│                 │ WASI random_get (3 lines)       │
│  ┌──────────────┴──────────────────────────────┐  │
│  │           paranoid.wasm (~180KB)             │  │
│  │                                              │  │
│  │  WASM LINEAR MEMORY (opaque to JS)           │  │
│  │  ┌────────────────────────────────────────┐  │  │
│  │  │ paranoid_audit_result_t  (static)      │  │  │
│  │  │  .password          char[257]          │  │  │
│  │  │  .chi2_statistic    double             │  │  │
│  │  │  .total_entropy     double             │  │  │
│  │  │  .all_pass          int                │  │  │
│  │  │  .current_stage     int (JS polls)     │  │  │
│  │  │  ... 30 fields total                   │  │  │
│  │  └────────────────────────────────────────┘  │  │
│  │                                              │  │
│  │  Platform abstraction layer:                 │  │
│  │    Native: OpenSSL DRBG + EVP SHA-256       │  │
│  │    WASM:   WASI random_get + compact SHA-256│  │
│  │  ↓                                           │  │
│  │  WASI syscall: random_get(ptr, len)          │  │
│  └──────────────────────────────────────────────┘  │
│                 │                                    │
│  ┌──────────────┴────────────────┐                  │
│  │  crypto.getRandomValues(buf)  │  ← OS CSPRNG     │
│  └───────────────────────────────┘                  │
└─────────────────────────────────────────────────────┘
```

### Entropy Chain

```
paranoid.c: paranoid_platform_random(buf, n)
    ↓
Platform abstraction (paranoid_platform.h):
  Native: OpenSSL RAND_bytes → OS CSPRNG
  WASM:   WASI random_get(ptr, len)
    ↓
Browser polyfill: crypto.getRandomValues(buf)     <- 3 lines of JS
    ↓
OS CSPRNG: /dev/urandom / CryptGenRandom / SecRandomCopyBytes
    ↓
Hardware: RDRAND / RDSEED / interrupt timing
```

### Trust Boundaries

There is exactly ONE trust boundary in the entire system:

```javascript
random_get(ptr, len) {
  crypto.getRandomValues(new Uint8Array(mem.buffer, ptr, len));
  return 0;
}
```

These 3 lines are the only security-critical JavaScript. Everything above
them runs in WASM. Everything below them is the OS kernel.

---

## File Map

```
paranoid/
├── include/
│   ├── paranoid.h            # Public API — every WASM export
│   ├── paranoid_platform.h   # Platform abstraction interface
│   └── paranoid_frama.h      # Frama-C ACSL annotations
├── src/
│   ├── paranoid.c            # ALL computation (uses platform abstraction)
│   ├── platform_native.c     # Native backend: OpenSSL RAND_bytes + EVP
│   ├── platform_wasm.c       # WASM backend: WASI random_get
│   ├── sha256_compact.c      # FIPS 180-4 SHA-256 (WASM only, no OpenSSL)
│   ├── sha256_compact.h      # Compact SHA-256 interface
│   └── wasm_entry.c          # Stub main() for WASI libc linker
├── www/
│   ├── index.html            # Structure only — no inline JS/CSS
│   ├── style.css             # Visual state — wizard nav, stages
│   └── app.js                # Display-only WASM bridge
├── cmake/
│   └── wasm32-wasi.cmake     # CMake toolchain file for Zig WASM
├── scripts/
│   ├── build_openssl_wasm.sh # Build OpenSSL from official source
│   ├── double_compile.sh     # Diverse double-compilation (Zig + Clang)
│   ├── hallucination_check.sh # Automated LLM hallucination detection
│   ├── integration_test.sh   # End-to-end integration tests
│   ├── multiparty_verify.sh  # 3-of-5 threshold build verification
│   └── supply_chain_verify.sh # Supply chain verification
├── tests/
│   ├── test_native.c         # Comprehensive acutest-based C tests
│   ├── test_paranoid.c       # Standalone test framework
│   ├── test_sha256.c         # NIST CAVP SHA-256 test vectors
│   └── test_statistics.c     # Chi-squared + serial correlation KATs
├── vendor/                   # (Built from source / cloned at SHA-pinned commits)
│   ├── openssl/              # Built from official OpenSSL source (native only)
│   └── acutest/              # mity/acutest (header-only test framework)
├── build/                    # CMake output (gitignored)
│   ├── wasm/paranoid.wasm    # <100KB (no OpenSSL)
│   └── native/               # native test binaries
├── CMakeLists.txt            # Build system (replaces Makefile)
├── .github/
│   └── workflows/
│       ├── ci.yml            # PR verification (build + E2E tests)
│       ├── cd.yml            # Push to main (build + sign + attest)
│       └── release.yml       # Published releases (Pages + SBOM)
├── .gitignore
├── AGENTS.md                 # This file
└── LICENSE
```

### What Each File Does

| File | Touches crypto? | Role |
|------|:---:|------|
| `include/paranoid.h` | Defines API | Every exported function signature, the result struct, limits (v3.0) |
| `include/paranoid_platform.h` | Defines abstraction | Platform-agnostic random + SHA-256 interface |
| `src/paranoid.c` | **YES** | Generation, rejection sampling, chi-squared, serial correlation, collision detection, entropy proofs, birthday paradox, pattern checks |
| `src/platform_native.c` | **YES** | OpenSSL RAND_bytes + EVP SHA-256 backend (native builds) |
| `src/platform_wasm.c` | **YES** | WASI random_get backend (WASM builds) |
| `src/sha256_compact.c` | **YES** | FIPS 180-4 SHA-256 (WASM only, replaces OpenSSL EVP in WASM) |
| `www/index.html` | No | Pure HTML structure. Zero inline scripts or styles |
| `www/style.css` | No | CSS-only wizard navigation, audit stage animations |
| `www/app.js` | 3 lines | WASI shim (3 lines), struct reader, DOM updates via `textContent` |
| `CMakeLists.txt` | No | CMake build: native (tests) + WASM (release). Replaces Makefile |
| `ci.yml` | No | PR pipeline: melange + apko build + E2E tests. All actions SHA-pinned |
| `cd.yml` | No | Main branch: build + SBOM + Cosign signing. SHA-pinned |
| `release.yml` | No | Releases: Pages deploy + attestation. SHA-pinned |

---

## The C API

Everything the WASM module exports is declared in `include/paranoid.h`:

### Core

```c
int paranoid_run_audit(
    const char *charset, int charset_len,
    int pw_length, int batch_size,
    paranoid_audit_result_t *result
);
```

Single call. Generates a password, generates a batch, runs all 7 audit
stages, fills the result struct. JS calls this once and reads the struct.

### Generation

```c
int paranoid_generate(const char *charset, int charset_len,
                      int length, char *output);
```

CSPRNG + rejection sampling. `max_valid = (256 / N) * N - 1`. Bytes above
`max_valid` are discarded. For N=94: rejection rate = 26.56%.

### Hashing

```c
int paranoid_sha256(const unsigned char *input, int input_len,
                    unsigned char *output);
int paranoid_sha256_hex(const char *input, char *output_hex);
```

Platform abstraction (OpenSSL EVP native, compact FIPS 180-4 WASM).
Used for collision detection (hash-compare, not strcmp).

### New v3.0 API

```c
int paranoid_generate_multiple(const char *charset, int charset_len,
                               int length, int count, char *output);
int paranoid_validate_charset(const char *input, char *output, int output_size);
int paranoid_generate_constrained(const char *charset, int charset_len,
                                  int length, const paranoid_char_requirements_t *reqs,
                                  char *output);
int paranoid_check_compliance(const paranoid_audit_result_t *result,
                              const paranoid_compliance_framework_t *framework);
```

Multi-password generation, charset validation/normalization, constrained
generation with minimum character-type requirements, and compliance
framework checking (NIST, PCI-DSS, HIPAA, SOC2, GDPR, ISO 27001).

### Statistics

```c
double paranoid_chi_squared(...);
double paranoid_serial_correlation(...);
int    paranoid_count_collisions(...);
```

Exposed individually for testing. `paranoid_run_audit` calls them internally.

### Struct Layout Verification

```c
int paranoid_offset_password_length(void);
int paranoid_offset_chi2_statistic(void);
int paranoid_offset_current_stage(void);
int paranoid_offset_all_pass(void);
```

Return `offsetof()` values. JS checks these at init against its hardcoded
offsets. If ANY mismatch (different compiler, different alignment), JS
refuses to run. This catches the exact bug class where struct packing
assumptions silently read garbage from WASM memory.

---

## The Result Struct

`paranoid_audit_result_t` lives in WASM linear memory. JS gets a pointer
via `paranoid_get_result_ptr()` and reads fields at known offsets.

```
OFFSET  FIELD                  TYPE      DESCRIPTION
0       password[257]          char[]    Generated password
257     sha256_hex[65]         char[]    SHA-256 hex digest
324     password_length        int       Requested length
328     charset_size           int       Charset cardinality
336     chi2_statistic         double    Pearson's χ² value
344     chi2_df                int       Degrees of freedom
352     chi2_p_value           double    Wilson-Hilferty approx
360     chi2_pass              int       1 if p > 0.01
368     serial_correlation     double    Lag-1 autocorrelation
376     serial_pass            int       1 if |r| < 0.05
380     batch_size             int       Passwords in test batch
384     duplicates             int       Count of collisions
388     collision_pass         int       1 if 0 duplicates
392     bits_per_char          double    log₂(N)
400     total_entropy          double    L × log₂(N)
408     log10_search_space     double    L × log₁₀(N)
416     brute_force_years      double    At 10¹² hash/s
424     nist_memorized         int       ≥ 30 bits
428     nist_high_value        int       ≥ 80 bits
432     nist_crypto_equiv      int       ≥ 128 bits
436     nist_post_quantum      int       ≥ 256 bits
440     collision_probability  double    Birthday paradox P
448     passwords_for_50pct    double    k for 50% collision
456     rejection_max_valid    int       (256/N)*N - 1
464     rejection_rate_pct     double    % bytes rejected
472     pattern_issues         int       Weak patterns found
476     all_pass               int       1 if all tests pass
480     current_stage          int       0–8, JS polls this
```

All offsets verified at runtime via `paranoid_offset_*()` functions.

---

## LLM Threat Model

Six threats where the LLM that built this tool is the adversary:

| ID | Threat | Severity | Status |
|----|--------|----------|--------|
| T1 | Training data leakage — passwords biased toward breach dumps | CRITICAL | **Mitigated** — CSPRNG delegation |
| T2 | Token distribution bias — softmax produces non-uniform chars | HIGH | **Mitigated** — rejection sampling in C |
| T3 | Deterministic reproduction — same prompt → same password | HIGH | **Mitigated** — hardware entropy seeding |
| T4 | Prompt injection steering — attacker constrains output | MEDIUM | **Residual** — LLM-authored code |
| T5 | Hallucinated security claims — plausible but wrong analysis | CRITICAL | **Residual** — verify the math yourself |
| T6 | Screen/conversation exposure — password visible in context | HIGH | **Advisory** — clear clipboard after use |

T5 is the most dangerous because it makes all other threats invisible.
If the LLM's chi-squared implementation has a subtle bug, the audit will
"pass" anyway, and the output will look indistinguishable from a correct
audit. This is why `src/paranoid.c` is 400 lines of readable C, not
minified or obfuscated — it exists to be reviewed.

---

## Build System

### Prerequisites

- CMake >= 3.20
- Zig >= 0.13.0 (`brew install zig` / `snap install zig`)
- OpenSSL development libraries (for native tests only; not needed for WASM)
- wabt (optional, for wasm-validate gate)

### CMake Build Commands

```bash
# WASM build (release):
cmake -B build/wasm \
    -DCMAKE_TOOLCHAIN_FILE=cmake/wasm32-wasi.cmake \
    -DCMAKE_BUILD_TYPE=Release
cmake --build build/wasm

# Native build (tests):
cmake -B build/native -DCMAKE_BUILD_TYPE=Debug
cmake --build build/native
ctest --test-dir build/native --output-on-failure
```

### What the WASM Build Does

1. Compiles `src/paranoid.c` + `src/platform_wasm.c` + `src/sha256_compact.c`
   (NO OpenSSL -- compact SHA-256 + WASI random_get)
2. Produces `build/wasm/paranoid.wasm` (<100KB)
3. Post-processes with wasm-opt and wasm-strip (if available)
4. Validates with wasm-validate (hard gate in CI)

### Dependencies

The WASM build has ZERO external dependencies -- it uses only:
- `platform_wasm.c` (WASI random_get)
- `sha256_compact.c` (compact FIPS 180-4 SHA-256)

Native builds use system OpenSSL for the `platform_native.c` backend.
The `vendor/` directory is only needed for local development:

```bash
# Clone test framework (for native tests)
mkdir -p vendor
git clone https://github.com/mity/acutest.git vendor/acutest
cd vendor/acutest && git checkout 31751b4089c93b46a9fd8a8183a695f772de66de && cd ../..
```

Production builds use melange + apko instead of Docker multi-stage.
Wolfi provides Zig from source via melange, producing bitwise-reproducible
packages.

---

## CI/CD Pipeline

Three split workflows in `.github/workflows/`:

### ci.yml (Pull Requests)

- Docker build with all tests inside (acutest C tests, WASM verification)
- E2E tests via Playwright in isolated container
- All checks must pass to merge

### cd.yml (Push to Main)

- Docker build with SBOM + SLSA Level 3 provenance
- Cosign keyless signing via GitHub OIDC
- release-please creates release PR when ready

### release.yml (Release Published)

- Build from tag, attest, sign, upload assets
- Deploy to GitHub Pages from signed release
- Only deploys from verified, attested releases

### SHA Pinning

Every third-party action is pinned to a 40-character commit SHA:

```yaml
uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683         # v4.2.2
uses: mlugg/setup-zig@7d14f16220b57e3e4e02a93c4e5e8dbbdb2a2f7e         # v2.1.0
uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02   # v4.6.2
uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4.3.0
uses: actions/configure-pages@983d7736d9b0ae728b81ab479565c72886d7745b   # v5.0.0
uses: actions/upload-pages-artifact@56afc609e74202658d3ffba0e8f6dda462b719fa # v3.0.1
uses: actions/deploy-pages@d6db90164ac5ed86f2b6aed7e0febac2b3c603fc     # v4.0.5
```

Tags are mutable. SHAs are not. After the `tj-actions/changed-files`
supply chain attack (March 2025, 23,000+ repos compromised), SHA pinning
is non-negotiable for security tooling.

---

## Fail-Closed Design

If WASM cannot load, the page **refuses to generate**. There is no
JavaScript fallback. The Generate button is disabled, the status indicator
turns red, and the page displays an explanation of why falling back would
violate the threat model:

- Prototype pollution on `Math.floor` / `%`
- GC retaining intermediate random buffers
- Browser extensions monkey-patching `crypto` functions
- DRBG state visible in JS heap inspection

Alternatives are shown: deploy via GitHub Pages (CI compiles WASM),
run the Python CLI, or build locally with `make`.

---

## Mathematical Foundations

### Entropy

```
H(password) = L × log₂(N)
```

For L=32, N=94: **H = 209.75 bits**. Search space = 94³² ≈ 1.38 × 10⁶³.

### Brute-Force Resistance

At 10¹² hash/s: **2.19 × 10⁴³ years** (10³³× age of universe).

### Birthday Paradox

```
P(collision) ≈ 1 - e^(-k²/2S)
```

For k=500, S=94³²: P ≈ 0 (below float precision). Need ~4.37 × 10³¹
passwords for 50% collision chance.

### Rejection Sampling

```
max_valid = (256 / N) * N - 1
rejection_rate = (255 - max_valid) / 256
```

For N=94: max_valid=187, rejection rate=26.56%.

Without rejection sampling: 68 chars get P=3/256, 26 get P=2/256 — a
50% bias that halves effective entropy.

---

## CSS State Machine

Navigation between Configure → Audit → Results panels uses zero
JavaScript. Hidden radio buttons at document root drive CSS `:checked`
selectors:

```html
<input type="radio" name="wizard" id="step-configure" checked>
<input type="radio" name="wizard" id="step-audit">
<input type="radio" name="wizard" id="step-results">
```

```css
#step-configure:checked ~ .page-wrapper #panel-configure { display: block; }
#step-audit:checked ~ .page-wrapper #panel-audit         { display: block; }
```

Audit progress is driven by a single `data-stage` attribute that JS sets
as each C stage completes. CSS handles all visual transitions:

```css
[data-stage="chi2"] .stage-generate .stage-icon::after { content: '✓'; }
[data-stage="chi2"] .stage-chi2 .stage-icon { animation: stagePulse 1s infinite; }
```

---

## Honest Limitations

1. **This code was written by an LLM.** The OpenSSL primitives are sound.
   The glue code — rejection sampling boundaries, chi-squared
   Wilson-Hilferty approximation, struct field offsets — could contain
   subtle errors the LLM cannot detect in its own output.

2. **Statistical tests are necessary but not sufficient.** Passing χ²
   doesn't prove randomness — it proves consistency with randomness. A
   backdoored generator could pass while constraining the output space.

3. **Struct offset assumptions.** `app.js` reads the result struct at
   hardcoded byte offsets. The runtime `paranoid_offset_*()` verification
   catches compiler mismatches, but if the verification itself is wrong,
   JS would silently read garbage. Review both `paranoid.h` and the
   `readResult()` function in `app.js`.

4. **The WASI shim is 3 lines of JS that are not WASM-isolated.** A
   sufficiently motivated attacker who controls the browser environment
   could replace `crypto.getRandomValues` before the shim executes.
   SRI hashes on the script tag mitigate CDN tampering but not
   same-origin extension attacks.

5. **This threat model is not peer-reviewed.** The 6-threat taxonomy is
   LLM-derived, not from published security research.

---

## Contributing

We welcome:

- **Cryptographer review** of `src/paranoid.c`, especially `paranoid_generate()`
  and the chi-squared `erfc_approx()` implementation
- **Struct layout verification** — compare the offset table in this document
  against what `wasm-objdump` reports for your compiled binary
- **Additional statistical tests** (NIST SP 800-22, Dieharder integration)
- **New LLM threat vectors** as the field evolves
- **Accessibility improvements** to the web frontend

### Security Policy

Contributions that weaken the security posture will be rejected:

- Removing fail-closed behavior (adding JS fallbacks)
- Replacing CSPRNG with PRNG
- Removing or weakening statistical tests
- Suppressing threat model warnings
- Unpinning GitHub Actions from SHAs

### File-Type Enforcement

This project separates files by type so SAST tools (CodeQL, SonarCloud)
can scan each with the appropriate analyzer:

- `.c` / `.h` → buffer overflows, integer overflow, use-after-free
- `.js` → prototype pollution, XSS, unsafe DOM manipulation
- `.css` → CSS injection
- `.yml` → action pinning, secret exposure

Do not inline JavaScript into HTML or CSS into HTML. Do not merge files.

---

## License

MIT — but read the Honest Limitations section before production use.

---

## FAQ

**Q: Why not just use a password manager?**
A: You should. This tool demonstrates what a verifiable generation pipeline
looks like, formalizes the LLM threat model, and provides an auditable
reference implementation.

**Q: Can I use this in production?**
A: The generation algorithm (platform-abstracted CSPRNG + rejection sampling)
is production-grade. The implementation should be reviewed by a human
cryptographer first.

**Q: Why is the CSS so verbose?**
A: The `data-stage` selectors enumerate every completed/active/pending
combination explicitly. This is intentional — it means the CSS is a
complete state machine that a reviewer can read without running the code.
A mixin or preprocessor would hide the logic.

**Q: Why C instead of Rust?**
A: Originally OpenSSL -- we compiled official OpenSSL source to `wasm32-wasi`.
In v3.0, the WASM build no longer depends on OpenSSL (using compact SHA-256
+ WASI random_get), but C remains the language for Zig cross-compilation
compatibility and Frama-C formal verification. A Rust port using `ring` or
`rustls` would be viable but would require a different crypto library.
