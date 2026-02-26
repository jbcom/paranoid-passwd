# AGENTS.md — paranoid v2

> **A C program that generates cryptographic passwords inside a WASM sandbox,
> audits them with formal statistical proofs, and treats the LLM that built it
> as an adversary.**

---

## One-Line Summary

`paranoid` compiles OpenSSL's CSPRNG to WebAssembly via Zig, runs a 7-layer
statistical audit entirely in C, and exposes results to a display-only JavaScript
bridge that reads a struct from WASM linear memory and sets `textContent` on
DOM elements. The browser never touches the random bytes.

---

## Why v2 Exists

v1 was a monolithic HTML file with 350 lines of JavaScript doing crypto
math. That created problems:

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

v2 fixes all three by treating this as what it is: a C project that
happens to render in a browser.

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
│  │  OpenSSL DRBG (AES-256-CTR, NIST SP 800-90A)│  │
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
paranoid.c: RAND_bytes(buf, n)
    ↓
OpenSSL 3 DRBG (AES-256-CTR, runs in WASM linear memory)
    ↓
WASI syscall: random_get(ptr, len)
    ↓
Browser polyfill: crypto.getRandomValues(buf)     ← 3 lines of JS
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
│   └── paranoid.h            # Public API — every WASM export
├── src/
│   └── paranoid.c            # ALL computation (400 lines)
├── www/
│   ├── index.html            # Structure only — no inline JS/CSS
│   ├── style.css             # Visual state — wizard nav, stages
│   └── app.js                # Display-only WASM bridge
├── vendor/
│   └── openssl-wasm/         # jedisct1/openssl-wasm (submodule)
├── build/                    # make output (gitignored)
│   ├── paranoid.wasm
│   └── site/                 # deployed to GitHub Pages
├── Makefile                  # Build system
├── .github/
│   └── workflows/
│       └── deploy.yml        # SHA-pinned CI/CD pipeline
├── .gitmodules
├── .gitignore
├── AGENTS.md                 # This file
└── LICENSE
```

### What Each File Does

| File | Lines | Touches crypto? | Role |
|------|------:|:---:|------|
| `include/paranoid.h` | 249 | Defines API | Every exported function signature, the result struct, limits |
| `src/paranoid.c` | 400 | **YES** | Generation, rejection sampling, chi-squared, serial correlation, collision detection, entropy proofs, birthday paradox, pattern checks, SHA-256 |
| `www/index.html` | 213 | No | Pure HTML structure. Zero inline scripts or styles. SRI hashes injected at build time |
| `www/style.css` | 834 | No | CSS-only wizard navigation (radio `:checked`), audit stage animations (`data-stage`), responsive layout |
| `www/app.js` | 436 | 3 lines | WASI shim (3 lines), struct reader, DOM updates via `textContent` |
| `Makefile` | 247 | No | `make` / `make site` / `make verify` / `make hash` / `make serve` / `make clean` |
| `deploy.yml` | 196 | No | 3-job pipeline: build → verify → deploy. All actions SHA-pinned |

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

OpenSSL EVP. Used for collision detection (hash-compare, not strcmp).

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

- Zig ≥ 0.14.0 (`brew install zig` / `snap install zig`)
- OpenSSL (for SRI hash computation during `make site`)
- wabt (optional, for `make verify`)

### Targets

```bash
make              # Build site (WASM + HTML/CSS/JS with SRI)
make build        # Compile paranoid.wasm only
make site         # Assemble site/ with injected SRI hashes
make verify       # Verify WASM exports and import namespaces
make hash         # Print SHA-256 and SRI of the binary
make serve        # Local dev server on :8080
make clean        # Remove build/
make info         # Show toolchain versions and paths
```

### What `make site` Does

1. Compiles `src/paranoid.c` against `vendor/openssl-wasm/precompiled/lib/libcrypto.a`
2. Produces `build/paranoid.wasm`
3. Computes SRI-384 hashes of `.wasm`, `.css`, `.js`
4. Injects hashes into `index.html` via `sed` (replacing `__WASM_SRI__` etc.)
5. Writes `BUILD_MANIFEST.json` recording all hashes, compiler version, commit SHA
6. Copies everything to `build/site/`

### Submodule

```bash
git submodule update --init --recursive
```

This clones `jedisct1/openssl-wasm` into `vendor/openssl-wasm/`. The
precompiled `libcrypto.a` (WASM target) is included in that repo.

---

## CI/CD Pipeline

`.github/workflows/deploy.yml` — three jobs:

### Job 1: `make site`

- Runner: `ubuntu-24.04` (pinned, not `latest`)
- Zig: 0.14.0 via `mlugg/setup-zig` (SHA-pinned)
- Runs `make site`, uploads `build/site/` as artifact
- Outputs WASM SHA-256 for cross-job verification

### Job 2: Verify

- Separate runner (independent of build environment)
- Downloads WASM artifact
- Verifies SHA-256 matches Job 1's output
- Uses `wasm-objdump` to confirm all required exports exist
- Checks that only `wasi_snapshot_preview1` imports are present

### Job 3: Deploy

- Only on `main`, only after build + verify pass
- Deploys `build/site/` to GitHub Pages
- Uses `actions/deploy-pages` (SHA-pinned)

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
A: The generation algorithm (OpenSSL CSPRNG + rejection sampling) is
production-grade. The implementation should be reviewed by a human
cryptographer first.

**Q: Why is the CSS so verbose?**
A: The `data-stage` selectors enumerate every completed/active/pending
combination explicitly. This is intentional — it means the CSS is a
complete state machine that a reviewer can read without running the code.
A mixin or preprocessor would hide the logic.

**Q: Why C instead of Rust?**
A: OpenSSL. `jedisct1/openssl-wasm` provides a maintained, pre-compiled
`libcrypto.a` for `wasm32-wasi`. Zig's `cc` can link against it directly
with zero configuration. A Rust port using `ring` or `rustls` would be
viable but would require building the crypto library from scratch.
