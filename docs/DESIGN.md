# Design Decisions

This document explains the key design decisions in `paranoid` and their rationale.

---

## Table of Contents

- [Core Design Principles](#core-design-principles)
- [Why C + WebAssembly](#why-c--webassembly)
- [Why No JavaScript Fallback](#why-no-javascript-fallback)
- [Why Rejection Sampling](#why-rejection-sampling)
- [Why 7 Statistical Tests](#why-7-statistical-tests)
- [Why CSS-Only Navigation](#why-css-only-navigation)
- [Why Separate Files](#why-separate-files)
- [Why SHA-Pinned Actions](#why-sha-pinned-actions)
- [Why SRI Hashes](#why-sri-hashes)
- [Why Static Result Struct](#why-static-result-struct)

---

## Core Design Principles

### 1. Paranoia as a Design Constraint

**Decision**: Treat the LLM that wrote this code as an adversary.

**Rationale**:
- LLMs are trained on password breach dumps (training data leakage)
- Token generation via softmax creates distribution bias
- LLMs produce plausible but incorrect security claims (hallucinations)
- If the LLM is compromised, every line of code is suspect

**Implications**:
- Minimize LLM-authored crypto logic (delegate to OpenSSL)
- Transparent disclosure of all limitations
- Request human cryptographer review
- Multiple independent verification layers

---

### 2. Fail-Closed > Fail-Open

**Decision**: If WASM cannot load, refuse to generate passwords.

**Rationale**:
- Silent fallbacks mask security failures
- Users believe they have WASM isolation when they don't
- JavaScript crypto is vulnerable (prototype pollution, GC retention, extensions)

**Trade-offs**:
- ❌ Reduced compatibility (requires WASM-capable browser)
- ✅ No silent security downgrades
- ✅ Clear error messages guide users to alternatives

---

### 3. Separation of Concerns

**Decision**: Separate HTML, CSS, JavaScript, and C into distinct files.

**Rationale**:
- CodeQL needs file extensions to classify code (`.c` vs `.js` vs `.css`)
- SAST tools scan each language with appropriate analyzers
- Security-critical code (C) is clearly delineated
- Reviewers can audit crypto logic without parsing DOM manipulation

**v1 problem**:
- Single HTML file with 350 lines of JavaScript
- Security-critical rejection sampling mixed with DOM updates
- CodeQL couldn't classify → vulnerabilities missed

---

## Why C + WebAssembly

### Decision: Rewrite from JavaScript to C, compile to WASM

**Rationale**:

1. **JavaScript is hostile to cryptography**:
   - Prototype pollution: `Object.prototype.valueOf = () => 0` breaks `%` operator
   - Garbage collector retains copies of intermediate `Uint8Array` buffers
   - Extensions can monkey-patch `Math.floor()`, `crypto.getRandomValues()`
   - Dynamic typing allows silent type coercion bugs

2. **WASM provides isolation**:
   - Linear memory opaque to JavaScript
   - No prototype chain (immune to pollution)
   - Deterministic execution (no JIT variability)
   - Stack and heap isolated from JS heap

3. **C enables formal verification**:
   - Static types catch errors at compile time
   - Memory model is explicit (no hidden allocations)
   - Tools like Frama-C can prove correctness (planned)
   - Struct layout is deterministic (with verification)

4. **OpenSSL is battle-tested**:
   - NIST SP 800-90A certified DRBG
   - 25+ years of cryptographic engineering
   - FIPS 140-2 validated (some builds)
   - Precompiled for WASM by jedisct1

**Trade-offs**:
- ❌ Requires build step (cannot edit single HTML file)
- ❌ Larger initial download (~180KB vs ~10KB for pure JS)
- ✅ Cryptographic security guarantees
- ✅ Formal verification path

**Alternatives considered**:
- **Rust**: Excellent choice, but no precompiled OpenSSL WASM (would need to build from source)
- **AssemblyScript**: Too close to JavaScript (inherits some weaknesses)
- **Go**: Large runtime overhead (~2MB WASM)

---

## Why No JavaScript Fallback

### Decision: Disable generation if WASM unavailable

**Rationale**:

1. **Threat model violation**: Fallback breaks WASM isolation guarantee

2. **Silent downgrade attack**:
   ```
   Attacker blocks WASM load → JS fallback activates
   User thinks they have WASM security → they don't
   ```

3. **JavaScript crypto weaknesses** (detailed):
   ```javascript
   // Prototype pollution attack
   Object.prototype.valueOf = function() {
     console.log('Intercepted:', this);
     return 0; // All modulo operations return 0
   };
   
   const charset = "abc...xyz";
   const byte = crypto.getRandomValues(new Uint8Array(1))[0];
   const char = charset[byte % charset.length]; // Always charset[0]!
   ```

4. **Memory retention**:
   ```javascript
   const buffer = new Uint8Array(32);
   crypto.getRandomValues(buffer);
   const password = buildPassword(buffer);
   // buffer is still in heap, GC hasn't collected
   // Heap inspection tools can read it
   ```

**User experience**:
- Generate button disabled
- Status indicator: red
- Clear explanation of why fallback would be unsafe
- Alternatives shown:
  - GitHub Pages deployment (WASM works)
  - Build locally
  - Python CLI (if implemented)

**Edge case handling**:
- Check `WebAssembly` global at load
- Check WASM `Memory` and `instantiate` APIs
- Graceful error message (not just "undefined")

---

## Why Rejection Sampling

### Decision: Use rejection sampling instead of modulo for character selection

**The Modulo Bias Problem**:

```c
// BIASED (v1 approach)
uint8_t byte = rand_byte();  // 0-255
char c = charset[byte % 94];

// For N=94:
// - Chars 0-67 appear for bytes 0-67, 94-161, 188-255 (3 ranges) → P = 3/256
// - Chars 68-93 appear for bytes 68-93, 162-187 (2 ranges) → P = 2/256
// 
// This is a 50% bias (3/2 = 1.5x more likely)
```

**Entropy loss**:
```
Ideal entropy: 32 × log₂(94) = 209.75 bits
Biased entropy: 32 × log₂(94) - 1.75 = ~208 bits
Loss: 1.75 bits (3.3× weaker against brute force)
```

**Rejection Sampling Fix**:

```c
// UNBIASED (v2 approach)
int max_valid = (256 / N) * N - 1;  // 187 for N=94

uint8_t byte;
do {
    RAND_bytes(&byte, 1);
} while (byte > max_valid);  // Reject 188-255

char c = charset[byte % N];  // Now uniform over 0-187
```

**Why this works**:
- `max_valid = 187` means 188 valid values (0-187)
- 188 = 2 × 94 (exactly 2 full periods)
- Each character appears exactly twice in 0-187 range
- Bytes 188-255 rejected (26.56% rejection rate)

**Cost**:
- ~36% more RNG calls on average
- Minimal performance impact (~1-2ms per password)

**Alternatives considered**:
- **Bit masking**: Complex for N ≠ 2^k
- **Floating point**: Non-deterministic (FPU rounding modes)
- **Uniform int distribution**: Essentially same algorithm

---

## Why 7 Statistical Tests

### Decision: Run 7 independent statistical tests on generated passwords

**Rationale**:

1. **No single test proves randomness**
   - Chi-squared only checks frequency (not order)
   - Serial correlation only checks lag-1 (not patterns)
   - Each test has blind spots

2. **Defense in depth**
   - 7 independent checks
   - If one has a bug, others still provide signal
   - Increases attacker cost (must defeat all 7)

3. **User trust**
   - Visible audit process
   - Each stage shown with progress indicator
   - Failing any test shows red ✗ (not hidden)

**The 7 Layers**:

1. **Chi-Squared Test** — Frequency distribution
   - Detects: Non-uniform character selection
   - Blind to: Order, patterns, correlations

2. **Serial Correlation** — Adjacent character independence
   - Detects: Lag-1 autocorrelation (e.g., 'a' followed by 'b' too often)
   - Blind to: Longer-range patterns, frequencies

3. **Collision Detection** — Uniqueness in 500-password batch
   - Detects: Duplicate passwords (catastrophic PRNG failure)
   - Blind to: Near-collisions, distribution

4. **Entropy Proofs** — Information-theoretic lower bound
   - Detects: Low entropy (e.g., short passwords)
   - Blind to: Distribution quality (assumes uniform)

5. **Birthday Paradox** — Collision probability calculation
   - Detects: Search space too small
   - Blind to: Actual collisions (probability only)

6. **Pattern Detection** — Heuristic checks
   - Detects: Runs ('aaaa'), sequences ('abcd'), keyboard patterns
   - Blind to: Subtle statistical anomalies

7. **NIST Conformance** — Standards compliance
   - Detects: Below-threshold entropy (AAL1/AAL2/AAL3)
   - Blind to: Implementation quality

**Why not NIST SP 800-22?**
- 15 tests, each requires 1MB+ of data
- Too slow for browser (seconds → minutes)
- Overkill for password generation (vs stream cipher testing)
- Planned for future (optional deep test mode)

---

## Why CSS-Only Navigation

### Decision: Use hidden radio buttons + CSS `:checked` for wizard navigation

**HTML**:
```html
<input type="radio" name="wizard" id="step-configure" checked>
<input type="radio" name="wizard" id="step-audit">
<input type="radio" name="wizard" id="step-results">

<div class="page-wrapper">
  <div id="panel-configure">...</div>
  <div id="panel-audit">...</div>
  <div id="panel-results">...</div>
</div>
```

**CSS**:
```css
#step-configure:checked ~ .page-wrapper #panel-configure { display: block; }
#step-audit:checked ~ .page-wrapper #panel-audit { display: block; }
#step-results:checked ~ .page-wrapper #panel-results { display: block; }
```

**Rationale**:

1. **Reduces JavaScript surface**
   - No `addEventListener('click')` for navigation
   - No manual class toggling
   - Less code = less attack surface

2. **Declarative state management**
   - State is in the DOM (radio checked state)
   - CSS selectors are the "state machine"
   - Reviewers can read state transitions without running code

3. **Accessibility**
   - Radio buttons are focusable, keyboard-navigable
   - Screen readers understand radio groups
   - No custom ARIA needed

**Trade-offs**:
- ❌ Verbose CSS (explicit state combinations)
- ❌ Limited to simple transitions (no complex animations)
- ✅ Zero JavaScript for navigation
- ✅ Fully auditable state machine

---

## Why Separate Files

### Decision: Separate HTML, CSS, JavaScript into distinct files

**v1 structure** (monolithic):
```html
<!DOCTYPE html>
<html>
<head>
  <style>
    /* 200 lines of CSS */
  </style>
</head>
<body>
  <script>
    // 350 lines of JavaScript (including crypto logic)
  </script>
</body>
</html>
```

**v2 structure** (separated):
```
www/
├── index.html    # Structure only
├── style.css     # Styles only
└── app.js        # Logic only
```

**Rationale**:

1. **CodeQL file-type classification**:
   - `.html` → HTML linter (XSS, injection)
   - `.css` → CSS analyzer (injection, selectors)
   - `.js` → JavaScript analyzer (prototype pollution, XSS)
   - `.c` → C analyzer (buffer overflow, use-after-free)

2. **SAST tool efficiency**:
   - Each tool optimized for one language
   - Mixing languages confuses heuristics
   - False negatives increase

3. **Security review focus**:
   - Crypto logic in `src/paranoid.c` (400 lines, auditable)
   - Display logic in `www/app.js` (436 lines, no crypto)
   - Reviewers can ignore HTML/CSS when auditing crypto

4. **SRI hash granularity**:
   - Separate hash for JS, CSS, WASM
   - CSS change doesn't invalidate JS cache
   - Fine-grained integrity checks

**Trade-offs**:
- ❌ More HTTP requests (3 files vs 1)
- ❌ Slightly slower initial load (not cached)
- ✅ SAST tools work correctly
- ✅ Security review is tractable

---

## Why SHA-Pinned Actions

### Decision: Pin all GitHub Actions to 40-character commit SHAs

**Example**:
```yaml
# ✅ Correct (SHA-pinned)
uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2

# ❌ Wrong (mutable tag)
uses: actions/checkout@v4
```

**Rationale**:

1. **Tags are mutable**:
   ```bash
   git tag -f v4.2.2 <malicious-commit>
   git push --force --tags
   ```
   Attacker can retag to point to backdoored code.

2. **Real-world supply chain attacks**:
   - `tj-actions/changed-files` (March 2025): Tag retag compromised 23,000+ repos
   - `codecov/codecov-action` (2021): Token exfiltration
   - `SolarWinds` (2020): Build system compromise

3. **SHAs are immutable**:
   - Git commit SHAs are cryptographic hashes
   - Cannot change commit without changing SHA
   - Retagging doesn't affect SHA-pinned workflows

**Maintenance cost**:
- Dependabot updates are SHA-based (still automated)
- Renovate can update SHAs (configure once)
- Manual updates require lookup: `git ls-remote`

**Trade-offs**:
- ❌ Less readable (SHA vs version number)
- ❌ Requires tooling for updates
- ✅ Immune to tag retag attacks
- ✅ Supply chain security best practice

---

## Why SRI Hashes

### Decision: Inject Subresource Integrity hashes for all assets

**HTML with SRI**:
```html
<script src="app.js" 
        integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K..." 
        crossorigin="anonymous"></script>
```

**Rationale**:

1. **CDN/proxy tampering detection**:
   - Attacker intercepts HTTP response
   - Modifies `app.js` to include malicious code
   - Browser computes hash, mismatch → refuse to load

2. **Deployment integrity**:
   - GitHub Pages served via Fastly CDN
   - SRI ensures CDN compromise doesn't propagate

3. **Cache poisoning defense**:
   - Attacker poisons shared cache
   - SRI hash mismatch → cache miss → refetch
   - Prevents serving stale/malicious cached versions

**Build-time injection**:
```bash
# Makefile
WASM_HASH=$(shell openssl dgst -sha384 -binary build/paranoid.wasm | openssl base64 -A)
sed -i "s|__WASM_SRI__|sha384-${WASM_HASH}|g" build/site/index.html
```

**Algorithm choice (SHA-384)**:
- SHA-256: Adequate but SHA-1 collision attacks exist
- SHA-384: More conservative (truncated SHA-512)
- SHA-512: Overkill for SRI (larger hashes, minimal benefit)

**Trade-offs**:
- ❌ Breaks if hashes mismatch (requires rebuild)
- ❌ Inline editing impossible (hash must be recomputed)
- ✅ Detects tampering
- ✅ Required for production deployment

---

## Why Static Result Struct

### Decision: Use a static global struct for results instead of malloc

**Implementation**:
```c
// Static allocation (v2)
static paranoid_audit_result_t global_result;

int paranoid_run_audit(...) {
    // Populate global_result
    memset(&global_result, 0, sizeof(global_result));
    // ...
}

paranoid_audit_result_t* paranoid_get_result_ptr(void) {
    return &global_result;
}
```

**Rationale**:

1. **Deterministic address**:
   - Static struct always at same WASM memory address
   - JavaScript can cache pointer (doesn't change)
   - No malloc/free to track

2. **No memory management bugs**:
   - No use-after-free (never freed)
   - No double-free
   - No memory leaks

3. **Simplified JavaScript**:
   ```javascript
   const resultPtr = wasmExports.paranoid_get_result_ptr();
   // Always valid, never changes
   ```

4. **Struct offset verification**:
   - Offsets relative to start of struct
   - Static allocation = predictable layout
   - Runtime verification catches misalignment

**Trade-offs**:
- ❌ Not thread-safe (only one result at a time)
- ❌ Cannot run multiple audits concurrently
- ✅ No memory management complexity
- ✅ Deterministic behavior
- ✅ Easier to verify

**Why not malloc?**
```c
// Heap allocation (rejected)
paranoid_audit_result_t* result = malloc(sizeof(paranoid_audit_result_t));
// Who frees it? JavaScript? C? 
// What if JavaScript reads after C frees? (use-after-free)
```

---

## Design Evolution

| Aspect | v1 | v2 | Rationale |
|--------|----|----|-----------|
| Language | JavaScript | C + WASM | Crypto isolation, formal verification path |
| File structure | Monolithic HTML | Separated files | CodeQL classification |
| Randomness | `crypto.getRandomValues()` | OpenSSL DRBG | NIST-certified CSPRNG |
| Distribution | Modulo | Rejection sampling | Eliminate 50% bias |
| Fallback | Silent JS fallback | Fail-closed | No silent downgrades |
| Tests | 3 basic | 7-layer audit | Defense in depth |
| Navigation | JavaScript | CSS `:checked` | Reduce JS surface |
| Actions | Version tags | SHA pins | Supply chain security |
| Integrity | None | SRI hashes | Tamper detection |

---

## Future Design Considerations

### Reproducible Builds

**Goal**: Bit-for-bit identical WASM from same source.

**Challenges**:
- Zig embeds timestamps in WASM
- OpenSSL library path may vary
- Build machine differences

**Planned approach**:
- Use `SOURCE_DATE_EPOCH` (deterministic timestamps)
- Containerized builds (Docker, same environment)
- Verify build artifacts match across machines

### Formal Verification

**Goal**: Mathematical proof of correctness.

**Candidates**:
- Frama-C for C code (ACSL annotations)
- TLA+ for rejection sampling algorithm
- Coq for statistical test proofs

**Challenges**:
- OpenSSL calls are opaque (FFI)
- Floating-point arithmetic non-deterministic (x86 vs ARM)

### Post-Quantum Readiness

**Goal**: 256-bit entropy for quantum resistance.

**Implications**:
- Password length ≥39 chars (94^39 > 2^256)
- NIST SP 800-90C (post-quantum DRBG)
- Lattice-based KDF for derived passwords

---

## Conclusion

Every design decision in `paranoid` prioritizes:

1. **Security over convenience**
2. **Transparency over obfuscation**
3. **Fail-closed over fail-open**
4. **Auditability over cleverness**

The result is a system where every component can be independently verified, every trust boundary is explicit, and every security claim is backed by measurable properties.
