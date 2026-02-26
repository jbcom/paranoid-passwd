# Statistical Audit Methodology

This document describes the 7-layer statistical audit system used to verify
cryptographic randomness in generated passwords.

**v3.0 additions**: Known-answer tests for chi-squared and serial correlation
(`tests/test_statistics.c`), NIST CAVP SHA-256 test vectors
(`tests/test_sha256.c`), Frama-C ACSL annotations for formal verification
(`include/paranoid_frama.h`), compliance framework checking (NIST, PCI-DSS,
HIPAA, SOC2, GDPR, ISO 27001).

---

## Table of Contents

- [Overview](#overview)
- [Layer 1: Chi-Squared Test](#layer-1-chi-squared-test)
- [Layer 2: Serial Correlation](#layer-2-serial-correlation)
- [Layer 3: Collision Detection](#layer-3-collision-detection)
- [Layer 4: Entropy Proofs](#layer-4-entropy-proofs)
- [Layer 5: Birthday Paradox](#layer-5-birthday-paradox)
- [Layer 6: Pattern Detection](#layer-6-pattern-detection)
- [Layer 7: NIST Conformance](#layer-7-nist-conformance)
- [Test Parameters](#test-parameters)
- [Pass Criteria](#pass-criteria)
- [Known Limitations](#known-limitations)
- [Verification](#verification)

---

## Overview

The audit system runs **7 independent statistical tests** on generated passwords. Each test targets a different cryptographic property:

| Layer | Property Tested | Blind Spots |
|-------|----------------|-------------|
| 1. Chi-Squared | Uniform frequency distribution | Order, correlations |
| 2. Serial Correlation | Independence (adjacent chars) | Long-range patterns |
| 3. Collision Detection | Uniqueness in batch | Distribution quality |
| 4. Entropy Proofs | Information-theoretic lower bound | Assumes uniformity |
| 5. Birthday Paradox | Collision probability | Actual collisions |
| 6. Pattern Detection | Heuristic checks | Subtle statistical anomalies |
| 7. NIST Conformance | Standards compliance | Implementation quality |

**Defense in Depth**: Each test has blind spots, but together they provide comprehensive coverage.

---

## Layer 1: Chi-Squared Test

### Purpose
Verify that character frequencies match expected uniform distribution.

### Null Hypothesis
H₀: Character frequencies follow uniform distribution (each char has equal probability).

### Test Statistic

```
χ² = Σ (Oᵢ - Eᵢ)² / Eᵢ

Where:
- Oᵢ = Observed frequency of character i
- Eᵢ = Expected frequency of character i
- Sum over all N characters in charset
```

### Implementation

```c
double paranoid_chi_squared(const char *password, int length,
                             const char *charset, int charset_len)
{
    int observed[256] = {0};
    double expected = (double)length / charset_len;
    
    // Count character frequencies
    for (int i = 0; i < length; i++) {
        for (int j = 0; j < charset_len; j++) {
            if (password[i] == charset[j]) {
                observed[j]++;
                break;
            }
        }
    }
    
    // Compute chi-squared statistic
    double chi2 = 0.0;
    for (int i = 0; i < charset_len; i++) {
        double diff = observed[i] - expected;
        chi2 += (diff * diff) / expected;
    }
    
    return chi2;
}
```

### Degrees of Freedom

```
df = N - 1

For N=94 (printable ASCII): df = 93
```

### P-Value Calculation

Using **Wilson-Hilferty approximation** (not exact chi-squared CDF):

```c
double wilson_hilferty_p_value(double chi2, int df)
{
    double z = pow(chi2 / df, 1.0/3.0) - (1.0 - 2.0/(9.0*df));
    z /= sqrt(2.0 / (9.0 * df));
    
    // Approximate p-value using complementary error function
    return 0.5 * erfc(z / sqrt(2.0));
}
```

**Why Wilson-Hilferty?**
- Exact CDF requires gamma function (complex)
- Approximation accurate for large df (our case: df=93)
- Computational efficiency (no special functions)

**Limitation**: Conservative for small samples (under-rejects H₀).

### Pass Criteria

```
p-value > 0.01 (fail to reject H₀ at 1% significance)
```

**Interpretation**:
- High p-value (>0.01): Data consistent with uniform distribution
- Low p-value (<0.01): Data inconsistent with uniform (reject)

### What This Detects
- ✅ Character frequency bias (some chars more common)
- ✅ Modulo bias (residual after poor rejection sampling)
- ❌ Does NOT detect: Order dependencies, patterns, runs

### Known Vulnerabilities (LLM-specific)

**Hallucination Risk**: LLM could implement:
```c
// WRONG: Inverted pass logic
int chi2_pass = (p_value < 0.01);  // Should be > 0.01

// WRONG: Incorrect degrees of freedom
double chi2 = compute_chi2(..., df = N);  // Should be N-1

// WRONG: Missing p-value calculation
return (chi2 < threshold);  // Arbitrary threshold, no p-value
```

**Verification**:
- [ ] Compare against NIST test vectors
- [ ] Verify df = N-1 (not N)
- [ ] Verify p-value > 0.01 passes (not <)
- [ ] Test with biased input (should fail)

---

## Layer 2: Serial Correlation

### Purpose
Verify independence between adjacent characters (no lag-1 autocorrelation).

### Null Hypothesis
H₀: Adjacent characters are independent (correlation ≈ 0).

### Test Statistic

```
r = Σ(xᵢ - x̄)(xᵢ₊₁ - x̄) / Σ(xᵢ - x̄)²

Where:
- xᵢ = Numeric value of character i
- x̄ = Mean character value
- Sum over positions 0 to L-2 (lag-1 pairs)
```

### Implementation

```c
double paranoid_serial_correlation(const char *password, int length,
                                    const char *charset, int charset_len)
{
    // Map characters to indices
    int indices[256];
    for (int i = 0; i < length; i++) {
        for (int j = 0; j < charset_len; j++) {
            if (password[i] == charset[j]) {
                indices[i] = j;
                break;
            }
        }
    }
    
    // Compute mean
    double mean = 0.0;
    for (int i = 0; i < length; i++) {
        mean += indices[i];
    }
    mean /= length;
    
    // Compute correlation
    double numerator = 0.0, denominator = 0.0;
    for (int i = 0; i < length - 1; i++) {
        double diff_i = indices[i] - mean;
        double diff_next = indices[i+1] - mean;
        numerator += diff_i * diff_next;
        denominator += diff_i * diff_i;
    }
    
    return numerator / denominator;
}
```

### Pass Criteria

```
|r| < 0.05 (weak correlation threshold)
```

**Interpretation**:
- r ≈ 0: No correlation (independent)
- r > 0: Positive correlation (similar chars adjacent)
- r < 0: Negative correlation (dissimilar chars adjacent)

### What This Detects
- ✅ Lag-1 dependencies (e.g., 'a' often followed by 'b')
- ✅ Markov chain bias (state-dependent generation)
- ❌ Does NOT detect: Longer-range patterns (lag > 1), frequency bias

### Known Limitations
- Only tests lag-1 (not lag-2, lag-3, etc.)
- Threshold 0.05 is heuristic (not statistically rigorous)
- Small sample size (32 chars) reduces power

---

## Layer 3: Collision Detection

### Purpose
Verify uniqueness in a batch of passwords (detect catastrophic PRNG failures).

### Null Hypothesis
H₀: All passwords in batch are unique.

### Method

```
1. Generate batch of K passwords (K = 500)
2. Compute SHA-256 hash of each password
3. Count duplicate hashes
4. Pass if duplicates = 0
```

### Implementation

```c
int paranoid_count_collisions(int batch_size, int pw_length,
                               const char *charset, int charset_len)
{
    unsigned char hashes[batch_size][32];  // SHA-256 = 32 bytes
    
    // Generate batch and hash each password
    for (int i = 0; i < batch_size; i++) {
        char password[257];
        paranoid_generate(charset, charset_len, pw_length, password);
        paranoid_sha256((unsigned char*)password, pw_length, hashes[i]);
    }
    
    // Count collisions
    int collisions = 0;
    for (int i = 0; i < batch_size; i++) {
        for (int j = i + 1; j < batch_size; j++) {
            if (memcmp(hashes[i], hashes[j], 32) == 0) {
                collisions++;
            }
        }
    }
    
    return collisions;
}
```

### Why SHA-256 Instead of strcmp?

**Security**: Avoids variable-length string comparison that leaks password length via timing.

```c
// UNSAFE: strcmp leaks timing information about password content/length
if (strcmp(pw1, pw2) == 0) { ... }

// BETTER: memcmp on fixed-size hashes — fixed comparison length (32 bytes)
// Note: memcmp itself is NOT constant-time (it short-circuits on first
// difference), but here we only compare hashes — not secrets — so timing
// leaks reveal nothing about the original passwords.
if (memcmp(hash1, hash2, 32) == 0) { ... }
```

### Pass Criteria

```
collisions = 0 (no duplicates)
```

### Expected Collision Rate

For K=500, N=94, L=32:

```
Search space S = 94³² ≈ 1.38 × 10⁶³

Birthday paradox:
P(collision) ≈ 1 - e^(-K²/2S)
            ≈ 1 - e^(-250000 / 2.76×10⁶³)
            ≈ 0 (below float64 precision)
```

**Conclusion**: Finding a collision in 500 passwords is astronomically unlikely.

### What This Detects
- ✅ Catastrophic PRNG failure (stuck state, zero output)
- ✅ Extremely small search space
- ❌ Does NOT detect: Distribution quality, subtle bias

---

## Layer 4: Entropy Proofs

### Purpose
Calculate information-theoretic entropy and verify against NIST standards.

### Shannon Entropy

```
H(X) = L × log₂(N)

Where:
- L = Password length (characters)
- N = Charset size (number of possible characters)
```

### For L=32, N=94:

```
H = 32 × log₂(94)
  = 32 × 6.554588851677637
  = 209.74684325368437 bits
```

### Search Space

```
S = N^L = 94³² ≈ 1.38 × 10⁶³
```

### Brute-Force Resistance

Assuming 10¹² hash/s (modern GPU farm):

```
Time = S / (rate × 60 × 60 × 24 × 365)
     = 1.38 × 10⁶³ / (10¹² × 31,536,000)
     ≈ 2.19 × 10⁴³ years
     ≈ 10³³ × age of universe (13.8 billion years)
```

### NIST SP 800-63B Thresholds

| Authenticator Assurance Level | Entropy Requirement | L=32, N=94 |
|-------------------------------|---------------------|------------|
| AAL1 (Memorized Secret) | ≥30 bits | ✅ 209.75 bits |
| AAL2 (High-Value Asset) | ≥80 bits | ✅ 209.75 bits |
| AAL3 (Crypto-Equivalent) | ≥128 bits | ✅ 209.75 bits |
| Post-Quantum (CNSA 2.0) | ≥256 bits | ❌ 209.75 bits (need L≥39) |

### Implementation

```c
void paranoid_compute_entropy(int pw_length, int charset_size,
                               paranoid_audit_result_t *result)
{
    double bits_per_char = log2(charset_size);
    double total_entropy = pw_length * bits_per_char;
    double log10_space = pw_length * log10(charset_size);
    
    // Brute-force time at 10^12 hash/s
    double operations = pow(charset_size, pw_length);
    double seconds = operations / 1e12;
    double years = seconds / (365.25 * 24 * 60 * 60);
    
    result->bits_per_char = bits_per_char;
    result->total_entropy = total_entropy;
    result->log10_search_space = log10_space;
    result->brute_force_years = years;
    
    // NIST conformance
    result->nist_memorized = (total_entropy >= 30);
    result->nist_high_value = (total_entropy >= 80);
    result->nist_crypto_equiv = (total_entropy >= 128);
    result->nist_post_quantum = (total_entropy >= 256);
}
```

### What This Detects
- ✅ Low entropy (short passwords, small charsets)
- ✅ Below NIST thresholds
- ❌ Does NOT detect: Non-uniform distribution (assumes ideal)

---

## Layer 5: Birthday Paradox

### Purpose
Calculate collision probability for given batch size.

### Formula

```
P(collision) ≈ 1 - e^(-k²/2S)

Where:
- k = Number of passwords in batch
- S = Search space (N^L)
```

### 50% Collision Threshold

```
k₅₀ = 1.177 × √S

For S = 94³²:
k₅₀ ≈ 4.37 × 10³¹ passwords
```

**Interpretation**: Need 4.37 × 10³¹ passwords before 50% chance of collision.

### Implementation

```c
void paranoid_birthday_paradox(int batch_size, int pw_length,
                                int charset_size,
                                paranoid_audit_result_t *result)
{
    double S = pow(charset_size, pw_length);
    double k = batch_size;
    
    // Collision probability
    double exponent = -(k * k) / (2.0 * S);
    double P = 1.0 - exp(exponent);
    
    // 50% threshold
    double k50 = 1.177 * sqrt(S);
    
    result->collision_probability = P;
    result->passwords_for_50pct = k50;
}
```

### What This Detects
- ✅ Insufficient search space
- ✅ Batch size too large for comfort
- ❌ Does NOT detect: Actual collisions (probability only)

---

## Layer 6: Pattern Detection

### Purpose
Heuristic checks for common weak patterns.

### Patterns Checked

1. **Runs** — Repeated characters
   ```
   "aaaa", "1111", "!!!!"
   ```

2. **Sequences** — Sequential ASCII values
   ```
   "abcd", "1234", "WXYZ"
   ```

3. **Keyboard patterns** — Common keyboard layouts
   ```
   "qwerty", "asdfgh", "zxcvbn"
   ```

### Implementation

```c
int paranoid_detect_patterns(const char *password, int length)
{
    int issues = 0;
    
    // Check for runs (length ≥ 4)
    for (int i = 0; i < length - 3; i++) {
        if (password[i] == password[i+1] &&
            password[i] == password[i+2] &&
            password[i] == password[i+3]) {
            issues++;
        }
    }
    
    // Check for sequences (length ≥ 4)
    for (int i = 0; i < length - 3; i++) {
        if ((password[i+1] == password[i] + 1) &&
            (password[i+2] == password[i] + 2) &&
            (password[i+3] == password[i] + 3)) {
            issues++;
        }
    }
    
    // Check for keyboard patterns
    const char *kb_patterns[] = {
        "qwerty", "asdfgh", "zxcvbn",
        "qaz", "wsx", "edc",
        NULL
    };
    for (int i = 0; kb_patterns[i]; i++) {
        if (strstr(password, kb_patterns[i])) {
            issues++;
        }
    }
    
    return issues;
}
```

### Pass Criteria

```
pattern_issues = 0 (no patterns detected)
```

### Known Limitations
- Heuristic-based (not statistically rigorous)
- Keyboard patterns are English QWERTY (not international)
- Cannot detect all possible patterns (infinite space)

### What This Detects
- ✅ Obvious weak patterns (runs, sequences)
- ✅ Common keyboard patterns
- ❌ Does NOT detect: Subtle statistical structure

---

## Layer 7: NIST Conformance

### Purpose
Verify compliance with NIST SP 800-63B entropy requirements.

### NIST Levels

| Level | Use Case | Entropy | L=32, N=94 |
|-------|----------|---------|------------|
| AAL1 | Memorized secrets (passwords) | ≥30 bits | ✅ Pass |
| AAL2 | High-value accounts | ≥80 bits | ✅ Pass |
| AAL3 | Cryptographic equivalence | ≥128 bits | ✅ Pass |
| CNSA 2.0 | Post-quantum resistance | ≥256 bits | ❌ Fail (need L≥39) |

### Implementation

```c
void paranoid_nist_conformance(double entropy,
                                paranoid_audit_result_t *result)
{
    result->nist_memorized = (entropy >= 30.0);
    result->nist_high_value = (entropy >= 80.0);
    result->nist_crypto_equiv = (entropy >= 128.0);
    result->nist_post_quantum = (entropy >= 256.0);
}
```

### What This Detects
- ✅ Below-threshold entropy
- ✅ Non-compliance with federal standards
- ❌ Does NOT detect: Implementation flaws

---

## Test Parameters

### Defaults

```c
#define DEFAULT_CHARSET "abcdefghijklmnopqrstuvwxyz" \
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
                        "0123456789" \
                        "!@#$%^&*()_+-=[]{}|;:,.<>?"

#define DEFAULT_LENGTH 32
#define DEFAULT_BATCH_SIZE 500
```

### Configurable

- Charset (any subset of printable ASCII)
- Password length (1-256 characters)
- Batch size for collision test (1-10000)

---

## Pass Criteria

All 7 layers must pass:

```
✅ Layer 1: p_value > 0.01
✅ Layer 2: |r| < 0.05
✅ Layer 3: collisions = 0
✅ Layer 4: entropy >= 30 bits
✅ Layer 5: P(collision) < 0.001
✅ Layer 6: pattern_issues = 0
✅ Layer 7: nist_memorized = true
```

If ANY layer fails, `all_pass = 0`.

---

## Known Limitations

### 1. Wilson-Hilferty Approximation
- Not exact chi-squared CDF
- Conservative for small samples
- Verified for df ≥ 30 (our case: df=93)

### 2. Serial Correlation Lag-1 Only
- Doesn't detect longer-range patterns
- Power reduced by small sample (L=32)

### 3. Collision Test Sample Size
- 500 passwords insufficient for birthday paradox validation
- Would need ~10³¹ for rigorous testing

### 4. Pattern Detection Heuristics
- Cannot enumerate all possible patterns
- QWERTY-specific (not international keyboards)

### 5. Assumes Correct Implementation
- If this code is LLM-authored and wrong, tests pass wrong data
- **T5: Hallucinated Security Claims** is the meta-threat

---

## Verification

### Known-Answer Tests (Planned)

```c
// Test with biased input (should fail)
void test_chi2_detects_bias() {
    const char *biased = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";  // All 'a'
    double chi2 = paranoid_chi_squared(biased, 32, charset, 94);
    double p = wilson_hilferty_p_value(chi2, 93);
    assert(p < 0.01);  // Should reject
}

// Test with uniform input (should pass)
void test_chi2_accepts_uniform() {
    // Use NIST test vector (known-good uniform data)
    const char *uniform = load_nist_vector("chi2_uniform.txt");
    double chi2 = paranoid_chi_squared(uniform, 32, charset, 94);
    double p = wilson_hilferty_p_value(chi2, 93);
    assert(p > 0.01);  // Should accept
}
```

### Cross-Implementation Testing (Planned)

Compare outputs against:
- Python `scipy.stats.chisquare()`
- R `chisq.test()`
- Julia `ChisqTest()`

If all agree → formula likely correct.

### Human Review Checklist

- [ ] Chi-squared formula matches textbook (Pearson 1900)
- [ ] Degrees of freedom = N-1 (not N)
- [ ] P-value interpretation correct (> 0.01 passes, not <)
- [ ] Rejection sampling max_valid = (256/N)*N - 1 (off-by-one check)
- [ ] Serial correlation uses lag-1 pairs (not all pairs)
- [ ] SHA-256 used for collision (not strcmp)

---

## Conclusion

The 7-layer audit provides defense in depth, but **no statistical test proves cryptographic randomness**. They prove consistency with randomness, not randomness itself.

**The only true verification is**:
1. Mathematical proof of algorithm correctness (formal verification)
2. Human review by cryptographers
3. Known-answer testing against published standards

This system should be reviewed by a **human cryptographer** before production use.
