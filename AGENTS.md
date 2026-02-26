# AGENTS.md — paranoid

> **A self-auditing cryptographic password generator that treats the LLM as an adversary to its own output.**

---

## Project Name

**paranoid** — because the correct threat model for LLM-generated passwords is one where you trust nothing, including the system generating them.

## One-Line Summary

`paranoid` generates passwords via hardware CSPRNG, then subjects them to a 7-layer audit that includes statistical tests, breach analysis, formal entropy proofs, and — uniquely — a threat model where the LLM that built the tool is treated as a potential source of compromise.

---

## Why This Exists

### The Problem

When you ask an LLM to "generate a random password," it doesn't. It samples from a learned probability distribution over text that *looks like* passwords. This means:

1. **Training data leakage**: LLMs have ingested millions of passwords from breach dumps (RockYou, LinkedIn, Adobe). Their "random" output is statistically biased toward passwords that already exist in the wild.

2. **Token distribution bias**: The softmax output layer produces non-uniform character probabilities. The letter 'e' will appear far more often than 'z', even in "random" passwords. Effective entropy per character can drop from the theoretical 6.5 bits to as low as 3.2 bits.

3. **Deterministic reproduction**: Given the same or similar prompts, LLMs may produce identical passwords across sessions and users. This is a catastrophic uniqueness failure with no analog in traditional cryptography.

4. **Hallucinated security analysis**: The LLM will confidently claim its password has "256-bit entropy" when it might have 60. The analysis *sounds* right because the model has learned what security writing looks like — but it has no ground truth.

### The Solution

`paranoid` separates concerns:
- **Generation** is delegated to OpenSSL's CSPRNG (CLI) or the Web Crypto API (browser). The LLM never chooses a single character.
- **Audit** is performed with verifiable mathematics — every entropy claim includes the derivation so a human can check it.
- **Threat modeling** explicitly includes the LLM itself, creating a unique recursive security posture: the tool documents why you shouldn't fully trust the tool.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    USER INTERFACE                        │
│              (CLI: Python | Web: HTML/JS)                │
└────────────────────────┬────────────────────────────────┘
                         │
         ┌───────────────┼───────────────┐
         ▼               ▼               ▼
┌─────────────┐  ┌──────────────┐  ┌───────────────┐
│  GENERATOR  │  │   AUDITOR    │  │ THREAT MODEL  │
│             │  │              │  │               │
│ openssl rand│  │ χ² test      │  │ T1: Training  │
│ Web Crypto  │  │ Serial corr  │  │ T2: Token     │
│ /dev/urandom│  │ Runs test    │  │ T3: Determin  │
│             │  │ Collision    │  │ T4: Injection  │
│ + rejection │  │ HIBP k-anon  │  │ T5: Hallucin  │
│   sampling  │  │ Pattern scan │  │ T6: Exposure   │
└──────┬──────┘  └──────┬───────┘  └───────┬───────┘
       │                │                   │
       └────────────────┼───────────────────┘
                        ▼
              ┌───────────────────┐
              │  FORMAL PROOFS    │
              │                   │
              │ Entropy: H=L·log₂N│
              │ Uniqueness:       │
              │  Birthday paradox │
              │ Brute-force time  │
              │ NIST compliance   │
              └───────────────────┘
```

### Generation Layer

Both implementations use the same strategy:

1. Request raw random bytes from the OS CSPRNG
2. Apply **rejection sampling** to ensure uniform distribution over the character set
3. Map accepted bytes to characters via modular arithmetic

**Why rejection sampling matters**: If your charset has 94 characters but bytes have 256 values, `byte % 94` gives 68 characters a probability of 3/256 while 26 get 2/256. That's a ~50% bias for some characters. Rejection sampling discards bytes above the largest multiple of 94 that fits in a byte, making every character exactly equiprobable.

### Audit Layer

| Test | What It Catches | Method |
|------|----------------|--------|
| Chi-squared | Non-uniform character distribution | Pearson's χ² with Wilson-Hilferty p-value |
| Serial correlation | Adjacent-character dependency (e.g., 'q' always followed by 'u') | Lag-1 autocorrelation |
| Runs test | Clustering of character types | Wald-Wolfowitz |
| Collision check | Duplicate passwords in batch | Hash set membership |
| HIBP k-anonymity | Password exists in breach dumps | SHA-1 prefix API (5-char prefix preserves privacy) |
| Pattern scan | Keyboard walks, triple repeats, sequential runs | Regex + ordinal comparison |

### LLM Threat Model

This is what makes `paranoid` unique. Six threats are analyzed:

| ID | Threat | Severity | Mitigated By |
|----|--------|----------|-------------|
| T1 | Training data leakage | CRITICAL | CSPRNG delegation |
| T2 | Token distribution bias | HIGH | CSPRNG delegation |
| T3 | Cross-session determinism | HIGH | Hardware entropy seeding |
| T4 | Prompt injection steering | MEDIUM | Subprocess isolation (partial) |
| T5 | Hallucinated security claims | CRITICAL | Verifiable math (partial) |
| T6 | Conversation context exposure | HIGH | Run locally (advisory) |

**T5 is the most important threat** — it's the reason this document exists. An LLM can write a security tool that *appears* correct, passes its own tests, and generates plausible analysis, but contains subtle mathematical errors that neither the LLM nor a non-expert user would catch. `paranoid` mitigates this by showing all work and recommending human review.

---

## Implementations

### 1. CLI (`password_auditor.py`)

- **Runtime**: Python 3.8+, OpenSSL
- **Entropy source**: `openssl rand` subprocess → rejection sampling
- **Audit**: Full 7-layer suite with 500-password statistical batch
- **Output**: Structured terminal report with formal proofs

```bash
python3 password_auditor.py
```

### 2. Web (`index.html`)

- **Runtime**: Any modern browser (Chrome, Firefox, Safari, Edge)
- **Entropy source**: `crypto.getRandomValues()` (Web Crypto API) → rejection sampling
- **Audit**: Real-time statistical tests on configurable batch size
- **Hosting**: Static HTML — works on GitHub Pages, Netlify, or `file://`
- **Zero dependencies**: No npm, no build step, no frameworks

```bash
# Local
open index.html

# GitHub Pages
# Just push to `main` branch and enable Pages in repo settings
```

---

## Mathematical Foundations

### Entropy Proof

For a password of length `L` drawn uniformly from an alphabet of size `N`:

```
H(password) = L × log₂(N)
```

**Proof**: Each character Xᵢ is an independent uniform random variable over {1, ..., N}. Shannon entropy of Xᵢ is H(Xᵢ) = log₂(N). By independence, H(X₁, ..., Xₗ) = Σ H(Xᵢ) = L × log₂(N). ∎

For the default configuration (L=32, N=94): **H = 209.75 bits**.

### Uniqueness Proof (Birthday Paradox)

The probability of at least one collision among `k` passwords from a space of size `S = N^L`:

```
P(collision) ≈ 1 - e^(-k² / 2S)
```

For S = 94³² ≈ 1.38 × 10⁶³, you would need approximately 4.37 × 10³¹ passwords before reaching a 50% collision probability. At 1 billion passwords per second, this would take ~1.39 × 10¹⁵ years — about 100,000× the age of the universe.

### Brute-Force Resistance

| Attack Speed | Time to Exhaust (expected) |
|---|---|
| 10⁹ hashes/sec (GPU cluster) | 2.19 × 10⁴⁶ years |
| 10¹⁰ hashes/sec (nation-state) | 2.19 × 10⁴⁵ years |
| 10¹² hashes/sec (theoretical) | 2.19 × 10⁴³ years |

---

## Honest Limitations

1. **This code was written by an LLM.** The cryptographic primitives (OpenSSL, Web Crypto) are sound, but the glue code — rejection sampling boundaries, statistical test implementations, p-value approximations — could contain subtle errors that the LLM cannot detect in its own output.

2. **The statistical tests are necessary but not sufficient.** Passing χ² and serial correlation tests does not *prove* randomness — it proves the output is consistent with randomness. A cleverly backdoored generator could pass these tests while constraining the output space.

3. **The HIBP check requires network access.** The CLI version validates the k-anonymity framework but cannot perform the actual API call in network-restricted environments. The web version can perform live checks.

4. **Passwords displayed anywhere are compromised.** Whether in a terminal, browser, or conversation — if it was displayed, assume it was observed. Production use should pipe directly to a password manager.

5. **This threat model is not peer-reviewed.** The six LLM-specific threats (T1–T6) are derived from the author's analysis of LLM failure modes, not from published security research. They should be treated as a starting framework, not a complete taxonomy.

---

## Contributing

We welcome contributions, especially:

- **Cryptographer review** of the rejection sampling and statistical test implementations
- **Additional statistical tests** (e.g., NIST SP 800-22 suite, Dieharder)
- **New LLM threat vectors** as the field evolves
- **Accessibility improvements** to the web frontend
- **Internationalization** of the charset and documentation

### Code of Conduct

This is a security tool. Contributions that weaken the security posture — even subtly — will be rejected. This includes:
- Reducing charset without justification
- Replacing CSPRNG with PRNG
- Removing or weakening statistical tests
- Suppressing threat model warnings

---

## License

MIT — but read the honest limitations section before deploying to production.

---

## FAQ

**Q: Why not just use a password manager's built-in generator?**
A: You should! This tool exists to (a) demonstrate what a trustworthy generation process looks like, (b) provide a framework for auditing *any* generator, and (c) formalize the LLM-specific threat model that no password manager addresses.

**Q: Is the web version as secure as the CLI?**
A: The entropy source is equivalent — `crypto.getRandomValues()` uses the same OS CSPRNG as `/dev/urandom`. The difference is the execution environment: browsers have a larger attack surface (extensions, XSS, screenshot tools).

**Q: Can I use this in production?**
A: The *generation algorithm* is production-grade. The *implementation* should be reviewed by a cryptographer first — see Honest Limitations #1.

**Q: Why is "hallucinated security claims" rated CRITICAL?**
A: Because it's the only threat that can make all other threats invisible. If the LLM incorrectly reports "all tests passed" for a biased generator, the user has no way to know — the analysis looks just as plausible as a correct one. This is why all math is shown explicitly.
