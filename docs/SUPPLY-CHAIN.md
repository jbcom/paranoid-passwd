# Supply Chain Security & Build Provenance

**CRITICAL: This document describes the COMPLETE supply chain security framework for paranoid, designed to detect and prevent attacks at EVERY stage of compilation, with ZERO trust assumptions.**

---

## Table of Contents

- [Zero-Trust Build Model](#zero-trust-build-model)
- [Build Provenance Ledger](#build-provenance-ledger)
- [Reproducible Build Protocol](#reproducible-build-protocol)
- [Multi-Party Verification](#multi-party-verification)
- [Dependency Verification](#dependency-verification)
- [Compiler Verification](#compiler-verification)
- [LLM Clean Room Protocol](#llm-clean-room-protocol)
- [Attestation Framework](#attestation-framework)

---

## Zero-Trust Build Model

### Core Principle

**TRUST NOTHING. VERIFY EVERYTHING.**

```
UNTRUSTED ZONE          VERIFICATION BARRIER          TRUSTED ZONE
───────────────         ────────────────────          ────────────
LLM-authored code    →  Human cryptographer review  →  Audited code
Source-built deps    →  Tag + commit SHA verification →  Pinned dependencies
Zig compiler         →  Reproducible builds         →  Verified binary
GitHub Actions       →  SHA-pinned actions          →  Immutable workflow
Build artifacts      →  Multi-party attestation     →  Signed WASM
Deployed assets      →  SRI hash verification       →  Tamper-proof site
```

### Threat Actors

1. **LLM (this code's author)** — Primary adversary, may hallucinate or inject backdoors
2. **Compromised dependencies** — Zig, melange/apko, GitHub Actions (native: OpenSSL; WASM: sha256_compact.c)
3. **Build environment** — GitHub-hosted runners, CI/CD pipeline
4. **Deployment infrastructure** — GitHub Pages, CDN (Fastly)
5. **Browser environment** — Extensions, DevTools, malicious scripts

---

## Build Provenance Ledger

### Purpose

**Cryptographic ledger** recording EVERY input, tool, and output in the build process.

### Ledger Format

```json
{
  "version": "1.0",
  "build_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2026-02-26T03:00:00Z",
  
  "source": {
    "repository": "https://github.com/jbcom/paranoid-passwd.git",
    "commit": "bc727e2a1f3e4b5c6d7e8f9a0b1c2d3e4f5a6b7c",
    "branch": "main",
    "commit_date": "2026-02-26T02:45:00Z",
    "commit_author": "jbdevprimary <2650679+jbdevprimary@users.noreply.github.com>",
    "commit_signature": "GPG key ABC123...",
    "files": {
      "src/paranoid.c": {
        "sha256": "a1b2c3d4e5f6...",
        "lines": 400,
        "llm_authored": true,
        "human_reviewed": false
      },
      "include/paranoid.h": {
        "sha256": "b2c3d4e5f6g7...",
        "lines": 249,
        "llm_authored": true,
        "human_reviewed": false
      }
    }
  },
  
  "dependencies": {
    "sha256_compact": {
      "type": "bundled_source",
      "path": "src/sha256_compact.c",
      "description": "Minimal SHA-256 for WASM build (no OpenSSL dependency)",
      "sha256": "a1b2c3d4e5f6...",
      "verified_against": "NIST FIPS 180-4 test vectors (tests/test_sha256.c)"
    },
    "note": "OpenSSL is NOT used in the WASM build. WASM uses WASI random_get() + sha256_compact.c. Native CLI uses system OpenSSL."
  },

  "tools": {
    "zig": {
      "version": "0.13.0",
      "binary_path": "/usr/bin/zig",
      "sha256": "f6g7h8i9j0k1...",
      "source": "melange-built from Wolfi (not downloaded tarball)"
    },
    "melange": {
      "version": "latest",
      "purpose": "Reproducible APK package builder"
    },
    "apko": {
      "version": "latest",
      "purpose": "Distroless OCI image assembler"
    }
  },
  
  "build_environment": {
    "os": "ubuntu-24.04",
    "kernel": "6.5.0-1022-azure",
    "arch": "x86_64",
    "runner": "github-hosted",
    "runner_id": "runner-abcd1234",
    "workflow_run_id": "123456789",
    "workflow_sha": "11bd71901bbe5b1630ceea73d27597364c9af683"
  },
  
  "compilation": {
    "command": "zig cc -target wasm32-wasi -I include -O3 -flto -fno-stack-protector -o build/paranoid.wasm src/paranoid.c src/sha256_compact.c src/wasm_entry.c",
    "flags": ["-target", "wasm32-wasi", "-O3", "-flto"],
    "duration_ms": 4523,
    "peak_memory_mb": 256,
    "cpu_time_ms": 3891
  },
  
  "outputs": {
    "build/paranoid.wasm": {
      "size_bytes": 184320,
      "sha256": "h8i9j0k1l2m3...",
      "sha384": "sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K...",
      "exports": [
        "paranoid_run_audit",
        "paranoid_generate",
        "paranoid_get_result_ptr",
        "paranoid_offset_password",
        "paranoid_offset_chi2_statistic",
        "paranoid_offset_all_pass"
      ],
      "imports": [
        "wasi_snapshot_preview1.random_get"
      ]
    },
    "build/site/index.html": {
      "size_bytes": 10234,
      "sha256": "i9j0k1l2m3n4...",
      "sri_injected": true,
      "wasm_sri": "sha384-oqVu...",
      "js_sri": "sha384-9rGH...",
      "css_sri": "sha384-BcDe..."
    }
  },
  
  "attestations": [
    {
      "type": "builder_signature",
      "builder": "github-actions-bot",
      "signature": "GPG signature...",
      "timestamp": "2026-02-26T03:00:05Z"
    },
    {
      "type": "reproducible_build_verification",
      "verifier": "independent-builder-1",
      "binary_hash_match": true,
      "timestamp": "2026-02-26T03:05:00Z"
    }
  ],
  
  "audit_trail": [
    {
      "stage": "source_checkout",
      "timestamp": "2026-02-26T02:59:00Z",
      "action": "git clone",
      "result": "success"
    },
    {
      "stage": "dependency_verification",
      "timestamp": "2026-02-26T02:59:30Z",
      "action": "Verify sha256_compact.c against NIST test vectors",
      "result": "success"
    },
    {
      "stage": "melange_build",
      "timestamp": "2026-02-26T02:59:45Z",
      "action": "melange build melange.yaml (reproducible APK)",
      "result": "success"
    },
    {
      "stage": "compilation",
      "timestamp": "2026-02-26T03:00:00Z",
      "action": "zig cc ...",
      "result": "success",
      "warnings": 0,
      "errors": 0
    },
    {
      "stage": "verification",
      "timestamp": "2026-02-26T03:00:10Z",
      "action": "wasm-objdump exports check",
      "result": "success",
      "exports_found": 15,
      "exports_expected": 15
    }
  ]
}
```

### Ledger Storage

```
build/
├── paranoid.wasm
├── site/
│   ├── index.html
│   ├── paranoid.wasm
│   ├── app.js
│   ├── style.css
│   └── BUILD_MANIFEST.json (public subset)
└── PROVENANCE.json (full ledger, signed)
```

**Public**: `BUILD_MANIFEST.json` (deployed with site)  
**Internal**: `PROVENANCE.json` (full audit trail, CI artifact)

---

## Reproducible Build Protocol

### Goal

**ANY builder, on ANY machine, produces BIT-FOR-BIT IDENTICAL WASM.**

### Protocol Steps

#### 1. Environment Setup

```bash
# Use melange/apko for deterministic environment (replaces Docker)
# melange builds APK packages from source in a reproducible manner
melange build melange.yaml --arch x86_64 --signing-key melange.rsa

# apko assembles a minimal OCI image from APK packages (distroless, no shell)
apko build apko.yaml ghcr.io/jbcom/paranoid-passwd:latest output.tar

# For local reproducibility verification:
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) \
  melange build melange.yaml --arch x86_64 --signing-key melange.rsa
```

**Key variables**:
- `SOURCE_DATE_EPOCH` — Deterministic timestamp (git commit time)
- `LANG=C` — Consistent locale
- `TZ=UTC` — Consistent timezone

#### 2. Source Verification

```bash
# Verify commit signature
git verify-commit HEAD

# Verify no local modifications
git diff --exit-code || { echo "Uncommitted changes!"; exit 1; }

# Verify melange package provenance
# melange records build inputs, toolchain versions, and source hashes in APK metadata
melange package-info output/packages/x86_64/paranoid-passwd-*.apk
# Should show: pinned source commit, Zig compiler version, build timestamp
```

#### 3. Tool Verification

```bash
# Verify Zig compiler via melange-provided package
# melange builds Zig from source as a Wolfi APK — no downloaded tarballs
apk info -L zig | grep "usr/bin/zig"
ZIG_HASH=$(sha256sum /usr/bin/zig | cut -d' ' -f1)
EXPECTED_ZIG_HASH="f6g7h8i9j0k1..."
[ "$ZIG_HASH" = "$EXPECTED_ZIG_HASH" ] || { echo "Zig compiler mismatch!"; exit 1; }

# Verify Zig APK provenance (melange records build inputs)
melange package-info output/packages/x86_64/zig-*.apk
```

#### 4. Build

```bash
# Clean build with CMake
cmake -B build -DCMAKE_BUILD_TYPE=Release \
  -DSOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
cmake --build build --clean-first

# Or via melange for fully reproducible package build
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) \
LANG=C \
TZ=UTC \
melange build melange.yaml --arch x86_64 --signing-key melange.rsa
```

#### 5. Verification

```bash
# Compute hash
WASM_HASH=$(sha256sum build/paranoid.wasm | cut -d' ' -f1)

# Compare against reference
REFERENCE_HASH="h8i9j0k1l2m3..."
if [ "$WASM_HASH" = "$REFERENCE_HASH" ]; then
  echo "✅ Reproducible build verified!"
else
  echo "❌ Hash mismatch!"
  echo "Expected: $REFERENCE_HASH"
  echo "Got:      $WASM_HASH"
  exit 1
fi
```

---

## Multi-Party Verification

### 3-of-5 Threshold Attestation

**Requirement**: 3 independent builders must produce identical binary before deployment.

### Builders

1. **GitHub Actions** (primary CI/CD)
2. **Independent Builder 1** (community volunteer, different cloud provider)
3. **Independent Builder 2** (community volunteer, different OS)
4. **Independent Builder 3** (security researcher, local machine)
5. **Independent Builder 4** (backup verifier)

### Process

```
1. GitHub Actions builds → hash_1 = h8i9j0k1l2m3...
2. Builder 1 builds      → hash_2 = h8i9j0k1l2m3... ✅ Match
3. Builder 2 builds      → hash_3 = h8i9j0k1l2m3... ✅ Match
4. Builder 3 builds      → hash_4 = h8i9j0k1l2m3... ✅ Match

3 matches confirmed → DEPLOY
```

**If ANY mismatch**:
```
1. GitHub Actions builds → hash_1 = h8i9j0k1l2m3...
2. Builder 1 builds      → hash_2 = DIFFERENT!!!   ❌ HALT

INVESTIGATION REQUIRED:
- Which builder is compromised?
- Is build environment tampered?
- Is source code maliciously modified?
- Is compiler backdoored?

DO NOT DEPLOY UNTIL RESOLVED
```

### Attestation Signing

Each builder signs their hash:

```bash
# Builder creates attestation
echo "{\"hash\": \"$WASM_HASH\", \"builder\": \"builder-1\", \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" > attestation.json
gpg --armor --detach-sign attestation.json

# Upload attestation.json + attestation.json.asc
```

### Verification Dashboard

```
https://paranoid-project.org/attestations/v3.0.0

Builder          Hash                               Status   Signature
─────────────────────────────────────────────────────────────────────────
GitHub Actions   h8i9j0k1l2m3...                    ✅ Match  ✅ Valid
Builder 1        h8i9j0k1l2m3...                    ✅ Match  ✅ Valid
Builder 2        h8i9j0k1l2m3...                    ✅ Match  ✅ Valid
Builder 3        WAITING...                         ⏳ Pending
Builder 4        WAITING...                         ⏳ Pending

Threshold: 3/5 required ✅ MET
```

---

## Dependency Verification

### Cryptographic Primitives (Platform Abstraction)

**v3 Architecture Change**: OpenSSL is NO LONGER used in the WASM build.

| Platform | RNG Source | Hash Function |
|----------|-----------|---------------|
| **Native (CLI)** | OpenSSL `RAND_bytes()` | OpenSSL `EVP_SHA256` |
| **WASM (Web)** | WASI `random_get()` | `sha256_compact.c` (bundled, no deps) |

**Threat**: `sha256_compact.c` is a minimal SHA-256 implementation bundled with the project.
Unlike OpenSSL (25+ years of audit), this code has a smaller trust base.

**Mitigation**:

```
WASM provenance chain (v3):
  Source (sha256_compact.c + paranoid.c) -> Zig compiler -> WASM
  RNG: WASI random_get() -> browser crypto.getRandomValues() -> OS CSPRNG
  Hash: sha256_compact.c (verified against NIST test vectors)
```

```bash
# Verify sha256_compact.c against known-answer tests (NIST FIPS 180-4)
cmake --build build --target test_sha256
./build/test_sha256  # Runs NIST test vectors

# Verify WASM imports — should ONLY import random_get (no OpenSSL)
wasm-objdump -x build/paranoid.wasm | grep "import"
# Expected: wasi_snapshot_preview1.random_get (and NOTHING else)

# For native CLI builds, OpenSSL is still used:
openssl version  # Verify OpenSSL is available for CLI builds
```

**Note**: The native CLI build (`packages/cli`) still uses OpenSSL via
`openssl rand` for CSPRNG. Only the WASM/web build has removed the
OpenSSL dependency in favor of WASI `random_get()` + `sha256_compact.c`.

### Known-Good Hash Registry

**File**: `known-good-hashes.txt`

```
# Zig 0.13.0 (linux-x86_64, melange-built from Wolfi)
f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0  /usr/bin/zig

# sha256_compact.c (bundled SHA-256 for WASM build)
a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5  src/sha256_compact.c

# (Add all critical dependencies)
```

**Verification**:
```bash
sha256sum -c known-good-hashes.txt || { echo "Hash mismatch!"; exit 1; }
```

---

## Compiler Verification

### Zig Compiler Backdoor Threat

**Ken Thompson's "Trusting Trust" attack** (1984):
```c
// Compiler backdoor (invisible in source)
if (compiling("paranoid.c")) {
    inject_backdoor();
}
if (compiling("compiler.c")) {
    inject_backdoor_generator();  // Self-propagating
}
```

**Mitigation: Diverse Double-Compilation**

```bash
# Build 1: Zig
zig cc -target wasm32-wasi ... -o build/paranoid-zig.wasm src/paranoid.c

# Build 2: Clang (different compiler)
clang --target=wasm32-wasi ... -o build/paranoid-clang.wasm src/paranoid.c

# Disassemble both
wasm2wat build/paranoid-zig.wasm > zig.wat
wasm2wat build/paranoid-clang.wasm > clang.wat

# Compare functionality (not byte-for-byte, but instruction sequence)
diff <(grep -E '^\s+(i32|f64|call)' zig.wat | sort) \
     <(grep -E '^\s+(i32|f64|call)' clang.wat | sort)

# If BOTH have same backdoor → conspiracy (unlikely)
# If ONE has backdoor → detected (different outputs)
```

**Alternative: Bootstrap from older compiler**:
```bash
# Use Zig 0.12.0 to compile Zig 0.13.0
# If 0.12.0 is clean, 0.13.0 should be clean
# Compare hashes across bootstrap chain
```

---

## LLM Clean Room Protocol

### Purpose

**Enable LLMs to work on this codebase WITHOUT introducing hallucinations or training data bias.**

### Protocol

#### 1. Entry Checkpoint (Before ANY code changes)

```markdown
# LLM Self-Audit Checklist

Before making changes to `paranoid`, I (the LLM) must:

- [ ] Acknowledge that I am the PRIMARY THREAT ACTOR
- [ ] Confirm all crypto logic delegated to platform CSPRNG (native: OpenSSL, WASM: WASI random_get)
- [ ] Verify rejection sampling formula: max_valid = (256/N)*N - 1 (not -0)
- [ ] Cross-check chi-squared formula against textbook (not LLM memory)
- [ ] Flag ALL statistical formulas for human review
- [ ] Never claim "this is correct" — always say "verify against known-answer tests"
- [ ] Request human cryptographer review before committing
```

#### 2. Code Generation Rules

```markdown
# LLM Code Generation Rules for Cryptographic Code

NEVER:
- [ ] Generate random numbers directly (use platform CSPRNG: OpenSSL RAND_bytes or WASI random_get)
- [ ] Implement crypto primitives (use OpenSSL EVP_* or verified bundled implementations)
- [ ] Use modulo without rejection sampling
- [ ] Claim formulas are correct (flag for verification)
- [ ] Suppress warnings or test failures
- [ ] Add JavaScript fallbacks

ALWAYS:
- [ ] Delegate RNG to platform CSPRNG (native: OpenSSL, WASM: WASI random_get)
- [ ] Use rejection sampling for uniform distribution
- [ ] Include human review markers: "TODO: HUMAN REVIEW"
- [ ] Reference textbook page numbers for formulas
- [ ] Add known-answer test cases
- [ ] Document assumptions and limitations
```

#### 3. Hallucination Detection

```bash
# Automated hallucination detector (runs on every commit)

# Check 1: No direct RNG in C code (must use RAND_bytes)
grep -n "rand()" src/paranoid.c && echo "HALLUCINATION: Direct rand() found!" && exit 1

# Check 2: Rejection sampling boundary correct
grep "max_valid.*256.*charset_len.*-.*1" src/paranoid.c || echo "HALLUCINATION: Wrong rejection boundary!" && exit 1

# Check 3: P-value interpretation correct
grep "p.*>.*0.01" src/paranoid.c || echo "HALLUCINATION: Inverted p-value logic!" && exit 1

# Check 4: Degrees of freedom correct
grep "df.*=.*charset_len.*-.*1" src/paranoid.c || echo "HALLUCINATION: Wrong degrees of freedom!" && exit 1

# Check 5: No TODO:HUMAN_REVIEW comments remaining in production
git grep "TODO.*HUMAN.*REVIEW" src/ include/ && echo "HALLUCINATION: Unreviewed LLM code!" && exit 1
```

#### 4. Training Data Firewall

**Problem**: LLM training includes password breach dumps.

**Solution**: Never let LLM generate password patterns directly.

```c
// ✅ CORRECT: LLM delegates to platform CSPRNG
int paranoid_generate(...) {
    for (int i = 0; i < length; i++) {
        uint8_t byte;
        do {
            // Native: RAND_bytes(&byte, 1)  — OpenSSL
            // WASM:   random_get(&byte, 1)   — WASI -> browser -> OS CSPRNG
            platform_random(&byte, 1);
        } while (byte > max_valid);
        output[i] = charset[byte % charset_len];
    }
}

// ❌ WRONG: LLM generates pattern
int paranoid_generate(...) {
    // "Based on my training, common secure patterns are..."
    const char *patterns[] = {"Xk9#", "mP2$", ...};  // BIASED!
    // ...
}
```

---

## Attestation Framework

### Wolfi-Based Supply Chain Security (melange + apko)

v3.0 replaces Docker multi-stage builds with melange + apko from the
Wolfi ecosystem. This provides stronger reproducibility guarantees.

| Feature | Implementation | Status |
|---------|---------------|--------|
| **SBOM** | melange APK includes SBOM | ✅ Implemented |
| **SLSA Level 3 Provenance** | melange build provenance | ✅ Implemented |
| **Cosign Keyless Signing** | GitHub OIDC via Sigstore | ✅ Implemented |
| **Wolfi Base Image** | apko distroless (no shell) | ✅ Implemented |
| **Reproducible Builds** | melange bitwise-reproducible | ✅ Implemented |

### SLSA Level 3 Compliance

**SLSA** = Supply-chain Levels for Software Artifacts

```
Level 0: No guarantees
Level 1: Build process documented
Level 2: Hosted build (GitHub Actions)
Level 3: Hardened build (non-falsifiable provenance)  ← CURRENT
Level 4: Highest (two-person review, hermetic builds)
```

**Current**: Level 3 (SBOM + Provenance + Keyless Signing)

### Build Features (melange + apko)

1. **Wolfi-provided toolchain**: Zig built from source via melange (not downloaded tarballs)
2. **SBOM per package**: Every APK includes a Software Bill of Materials
3. **SLSA provenance**: Non-falsifiable build attestation with source/builder identity
4. **Cosign signature**: Keyless signing via GitHub OIDC, recorded in Rekor transparency log
5. **Bitwise reproducible**: melange produces identical packages from same source
6. **Distroless final image**: apko produces minimal images (no shell, no package manager)

### Verification Commands

**Verify Cosign Signature:**
```bash
cosign verify ghcr.io/jbcom/paranoid-passwd:latest \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity-regexp="https://github.com/jbcom/paranoid-passwd/.*"
```

**View SBOM:**
```bash
cosign verify-attestation ghcr.io/jbcom/paranoid-passwd:latest \
  --type spdxjson \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity-regexp="https://github.com/jbcom/paranoid-passwd/.*"
```

**View SLSA Provenance:**
```bash
cosign verify-attestation ghcr.io/jbcom/paranoid-passwd:latest \
  --type slsaprovenance \
  --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
  --certificate-identity-regexp="https://github.com/jbcom/paranoid-passwd/.*"
```

**Check Rekor Transparency Log:**
```bash
rekor-cli search --email "github-actions@github.com" \
  --artifact ghcr.io/jbcom/paranoid-passwd:latest
```

### Provenance Format (SLSA v0.2)

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name": "ghcr.io/jbcom/paranoid-passwd",
      "digest": {
        "sha256": "<image-digest>"
      }
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "predicate": {
    "builder": {
      "id": "https://github.com/actions/runner/v2"
    },
    "buildType": "https://github.com/jbcom/paranoid-passwd/build/v1",
    "invocation": {
      "configSource": {
        "uri": "git+https://github.com/jbcom/paranoid-passwd@refs/heads/main",
        "digest": {"sha1": "<commit-sha>"},
        "entryPoint": "melange.yaml"
      }
    },
    "metadata": {
      "buildStartedOn": "<timestamp>",
      "buildFinishedOn": "<timestamp>",
      "completeness": {
        "parameters": true,
        "environment": true,
        "materials": true
      },
      "reproducible": true
    },
    "materials": [
      {
        "uri": "git+https://github.com/jbcom/paranoid-passwd",
        "digest": {"sha1": "<commit-sha>"}
      },
      {
        "uri": "pkg:apk/wolfi/zig",
        "digest": {"sha256": "<melange-zig-apk-hash>"},
        "annotations": {"source": "melange-built from Wolfi"}
      },
      {
        "uri": "cgr.dev/chainguard/wolfi-base:latest",
        "digest": {"sha256": "<wolfi-base-image-hash>"},
        "annotations": {"builder": "apko"}
      }
    ]
  }
}
```

### Keyless Signing Flow (Cosign + Sigstore)

```
GitHub Actions workflow
    │
    ├─→ Request OIDC token from GitHub
    │
    ├─→ Exchange token for ephemeral certificate (Fulcio CA)
    │
    ├─→ Sign image digest with ephemeral key
    │
    ├─→ Record signature in Rekor transparency log
    │
    └─→ Discard ephemeral key (no secrets to manage!)
```

**Advantages over traditional GPG signing:**
- Zero private key management
- Ephemeral certificates (no rotation required)
- Public transparency log (audit trail)
- Identity bound to GitHub workflow (not just key possession)

---

## Verification Checklist

Before ANY deployment:

### Source Verification
- [ ] All commits GPG-signed by known developers
- [ ] No uncommitted local changes
- [ ] WASM build: `sha256_compact.c` passes NIST FIPS 180-4 test vectors
- [ ] Native CLI: OpenSSL available at expected version
- [ ] melange package provenance records correct source commit and toolchain
- [ ] Dependency hashes match known-good registry

### Tool Verification
- [ ] Zig compiler hash matches known-good (melange-built from Wolfi)
- [ ] All GitHub Actions SHA-pinned (no tags)

### Build Verification
- [ ] Build completes without warnings
- [ ] WASM exports match expected list (15 functions)
- [ ] WASM imports only `wasi_snapshot_preview1.random_get`
- [ ] Binary size within expected range (180KB ± 10KB)

### Reproducibility Verification
- [ ] 3 independent builders produce identical hash
- [ ] Diverse double-compilation (Zig + Clang) functionally equivalent
- [ ] Build provenance ledger generated and signed

### Security Verification
- [ ] SRI hashes computed and injected
- [ ] No LLM-generated random number code
- [ ] Rejection sampling formula correct (verified against textbook)
- [ ] Chi-squared formula correct (verified against NIST)
- [ ] All TODOs and HUMAN_REVIEW markers resolved
- [ ] Security scan (CodeQL, Snyk) passes

### Deployment Verification
- [ ] Attestations from 3/5 builders collected
- [ ] Provenance signed and uploaded to transparency log
- [ ] SRI hashes in deployed HTML match build
- [ ] WASM hash in GitHub release matches deployed binary

---

## Emergency Response

### If Supply Chain Attack Detected

1. **HALT DEPLOYMENT IMMEDIATELY**
2. **Notify maintainers** (security@paranoid-project.org)
3. **Preserve evidence**:
   - Build logs
   - Binary artifacts
   - Provenance ledger
   - Attestations
4. **Investigation**:
   - Which builder(s) produced different hash?
   - When did hash diverge (git bisect)?
   - Is source code compromised?
   - Is compiler compromised?
   - Is build environment compromised?
5. **Remediation**:
   - Roll back to last known-good version
   - Rebuild from trusted sources
   - Re-verify entire supply chain
6. **Disclosure**:
   - Public incident report (SECURITY.md)
   - CVE assignment if applicable
   - Notify downstream users

---

## Conclusion

This supply chain security framework is designed to:

1. **Detect** ANY deviation from expected behavior
2. **Prevent** compromised artifacts from reaching users
3. **Verify** EVERY stage of compilation
4. **Audit** COMPLETE provenance ledger
5. **Trust NOTHING** — not even the LLM that wrote this document

**The goal: ZERO chance of supply chain compromise.**

If you find a gap in this framework, it's a security vulnerability. Report it.
