# Development Guide

Welcome to the `paranoid` development guide! This document covers development setup, testing, contributing guidelines, and project conventions.

---

## Table of Contents

- [Development Setup](#development-setup)
- [Building](#building)
- [Testing](#testing)
- [Contributing](#contributing)
- [Code Style](#code-style)
- [Project Structure](#project-structure)
- [Troubleshooting](#troubleshooting)

---

## Development Setup

### Prerequisites

**Required**:
- **Zig ≥ 0.13.0** — C/C++ compiler with WebAssembly support
  - macOS: `brew install zig`
  - Ubuntu/Debian: `snap install zig --classic --beta`
  - Windows: Download from https://ziglang.org/download/
  
- **Git** — For cloning the repository
  
- **OpenSSL** — For SRI hash computation during build
  - macOS: `brew install openssl`
  - Ubuntu/Debian: `apt-get install openssl`

**Optional**:
- **wabt** (WebAssembly Binary Toolkit) — For WASM verification
  - macOS: `brew install wabt`
  - Ubuntu/Debian: `apt-get install wabt`
  
- **Python 3** — For local development server (`make serve`)

### Clone the Repository

```bash
# Clone the repository
git clone https://github.com/jbcom/paranoid-passwd.git
cd paranoid-passwd

# For Docker builds (recommended): OpenSSL is built from official source automatically
docker build -t paranoid-passwd .

# For local development: build OpenSSL from source and clone test framework
# OpenSSL is compiled from official source using the build script:
./scripts/build_openssl_wasm.sh
# This clones openssl/openssl at tag openssl-3.4.0, applies patches, and
# compiles with Zig to produce vendor/openssl/lib/libcrypto.a

# Clone test framework manually at the pinned commit:
mkdir -p vendor
git clone https://github.com/mity/acutest.git vendor/acutest
cd vendor/acutest && git checkout 31751b4089c93b46a9fd8a8183a695f772de66de && cd ../..
```

### Verify Toolchain

```bash
make info
```

**Expected output**:
```
=== Paranoid Build Info ===
Zig version: 0.13.0
OpenSSL version: OpenSSL 3.x.x
Zig CC: /usr/local/bin/zig cc
OpenSSL library: vendor/openssl/lib/libcrypto.a (built from source)
wabt installed: yes
```

---

## Building

### Quick Build

```bash
# Build everything (WASM + site with SRI hashes)
make

# Or explicitly:
make site
```

### Build Targets

| Target | Description |
|--------|-------------|
| `make` | Default target (same as `make site`) |
| `make build` | Compile WASM only (`build/paranoid.wasm`) |
| `make site` | Assemble deployable site with SRI hashes (`build/site/`) |
| `make verify` | Verify WASM exports/imports (requires wabt) |
| `make hash` | Print SHA-256 and SRI hashes of WASM binary |
| `make serve` | Start local HTTP server on port 8080 |
| `make clean` | Remove all build artifacts |
| `make info` | Show toolchain configuration |

### Build Process

When you run `make site`, the build system:

1. **Compiles C → WASM**
   ```bash
   zig cc -target wasm32-wasi src/paranoid.c src/wasm_entry.c \
     -I include \
     -I vendor/openssl/include \
     -L vendor/openssl/lib \
     -l crypto \
     -o build/paranoid.wasm
   ```

2. **Computes SRI hashes**
   - SHA-384 of `paranoid.wasm`
   - SHA-384 of `app.js`
   - SHA-384 of `style.css`

3. **Injects hashes into HTML**
   - Replaces `__WASM_SRI__`, `__JS_SRI__`, `__CSS_SRI__` placeholders
   - Uses `sed` for inline substitution

4. **Creates build manifest**
   - `build/site/BUILD_MANIFEST.json`
   - Records hashes, compiler version, commit SHA, timestamp

5. **Copies files to `build/site/`**
   - `index.html` (with injected SRI hashes)
   - `paranoid.wasm`
   - `app.js`
   - `style.css`

### Build Artifacts

```
build/
├── paranoid.wasm          # Compiled WASM binary (~180KB)
├── site/                  # Deployable site
│   ├── index.html         # HTML with SRI hashes
│   ├── paranoid.wasm      # WASM binary
│   ├── app.js             # JavaScript bridge
│   ├── style.css          # Styles
│   └── BUILD_MANIFEST.json  # Build metadata
```

---

## Testing

### Manual Testing

```bash
# 1. Build the site
make site

# 2. Start local server
make serve
# Opens http://localhost:8080

# 3. Open in browser and test:
#    - Click "Generate + Run 7-Layer Audit"
#    - Verify all 7 stages complete with green checkmarks
#    - Check console for errors
#    - Inspect Network tab for WASM loading
```

### Verification Commands

```bash
# Verify WASM exports (requires wabt)
make verify

# Expected output:
# ✓ paranoid_run_audit found
# ✓ paranoid_get_result_ptr found
# ✓ paranoid_offset_* functions found
# ✓ Only wasi_snapshot_preview1 imports found
```

```bash
# Print binary hashes
make hash

# Expected output:
# SHA-256: <64-char hex>
# SRI-384: sha384-<base64>
```

### Automated Testing (Planned)

**Unit tests** (not yet implemented):
```bash
# Planned test commands
make test-c        # Unit tests for C code
make test-js       # Unit tests for JavaScript
make test-e2e      # End-to-end tests with Playwright
```

**Test coverage targets**:
- [ ] Rejection sampling (boundary cases, rejection rates)
- [ ] Chi-squared calculation (known test vectors)
- [ ] Struct offset verification (fuzz testing)
- [ ] Full audit pipeline (integration test)
- [ ] WASM loading and error handling
- [ ] UI state transitions

---

## Contributing

### Contribution Workflow

1. **Fork the repository** on GitHub

2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**
   - Follow [Code Style](#code-style) guidelines
   - Update documentation if needed
   - Add tests if applicable

4. **Test your changes**
   ```bash
   make clean
   make site
   make verify
   make serve
   # Test manually in browser
   ```

5. **Commit with descriptive messages**
   ```bash
   git commit -m "feat: Add XYZ feature"
   # Or: "fix: Resolve ABC bug"
   # Or: "docs: Update README"
   ```

6. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```

7. **Open a Pull Request** on GitHub

### Contribution Guidelines

**We welcome**:
- ✅ Cryptographer review of `src/paranoid.c`
- ✅ Statistical test improvements
- ✅ Documentation improvements
- ✅ Accessibility enhancements
- ✅ Bug fixes
- ✅ New threat vectors (LLM security)

**We will reject**:
- ❌ Changes that weaken security (removing fail-closed, adding JS fallback)
- ❌ Unpinning GitHub Actions from SHAs
- ❌ Inlining JS into HTML or CSS into HTML
- ❌ Removing statistical tests
- ❌ Suppressing threat model warnings

### Pull Request Checklist

- [ ] Code follows style guidelines (see [Code Style](#code-style))
- [ ] Documentation updated (README, AGENTS.md, inline comments)
- [ ] Tests pass (`make verify`, manual browser testing)
- [ ] No security regressions (review [SECURITY.md](SECURITY.md))
- [ ] Commit messages are descriptive
- [ ] PR description explains **why** (not just what)

---

## Code Style

### C Code Style

**File**: `src/paranoid.c`, `include/paranoid.h`

```c
// Use snake_case for functions
int paranoid_generate(const char *charset, int len, ...);

// Use descriptive variable names
int max_valid = (256 / charset_len) * charset_len - 1;

// Add comments for non-obvious logic
// Rejection sampling: discard bytes > max_valid to avoid modulo bias
while (byte > max_valid) {
    RAND_bytes(&byte, 1);
}

// Use consistent indentation (4 spaces, no tabs)
if (condition) {
    do_something();
} else {
    do_something_else();
}
```

**Conventions**:
- Snake_case for functions, variables
- ALL_CAPS for constants
- Descriptive names (no `i`, `j`, `k` unless loop indices)
- Comments explain **why**, not **what**

### JavaScript Code Style

**File**: `www/app.js`

```javascript
// Use camelCase for functions, variables
function loadWasm(wasmPath) { ... }

// Use async/await (not .then())
async function init() {
    const response = await fetch('paranoid.wasm');
    // ...
}

// Add JSDoc for public functions
/**
 * Reads the audit result struct from WASM memory.
 * @returns {Object} Parsed audit result
 */
function readResult() { ... }

// Use 2-space indentation
if (condition) {
  doSomething();
} else {
  doSomethingElse();
}
```

**Conventions**:
- camelCase for functions, variables
- PascalCase for classes (if any)
- Use `const` by default, `let` only when reassignment needed
- No `var`
- JSDoc for public APIs

### CSS Code Style

**File**: `www/style.css`

```css
/* Use kebab-case for class names */
.wizard-panel { ... }

/* Group related selectors */
.stage-generate,
.stage-chi2,
.stage-serial {
    /* shared styles */
}

/* Use 2-space indentation */
.panel {
  display: flex;
  flex-direction: column;
}

/* Comment complex selectors */
/* Wizard navigation: hide panels unless their radio is checked */
#step-audit:checked ~ .page-wrapper #panel-audit {
    display: block;
}
```

**Conventions**:
- kebab-case for class names
- Alphabetical property order within blocks
- 2-space indentation
- Comments for non-obvious logic

---

## Project Structure

```
paranoid/
├── .github/
│   ├── copilot-instructions.md   # Copilot agent configuration
│   └── workflows/
│       ├── ci.yml                 # PR verification (Docker build + E2E tests)
│       ├── cd.yml                 # Push to main (SBOM + Cosign + release-please)
│       └── release.yml            # Deploy from signed releases
├── docs/
│   ├── ARCHITECTURE.md            # System architecture
│   ├── DESIGN.md                  # Design decisions
│   ├── THREAT-MODEL.md            # Threat analysis
│   ├── AUDIT.md                   # Statistical methodology
│   └── BUILD.md                   # Build system internals
├── include/
│   └── paranoid.h                 # Public C API (249 lines)
├── src/
│   └── paranoid.c                 # All computation (400 lines)
├── patches/
│   ├── 01-wasi-config.patch       # WASI platform configuration
│   ├── 02-rand-wasi.patch         # WASI random entropy source
│   └── 03-ssl-cert-posix-io.patch # SSL cert POSIX I/O adjustments
├── scripts/
│   └── build_openssl_wasm.sh      # Build OpenSSL from official source
├── vendor/
│   └── openssl/                   # Built from official OpenSSL source (openssl-3.4.0)
│       ├── include/openssl/       # OpenSSL headers (from build)
│       ├── lib/libcrypto.a        # Compiled for wasm32-wasi
│       └── BUILD_PROVENANCE.txt   # Records source tag, commit, compiler, patches
├── www/
│   ├── index.html                 # Structure only (213 lines)
│   ├── style.css                  # CSS-only wizard (834 lines)
│   └── app.js                     # Display-only bridge (436 lines)
├── build/                         # Created by make (gitignored)
│   ├── paranoid.wasm
│   └── site/
│       ├── index.html
│       ├── paranoid.wasm
│       ├── app.js
│       ├── style.css
│       └── BUILD_MANIFEST.json
├── .gitignore
├── Dockerfile                    # Multi-stage build (deps, test, build, verify)
├── AGENTS.md                      # Complete project documentation
├── CHANGELOG.md                   # Version history
├── DEVELOPMENT.md                 # This file
├── LICENSE                        # MIT License
├── Makefile                       # Build system
├── README.md                      # Project overview
└── SECURITY.md                    # Security policy
```

### Component Boundaries

| Component | Role | Touches Crypto? |
|-----------|------|:---------------:|
| `src/paranoid.c` | **ALL** computation | ✅ YES |
| `src/wasm_entry.c` | WASM entry point | No |
| `include/paranoid.h` | C API definitions | No |
| `www/app.js` | WASM bridge (3-line shim + struct reader) | ⚠️ 3 lines |
| `www/index.html` | HTML structure | No |
| `www/style.css` | Visual state management | No |
| `Makefile` | Build orchestration | No |
| `.github/workflows/ci.yml` | PR verification | No |
| `.github/workflows/cd.yml` | Push to main | No |
| `.github/workflows/release.yml` | Releases | No |

**Security-critical code**:
1. `src/paranoid.c` — Rejection sampling, chi-squared, SHA-256
2. `www/app.js` (lines 15-17) — WASI shim calling `crypto.getRandomValues()`

---

## Troubleshooting

### Zig Not Found

**Error**: `zig: command not found`

**Solution**:
```bash
# macOS
brew install zig

# Ubuntu/Debian
snap install zig --classic --beta

# Or download from https://ziglang.org/download/
```

### Dependencies Not Available

**Error**: `vendor/openssl/lib/libcrypto.a: No such file`

**Solution** (recommended): Use Docker — it builds OpenSSL from official source automatically:
```bash
docker build -t paranoid-passwd .
```

**Solution** (local development): Build OpenSSL from source using the build script:
```bash
./scripts/build_openssl_wasm.sh
# This clones official OpenSSL at tag openssl-3.4.0, applies patches,
# and compiles with Zig to produce vendor/openssl/lib/libcrypto.a

# Clone test framework:
mkdir -p vendor
git clone https://github.com/mity/acutest.git vendor/acutest
cd vendor/acutest && git checkout 31751b4089c93b46a9fd8a8183a695f772de66de && cd ../..
```

### WASM Verification Fails

**Error**: `make verify` reports missing exports

**Solution**:
1. Check if `wabt` is installed: `wasm-objdump --version`
2. Install if missing: `brew install wabt` (macOS) or `apt-get install wabt` (Ubuntu)
3. Rebuild: `make clean && make build`
4. Verify again: `make verify`

### SRI Hash Mismatch in Browser

**Error**: Browser console shows "Subresource Integrity check failed"

**Cause**: Cached old version of WASM/JS/CSS

**Solution**:
1. Hard refresh: Ctrl+Shift+R (Windows/Linux) or Cmd+Shift+R (macOS)
2. Clear browser cache
3. Rebuild: `make clean && make site`

### WASM Loading Fails in Browser

**Error**: "WebAssembly failed to load"

**Debugging**:
1. Open browser DevTools → Console
2. Look for specific error message
3. Check Network tab — verify `paranoid.wasm` returns 200 status
4. Verify MIME type: `application/wasm`
5. Check file size: Should be ~180KB

**Common causes**:
- MIME type not set (use `make serve` or configure web server)
- SRI hash mismatch (see above)
- Browser doesn't support WASM (upgrade browser)
- Mixed content (HTTPS page loading HTTP WASM)

### Build Artifacts Not Cleaned

**Error**: `make` uses old files after changes

**Solution**:
```bash
make clean
make site
```

### Port 8080 Already in Use

**Error**: `make serve` fails with "Address already in use"

**Solution**:
```bash
# Find process using port 8080
lsof -i :8080

# Kill it
kill -9 <PID>

# Or use different port
cd build/site && python3 -m http.server 8081
```

---

## Advanced Topics

### Debugging WASM

```bash
# Disassemble WASM to WAT (WebAssembly Text)
wasm2wat build/paranoid.wasm > paranoid.wat

# Inspect exports
wasm-objdump -x build/paranoid.wasm | grep "export name"

# Inspect imports
wasm-objdump -x build/paranoid.wasm | grep "import module"

# Check binary size
ls -lh build/paranoid.wasm
```

### Adding a New Export

1. **Add to C API** (`include/paranoid.h`):
   ```c
   __attribute__((export_name("paranoid_new_function")))
   int paranoid_new_function(int arg);
   ```

2. **Implement in C** (`src/paranoid.c`):
   ```c
   int paranoid_new_function(int arg) {
       // implementation
   }
   ```

3. **Rebuild**:
   ```bash
   make clean && make build
   ```

4. **Verify export exists**:
   ```bash
   make verify
   # Should show "✓ paranoid_new_function found"
   ```

5. **Call from JavaScript** (`www/app.js`):
   ```javascript
   const result = wasmExports.paranoid_new_function(42);
   ```

### Modifying Struct Layout

**⚠️ WARNING**: Changing `paranoid_audit_result_t` requires updating **both** C and JS.

1. **Update struct** (`include/paranoid.h`):
   ```c
   typedef struct {
       char password[257];
       int new_field;  // Add new field
       // ... rest of struct
   } paranoid_audit_result_t;
   ```

2. **Update offset function** (`src/paranoid.c`):
   ```c
   int paranoid_offset_new_field(void) {
       return offsetof(paranoid_audit_result_t, new_field);
   }
   ```

3. **Update JavaScript reader** (`www/app.js`):
   ```javascript
   const OFFSETS = {
       // ... existing offsets
       NEW_FIELD: 260,  // Must match C offsetof()
   };

   function verifyOffsets() {
       // ... existing checks
       checkOffset('NEW_FIELD', exports.paranoid_offset_new_field);
   }
   ```

4. **Test**:
   ```bash
   make clean && make site && make serve
   # Offset verification will catch mismatches
   ```

---

## Resources

- **Zig Documentation**: https://ziglang.org/documentation/
- **OpenSSL**: https://github.com/openssl/openssl
- **WebAssembly Spec**: https://webassembly.github.io/spec/
- **WASI Spec**: https://github.com/WebAssembly/WASI
- **NIST SP 800-90A**: https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final
- **NIST SP 800-63B**: https://pages.nist.gov/800-63-3/sp800-63b.html

---

## Getting Help

- **GitHub Issues**: https://github.com/jbcom/paranoid-passwd/issues
- **GitHub Discussions**: https://github.com/jbcom/paranoid-passwd/discussions
- **Security Issues**: See [SECURITY.md](SECURITY.md) for reporting guidelines
- **Email**: hello@paranoid-project.org

---

**Happy hacking! 🔒**
