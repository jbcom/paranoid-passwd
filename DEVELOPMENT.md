# Development Guide

Welcome to the `paranoid-passwd` development guide! This document covers development setup, testing, contributing guidelines, and project conventions.

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
- **Zig >= 0.13.0** -- C/C++ compiler with WebAssembly support
  - macOS: `brew install zig`
  - Ubuntu/Debian: `snap install zig --classic --beta`
  - Windows: Download from https://ziglang.org/download/

- **CMake >= 3.20** -- Build system
  - macOS: `brew install cmake`
  - Ubuntu/Debian: `apt-get install cmake`

- **Git** -- For cloning the repository

- **OpenSSL** (development libraries) -- For native builds only; not needed for WASM
  - macOS: `brew install openssl`
  - Ubuntu/Debian: `apt-get install libssl-dev`

**Optional**:
- **wabt** (WebAssembly Binary Toolkit) -- For WASM verification
  - macOS: `brew install wabt`
  - Ubuntu/Debian: `apt-get install wabt`

- **Python 3** -- For local development server
- **melange + apko** -- For production container builds (Wolfi ecosystem)

### Clone the Repository

```bash
# Clone the repository
git clone https://github.com/jbcom/paranoid-passwd.git
cd paranoid-passwd

# For production builds (recommended): use melange/apko
melange build melange.yaml --arch x86_64 --runner docker

# For local development: just build with CMake
# CMake automatically fetches acutest via FetchContent -- no manual vendor setup needed
cmake -B build/native -DCMAKE_BUILD_TYPE=Debug
cmake --build build/native
```

### Verify Toolchain

```bash
zig version && cmake --version
```

**Expected output**:
```
0.13.0
cmake version 3.x.x
```

---

## Building

### Quick Build

```bash
# Build WASM (release)
cmake -B build/wasm -DCMAKE_TOOLCHAIN_FILE=cmake/wasm32-wasi.cmake -DCMAKE_BUILD_TYPE=Release && cmake --build build/wasm

# Or build native (debug + tests)
cmake -B build/native -DCMAKE_BUILD_TYPE=Debug && cmake --build build/native
```

### Build Targets

| Target | Command |
|--------|---------|
| WASM build (release) | `cmake -B build/wasm -DCMAKE_TOOLCHAIN_FILE=cmake/wasm32-wasi.cmake -DCMAKE_BUILD_TYPE=Release && cmake --build build/wasm` |
| Native build (debug) | `cmake -B build/native -DCMAKE_BUILD_TYPE=Debug && cmake --build build/native` |
| Run native tests | `ctest --test-dir build/native --output-on-failure` |
| Verify WASM exports | `wasm-objdump -x build/wasm/paranoid.wasm` |
| Print WASM hash | `sha256sum build/wasm/paranoid.wasm` |
| Local dev server | `cd www && python3 -m http.server 8080` |
| Clean all artifacts | `rm -rf build/` |
| Show toolchain info | `zig version && cmake --version` |

### Build Process

When you run the CMake WASM build, the build system:

1. **Configures the WASM toolchain**
   ```bash
   cmake -B build/wasm \
     -DCMAKE_TOOLCHAIN_FILE=cmake/wasm32-wasi.cmake \
     -DCMAKE_BUILD_TYPE=Release
   ```

2. **Compiles C -> WASM** (no OpenSSL in WASM)
   ```bash
   cmake --build build/wasm
   # Compiles: src/paranoid.c + src/platform_wasm.c + src/sha256_compact.c
   # Uses WASI random_get + compact FIPS 180-4 SHA-256
   # Produces: build/wasm/paranoid.wasm (<100KB)
   ```

3. **Post-processes the WASM binary**
   - Runs `wasm-opt` and `wasm-strip` (if available)
   - Validates with `wasm-validate` (hard gate in CI)

4. **Creates build manifest**
   - `build/wasm/BUILD_MANIFEST.json`
   - Records hashes, compiler version, commit SHA, timestamp
   - Loaded at runtime by `app.js` (no SRI placeholder injection)

5. **Artifacts are ready to serve from `www/`**
   - Copy `build/wasm/paranoid.wasm` into `www/` for development
   - Or use the CI pipeline which assembles the deployable site automatically

### Build Artifacts

```
build/
├── wasm/                     # WASM build output
│   ├── paranoid.wasm         # Compiled WASM binary (<100KB)
│   └── BUILD_MANIFEST.json   # Build metadata
└── native/                   # Native build output
    ├── test_native            # Acutest-based test runner
    ├── test_sha256            # NIST CAVP SHA-256 tests
    ├── test_statistics        # Chi-squared + serial correlation KATs
    └── test_paranoid          # Standalone test framework
```

---

## Testing

### Native C Tests (via CTest)

```bash
# Build and run all native C tests
cmake -B build/native -DCMAKE_BUILD_TYPE=Debug && cmake --build build/native && ctest --test-dir build/native --output-on-failure
```

Test binaries produced:
- `test_native` -- Comprehensive acutest-based C tests
- `test_sha256` -- NIST CAVP SHA-256 test vectors
- `test_statistics` -- Chi-squared + serial correlation known-answer tests
- `test_paranoid` -- Standalone test framework

### E2E Tests (via Playwright)

```bash
cd tests/e2e && npm install && npx playwright test
```

### Manual Testing

```bash
# 1. Build the WASM
cmake -B build/wasm -DCMAKE_TOOLCHAIN_FILE=cmake/wasm32-wasi.cmake -DCMAKE_BUILD_TYPE=Release && cmake --build build/wasm

# 2. Copy WASM + manifest to www/ for development
cp build/wasm/paranoid.wasm www/
cp build/wasm/BUILD_MANIFEST.json www/

# 3. Start local server
cd www && python3 -m http.server 8080
# Opens http://localhost:8080

# 4. Open in browser and test:
#    - Click "Generate + Run 7-Layer Audit"
#    - Verify all 7 stages complete with green checkmarks
#    - Check console for errors
#    - Inspect Network tab for WASM loading
```

### Verification Commands

```bash
# Verify WASM exports (requires wabt)
wasm-objdump -x build/wasm/paranoid.wasm

# Expected output includes:
# - paranoid_run_audit
# - paranoid_get_result_ptr
# - paranoid_offset_* functions
# - Only wasi_snapshot_preview1 imports
```

```bash
# Print binary hash
sha256sum build/wasm/paranoid.wasm
```

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
   rm -rf build/
   cmake -B build/wasm -DCMAKE_TOOLCHAIN_FILE=cmake/wasm32-wasi.cmake -DCMAKE_BUILD_TYPE=Release && cmake --build build/wasm
   wasm-objdump -x build/wasm/paranoid.wasm
   cmake -B build/native -DCMAKE_BUILD_TYPE=Debug && cmake --build build/native && ctest --test-dir build/native --output-on-failure
   cp build/wasm/paranoid.wasm www/
   cd www && python3 -m http.server 8080
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
- Cryptographer review of `src/paranoid.c`
- Statistical test improvements
- Documentation improvements
- Accessibility enhancements
- Bug fixes
- New threat vectors (LLM security)

**We will reject**:
- Changes that weaken security (removing fail-closed, adding JS fallback)
- Unpinning GitHub Actions from SHAs
- Inlining JS into HTML or CSS into HTML
- Removing statistical tests
- Suppressing threat model warnings

### Pull Request Checklist

- [ ] Code follows style guidelines (see [Code Style](#code-style))
- [ ] Documentation updated (README, AGENTS.md, inline comments)
- [ ] Native tests pass (`ctest --test-dir build/native --output-on-failure`)
- [ ] WASM builds successfully and passes `wasm-objdump` verification
- [ ] No security regressions (review [SECURITY.md](SECURITY.md))
- [ ] Commit messages are descriptive
- [ ] PR description explains **why** (not just what)

---

## Code Style

### C Code Style

**Files**: `src/paranoid.c`, `src/platform_native.c`, `src/platform_wasm.c`, `src/sha256_compact.c`, `include/paranoid.h`, `include/paranoid_platform.h`

```c
// Use snake_case for functions
int paranoid_generate(const char *charset, int len, ...);

// Use descriptive variable names
int max_valid = (256 / charset_len) * charset_len - 1;

// Add comments for non-obvious logic
// Rejection sampling: discard bytes > max_valid to avoid modulo bias
while (byte > max_valid) {
    paranoid_platform_random(&byte, 1);
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
paranoid-passwd/
├── .github/
│   ├── copilot-instructions.md   # Copilot agent configuration
│   └── workflows/
│       ├── ci.yml                 # PR verification (melange/apko build + E2E tests)
│       ├── cd.yml                 # Push to main (SBOM + Cosign + release-please)
│       └── release.yml            # Deploy from signed releases
├── cmake/
│   └── wasm32-wasi.cmake         # CMake toolchain file for Zig WASM cross-compilation
├── docs/
│   ├── ARCHITECTURE.md            # System architecture
│   ├── DESIGN.md                  # Design decisions
│   ├── THREAT-MODEL.md            # Threat analysis
│   ├── AUDIT.md                   # Statistical methodology
│   ├── BUILD.md                   # Build system internals
│   └── SUPPLY-CHAIN.md            # Supply chain security framework
├── include/
│   ├── paranoid.h                 # Public C API (every WASM export)
│   └── paranoid_platform.h        # Platform abstraction interface
├── src/
│   ├── paranoid.c                 # ALL computation (uses platform abstraction)
│   ├── platform_native.c          # Native backend: OpenSSL RAND_bytes + EVP SHA-256
│   ├── platform_wasm.c            # WASM backend: WASI random_get
│   └── sha256_compact.c           # FIPS 180-4 SHA-256 (WASM only, no OpenSSL)
├── tests/
│   ├── test_native.c              # Comprehensive acutest-based C tests
│   ├── test_paranoid.c            # Standalone test framework
│   ├── test_sha256.c              # NIST CAVP SHA-256 test vectors
│   └── test_statistics.c          # Chi-squared + serial correlation KATs
├── www/
│   ├── index.html                 # Structure only (no inline JS/CSS)
│   ├── style.css                  # CSS-only wizard (visual state mgmt)
│   └── app.js                     # Display-only WASM bridge
├── build/                         # Created by CMake (gitignored)
│   ├── wasm/
│   │   ├── paranoid.wasm          # <100KB (no OpenSSL)
│   │   └── BUILD_MANIFEST.json    # Build metadata
│   └── native/                    # Native test binaries
├── .gitignore
├── AGENTS.md                      # Complete project documentation
├── apko.yaml                      # Container image assembly (Wolfi ecosystem)
├── CHANGELOG.md                   # Version history
├── CMakeLists.txt                 # Build system (replaces Makefile)
├── DEVELOPMENT.md                 # This file
├── LICENSE                        # MIT License
├── melange.yaml                   # Package build definition (Wolfi ecosystem)
├── README.md                      # Project overview
└── SECURITY.md                    # Security policy
```

### Component Boundaries

| Component | Role | Touches Crypto? |
|-----------|------|:---------------:|
| `src/paranoid.c` | **ALL** computation | YES |
| `src/platform_native.c` | OpenSSL RAND_bytes + EVP SHA-256 backend | YES |
| `src/platform_wasm.c` | WASI random_get backend | YES |
| `src/sha256_compact.c` | FIPS 180-4 SHA-256 (WASM only) | YES |
| `include/paranoid.h` | C API definitions | No |
| `include/paranoid_platform.h` | Platform abstraction interface | No |
| `www/app.js` | WASM bridge (3-line shim + struct reader) | 3 lines |
| `www/index.html` | HTML structure | No |
| `www/style.css` | Visual state management | No |
| `CMakeLists.txt` | Build orchestration | No |
| `.github/workflows/ci.yml` | PR verification | No |
| `.github/workflows/cd.yml` | Push to main | No |
| `.github/workflows/release.yml` | Releases | No |

**Security-critical code**:
1. `src/paranoid.c` -- Rejection sampling, chi-squared, SHA-256
2. `src/platform_wasm.c` -- WASI random_get delegation
3. `src/platform_native.c` -- OpenSSL RAND_bytes delegation
4. `src/sha256_compact.c` -- FIPS 180-4 SHA-256 implementation
5. `www/app.js` (lines 15-17) -- WASI shim calling `crypto.getRandomValues()`

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

### CMake Not Found

**Error**: `cmake: command not found`

**Solution**:
```bash
# macOS
brew install cmake

# Ubuntu/Debian
apt-get install cmake
```

### WASM Compilation Fails

**Error**: CMake WASM build fails

**Note**: The WASM build does NOT use OpenSSL. It uses `src/platform_wasm.c` (WASI random_get) and `src/sha256_compact.c` (compact FIPS 180-4 SHA-256). If you see OpenSSL-related errors, ensure you are using the correct toolchain file:

```bash
cmake -B build/wasm -DCMAKE_TOOLCHAIN_FILE=cmake/wasm32-wasi.cmake -DCMAKE_BUILD_TYPE=Release
cmake --build build/wasm
```

For native builds that DO use OpenSSL:
```bash
# macOS
brew install openssl

# Ubuntu/Debian
apt-get install libssl-dev
```

### WASM Verification Fails

**Error**: `wasm-objdump` reports missing exports

**Solution**:
1. Check if `wabt` is installed: `wasm-objdump --version`
2. Install if missing: `brew install wabt` (macOS) or `apt-get install wabt` (Ubuntu)
3. Rebuild:
   ```bash
   rm -rf build/wasm
   cmake -B build/wasm -DCMAKE_TOOLCHAIN_FILE=cmake/wasm32-wasi.cmake -DCMAKE_BUILD_TYPE=Release
   cmake --build build/wasm
   ```
4. Verify again: `wasm-objdump -x build/wasm/paranoid.wasm`

### WASM Loading Fails in Browser

**Error**: "WebAssembly failed to load"

**Debugging**:
1. Open browser DevTools -> Console
2. Look for specific error message
3. Check Network tab -- verify `paranoid.wasm` returns 200 status
4. Verify MIME type: `application/wasm`
5. Check file size: Should be <100KB

**Common causes**:
- MIME type not set (use `cd www && python3 -m http.server 8080` or configure web server)
- Browser doesn't support WASM (upgrade browser)
- Mixed content (HTTPS page loading HTTP WASM)

### BUILD_MANIFEST.json Missing or Incorrect

**Error**: "Failed to fetch BUILD_MANIFEST.json" or provenance data shows placeholders

**Debugging**:
1. Verify the file exists after WASM build: `ls build/wasm/BUILD_MANIFEST.json`
2. If missing, rebuild WASM — CMake generates it as a post-build step
3. For local dev, copy it to `www/`: `cp build/wasm/BUILD_MANIFEST.json www/`
4. In CI, the melange pipeline installs it alongside other site assets

**Common causes**:
- Forgot to copy `BUILD_MANIFEST.json` alongside `paranoid.wasm` to serving directory
- Stale build directory (run `rm -rf build/` and rebuild)
- CORS blocking fetch if serving from `file://` protocol (use `python3 -m http.server`)

### Build Artifacts Not Cleaned

**Error**: Build uses old files after changes

**Solution**:
```bash
rm -rf build/
cmake -B build/wasm -DCMAKE_TOOLCHAIN_FILE=cmake/wasm32-wasi.cmake -DCMAKE_BUILD_TYPE=Release && cmake --build build/wasm
```

### Port 8080 Already in Use

**Error**: Dev server fails with "Address already in use"

**Solution**:
```bash
# Find process using port 8080
lsof -i :8080

# Kill it
kill -9 <PID>

# Or use different port
cd www && python3 -m http.server 8081
```

---

## Advanced Topics

### Debugging WASM

```bash
# Disassemble WASM to WAT (WebAssembly Text)
wasm2wat build/wasm/paranoid.wasm > paranoid.wat

# Inspect exports
wasm-objdump -x build/wasm/paranoid.wasm | grep "export name"

# Inspect imports
wasm-objdump -x build/wasm/paranoid.wasm | grep "import module"

# Check binary size
ls -lh build/wasm/paranoid.wasm
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
   rm -rf build/wasm
   cmake -B build/wasm -DCMAKE_TOOLCHAIN_FILE=cmake/wasm32-wasi.cmake -DCMAKE_BUILD_TYPE=Release && cmake --build build/wasm
   ```

4. **Verify export exists**:
   ```bash
   wasm-objdump -x build/wasm/paranoid.wasm | grep paranoid_new_function
   ```

5. **Call from JavaScript** (`www/app.js`):
   ```javascript
   const result = wasmExports.paranoid_new_function(42);
   ```

### Modifying Struct Layout

**WARNING**: Changing `paranoid_audit_result_t` requires updating **both** C and JS.

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
   rm -rf build/
   cmake -B build/wasm -DCMAKE_TOOLCHAIN_FILE=cmake/wasm32-wasi.cmake -DCMAKE_BUILD_TYPE=Release && cmake --build build/wasm
   cmake -B build/native -DCMAKE_BUILD_TYPE=Debug && cmake --build build/native && ctest --test-dir build/native --output-on-failure
   cp build/wasm/paranoid.wasm www/
   cd www && python3 -m http.server 8080
   # Offset verification will catch mismatches
   ```

### melange/apko Builds (Production)

Production container images use the Wolfi ecosystem instead of Docker multi-stage builds:

```bash
# Build the package with melange
melange build melange.yaml --arch x86_64 --runner docker

# Assemble the container image with apko
apko build apko.yaml paranoid-passwd:latest paranoid-passwd.tar

# Load and run
docker load < paranoid-passwd.tar
docker run --rm -p 8080:8080 paranoid-passwd:latest
```

Wolfi provides Zig from source via melange, producing bitwise-reproducible packages. This replaces the previous Docker multi-stage build approach.

---

## Resources

- **Zig Documentation**: https://ziglang.org/documentation/
- **CMake Documentation**: https://cmake.org/documentation/
- **WebAssembly Spec**: https://webassembly.github.io/spec/
- **WASI Spec**: https://github.com/WebAssembly/WASI
- **melange**: https://github.com/chainguard-dev/melange
- **apko**: https://github.com/chainguard-dev/apko
- **NIST SP 800-90A**: https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final
- **NIST SP 800-63B**: https://pages.nist.gov/800-63-3/sp800-63b.html

---

## Getting Help

- **GitHub Issues**: https://github.com/jbcom/paranoid-passwd/issues
- **GitHub Discussions**: https://github.com/jbcom/paranoid-passwd/discussions
- **Security Issues**: See [SECURITY.md](SECURITY.md) for reporting guidelines
- **Email**: hello@paranoid-project.org

---

**Happy hacking!**
