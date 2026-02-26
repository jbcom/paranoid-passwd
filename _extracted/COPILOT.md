# COPILOT.md — Repository Scaffolding Prompt

> **Give this file to GitHub Copilot (Copilot Chat, Copilot Workspace, or
> Claude Code) along with `files.zip` at the repository root.**

---

## Task

Extract `files.zip` in the repository root and scaffold a working `paranoid`
repository. The zip contains the complete source for a C-to-WASM password
generator. Your job is to place every file in its correct location, initialize
the git submodule, and verify the build system works.

---

## Step 1: Extract the archive

```bash
unzip files.zip -d _extracted
```

The zip contains these files (flat, no directory structure):

```
paranoid.h          → include/paranoid.h
paranoid.c          → src/paranoid.c
index.html          → www/index.html
app.js              → www/app.js
style.css           → www/style.css
Makefile            → Makefile
deploy.yml          → .github/workflows/deploy.yml
.gitmodules         → .gitmodules
.gitignore          → .gitignore
AGENTS.md           → AGENTS.md
```

## Step 2: Create directory structure and place files

```bash
# Create directories
mkdir -p include src www .github/workflows

# Move files to correct locations
mv _extracted/paranoid.h    include/paranoid.h
mv _extracted/paranoid.c    src/paranoid.c
mv _extracted/index.html    www/index.html
mv _extracted/app.js        www/app.js
mv _extracted/style.css     www/style.css
mv _extracted/Makefile      Makefile
mv _extracted/deploy.yml    .github/workflows/deploy.yml
mv _extracted/.gitmodules   .gitmodules
mv _extracted/.gitignore    .gitignore
mv _extracted/AGENTS.md     AGENTS.md

# Clean up
rm -rf _extracted files.zip
```

## Step 3: Initialize the OpenSSL submodule

The `.gitmodules` file references `vendor/openssl-wasm`. Initialize it:

```bash
git submodule update --init --recursive --depth=1
```

This clones `https://github.com/jedisct1/openssl-wasm.git` into
`vendor/openssl-wasm/`. Verify the precompiled library exists:

```bash
ls -lh vendor/openssl-wasm/precompiled/lib/libcrypto.a
# Should be ~2-4MB
```

## Step 4: Verify the Makefile works

```bash
make info      # Shows toolchain configuration
make build     # Compiles src/paranoid.c → build/paranoid.wasm
make verify    # Checks WASM exports and imports (needs wabt)
make hash      # Prints SHA-256 and SRI hashes
make site      # Assembles build/site/ with SRI injection
```

If Zig is not installed:

```bash
# macOS
brew install zig

# Ubuntu/Debian
snap install zig --classic --beta

# Or use the setup-zig action in CI (already configured in deploy.yml)
```

If wabt is not installed (needed for `make verify`):

```bash
sudo apt-get install wabt    # Ubuntu
brew install wabt             # macOS
```

## Step 5: Verify the final repository structure

```
paranoid/
├── .github/
│   └── workflows/
│       └── deploy.yml            ← SHA-pinned CI/CD
├── include/
│   └── paranoid.h                ← Public C API (249 lines)
├── src/
│   └── paranoid.c                ← All computation (400 lines)
├── www/
│   ├── index.html                ← Structure only (213 lines)
│   ├── style.css                 ← Visual state mgmt (834 lines)
│   └── app.js                    ← Display-only bridge (436 lines)
├── vendor/
│   └── openssl-wasm/             ← Submodule (jedisct1)
│       └── precompiled/
│           ├── include/openssl/  ← OpenSSL headers
│           └── lib/libcrypto.a   ← Precompiled for wasm32-wasi
├── build/                        ← Created by make (gitignored)
├── .gitmodules
├── .gitignore
├── AGENTS.md                     ← Full project documentation
├── COPILOT.md                    ← This file (delete after setup)
└── Makefile
```

## Step 6: Create LICENSE and README

Create `LICENSE` with MIT text (year: 2025, author: "paranoid contributors").

Create `README.md`:

```markdown
# paranoid

A self-auditing cryptographic password generator that treats the LLM
that built it as an adversary.

**[Live Demo](https://USERNAME.github.io/paranoid)** ·
**[Full Documentation](AGENTS.md)**

## What is this?

A C program compiled to WebAssembly. Generates passwords via OpenSSL's
CSPRNG inside a WASM sandbox, runs a 7-layer statistical audit (chi-squared,
serial correlation, collision detection, entropy proofs, birthday paradox,
pattern checks), and presents results through a display-only JavaScript
bridge. The browser never touches the random bytes.

## Quick Start

```bash
git clone --recursive https://github.com/USERNAME/paranoid.git
cd paranoid
make site
make serve    # http://localhost:8080
```

## Build

Requires Zig ≥ 0.14.0. See AGENTS.md for details.

```bash
make              # Build everything
make verify       # Check WASM exports
make hash         # Print binary hashes
```

## Architecture

- `src/paranoid.c` — ALL computation (400 lines of C)
- `www/app.js` — Display-only WASM bridge (reads a struct, sets textContent)
- `www/style.css` — CSS-only wizard navigation and audit stage animations
- No JavaScript fallback. If WASM fails, the tool refuses to run.

See [AGENTS.md](AGENTS.md) for the threat model, mathematical proofs,
and honest limitations.

## License

MIT
```

Replace `USERNAME` with the actual GitHub username.

## Step 7: Enable GitHub Pages

After pushing to GitHub:

1. Go to Settings → Pages
2. Source: "GitHub Actions"
3. The `deploy.yml` workflow will build and deploy automatically on push to `main`

## Step 8: Verify locally

```bash
make site
cd build/site
python3 -m http.server 8080
# Open http://localhost:8080
# Click "Generate + Run 7-Layer Audit"
# Verify all 7 stages complete with green checkmarks
```

---

## Critical Constraints

1. **Do NOT alter `src/paranoid.c` or `include/paranoid.h`.** These contain
   the cryptographic logic. Any change requires review by someone who
   understands rejection sampling and statistical testing.

2. **Do NOT inline JS into HTML or CSS into HTML.** Separate files enable
   CodeQL to scan each type with the correct analyzer.

3. **Do NOT add a JavaScript fallback.** The fail-closed architecture is
   intentional. See AGENTS.md "Fail-Closed Design".

4. **Do NOT unpin GitHub Actions SHAs.** Tags are mutable. SHAs are not.

5. **Do NOT delete AGENTS.md.** It is the project's security documentation
   and threat model.

6. **You CAN delete this file (COPILOT.md)** after scaffolding is complete.
