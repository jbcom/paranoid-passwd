# CLAUDE.md — Handoff Prompt for Claude Code

> **Mission**: Take three existing source files (`AGENTS.md`, `index.html`, `password_auditor.py`) and scaffold them into a production-grade open source monorepo called **paranoid** — a self-auditing cryptographic password generator with an LLM threat model.

---

## Context

You have three files in the repo root:

1. **`AGENTS.md`** — Full project documentation (architecture, threat model, math proofs, contribution guidelines)
2. **`index.html`** — A standalone single-page web frontend using Web Crypto API for password generation and a 7-layer audit suite. Zero external runtime dependencies. Currently a single HTML file with inline CSS/JS.
3. **`password_auditor.py`** — A CLI tool that generates passwords via `openssl rand`, runs statistical tests (chi-squared, serial correlation, runs test, collision check), performs breach analysis, and outputs a structured terminal report with formal entropy/uniqueness proofs.

Your job is to turn these into a properly structured **Nx monorepo** managed by **pnpm**, linted/formatted by **Biome 2.4**, secured by **GitHub Advanced Security** features, analyzed by **SonarCloud**, and tested with coverage reporting across both the Python and JavaScript codebases.

---

## 1. Monorepo Structure

Create the following layout. Do NOT delete or significantly alter the logic in the three source files — refactor their location and modularity, but preserve all functionality.

```
paranoid/
├── .github/
│   ├── CODEOWNERS
│   ├── FUNDING.yml
│   ├── dependabot.yml
│   ├── SECURITY.md
│   └── workflows/
│       ├── ci.yml                    # Main CI pipeline
│       ├── codeql.yml                # GitHub CodeQL analysis
│       ├── sonarcloud.yml            # SonarCloud analysis
│       └── release.yml               # GitHub Pages deploy + PyPI/GitHub Release
├── packages/
│   ├── web/                          # The HTML/JS frontend
│   │   ├── src/
│   │   │   ├── index.html            # Refactored from root index.html
│   │   │   ├── generator.js          # Extracted: CSPRNG generation + rejection sampling
│   │   │   ├── audit.js              # Extracted: chi-squared, serial correlation, collision
│   │   │   ├── threats.js            # Extracted: threat model data + rendering
│   │   │   ├── proofs.js             # Extracted: entropy calc, uniqueness calc, NIST
│   │   │   ├── ui.js                 # Extracted: DOM manipulation, rendering helpers
│   │   │   └── main.js               # Entry point: imports + wires everything together
│   │   ├── __tests__/
│   │   │   ├── generator.test.js     # Unit tests for CSPRNG + rejection sampling
│   │   │   ├── audit.test.js         # Unit tests for statistical tests
│   │   │   ├── proofs.test.js        # Unit tests for entropy/uniqueness math
│   │   │   └── integration.test.js   # End-to-end: generate → audit → verify results
│   │   ├── package.json
│   │   ├── vite.config.js            # Vite for dev server + production build
│   │   └── project.json              # Nx project configuration
│   └── cli/                          # The Python CLI tool
│       ├── src/
│       │   └── paranoid/
│       │       ├── __init__.py
│       │       ├── __main__.py        # Entry point: `python -m paranoid`
│       │       ├── generator.py       # Extracted: openssl rand + rejection sampling
│       │       ├── audit.py           # Extracted: chi-squared, serial corr, runs, collision
│       │       ├── breach.py          # Extracted: HIBP k-anonymity + pattern checks
│       │       ├── threats.py         # Extracted: LLM threat model analysis
│       │       ├── proofs.py          # Extracted: entropy proof, uniqueness proof
│       │       ├── self_audit.py      # Extracted: LLM self-audit checks
│       │       └── report.py          # Extracted: terminal output formatting
│       ├── tests/
│       │   ├── conftest.py
│       │   ├── test_generator.py      # Unit tests for CSPRNG generation
│       │   ├── test_audit.py          # Unit tests for statistical suite
│       │   ├── test_breach.py         # Unit tests for breach analysis
│       │   ├── test_proofs.py         # Unit tests for mathematical proofs
│       │   └── test_integration.py    # Full pipeline: generate → audit → report
│       ├── pyproject.toml             # Python packaging (PEP 621), pytest config, ruff
│       └── project.json              # Nx project configuration
├── AGENTS.md                          # Keep in root (the project doc)
├── CLAUDE.md                          # This file (keep for future Claude Code sessions)
├── README.md                          # Create: public-facing README (shorter than AGENTS.md)
├── LICENSE                            # MIT license
├── nx.json                            # Nx workspace configuration
├── pnpm-workspace.yaml                # pnpm workspace definition
├── package.json                       # Root package.json
├── biome.json                         # Biome 2.4 configuration
├── sonar-project.properties           # SonarCloud configuration
└── .editorconfig
```

---

## 2. Nx Configuration

### `nx.json`

```jsonc
{
  "$schema": "https://raw.githubusercontent.com/nrwl/nx/master/packages/nx/schemas/nx-schema.json",
  "namedInputs": {
    "default": ["{projectRoot}/**/*", "sharedGlobals"],
    "sharedGlobals": ["{workspaceRoot}/biome.json", "{workspaceRoot}/nx.json"],
    "production": ["default", "!{projectRoot}/**/*.test.*", "!{projectRoot}/__tests__/**/*"]
  },
  "targetDefaults": {
    "build": {
      "dependsOn": ["^build"],
      "inputs": ["production", "^production"],
      "cache": true
    },
    "test": {
      "inputs": ["default", "^production"],
      "cache": true
    },
    "lint": {
      "inputs": ["default"],
      "cache": true
    }
  },
  "plugins": [
    {
      "plugin": "@nx/vite/plugin",
      "options": { "buildTargetName": "build", "serveTargetName": "dev" }
    }
  ],
  "defaultBase": "main"
}
```

### `packages/web/project.json`

Define targets:
- **`build`**: `vite build` — produces `dist/` with a single `index.html` (inline all JS for GitHub Pages compatibility)
- **`dev`**: `vite` — local dev server with HMR
- **`test`**: `vitest run --coverage` — run tests with v8 coverage
- **`lint`**: `biome check packages/web/src`
- **`format`**: `biome format --write packages/web/src`

### `packages/cli/project.json`

Define targets:
- **`build`**: No-op or `python -m build` if publishing to PyPI
- **`test`**: `pytest tests/ --cov=src/paranoid --cov-report=xml:coverage.xml --cov-report=term`
- **`lint`**: `ruff check src/ tests/`  (Python linting stays with ruff — Biome handles JS)
- **`format`**: `ruff format src/ tests/`
- **`run`**: `python -m paranoid` — execute the CLI tool

Use `nx:run-commands` executor for all Python targets since Nx doesn't have native Python support. Example:

```json
{
  "targets": {
    "test": {
      "executor": "nx:run-commands",
      "options": {
        "command": "pytest tests/ --cov=src/paranoid --cov-report=xml:coverage.xml --cov-report=term-missing",
        "cwd": "packages/cli"
      }
    }
  }
}
```

### Root Nx commands to wire up

In root `package.json` scripts:

```json
{
  "scripts": {
    "build": "nx run-many -t build",
    "test": "nx run-many -t test",
    "test:web": "nx test web",
    "test:cli": "nx test cli",
    "lint": "nx run-many -t lint",
    "format": "nx run-many -t format",
    "dev": "nx dev web",
    "check": "biome check .",
    "audit:all": "nx run-many -t test,lint"
  }
}
```

---

## 3. pnpm Configuration

### `pnpm-workspace.yaml`

```yaml
packages:
  - 'packages/*'
```

### Root `package.json`

```json
{
  "name": "paranoid",
  "private": true,
  "packageManager": "pnpm@9.15.4",
  "engines": { "node": ">=20.0.0" },
  "devDependencies": {
    "nx": "^20.x",
    "@biomejs/biome": "2.4.0",
    "@nx/vite": "^20.x"
  }
}
```

### `packages/web/package.json`

```json
{
  "name": "@paranoid/web",
  "version": "0.1.0",
  "type": "module",
  "private": true,
  "devDependencies": {
    "vite": "^6.x",
    "vitest": "^3.x",
    "@vitest/coverage-v8": "^3.x",
    "jsdom": "^26.x"
  }
}
```

---

## 4. Biome 2.4 Configuration

### `biome.json`

Use Biome 2.4 features. Key requirements:
- Enable the **linter**, **formatter**, and **import organizer**
- Target JS files in `packages/web/src/` and `packages/web/__tests__/`
- Ignore `dist/`, `node_modules/`, `coverage/`, and all Python files
- Use **tabs for indentation** (Biome default), or 2-space if you prefer — just be consistent
- Enable `recommended` rules plus these specific ones:
  - `suspicious.noExplicitAny`: error
  - `correctness.noUnusedVariables`: warn
  - `style.noNonNullAssertion`: warn
  - `complexity.noForEach`: off (we use forEach legitimately)

```json
{
  "$schema": "https://biomejs.dev/schemas/2.4.0/schema.json",
  "vcs": {
    "enabled": true,
    "clientKind": "git",
    "useIgnoreFile": true,
    "defaultBranch": "main"
  },
  "files": {
    "include": ["packages/web/**/*.js", "packages/web/**/*.html"],
    "ignore": ["**/dist/**", "**/coverage/**", "**/node_modules/**", "packages/cli/**"]
  },
  "formatter": {
    "enabled": true,
    "indentStyle": "space",
    "indentWidth": 2,
    "lineWidth": 120
  },
  "linter": {
    "enabled": true,
    "rules": {
      "recommended": true,
      "complexity": {
        "noForEach": "off"
      },
      "correctness": {
        "noUnusedVariables": "warn"
      }
    }
  },
  "javascript": {
    "formatter": {
      "quoteStyle": "single",
      "semicolons": "always"
    }
  }
}
```

**Important**: Python linting is handled by **ruff** (configured in `pyproject.toml`), NOT Biome. Biome is JS/TS only. Do not attempt to run Biome on `.py` files.

---

## 5. Vite Configuration (Web Package)

### `packages/web/vite.config.js`

The key requirement: the production build MUST output a **single `index.html`** file with all JS inlined. This is because the project needs to work on GitHub Pages without a server, and the original `index.html` was a self-contained single file. Use `vite-plugin-singlefile` or equivalent to achieve this.

```js
import { defineConfig } from 'vite';
import { viteSingleFile } from 'vite-plugin-singlefile';

export default defineConfig({
  root: 'src',
  build: {
    outDir: '../dist',
    emptyOutDir: true,
  },
  plugins: [viteSingleFile()],
  test: {
    environment: 'jsdom',
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov', 'json'],
      reportsDirectory: '../coverage',
    },
  },
});
```

Add `vite-plugin-singlefile` as a devDependency in `packages/web/package.json`.

### JS Module Extraction

When breaking `index.html` into modules, the key exports from each file should be:

**`generator.js`**:
```js
export function generatePassword(length, charset) { /* ... */ }
// Preserve: rejection sampling, crypto.getRandomValues()
```

**`audit.js`**:
```js
export function chiSquaredTest(passwords, charset) { /* ... */ }
export function serialCorrelation(passwords) { /* ... */ }
export function collisionCheck(passwords) { /* ... */ }
export function erfc(x) { /* ... */ }
```

**`proofs.js`**:
```js
export function entropyCalc(N, L) { /* ... */ }
export function uniquenessCalc(N, L, k) { /* ... */ }
```

**`threats.js`**:
```js
export const THREATS = [ /* ... */ ];
```

**`ui.js`**:
```js
export function renderFreqBars(freq, charset, expected) { /* ... */ }
export function renderNIST(totalEntropy) { /* ... */ }
export function renderThreats() { /* ... */ }
export function renderSelfAudit(charset) { /* ... */ }
// ... other DOM helpers
```

**`main.js`**:
```js
import { generatePassword } from './generator.js';
import { chiSquaredTest, serialCorrelation, collisionCheck } from './audit.js';
// ... wire up the runFullAudit function and DOM event listeners
```

The `index.html` should then just have a `<script type="module" src="./main.js"></script>` tag instead of the inline `<script>` block.

---

## 6. Python Configuration

### `packages/cli/pyproject.toml`

```toml
[project]
name = "paranoid-passgen"
version = "0.1.0"
description = "Self-auditing cryptographic password generator with LLM threat model"
readme = "../../README.md"
license = "MIT"
requires-python = ">=3.10"
authors = [{ name = "paranoid contributors" }]
keywords = ["password", "security", "cryptography", "audit", "llm"]
classifiers = [
    "Development Status :: 3 - Alpha",
    "Topic :: Security :: Cryptography",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3",
]

[project.scripts]
paranoid = "paranoid.__main__:main"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/paranoid"]

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "--strict-markers -v"

[tool.coverage.run]
source = ["src/paranoid"]
branch = true

[tool.coverage.report]
fail_under = 80
show_missing = true
exclude_lines = ["pragma: no cover", "if __name__", "raise NotImplementedError"]

[tool.ruff]
target-version = "py310"
line-length = 100
src = ["src", "tests"]

[tool.ruff.lint]
select = ["E", "F", "W", "I", "N", "UP", "S", "B", "A", "C4", "PT", "RUF"]
ignore = ["S603", "S607"]  # subprocess calls are intentional in this project

[tool.ruff.lint.per-file-ignores]
"tests/**/*.py" = ["S101"]  # assert is fine in tests
```

### Python Module Extraction

Break `password_auditor.py` into the module structure defined above. Each module should be importable independently:

- `generator.py`: `generate_password_openssl()`, `generate_password_urandom()`
- `audit.py`: `chi_squared_test()`, `serial_correlation_test()`, `runs_test()`, `repetition_check()`
- `breach.py`: `hibp_check_offline()`, `common_pattern_check()`
- `threats.py`: `llm_threat_analysis()`
- `proofs.py`: `entropy_proof()`, `uniqueness_proof()`
- `self_audit.py`: `self_audit()`
- `report.py`: All the `header()`, `log()`, and terminal formatting
- `__main__.py`: The `main()` function that orchestrates everything

---

## 7. Testing Strategy

### JavaScript Tests (Vitest)

Use `vitest` with `jsdom` environment. Critical tests to write:

**`generator.test.js`**:
- `generatePassword` returns correct length for all charsets
- All characters in output belong to the specified charset
- Rejection sampling produces uniform distribution (generate 10,000 chars, chi-squared test with p > 0.01)
- No duplicate passwords in a batch of 100 (collision check)
- Edge cases: length=8, length=128, single-char charset

**`audit.test.js`**:
- `chiSquaredTest` returns p > 0.01 for uniform input, p < 0.01 for heavily biased input
- `serialCorrelation` returns near-zero for random input, high value for `aababab...` pattern
- `collisionCheck` correctly counts known duplicates
- `erfc` matches known values: erfc(0) ≈ 1, erfc(∞) → 0

**`proofs.test.js`**:
- `entropyCalc(94, 32)` returns total ≈ 209.75 bits
- `entropyCalc(62, 16)` returns total ≈ 95.27 bits
- `uniquenessCalc` for large spaces returns collision probability ≈ 0
- `uniquenessCalc` for tiny spaces (N=2, L=3, k=5) returns non-trivial collision probability

**`integration.test.js`**:
- Full `runFullAudit` flow: mock DOM, verify all panels populated, all badges set
- Verify no errors thrown for each charset option

### Python Tests (pytest)

**`test_generator.py`**:
- Output length matches requested length
- All characters in output belong to charset
- Uniformity test on 10,000 characters (chi-squared, p > 0.01)
- `generate_password_openssl` and `generate_password_urandom` produce different passwords
- Rejection sampling boundary: verify `max_valid` calculation for various charset sizes

**`test_audit.py`**:
- Chi-squared test passes for uniform data, fails for biased data
- Serial correlation near zero for random, nonzero for patterned
- Runs test within expected range
- Repetition check catches known duplicates

**`test_breach.py`**:
- SHA-1 hash computed correctly (compare against known hash)
- k-anonymity prefix is first 5 characters of hash
- Pattern check catches `qwerty`, `12345`, triple repeats
- Pattern check passes on random passwords

**`test_proofs.py`**:
- Entropy calculation: verify `94^32` entropy = 209.75 bits
- Birthday paradox: collision probability for known small inputs matches manual calculation
- Brute-force time estimates are in correct order of magnitude
- NIST comparison thresholds are correct

**`test_integration.py`**:
- Full `main()` runs without errors (capture stdout, verify exit code 0)
- Output contains all expected section headers
- Output reports "ALL TESTS PASSED" for default configuration

### Coverage Requirements

- **JavaScript**: ≥ 85% line coverage, ≥ 80% branch coverage
- **Python**: ≥ 80% line coverage (set in `pyproject.toml` `fail_under`)
- Both produce **LCOV** reports for SonarCloud ingestion

---

## 8. GitHub Actions Workflows

### `.github/workflows/ci.yml` — Main CI

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

jobs:
  lint:
    name: Lint
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: pnpm
      - run: pnpm install --frozen-lockfile
      - name: Biome check (JS)
        run: pnpm exec biome check packages/web/
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - name: Install Python deps
        run: pip install ruff
      - name: Ruff check (Python)
        run: ruff check packages/cli/src packages/cli/tests

  test-web:
    name: Test (Web)
    runs-on: ubuntu-latest
    needs: lint
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: pnpm
      - run: pnpm install --frozen-lockfile
      - name: Run tests with coverage
        run: pnpm exec nx test web
      - uses: actions/upload-artifact@v4
        with:
          name: web-coverage
          path: packages/web/coverage/lcov.info

  test-cli:
    name: Test (CLI)
    runs-on: ubuntu-latest
    needs: lint
    strategy:
      matrix:
        python-version: ['3.10', '3.11', '3.12']
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      - name: Install dependencies
        run: |
          pip install pytest pytest-cov
          pip install -e packages/cli/
      - name: Run tests with coverage
        run: |
          cd packages/cli
          pytest tests/ --cov=src/paranoid --cov-report=xml:coverage.xml --cov-report=term-missing
      - uses: actions/upload-artifact@v4
        if: matrix.python-version == '3.12'
        with:
          name: cli-coverage
          path: packages/cli/coverage.xml

  build-web:
    name: Build (Web)
    runs-on: ubuntu-latest
    needs: test-web
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: pnpm
      - run: pnpm install --frozen-lockfile
      - run: pnpm exec nx build web
      - uses: actions/upload-artifact@v4
        with:
          name: web-dist
          path: packages/web/dist/
```

### `.github/workflows/codeql.yml` — GitHub CodeQL

```yaml
name: CodeQL

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'  # Weekly Monday 6am

jobs:
  analyze:
    name: Analyze
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    strategy:
      matrix:
        language: [javascript, python]
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
        with:
          languages: ${{ matrix.language }}
      - uses: github/codeql-action/autobuild@v3
      - uses: github/codeql-action/analyze@v3
```

### `.github/workflows/sonarcloud.yml` — SonarCloud

```yaml
name: SonarCloud

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  sonarcloud:
    name: SonarCloud Analysis
    runs-on: ubuntu-latest
    needs: []  # Can run in parallel or after CI
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for blame
      - uses: pnpm/action-setup@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: pnpm
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pnpm install --frozen-lockfile
      - run: pip install pytest pytest-cov
      - run: pip install -e packages/cli/

      # Generate both coverage reports
      - name: Test web with coverage
        run: pnpm exec nx test web
      - name: Test CLI with coverage
        run: |
          cd packages/cli
          pytest tests/ --cov=src/paranoid --cov-report=xml:coverage.xml

      - uses: SonarSource/sonarcloud-github-action@v3
        env:
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### `.github/workflows/release.yml` — GitHub Pages Deploy

```yaml
name: Deploy to GitHub Pages

on:
  push:
    branches: [main]
    paths:
      - 'packages/web/**'

permissions:
  pages: write
  id-token: write

jobs:
  deploy:
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: pnpm
      - run: pnpm install --frozen-lockfile
      - run: pnpm exec nx build web
      - uses: actions/configure-pages@v5
      - uses: actions/upload-pages-artifact@v3
        with:
          path: packages/web/dist
      - id: deployment
        uses: actions/deploy-pages@v4
```

---

## 9. GitHub Security Configuration

### `.github/dependabot.yml`

```yaml
version: 2
updates:
  - package-ecosystem: npm
    directory: /
    schedule:
      interval: weekly
    groups:
      dev-dependencies:
        patterns: ["*"]
        update-types: ["minor", "patch"]
    open-pull-requests-limit: 10

  - package-ecosystem: pip
    directory: /packages/cli
    schedule:
      interval: weekly
    open-pull-requests-limit: 5

  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
```

### `.github/SECURITY.md`

Write a security policy that:
- Explains the project's unique position (LLM-authored security tool)
- Directs vulnerability reports to GitHub Security Advisories (private)
- Explicitly states that cryptographic implementation review is welcome
- Lists the known residual risks from AGENTS.md (T4, T5, T6)
- Notes that the CSPRNG delegation strategy is the primary security boundary

### `.github/CODEOWNERS`

```
# Global
* @<maintainer-placeholder>

# Cryptographic code requires careful review
packages/web/src/generator.js  @<crypto-reviewer-placeholder>
packages/cli/src/paranoid/generator.py  @<crypto-reviewer-placeholder>
packages/web/src/audit.js  @<crypto-reviewer-placeholder>
packages/cli/src/paranoid/audit.py  @<crypto-reviewer-placeholder>
```

---

## 10. SonarCloud Configuration

### `sonar-project.properties`

```properties
sonar.organization=<org-placeholder>
sonar.projectKey=<project-key-placeholder>
sonar.projectName=paranoid

# Sources
sonar.sources=packages/web/src,packages/cli/src
sonar.tests=packages/web/__tests__,packages/cli/tests

# Exclusions
sonar.exclusions=**/dist/**,**/node_modules/**,**/coverage/**,**/__pycache__/**

# JavaScript coverage (LCOV from Vitest)
sonar.javascript.lcov.reportPaths=packages/web/coverage/lcov.info

# Python coverage (Cobertura XML from pytest-cov)
sonar.python.coverage.reportPaths=packages/cli/coverage.xml

# Encoding
sonar.sourceEncoding=UTF-8

# Quality Gate: enforce on new code
sonar.qualitygate.wait=true
```

---

## 11. Additional Files to Create

### `README.md` (root)

A shorter, public-facing README that includes:
- Project name, tagline, and badge row (CI status, SonarCloud quality gate, coverage, license)
- One-paragraph description
- Screenshot/demo link (GitHub Pages URL)
- Quick start: `pnpm install && pnpm dev` (web) and `pip install -e packages/cli && paranoid` (CLI)
- Link to AGENTS.md for full documentation
- License (MIT)

### `LICENSE`

Standard MIT license.

### `.editorconfig`

```ini
root = true

[*]
indent_style = space
indent_size = 2
end_of_line = lf
charset = utf-8
trim_trailing_whitespace = true
insert_final_newline = true

[*.py]
indent_size = 4

[*.md]
trim_trailing_whitespace = false
```

### `.gitignore`

```
node_modules/
dist/
coverage/
.nx/
*.pyc
__pycache__/
*.egg-info/
.pytest_cache/
.ruff_cache/
.vite/
```

---

## 12. Execution Order

Run these steps in order:

1. **Scaffold directory structure** — Create all directories and empty files
2. **Move and refactor source files** — Extract `index.html` into modules, extract `password_auditor.py` into Python package
3. **Create configuration files** — `nx.json`, `biome.json`, `pnpm-workspace.yaml`, `pyproject.toml`, `vite.config.js`, etc.
4. **Create GitHub workflows** — All four YAML files
5. **Create GitHub security files** — `dependabot.yml`, `SECURITY.md`, `CODEOWNERS`
6. **Create SonarCloud config** — `sonar-project.properties`
7. **Write tests** — JS tests (Vitest) and Python tests (pytest)
8. **Create README.md and LICENSE**
9. **Run `pnpm install`** — Install all dependencies
10. **Run `pnpm exec nx run-many -t lint`** — Verify Biome and ruff pass
11. **Run `pnpm exec nx run-many -t test`** — Verify all tests pass
12. **Run `pnpm exec nx build web`** — Verify the web build produces a single `index.html`
13. **Verify the built `index.html` works** — Open it and confirm all functionality preserved

---

## 13. Critical Constraints

- **Do NOT alter the cryptographic logic.** The rejection sampling algorithm, charset construction, and CSPRNG delegation must be preserved exactly. These are the security-critical paths.
- **Do NOT add runtime dependencies to the web package.** The entire point is zero-dependency, single-file output. Dev dependencies (Vite, Vitest, Biome) are fine.
- **Biome 2.4 specifically.** Pin to `2.4.0` in `package.json`. Do not use 1.x or unstable versions.
- **The built web artifact must work on `file://` protocol.** No absolute paths, no server-required features, no dynamic imports in the production bundle.
- **Python 3.10+ compatibility.** Don't use 3.12+ features like `type` statements.
- **All coverage reports must be in formats SonarCloud can ingest.** LCOV for JS, Cobertura XML for Python.
- **Nx caching must work.** Ensure all `inputs` and `outputs` are correctly defined so `nx affected` and caching function properly.
- **Placeholder values.** Use `<placeholder>` syntax for values that require repo-specific configuration (SonarCloud org, CODEOWNERS usernames, etc.). Add a comment near each explaining what needs to be filled in.

---

## 14. Verification Checklist

Before considering the task complete, verify:

- [ ] `pnpm install` succeeds with no errors
- [ ] `pnpm exec biome check packages/web/` passes
- [ ] `ruff check packages/cli/src packages/cli/tests` passes  
- [ ] `pnpm exec nx test web` — all JS tests pass, coverage ≥ 85%
- [ ] `pnpm exec nx test cli` — all Python tests pass, coverage ≥ 80%
- [ ] `pnpm exec nx build web` — produces `packages/web/dist/index.html`
- [ ] The built `index.html` is a single self-contained file
- [ ] `python -m paranoid` runs and produces the full audit report
- [ ] `nx graph` shows correct dependency graph (web and cli are independent)
- [ ] All four GitHub Actions workflows have valid YAML syntax
- [ ] `sonar-project.properties` references correct coverage report paths
- [ ] `AGENTS.md` is preserved unmodified in repo root
- [ ] `README.md` exists with badges and quick start instructions
- [ ] `LICENSE` file exists (MIT)
- [ ] `.gitignore` covers all generated artifacts
