---
title: Standards
updated: 2026-04-09
status: current
domain: technical
---

# Code Standards — paranoid-passwd

## Non-Negotiable Constraints

1. No stub bodies — every declared function must be implemented. The only
   permitted `TODO` marker is `// TODO: HUMAN_REVIEW - <reason>` on
   cryptographic or statistical code.
2. All crypto changes require `// TODO: HUMAN_REVIEW - <reason>` and a tracking issue.
3. All GitHub Actions must be pinned to 40-character commit SHAs, never version tags.
4. No JavaScript fallbacks for WASM failures — fail-closed is a security requirement.
5. No inline JS or CSS in HTML — CodeQL requires file-type separation.

## File Length Targets

Target 300 lines per file where practical. Larger files are acceptable when
needed for cohesion (single-file SHA-256 implementation, comprehensive build
or supply-chain documentation, single CSS state machine). Files currently
above target — `src/paranoid.c`, `include/paranoid.h`, `www/style.css`,
`www/app.js`, several `docs/*.md` — are tracked for refactoring opportunity
but are not blockers.

## C Style

Files: `src/*.c`, `include/*.h`

- Indentation: 4 spaces, no tabs
- Naming: `snake_case` for functions and variables, `ALL_CAPS` for macros and constants
- Prefix all public API functions with `paranoid_`
- Prefix platform functions with `paranoid_platform_`
- Comments explain why, not what
- Flag all statistical or cryptographic logic with `// TODO: HUMAN_REVIEW - <reason>`
- WASM exports use the toolchain default (`extern "C"` + linker `--export`)
  driven by the CMake `wasm32-wasi.cmake` toolchain. Do not add
  `__attribute__((export_name(...)))` unless the build switches to that mechanism.

```c
// Correct rejection sampling — document the formula
int max_valid = (256 / charset_len) * charset_len - 1;  // uniform over [0, max_valid]
uint8_t byte;
do {
    paranoid_platform_random(&byte, 1);
} while (byte > max_valid);
output[i] = charset[byte % charset_len];
```

## JavaScript Style

File: `www/app.js`

- Indentation: 2 spaces
- Naming: `camelCase` for functions and variables, `UPPER_CASE` for constants
- `const` by default, `let` only when reassignment is required, never `var`
- `async`/`await`, never `.then()` chains
- JSDoc on all exported or significant functions
- `app.js` must not contain any cryptographic logic — reading struct offsets and
  calling `textContent` only

## CSS Style

File: `www/style.css`

- Indentation: 2 spaces
- Naming: `kebab-case` for class and ID names
- Alphabetical property order within a rule block
- Comment complex selectors, especially CSS state machine transitions

## HTML Style

File: `www/index.html`

- No inline `<style>` or `<script>` blocks
- All external assets loaded via `<link rel="stylesheet">` and `<script src="...">`
- Semantic HTML5 elements (`<main>`, `<section>`, `<header>`, etc.)

## Git and CI

- Conventional Commits: `feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`
- All PRs require at least one human review before merge
- Required CI checks: `native-test`, `wasm-build`, `e2e-test`, `codeql`
- Never force-push to `main`
- Squash-merge PRs

## Markdown

- All `.md` files in root and `docs/` must have YAML frontmatter with
  `title`, `updated`, `status`, and `domain` fields
- No emojis in headings

## Security Code Review Checklist

Before merging any PR that touches C files:

- [ ] `rand()` or `srand()` absent from all new code
- [ ] Rejection sampling: `max_valid = (256/N)*N - 1`
- [ ] Chi-squared p-value: `pass = (p > 0.01)`, df = N-1
- [ ] No new OpenSSL calls in WASM-targeted source files
- [ ] No new direct calls to `random_get` outside `src/platform_wasm.c`
- [ ] Struct offsets: any new fields have corresponding `paranoid_offset_*()` exports
