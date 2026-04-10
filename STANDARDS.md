---
title: Standards
updated: 2026-04-09
status: current
domain: technical
---

# Code Standards — paranoid-passwd

## Non-Negotiable Constraints

1. Max 300 lines per file (all languages).
2. No `TODO` or stub bodies — every function must be implemented.
3. All crypto changes require `// TODO: HUMAN_REVIEW - <reason>` and a tracking issue.
4. All GitHub Actions must be pinned to 40-character commit SHAs, never version tags.
5. No JavaScript fallbacks for WASM failures — fail-closed is a security requirement.
6. No inline JS or CSS in HTML — CodeQL requires file-type separation.

## C Style

Files: `src/*.c`, `include/*.h`

- Indentation: 4 spaces, no tabs
- Naming: `snake_case` for functions and variables, `ALL_CAPS` for macros and constants
- Prefix all public API functions with `paranoid_`
- Prefix platform functions with `paranoid_platform_`
- Comments explain why, not what
- Flag all statistical or cryptographic logic with `// TODO: HUMAN_REVIEW - <reason>`
- Use `__attribute__((export_name("...")))` for every WASM export in `include/paranoid.h`

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
- Max 300 lines per file
- No emojis in headings

## Security Code Review Checklist

Before merging any PR that touches C files:

- [ ] `rand()` or `srand()` absent from all new code
- [ ] Rejection sampling: `max_valid = (256/N)*N - 1`
- [ ] Chi-squared p-value: `pass = (p > 0.01)`, df = N-1
- [ ] No new OpenSSL calls in WASM-targeted source files
- [ ] No new direct calls to `random_get` outside `src/platform_wasm.c`
- [ ] Struct offsets: any new fields have corresponding `paranoid_offset_*()` exports
