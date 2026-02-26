# Branch Protection Settings

Recommended branch protection configuration for the `main` branch.
These settings cannot be configured via code -- they must be applied
manually in the repository settings at:

    Settings > Branches > Branch protection rules > main

---

## Required Settings

### Require pull request reviews before merging

- **Required approving reviews:** 1
- **Dismiss stale pull request approvals when new commits are pushed:** Yes
- **Require review from code owners:** Yes (when CODEOWNERS file exists)

### Require status checks to pass before merging

The following status checks MUST pass before a PR can be merged:

| Status Check | Workflow | Purpose |
|-------------|----------|---------|
| `native-test` | ci.yml | Native C build + CTest unit tests |
| `wasm-build` | ci.yml | WASM cross-compilation + wasm-validate |
| `e2e-test` | ci.yml | Playwright browser tests |
| `codeql` | ci.yml / codeql.yml | Static security analysis (C/C++, JS) |
| `hallucination-check` | ci.yml | LLM hallucination detection |
| `supply-chain-verify` | ci.yml | Supply chain integrity verification |

Optional but recommended:

| Status Check | Workflow | Purpose |
|-------------|----------|---------|
| `sonarcloud` | ci.yml | SonarCloud quality gate |
| `shellcheck` | ci.yml | Shell script linting |

### Require branches to be up to date before merging

- **Require branches to be up to date before merging:** Yes

This ensures PRs are tested against the latest main branch state,
preventing "semantic merge conflicts" where two individually-correct
changes break when combined.

### Restrict who can push to matching branches

- **Restrict pushes that create matching branches:** Yes
- Only allow repository admins and the release-please bot to push
  directly to main.

## Prohibited Actions

- **Allow force pushes:** No (never)
- **Allow deletions:** No (never)

## Rationale

These settings enforce the paranoid-passwd security model:

1. **No unreviewed code on main** -- Every change requires human review.
   This is critical because the project's threat model identifies the
   LLM as the primary adversary (see AGENTS.md).

2. **All tests must pass** -- The CI pipeline includes hallucination
   detection, supply chain verification, and statistical test validation
   alongside standard unit and E2E tests.

3. **Up-to-date branches** -- Prevents merging stale PRs that could
   introduce regressions when combined with recently merged changes.

4. **No force push** -- Preserves the complete git history for audit
   trail purposes. The supply chain security model requires traceable,
   immutable commit history.

---

## Applying These Settings

1. Navigate to the repository on GitHub
2. Go to Settings > Branches
3. Click "Add branch protection rule" (or edit existing)
4. Set "Branch name pattern" to `main`
5. Enable each setting listed above
6. Click "Create" or "Save changes"
