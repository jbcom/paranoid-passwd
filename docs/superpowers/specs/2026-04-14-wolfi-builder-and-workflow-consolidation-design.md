---
title: Wolfi Builder Image + Workflow Consolidation
updated: 2026-04-14
status: approved
domain: technical
---

# Wolfi Builder Image + Workflow Consolidation

## Purpose

Replace every `apt-get install` and external toolchain `curl` in the
project's CI/CD with a single Wolfi-based builder image we own and
sign. Cut the workflow file count from 6 to 3, each with one clear
responsibility. Bring the supply-chain story for CI/CD up to the
same standard the project already applies to runtime artifacts.

## Why

Today's pipelines trust:

- The GitHub-managed `ubuntu-24.04` runner image
- Ubuntu apt repositories (TLS only, no per-package SHA pinning by us)
- `ziglang.org` for the Zig tarball (now SHA-verified, but a separate trust root)
- Each individual GitHub Action commit (verified, but each is a chain root)

That's four trust chains, each independently breakable. Wolfi consolidates
them into one: every package is signed by `wolfi-signing.rsa.pub`, every
source SHA is locked in the apk's recipe, and the build environment is
hermetic. By owning a builder image built on top of `wolfi-base`, we get
one chain we control, signed by us via cosign.

Workflow consolidation is a parallel concern: today's 6 files (`ci.yml`,
`cd.yml`, `release.yml`, `cli-release.yml`, `codeql.yml`, `scorecard.yml`)
have overlapping triggers, one outright duplicate (CodeQL in two places),
and split-brain release logic between `release.yml` and `cli-release.yml`.
Three files with named purposes are easier to audit and harder to break.

## Scope

In scope:
- New `builder/` directory containing the Wolfi builder image recipe
- New `builder.yml` workflow that builds + signs + pushes the image to
  `ghcr.io/jbcom/paranoid-passwd-builder:<sha>` on push to main
- Switch `ci.yml`, `release.yml` (was `cli-release.yml`), and the build
  steps inside `cd.yml` to use that image as their `container:`
- Consolidate 6 workflows → 3 (`ci.yml`, `release.yml`, `cd.yml`)
- Delete `codeql.yml`, `scorecard.yml`, `cli-release.yml`
- Move CodeQL into the `ci.yml` matrix (not a separate file)
- Move OpenSSF Scorecard into `ci.yml` (push:main trigger only)
- Zig version bumps from 0.13.0 to 0.14.1 (the version Wolfi ships)

Out of scope:
- Reproducible-build cross-check between Wolfi apk and cli-release tarballs
  (issue #26 — separate work)
- Touching `paranoid.c` or `include/paranoid.h` in any way (gated)
- Changing the artifact contract for the tap repo
- Changing test code

## Architecture

### The builder image

```
ghcr.io/jbcom/paranoid-passwd-builder
├── built FROM cgr.dev/chainguard/wolfi-base
├── apk add: zig (0.14.1), cmake (3.31.7), bash (5.2.37),
│            wabt (for wasm-validate), binaryen (for wasm-opt),
│            curl (for any SHA-verified downloads needed),
│            git (for git rev-parse in workflows),
│            tar, gzip, coreutils
├── tagged: <sha-of-builder-recipe>, latest
└── signed: cosign keyless via sigstore OIDC (same chain as cli-release)
```

The image recipe lives at `builder/Dockerfile` (a single FROM + apk add
+ minimal labels). A separate `builder/melange.yaml` is NOT used —
melange builds Wolfi packages, but our builder is a Wolfi *consumer*
that needs an image, which `apko` can produce. We use a Dockerfile
because the input is just "wolfi-base + a few apks" and Dockerfile is
clearer than apko's YAML for that simple case.

### The new workflow shape

```
.github/workflows/
├── builder.yml          NEW: builds + signs + pushes the builder image
├── ci.yml               REWRITTEN: jobs run inside builder image
├── release.yml          RENAMED from cli-release.yml: cross-compile + sigstore
└── cd.yml               UPDATED: build steps run inside builder image
```

Files DELETED:
- `codeql.yml` → its full job (init / autobuild / analyze / upload-sarif
  for both c-cpp and javascript) becomes the canonical CodeQL job inside
  `ci.yml`. The existing `Analyze (c-cpp)` / `Analyze (javascript)` jobs
  in ci.yml today are duplicate-but-incomplete; they get replaced by the
  full standalone version. Net result: ONE CodeQL run per PR/push, with
  SARIF upload to GitHub Code Scanning.
- `scorecard.yml` → its single job becomes a `scorecard` job inside
  `ci.yml`, gated with `if: github.event_name == 'push'` so it runs only
  on push:main, never on PR (Scorecard's webapp upload doesn't work for
  PRs and the failures pollute PR status).
- `cli-release.yml` → renamed to `release.yml` (the existing `release.yml`'s
  GitHub Pages deploy moves into `cd.yml` since Pages-deploy is part of CD)

### Trigger map

| Workflow | Triggers | Jobs |
|---|---|---|
| `builder.yml` | push:main on `builder/**` paths; manual | build → cosign-sign → push to ghcr |
| `ci.yml` | pull_request; push:main | native-build, wasm-build, e2e, codeql, sonarcloud, shellcheck, hallucination, supply-chain, scorecard (push:main only) |
| `release.yml` | release:published filter `paranoid-passwd-v*`; manual | cross-compile matrix → tarballs → sigstore attest → upload |
| `cd.yml` | push:main | wolfi-melange-build, release-please, pages-deploy |

### Container usage

Every job that compiles or tests our code uses:

```yaml
jobs:
  whatever:
    runs-on: ubuntu-24.04
    container:
      image: ghcr.io/jbcom/paranoid-passwd-builder@sha256:<digest>
      credentials:
        username: ${{ github.actor }}
        password: ${{ secrets.CI_GITHUB_TOKEN }}
```

The image is pinned by sha256 digest, not tag — same approach as our
GitHub Actions SHA pinning. The digest is updated via dependabot once
we configure dependabot to track Docker image deps.

### Why container: instead of a custom runner

GitHub-hosted runners with a `container:` directive give us:
- Hermetic builds (everything happens inside the image)
- The `ubuntu-24.04` host is just an orchestrator providing Docker
- Cached image pulls between jobs (huge speedup)
- No infrastructure to manage (no self-hosted runner pool)

We do NOT switch to self-hosted runners. The risk surface there
(physical hardware compromise, agent-update push) is worse than what
we have now.

## Implementation plan (high level)

1. **`builder/`** — Dockerfile + cosign-sign workflow. Push initial
   image to ghcr. Verify locally with `cosign verify`.
2. **`builder.yml`** — only triggers on `builder/**` changes + manual.
3. **Switch one workflow at a time, in safety order:**
   - `release.yml` (formerly `cli-release.yml`) first — currently broken
     anyway after the v3.2.0 partial release, so a rewrite is least risky
   - `ci.yml` second — folding in CodeQL + Scorecard
   - `cd.yml` last — folds in the `release.yml` Pages-deploy logic
4. **Delete the three obsolete files** in the same PR as the third switch.

Each switch is an independent PR. Do not bundle.

### Zig version bump

Zig 0.14.1 ships in Wolfi. The current 0.13.0 was kept partly because
0.14.0 had a known WASM codegen bug (per project memory). 0.14.1 is past
that. The first PR to use the builder image will trigger CI; the existing
WASM-validate gate in `ci.yml` will reject any regression before merge.

If 0.14.1 produces a broken WASM, we revert and either pin a known-good
Zig in the builder image (build from source via melange) or wait for
0.14.2.

## Testing

- `cosign verify` against the published builder image
- `gh workflow run ci.yml` on a feature branch with the builder image swap
- WASM binary diff before/after Zig version bump (acceptance: same imports,
  same exports, runtime tests still pass)
- E2E Playwright suite passes
- One full release dry-run via `gh workflow run release.yml -f tag=...`
  against an existing tag

## Risk register

| Risk | Mitigation |
|---|---|
| Zig 0.14.1 produces a broken WASM | wasm-validate gate in ci.yml catches at PR time |
| Builder image becomes a single point of failure | Pinned by sha256 digest; rebuilds reproducible |
| ghcr image compromise | cosign-signed; verify on every pull |
| Wolfi-base unmaintained / disappears | Vendor the apk index SHA in the builder recipe; same as any pinned dep |
| Existing release.yml deletion loses the Pages deploy | Pages-deploy logic moves into cd.yml in the same PR — no gap |
| CodeQL + Scorecard inside ci.yml change cadence | Scorecard already runs weekly via cron; keep that. Change only the `push:main` path |

## Definition of Done

- `ghcr.io/jbcom/paranoid-passwd-builder:<sha>` exists and is cosign-verifiable
- All three workflows (`ci.yml`, `release.yml`, `cd.yml`) use the builder image
- The three deleted files are gone from `.github/workflows/`
- A passing `release.yml` run produces all 4 CLI tarballs + checksums + attestations
- Zero `apt-get install` or `curl https://ziglang.org` lines remain in any
  workflow
- The Wolfi paranoid-passwd-cli subpackage still builds in `cd.yml`
- Documentation in `docs/SUPPLY-CHAIN.md` updated to describe the
  single-trust-root model

## Non-goals

- Self-hosted runners
- Kubernetes / job-scheduling infrastructure
- Replacing GitHub Actions
- A separate CI for the builder image's own dependencies (we trust Wolfi
  for that, by design)
