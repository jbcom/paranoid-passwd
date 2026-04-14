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
- New `.github/actions/builder/` directory: Dockerfile + entrypoint.sh
  + action.yml (Docker container action, no registry push)
- Switch `ci.yml`, `release.yml` (was `cli-release.yml`), and the build
  steps inside `cd.yml` to use the action via `uses: ./.github/actions/builder`
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

### The builder action (Pattern D — chosen)

A **Docker container action living in-repo** at `.github/actions/builder/`,
NOT a published image. Three files:

```
.github/actions/builder/
├── action.yml       runs.using: docker, image: Dockerfile
├── Dockerfile       FROM cgr.dev/chainguard/wolfi-base + apk add zig 0.14.1, cmake, wabt, binaryen, bash, openssl-dev, ninja, git, curl, tar, gzip, coreutils
└── entrypoint.sh    exec bash on $INPUT_RUN with strict flags
```

GitHub Actions builds the Dockerfile per-job from this directory, bind-mounts
`$GITHUB_WORKSPACE` into the container, and runs the entrypoint with
`INPUT_RUN` set from the workflow step's `with: run:`.

Use from any workflow:

```yaml
- name: Build CLI
  uses: ./.github/actions/builder
  with:
    run: |
      cmake -B build/cli -DCMAKE_BUILD_TYPE=Release
      cmake --build build/cli --target paranoid_cli
```

**Why Pattern D (chosen) over a published ghcr image (rejected):**

- **No registry, no push step, no signing infrastructure.** The
  Dockerfile in the repo IS the source of truth.
- **No digest tracking.** A change to the toolchain is a change to the
  Dockerfile is a normal PR diff. The PR that touches the Dockerfile is
  the PR that adopts the new toolchain — atomically.
- **Eliminates trust roots.** No ghcr.io. No cosign signature chain.
  No "is this digest the one we signed?" verification dance. Just
  Wolfi (via `cgr.dev/chainguard/wolfi-base`) and the Dockerfile in
  this repo.
- **Local reproducibility.** `cd .github/actions/builder && docker build .`
  reproduces exactly what CI runs.

**Trade-off accepted:** GitHub-hosted runners are ephemeral, so each cold
job pulls `wolfi-base` and runs `apk add` again. ~30–60s per cold job.
Worth it for the simpler trust model.

### The new workflow shape

```
.github/
├── actions/builder/     NEW: Docker container action (Pattern D)
└── workflows/
    ├── ci.yml           REWRITTEN: steps run via uses: ./.github/actions/builder
    ├── release.yml      RENAMED from cli-release.yml: cross-compile + sigstore
    └── cd.yml           UPDATED: build steps via uses: ./.github/actions/builder
```

NO `builder.yml` workflow exists. The action's Dockerfile is built
per-job by GitHub Actions when a workflow uses it.

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
| `ci.yml` | pull_request; push:main | native-build, wasm-build, e2e, codeql, sonarcloud, shellcheck, hallucination, supply-chain, scorecard (push:main only) |
| `release.yml` | release:published filter `paranoid-passwd-v*`; manual | cross-compile matrix → tarballs → sigstore attest → upload |
| `cd.yml` | push:main | wolfi-melange-build, release-please, pages-deploy |

### Action usage

Every step that compiles or tests our code uses:

```yaml
- name: Build CLI
  uses: ./.github/actions/builder
  with:
    run: |
      cmake -B build/cli -DCMAKE_BUILD_TYPE=Release
      cmake --build build/cli --target paranoid_cli
```

No `container:` job-level config. No image digest. The action handles
container creation per step; subsequent non-builder steps run on the
host runner as usual.

### Why action-per-step instead of job-level container:

The GitHub Actions `container:` directive at the JOB level requires
the image to live in a registry — a locally-built `image: Dockerfile`
isn't accepted. To avoid the registry, we make the builder a per-step
action and accept that each compile-step builds (cached) the Dockerfile.

We do NOT switch to self-hosted runners. The risk surface there
(physical hardware compromise, agent-update push) is worse than what
we have now.

## Implementation plan (high level)

1. **`.github/actions/builder/`** — Dockerfile + entrypoint.sh +
   action.yml. No registry, no separate workflow.
2. **Switch one workflow at a time, in safety order:**
   - `release.yml` (formerly `cli-release.yml`) first — currently broken
     anyway after the v3.2.0 partial release, so a rewrite is least risky
   - `ci.yml` second — folding in CodeQL + Scorecard
   - `cd.yml` last — folds in the `release.yml` Pages-deploy logic
3. **Delete the three obsolete files** in the same PR as the third switch.

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

- Local smoke: `cd .github/actions/builder && docker build .` succeeds
- `gh workflow run ci.yml` on a feature branch using the new action
- WASM binary diff before/after Zig version bump (acceptance: same imports,
  same exports, runtime tests still pass)
- E2E Playwright suite passes
- One full release dry-run via `gh workflow run release.yml -f tag=...`
  against an existing tag

## Risk register

| Risk | Mitigation |
|---|---|
| Zig 0.14.1 produces a broken WASM | wasm-validate gate in ci.yml catches at PR time |
| Per-job Docker build slows pipelines | Acceptable trade for trust-model simplicity. Worst case ~60s/cold-job. Buildx cache on the runner can mitigate if needed. |
| `cgr.dev/chainguard/wolfi-base` unavailable | Same single-vendor risk as Wolfi itself; if we lose Wolfi we have bigger problems. Mirror via apko build if it ever happens. |
| Existing release.yml deletion loses the Pages deploy | Pages-deploy logic moves into cd.yml in the same PR — no gap |
| CodeQL + Scorecard inside ci.yml change cadence | Scorecard already runs weekly via cron; keep that. Change only the `push:main` path |

## Definition of Done

- `.github/actions/builder/{action.yml,Dockerfile,entrypoint.sh}` exist
- All three workflows (`ci.yml`, `release.yml`, `cd.yml`) use
  `uses: ./.github/actions/builder` for every compile/test step
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
