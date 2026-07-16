---
title: CI Design
---

# CI Design

The CI/CD trust model splits into two disjoint tiers. Every cache, prebuilt
image, or restored artifact is assigned to exactly one tier, and nothing
crosses from Tier A into Tier B. This document is the versioned record of
that reasoning — it changes only when the tier boundary itself changes.

## The Two Tiers

**Tier A — PR-gate, may be cached, optimized for speed.** Everything
triggered by `pull_request`, a non-default-branch `push`, or
`workflow_dispatch`, whose only output is a pass/fail gate plus disposable
artifacts: fmt, clippy, test, docs build, dependency scan, security
assurance.

**Tier B — release/attestation, must stay hermetic.** `release.yml`'s
`build-native` matrix and anything producing a signed, attested, or
published artifact: `tar.gz`/`.zip`/`.deb`/`.dmg`/`.msi`, provenance, SBOM
attestation, the Pages deploy of release docs.

No cache key, restored artifact, or prebuilt image consumed by Tier B may
ever be writable by a Tier A trigger. This is the tj-actions/TanStack
lesson: the attack needs one cache reachable from both a fork/PR trigger and
a release trigger. The tier split structurally denies that by construction,
not by a permissions review that has to be re-verified every change.

## What May Be Cached (Tier A Only)

1. The compiled Wolfi builder image, pulled by immutable `@sha256` digest
   from GHCR, never rebuilt in-job.
2. `cargo`'s `target/` directory and test-binary archive, via
   `Swatinem/rust-cache`, with `save-if` gated to `main` so fork PRs
   restore-only and can never write.
3. tox/Sphinx virtualenvs, via `actions/cache` keyed on content hashes.

All three are correctness-transparent: a poisoned or stale entry can only
make a Tier A gate compile or test wrong code, which that gate's own suite
then rejects. It cannot reach a published artifact because Tier B never
reads any of them.

## What Must Stay Hermetic (Tier B, Untouched)

Wolfi base pinned by `@sha256`; every `apk` pinned to an exact `-rN`
version; the RustSec advisory DB pinned to a git rev; vendored crates plus
`cargo --locked --frozen --offline`. Release builds compile cold, inside the
digest-pinned image, with no `rust-cache`, no restored `target/`, no GHA
cache of any kind. Release stays reproducible-by-construction: same image
bytes plus same `vendor/` plus same source equals same binary.

The prebuilt GHCR image does not weaken this. It is byte-identical to
today's per-job Dockerfile build — same Dockerfile, same digest — just built
once and pinned instead of rebuilt N times per PR.

## Why the Builder Image Is the Dominant Waste

`.github/actions/builder` is a `runs: using: docker, image: Dockerfile`
container action. GitHub rebuilds the entire Wolfi image — `apk` installs,
`pip install tox`, `cargo install sphinx-rustdocgen`, the advisory-db clone,
smoke checks, roughly 2.5–3.2 minutes — from scratch on every job
invocation, with zero layer cache. That happens roughly five times per PR
across `ci.yml` (rust, docs, dependency-scan), `security-assurance.yml`, and
every push to `cd.yml`. Prebuilding once to GHCR and consuming by digest is
the single highest-ROI change here, and it is a strict security improvement:
a digest pin beats a per-job rebuild-from-Dockerfile that can silently drift
between runs if the Dockerfile's own inputs (e.g. upstream mirrors) hiccup.

## Cache Poisoning Is Solved by Posture, Not Permissions

Locked, frozen, offline, and vendored already means Tier A has no
*dependency* cache to poison — `cargo` never touches a registry. The only
new cached surface is the compiled object cache (`target/`) and the builder
image, and both are Tier-A-only: fork PRs restore but cannot write
(`save-if` plus GitHub's read-only-cache-for-untrusted-triggers backstop).
Merge is never gated on cache warmth — a cold cache must still produce a
correct, complete build.

## Sequencing Constraint

Splitting `fmt` out of `make ci` into its own fail-fastest job only pays off
once container-spin-up is cheap. Before the GHCR image lands, splitting fmt
adds a second full image rebuild for near-zero benefit. P6.5 is explicitly
sequenced after P6.1 for this reason; do not reorder.

## Changes

### P6.1 — Prebuild the Wolfi builder image to GHCR, consume by digest

`.github/workflows/builder-image.yml` builds
`.github/actions/builder/Dockerfile` via `docker/setup-buildx-action` +
`docker/build-push-action`, with `cache-from`/`cache-to type=gha,mode=max`,
and pushes to `ghcr.io/jbcom/paranoid-passwd-builder`. Triggers: `push` with
`paths: ['.github/actions/builder/**']` on `main`, a weekly `schedule`, and
`workflow_dispatch`. The publish job carries `permissions: packages: write`
and is unreachable from `pull_request` — a fork PR can never publish an
image. `.github/actions/builder/action.yml` moves from `image: Dockerfile`
to `image: docker://ghcr.io/jbcom/paranoid-passwd-builder@sha256:<digest>`,
with the Dockerfile retained in-repo as the build source of truth.

**Expected saving:** ~2.5–3.2 min per job × ~5 jobs/PR ≈ 12–16 min of
wall-clock removed per PR. Jobs run in parallel, so the PR critical path
drops from ~22.5 min toward ~19–20 min immediately; the redundant
docs/dep-scan/assurance image builds vanish entirely. Push-to-main sheds the
`cd.yml` rebuild too.

**Risk (MEDIUM):** the GHCR image must exist and its digest must be pinned
before the consuming workflows switch — see Bootstrap Ordering below. A
stale digest means CI runs old tooling until the next scheduled or
paths-triggered rebuild lands a bump. The image is Tier-A-consumed for PR
gates and Tier-B-consumed for release's Linux legs, but because it is
byte-identical to today's Dockerfile build and pinned by digest, the
hermetic guarantee is preserved, not weakened.

**Rollback:** revert `action.yml`'s `image:` field back to `Dockerfile`. The
Dockerfile stays in-repo as the GHCR build's source of truth, so this is a
one-line revert with zero other changes.

### Bootstrap Ordering

The GHCR image does not exist until `builder-image.yml` has run once on
`main`, and this PR cannot know that digest in advance. The switch ships
**ready-but-gated**:

1. This PR adds `builder-image.yml` and leaves
   `.github/actions/builder/action.yml` on `image: Dockerfile` (the current,
   working, digest-pinned-Wolfi-base build). The `docker://` consumption
   line is present in `action.yml` but commented out, alongside a comment
   pointing at the bootstrap script.
2. `scripts/bump_builder_digest.sh` is added. It resolves the current
   `ghcr.io/jbcom/paranoid-passwd-builder:latest` digest via `docker
   buildx imagetools inspect` (or `skopeo inspect` if present) and rewrites
   `action.yml`'s commented `docker://...@sha256:` line to the resolved
   digest, then uncomments it and comments out `image: Dockerfile`.
3. After this PR merges to `main`, `builder-image.yml` runs (path trigger
   fires on the `.github/actions/builder/**` change) and publishes the
   first image.
4. The bootstrap script is then run once, in a follow-up commit, to flip
   `action.yml` onto the digest-pinned `docker://` reference. From that
   point forward, `builder-image.yml`'s weekly schedule plus
   `workflow_dispatch` is the update path — bump the digest, open a PR, let
   CI prove the new image still builds green, merge.

This ordering means `action.yml` never references a digest that does not
exist yet, and the working tree is never left with a broken builder action
mid-PR.

### P6.2 — Deduplicate builder rebuilds and verify-assurance runs

After P6.1, `security-assurance.yml` consumes the GHCR image instead of
rebuilding it, and is reduced to the base-ref-diffed
`security_assurance_gate.py` delta, since `make ci` already runs
verify-assurance. The `security-assurance-report.{json,md}` artifact upload
is preserved. `fetch-depth: 0` is preserved for the base-ref diff.

**Expected saving:** ~3–4.5 min per PR. **Risk:** LOW — Tier A gate,
trust-neutral. **Rollback:** restore the standalone rebuilding form,
one-file revert.

### P6.3 — Tier-A cargo target-dir caching, fork-PR write protection

`ci.yml`'s Rust job gets `Swatinem/rust-cache`, SHA-pinned, with `save-if:
github.ref == 'refs/heads/main'`, `CARGO_INCREMENTAL=0` at workflow env, and
`CARGO_TARGET_DIR` pointed at a host-mounted path the action can persist
(overriding the Dockerfile's ephemeral `/tmp/cargo-target`).
`release.yml`'s `build-native` legs carry no `rust-cache` step and restore
no `target/` — verified by grep, not by convention.

**Expected saving:** ~6–9 min per PR on warm cache. **Risk:** MEDIUM,
mitigated by `save-if` main-only, the GitHub read-only-cache backstop, and
the fact that a poisoned `target/` can only miscompile a Tier A gate that
its own suite then rejects — Tier B never restores it. **Rollback:** delete
the cache step and the target-dir override.

### P6.4 — Cache the docs/tox toolchain, remove the double docs build

`ci.yml`'s docs job consumes the GHCR image (so `sphinx-rustdocgen`'s
`cargo install` cost disappears) and adds `actions/cache`, SHA-pinned, keyed
on `tox.ini` plus docs-requirement content hashes. The redundant docs build
between `ci.yml` and `cd.yml`'s `deploy-pages` on push-to-main is reduced —
but `deploy-pages` carries `id-token:write` and is Tier-B-adjacent, so it
must never restore a PR-writable cache. It keeps building fresh from the
digest-pinned image; only the `ci.yml` PR-side docs venv is cached.

**Expected saving:** docs job ~6–7 min → ~1–1.5 min; `deploy-pages` ~3.5–4
min → ~1.5 min. **Risk:** LOW. **Rollback:** remove the cache step.

### P6.5 — Split fmt into a fastest-first Tier-A job

After P6.1, `cargo fmt --check` runs as its own job, separate from
clippy+test (which keeps `rust-cache`). Must not precede P6.1 — see
Sequencing Constraint above.

**Expected saving:** marginal on the happy path, but a formatting-only
mistake reports in under a minute instead of after a full compile. **Risk:**
LOW. **Rollback:** re-merge into `make ci`.

### P6.6 — Least-privilege and trust-boundary audit

Every Tier A workflow keeps `permissions: {}` at top level with per-job
least privilege. `packages: write` exists only on the builder-image publish
job (push/schedule-only, unreachable from `pull_request`). `id-token:write`
exists only on Tier B / deploy jobs and never on a job that restores a
PR-writable cache. A written boundary table enumerates every cache, who can
write it, who reads it, and asserts no cache is both PR-writable and
release-readable.

## Rejected Options

**sccache with the GHA cache backend.** sccache's object-level dedup shines
across large multi-crate, multi-job matrices sharing objects across many
jobs. Neither tokio, ruff, nor rust-analyzer use it — all chose
`rust-cache` or plain `CARGO_INCREMENTAL=0` plus nextest. With three crates
and an offline/vendored/locked posture, sccache's dedup would not beat
`rust-cache`'s simpler `target/` tarball enough to justify a second caching
subsystem that itself needs Tier-A/Tier-B boundary reasoning.

**`cargo-nextest --partition` matrix sharding.** The test suite is small
today; partitioning multiplies container-mount/image-pull overhead and adds
an all-green summary job for a suite that is not the bottleneck. Revisit
only if the statistical/property suite grows slow — then hashed partitioning
stable across vendored-set changes, plus nextest archive build-reuse, is the
right shape.

**Registry cache exporter (`type=registry`) instead of `type=gha` for the
image build.** The registry exporter earns its keep when cache needs to
span repos/branches or exceed the 10 GB GHA cache cap. A single-repo builder
image with a handful of layers fits GHA cache comfortably; `type=gha,
mode=max` is simpler and sufficient. A registry cache would add another
cross-boundary shared surface for no benefit at this scale.

**Sharing a warm `rust-cache`/target-dir between PR gates and
`release.yml`'s Linux `build-native` legs.** Hard no. This is exactly the
tj-actions/TanStack cache-poisoning vector: a cache reachable from both a
fork/PR trigger and the release/attestation trigger. Release stays
cold-compile, locked/frozen/offline, inside the digest-pinned image. The
speed cost on release is accepted and non-negotiable — release runs on
tag-publish, not the PR feedback loop, so it is not the optimization target.

**Caching `vendor/` or a cargo registry cache.** Pointless and
boundary-risky. `vendor/` is committed and builds are `--offline --frozen`,
so `cargo` never touches a registry — there is no dependency cache to warm.
This *is* the mitigation the vendored posture exists to provide; adding a
cache here would manufacture a poisoning surface the vendored posture was
specifically built to eliminate.

**Moving CodeQL / OpenSSF Scorecard / the fleet-managed JS-TS CodeQL into
the builder, or consolidating them.** Out of scope and structurally
constrained. The JS-TS CodeQL workflow is fleet-managed
(`jbdevprimary/gh-fleet-sync`), do-not-edit-in-place, and exists to satisfy
an Enterprise branch-protection rule. Scorecard is deliberately isolated
because its webapp refuses results if any co-workflow job carries
`id-token:write` (conflicts with `cd.yml`'s Pages OIDC). `ci.yml` vs
`cd.yml` CodeQL are complementary (non-push vs. push gating), not truly
redundant. Touching these risks branch-protection/OIDC breakage for
~1–2 min/lang of native-runner time that is not the bottleneck.

**Switching the builder from a Dockerfile container action to an
apko/melange-defined image.** Tempting for Wolfi-native reproducibility, but
it is a large migration that changes the trust root's tooling and every
pinned-package mechanism at once, for no additional PR-speed win beyond what
GHCR-prebuild-by-digest already delivers. The current Dockerfile already
achieves a digest-pinned Wolfi base plus pinned `apk` versions. Deferred as
possible future hardening, not part of the speed-maximization work.

## Supply-Chain Gate Interaction

`scripts/supply_chain_verify.sh` asserts the builder image is
Wolfi-based and digest-pinned by grepping fixed strings out of
`.github/actions/builder/Dockerfile` itself (the `FROM
cgr.dev/chainguard/wolfi-base@sha256:...` line and pinned `ARG` values), not
out of `action.yml`'s `image:` field. Keeping the Dockerfile as the GHCR
build's source of truth during the bootstrap window (see Bootstrap Ordering)
means this gate's existing assertions keep passing unchanged whether
`action.yml` points at `Dockerfile` or at the pinned `docker://...@sha256:`
reference — no allowlist changes were needed for P6.1.

Once `action.yml` is flipped to consume the GHCR digest, a future item
should extend `scripts/supply_chain_verify.sh` to also assert the
`docker://ghcr.io/jbcom/paranoid-passwd-builder@sha256:` reference in
`action.yml` matches an image whose provenance traces back to a
`builder-image.yml` run against the current `Dockerfile` — so the
gate cannot be satisfied by a digest pointing at stale or hand-pushed image
content. That assertion is out of scope for P6.1: it depends on the digest
that only exists after this PR's bootstrap step runs (see Bootstrap
Ordering), so the check would be untestable at PR-review time.
