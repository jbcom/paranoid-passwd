# paranoid-passwd — Implementation Directive (overhauled 2026-07-16T22:00Z)

Full top-to-bottom completion mandate. Source: adversarially-verified
comprehensive review + architecture review + CI-modernization research
(design: docs/reference/ci-design.md once P6.1 lands).

## Operating model (amended by user)

- ONE long-running local branch: `directive-completion` (worktree e2e-wt).
  All remaining work lands there as forward commits via executor workflows;
  ONE final PR when the queue drains. No other branches, ever.
- In-flight merges: PR #146 (integration) squash-merges on green, then the
  integration branch + int-fix-wt worktree are deleted and main merges into
  directive-completion. PR #138 (dependabot) merges after its rebase goes
  green (expected-SHA updates in assurance scripts are in-scope work if red).
- Orchestrator: main session, with a ScheduleWakeup heartbeat every ~25 min
  auditing ALL state (PRs, workflows, Monitor gaps) and a persistent PR-state
  Monitor. Executors: Sonnet default via Workflow; haiku for mechanical
  sweeps; opus/fable for the hardest verify/design stages. Every executor
  prompt carries the no-delete/no-destructive-git rules and the idempotency
  preamble; every workflow loop try/catches per item.
- Directive hygiene: flips land in the item's commit on directive-completion.
  The main-checkout mirror stays uncommitted and truthful ([WAIT]-annotated)
  for the anti-stop hook.

## Done (merged to main or on the integration/directive-completion lineage)

P0.1-P0.7 (security hardening incl. SecretString constant-time eq,
realloc/clear/pop zeroization, 256 MiB Argon2id with header compat, audit
redaction at the sink, WASM claim reconciliation) · P2.1-P2.3, P2.5
(scriptable TUI, capability detection + --detect-environment, first-run
approval screen, PTY e2e: lockout recovery / rotation / restart persistence)
· P3.1-P3.4 (Dependency Scan job + advisory fixes + allowlist, required
checks live, local-only disposition for NDK/wasm checks, builder retries) ·
P4.2-P4.4, P4.6 (subcommand docs, version-drift gate incl. busybox/pipefail
portability, six-framework reference, mechanical doc-coverage gates) ·
P5.3a CONTRIBUTING.md + published page · P5.4 scaffolding untracked ·
P6.0 CI research + two-tier trust design.

## Queue (strict order on directive-completion)

- [x] P1.1-P1.5 architecture refactors — commits 0fe61bca, 47b5bd1a,
  d443e78a, 233c5ab7, 50452bc9. Gate green EXCEPT test-tui-e2e
  recovery_secret_rotation_flow (regression bisected to predate P1 entirely
  — see P1.R).
- [x] P1.R Fix the TUI e2e regression (rotation flow init step). Bisection
  via git-archive probe builds (703d8db4, cb4f9c6e, 3e89c5cc, 838fc939,
  2760055f) proved the failure predates all five P1 commits: 703d8db4 (last
  commit before the P1 window) already reproduces it, and 2760055f (where it
  last passed 4/4) passes cleanly. First bad commit: the `7af19764` merge,
  behaviorally caused by `91fd4f6f` (Argon2id memory cost 64->256 MiB)
  combined with the pre-existing `submit_vault_init` -> `refresh()` pattern
  that performed a *second* full Argon2id derivation immediately after
  init's first one. In a debug build each derivation costs ~5-6s, so the
  two sequential derivations blew the harness's 10s timeout (not an
  infinite hang — verified by timing `vault init` + `vault list` via the
  debug CLI directly: ~5-10s each). Fixed forward by adding
  `init_vault_unlocked` (paranoid-vault/src/lifecycle.rs) returning the
  already-unlocked vault from init instead of just the header, and
  threading that handle through `submit_vault_init` /
  `auto_enroll_device_keyslot` (paranoid-cli/src/vault_tui/screen_state.rs)
  so vault creation never re-derives the KEK it just derived. `init_vault`
  keeps its original signature for the ~90 existing callers that want only
  the header. make test-tui-e2e green 2x consecutively; cargo test -p
  paranoid-cli -p paranoid-vault clean (75 tests); fmt+clippy -D warnings
  clean on both crates.
- [x] P6.1 GHCR digest-pinned builder image (+ design doc committed to
  docs/reference/) — biggest CI win, trust-improving; bootstrap ordering per
  design.json. docs/reference/ci-design.md versions the two-tier trust
  design. `.github/workflows/builder-image.yml` builds + publishes
  ghcr.io/jbcom/paranoid-passwd-builder (push paths-scoped to
  .github/actions/builder/**, weekly schedule, workflow_dispatch;
  packages:write scoped to that job only, unreachable from pull_request).
  `.github/actions/builder/action.yml` stays on `image: Dockerfile`
  (bootstrap-gated: the digest does not exist pre-merge) with the
  `docker://...@sha256:<digest>` line present-but-commented, plus
  `scripts/bump_builder_digest.sh` to flip it once the first GHCR image
  exists post-merge. supply_chain_verify.sh checked against the new
  workflow/action.yml — its builder-pin assertions read the Dockerfile
  directly, not action.yml, so no allowlist change was needed; a follow-up
  item to assert the eventual docker:// digest is noted in
  ci-design.md's "Supply-Chain Gate Interaction" section.
- [x] P6.2 dedupe builder rebuilds + verify-assurance runs across workflows.
  security-assurance.yml no longer runs `make verify-assurance` (already run
  by ci.yml's `make ci` on the same PR); reduced to the base-ref-diffed
  `security_assurance_gate.py` run + report-artifact upload only, same
  "Security Assurance" check name, fetch-depth:0 preserved. ci.yml's `docs`
  job now skips on push-to-main (`if: github.event_name != 'push'`) since
  cd.yml's deploy-pages job builds the same Sphinx site fresh on every push;
  docs job still runs (with linkcheck) on pull_request, where deploy-pages
  never runs. Builder image rebuild dedup itself is P6.1's bootstrap
  (`image: Dockerfile` until the digest-bump script flips it); no workflow
  here still triggers a redundant in-job image *build* beyond that
  documented bootstrap gap.
- [x] P6.3 Tier-A cargo target cache (save-if main-only; release restores
  nothing).
- [x] P6.4 docs/tox toolchain cache (deploy-pages stays cache-free:
  id-token:write). Double docs build already killed by P6.2.
- [x] P6.5 fmt fastest-first job split. New `fmt` job in ci.yml runs
  `cargo fmt --check` (matching make's exact flag) standalone via the
  builder action, ahead of and independent from the `rust` job (which keeps
  clippy+test+rust-cache). Sequenced after P6.1 per ci-design.md's
  "Sequencing Constraint" — P6.1 already landed, so this job pulls the
  digest-pinned builder image rather than rebuilding it. `make ci`'s local
  behavior is unchanged (still runs fmt as its first step). Not added to
  `scripts/verify_branch_protection.sh`'s required-checks list — additive,
  non-required until the orchestrator updates branch protection post-merge.
- [x] P6.6 least-privilege + trust-boundary audit of all workflows. Audited
  every workflow file directly (permissions, concurrency, SHA-pinning,
  cache reachability). Found and fixed two gaps: (1) scorecard.yml's
  top-level `permissions: read-all` was broader than its job needed
  (tightened to `{}`; job-level grants unchanged and sufficient); (2)
  ci.yml's docs job used a single ungated `actions/cache` step for the
  `.tox` venv — unlike Swatinem/rust-cache, plain actions/cache has no
  save-if, so a same-repo PR branch could write the cache; split into
  `actions/cache/restore` (every run) + `actions/cache/save` (gated
  `github.ref == 'refs/heads/main'`, mirroring the rust job's save-if).
  Confirmed: all external actions SHA-pinned (grep, zero non-pinned
  matches); packages:write only on builder-image.yml's publish job
  (push/schedule/dispatch, unreachable from pull_request); id-token:write
  only on cd.yml deploy-pages, release.yml's three Tier B jobs, and
  scorecard.yml (isolated per OSSF requirement), none of which restore any
  cache; all pull_request-triggered workflows (ci.yml, security-assurance.yml,
  codeql.yml) have concurrency + cancel-in-progress:true; release.yml has
  zero actions/cache or rust-cache references anywhere (Tier B stays cold).
  codeql.yml (fleet-managed, do-not-edit-in-place) and scorecard.yml's
  id-token isolation left untouched as designed. Full claim-backed audit
  table written to docs/reference/ci-design.md's "P6.6" section. Verified:
  actionlint clean, python3 yaml parse clean on all 7 workflow files,
  scripts/validate-docs.sh clean.
- [ ] P6.7 test-execution parallelism (owner research: Wolfi ships no
  cargo-nextest/mold/lld; rust-lld absent from pinned toolchain) — evaluate
  vendoring cargo-nextest (precedent: sphinx-rustdocgen) vs make-level
  parallel per-crate test runs; before/after CI timing evidence required;
  linker findings into ci-design.md rejected-options.
- [ ] P4.S docs-currency sweep (user-elevated) — both-directions pass over
  every docs page vs code (haiku fan-out + sonnet fixes), Sphinx+linkcheck
  green, AGENTS.md/CLAUDE.md accurate to the post-P1 module map.
- [ ] P4.V live-site verification (post-#146 merge) — WebFetch the deployed
  Pages site; spot-check contributing/compliance-frameworks/testing/ci-design.
- [ ] P7.1 Atomic backup restore — temp-sibling DB + atomic replace
  (mutation_handlers.rs:418, #146 review).
- [x] P7.2 Auto-lock hardening — never on EnvironmentApproval; purge
  options.auth + secret forms on lock (screen_state.rs:1584).
- [ ] P7.3 Export safety — reject source==destination; temp-file atomic
  rename (backup_transfer.rs:210).
- [ ] P7.4 Transactional imports; temp-DB restores (backup_transfer.rs:440).
- [x] P7.5 Zeroize MnemonicRecoveryEnrollment (SecretString + redacted
  Debug, keyslots.rs:98) — completes the P0 sweep.
- [ ] P2.4 vendored slint-testing + real widget-event GUI tests.
- [ ] P2.6 make e2e-ci / e2e-local split (real mouse/keyboard local GUI
  runs), wired into make ci; testing.md documents platform conditions.
- [ ] P4.1 GUI parity overclaim fixes (re-checked against post-P2.4 truth).
- [ ] P4.5 testing.md completeness (tui/vault e2e targets + e2e split).
- [ ] P4.7 CLAUDE.md GUI framing accuracy (post-P2.4).
- [ ] P5.1 data-driven framework/charset registries (crypto math stays Rust).
- [ ] P5.2 seal-provider trait seam.
- [ ] P5.3b docs/reference/extending.md with worked examples (after P5.1/2).
- [ ] FINAL: full gate (make ci + quality + e2e-ci + e2e-local on this
  machine), docs both-directions sweep, open the single PR, babysit to
  squash-merge, verify the app RUNS (TUI + GUI), release-please takes over.

## Standing constraints

Zero-exception rules in CLAUDE.md; two-tier cache/trust boundary per
design.json; no new branches; no amends to pushed commits; executor
placeholder-output checks mandatory.
