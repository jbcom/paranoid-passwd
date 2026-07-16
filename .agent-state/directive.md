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
  recovery_secret_rotation_flow (regression introduced within P1, being
  bisected — release-blocking).
- [ ] P1.R Fix the P1-introduced TUI e2e regression (rotation flow init
  step) — bisect 703d8db4..50452bc9, root-cause, fix forward. Related: the
  CI-container vault_flow failure under debug on int-fix-wt.
- [ ] P6.1 GHCR digest-pinned builder image (+ design doc committed to
  docs/reference/) — biggest CI win, trust-improving; bootstrap ordering per
  design.json.
- [ ] P6.2 dedupe builder rebuilds + verify-assurance runs across workflows.
- [ ] P6.3 Tier-A cargo target cache (save-if main-only; release restores
  nothing).
- [ ] P6.4 docs/tox toolchain cache + kill double docs build (deploy-pages
  stays cache-free: id-token:write).
- [ ] P6.5 fmt fastest-first job split.
- [ ] P6.6 least-privilege + trust-boundary audit of all workflows.
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
