# paranoid-passwd — Implementation Directive

Full top-to-bottom completion mandate (2026-07-16). Source: comprehensive
7-dimension review (27+ Sonnet 5 executor agents, adversarially verified) +
completeness critic + dedicated architecture review.

## Operating model

- **Orchestrator**: main Claude session. **Executors**: Sonnet 5 agents via
  Workflow, one workflow per work unit, adversarial verify on risky changes.
- One local branch per work unit (a `##` section below unless noted), forward
  commits, one PR at the end of the unit, squash-merge when green + threads
  resolved. Flip `[ ]`→`[x]` in the same commit that lands the item.
- Every commit: docs and tests move with code. `make ci` green locally before
  push. Zero-exception rules in CLAUDE.md are non-negotiable.
- Definition of done for the whole directive: nothing undone, untested, or
  undocumented; no outdated or extraneous docs; no AI design tropes; `make ci`,
  `make quality`, and `make e2e-ci` green in all environments. `make e2e-local`
  is required only on supported real-display platforms (this macOS dev machine
  qualifies), with platform-specific exceptions documented in testing.md.

## P0 — Security correctness (branch: security-hardening)

- [ ] **P0.1 Redact `Debug` for `UnlockedVault`** — manual `fmt::Debug` that
  redacts the `Zeroizing<Vec<u8>>` master key (`paranoid-vault/src/lib.rs:929`);
  sweep all crates for other secret-bearing `#[derive(Debug)]` structs.
  Accept: a test asserting `format!("{:?}", vault)` contains no key bytes.
- [ ] **P0.2 Secret wrappers in TUI form state** — `vault_tui.rs:736-748` holds
  master password, mnemonic phrase, and key passphrase as plain `String` in
  `#[derive(Debug)]` forms; wrap in the existing Zeroizing/redacting secret
  type. Accept: Debug output test + zeroize-on-drop preserved.
- [ ] **P0.3 Delete duplicate `secure_preview`** — `paranoid-cli/src/main.rs:662`
  re-implements the byte-indexed (UTF-8-panicking) version fixed in PR #136;
  delete and import `paranoid_core::secure_preview` (as `tui.rs:12` already
  does). Accept: no local definition remains; CLI tests pass with multi-byte
  input.
- [ ] **P0.4 Enforce audit redaction by construction** — `AuditRedactor`
  (`paranoid-audit/src/lib.rs:1089`) is implemented + tested but never invoked
  from production paths; wire it into `AuditTrail::record` (or pre-sink
  dispatch) so redaction is not opt-in. Accept: test proving a secret-shaped
  attribute is redacted through the public record→sink path.
- [ ] **P0.5 KDF known-answer lock** — assert Argon2id defaults
  (`DEFAULT_MEMORY_COST_KIB == 65_536`, `DEFAULT_ITERATIONS == 3`,
  `DEFAULT_PARALLELISM == 1`, `paranoid-vault/src/lib.rs:46-48`) in a unit test
  so cost regressions can't land silently.
- [ ] **P0.7 Evaluate Argon2id parameter strength** (review feedback, PR #140)
  — assess defaults against current OWASP Argon2id guidance; for a "paranoid"
  posture the 64 MiB memory cost is likely low (libsodium MODERATE tier is
  256 MiB / 3 iter). If raised: new defaults apply to newly created vaults
  only (existing vaults unlock via header-stored `VaultKdfParams`), update the
  P0.5 KAT and `docs/reference/vault-format.md`, and add an unlock test for a
  vault created with the old params.
- [ ] **P0.6 WASM surface vs rule #2 reconciliation** (premise corrected per
  PR #140 review) — the GUI wasm32 cdylib entrypoint exists
  (`paranoid-gui/Cargo.toml:17,32-36`) but is deliberately runtime-gated
  ("disabled until … threat-modeled"), and `hallucination_check.sh:107-120`
  ALREADY structurally verifies the wasm32 dependency tree excludes
  `paranoid-core`/`paranoid-vault`/`openssl-sys`/`rusqlite` (invoked via
  `make verify-assurance`). **Decision**: keep the gated compile-check and the
  existing dep-tree structural check as the primary enforcement. Remaining
  fix: (a) verify `docs/reference/assurance-claims.md` wording matches the
  actual posture (compile-checked, runtime-disabled, dep-tree-verified,
  threat-model pending) and correct any overclaim; (b) add a supplementary
  source-level assertion that the wasm32 `wire_callbacks` branch contains the
  gating message and no vault/core symbol references (structural, not
  message-only); (c) note the gated exception explicitly in CLAUDE.md rule #2
  wording.

## P1 — Architecture refactors (branch: seal-and-crypto-boundaries)

- [ ] **P1.1 Seal posture single source of truth** (citation corrected per
  PR #140 review: `paranoid-ops/lib.rs:1363-1663` is `#[cfg(test)]` fixtures,
  not a production path) — `paranoid-vault` never depends on `paranoid-seal`;
  the production posture derivation lives in `vault_cli.rs:610-685`, outside
  the crate that owns keyslot state. Add the vault→seal dependency, move
  derivation onto `UnlockedVault`/`VaultHeader`, make the CLI call through it
  (refactor, not shim — callers move in the same commit). Accept: exactly one
  production derivation site, in `paranoid-vault`; test fixtures constructing
  `VaultSealPosture` directly are exempt.
- [ ] **P1.2 `mtls_transport` disposition** — 546-line public module in
  `paranoid-ops` with zero callers in cli/gui. **Decision**: not speculative
  infra we ship as dead pub API — gate behind a cargo feature consumed by its
  integration tests, and document the intended remote-ops consumer in
  `docs/reference/architecture.md`; wire-in happens when that feature ships.
- [ ] **P1.3 Single mTLS construction path** — `paranoid-audit` hand-builds an
  `SslConnector` for the external-device probe, duplicating
  `OpsMtlsClientConfig` logic. Extract one shared helper (in `paranoid-core`,
  consistent with single-crypto-surface) used by both.
- [ ] **P1.4 X.509 primitives into core** — `paranoid-vault` imports `openssl`
  directly for `load_certificate` / `certificate_fingerprint_hex` /
  `certificate_time_to_epoch` / `inspect_certificate_pem`
  (`lib.rs:3453-3523`); move the primitives to `paranoid-core`, drop vault's
  direct `openssl` dependency if nothing else needs it.
- [ ] **P1.5 Split the monoliths** — `paranoid-vault/src/lib.rs` (6,268 lines)
  and `vault_tui.rs` into responsibility modules (vault: keyslots /
  backup-transfer / recovery-posture / lifecycle; tui: screen state / panels /
  mutation handlers). Pure moves + visibility fixes, no behavior change;
  test counts stay identical.

## P2 — E2E & capability detection (branch: e2e-and-detection; ordered — later items depend on earlier)

- [ ] **P2.1 Scriptable TUI driving surface** — extract the event-independent
  step function (`App::handle_key`, `tui.rs:355`, plus worker polling) into a
  testable surface and add a deterministic scripted mode
  (`--script <path>` / `PARANOID_TUI_SCRIPT`, matching the existing
  `PARANOID_TEST_DEVICE_STORE_DIR` pattern) feeding newline-delimited key
  sequences. This is the prerequisite for P2.3/P2.5 and for agentic control of
  the TUI. Accept: a scripted run completes the generator wizard headlessly.
- [ ] **P2.2 Capability-detection evidence module** — first-run/install-time
  probes for OS keychain (`keyring`), clipboard (`arboard`), display server
  (Quartz/X11/Wayland/none), and configured seal providers, modeled on the
  existing `FederalCryptoProviderEvidence::collect_from_environment()` pattern;
  expose via `--detect-environment` CLI flag (parallel to
  `--federal-evidence`). Evidence structs, serde-locked wire shape, KATs.
- [ ] **P2.3 TUI environment-approval screen** — first screen when no vault
  exists at `default_vault_path()` (`native_access.rs:201-222`) and reachable
  by hotkey: renders detected capabilities + suggested seal-provider
  configuration, user accepts/adjusts. Accept: PTY e2e drives the approval
  flow via the P2.1 scripted mode.
- [ ] **P2.4 Vendor `slint-testing` + real widget-event GUI tests** — add
  dev-dependency matching vendored slint 1.16.1 (cargo vendor per the
  locked/frozen/offline rule), then in-process tests using
  `slint::testing::send_mouse_click`/keyboard events driving the REAL widget
  tree (init-vault → add-login → generate-rotate → enroll-mnemonic →
  export-backup), asserting window property state. Closes the gap where GUI
  e2e bypasses callback wiring entirely.
- [ ] **P2.5 Extend TUI PTY e2e** — wrong-password → `UnlockBlocked` seal
  screen → recover; recovery-secret rotation; and a second PTY session against
  the same vault proving restart persistence (items + keyslots visible,
  unlock works).
- [ ] **P2.6 e2e matrix split: `make e2e-ci` / `make e2e-local`** — `e2e-ci`
  aggregates the headless-deterministic set (CLI contract, vault CLI, PTY TUI,
  xvfb GUI screenshot + slint-testing widget tests); `e2e-local` adds
  real-display/real-input runs: on macOS drive the actual GUI with real mouse
  clicks and keyboard via the OS event system (e.g. `cliclick`/CGEvent
  harness) through password generation, vault unseal, and vault management.
  Document the split and per-platform requirements in
  `docs/reference/testing.md`. Accept: `e2e-ci` green in all environments and
  wired into `make ci`; `e2e-local` green on supported real-display platforms
  (this macOS dev machine), with platform exceptions documented.

## P3 — CI/release hardening (branch: ci-hardening)

- [x] **P3.1 PR-gated dependency/SAST job** — cargo-audit, osv-scanner (min
  set; ideally `PARANOID_RUN_LOCAL_SCANNERS=1 make verify-deep`) in the builder
  container on every PR; today scanners run only in local `make quality`.
- [x] **P3.2 Required checks** — add `Security Assurance` to branch-protection
  required checks and to `verify_branch_protection.sh:18-23` expected list.
- [x] **P3.3 Android/WASM compile-checks in CI** — resolved as documented-risk
  disposition: the hermetic Wolfi builder has no rustup/NDK/wasm32 std (verified
  empirically in the pinned base image), so both checks stay local-only with
  root cause recorded in AGENTS.md + testing.md.
- [x] **P3.4 Builder-image retry hardening** — wrap `apk add`/`pip install` in
  bounded retry loops; the PR #136 Docs Build failure was a transient Wolfi
  CDN error requiring manual re-run.

## P4 — Documentation truth (branch: docs-truth)

- [ ] **P4.1 Fix GUI parity overclaims** — `docs/reference/architecture.md`
  (lines ~56-61, 135, 167, 218, 221), `docs/guides/tui.md:171`: scope GUI
  claims to the actual 8-callback surface; `docs/reference/testing.md:297-300`:
  remove fabricated GUI coverage claims (keyslot inspection, rotation, rewrap,
  rebind coverage that doesn't exist). Re-check after P2.4 lands and update to
  the then-true surface.
- [ ] **P4.2 Document the six undocumented vault subcommands** — `vault show`,
  `update`, `update-note`, `update-card`, `update-identity`, `delete` in
  `docs/getting-started/index.md`.
- [ ] **P4.3 Version-pin drift** — `docs/public/install.sh:6` and
  `docs/getting-started/index.md:48` still say v3.6.5; fix to current and add
  a validate-docs.sh assertion tying doc version strings to workspace
  Cargo.toml so the class is dead.
- [ ] **P4.4 Document all six compliance frameworks** — hipaa/soc2/gdpr/
  iso27001 appear nowhere in the Sphinx site despite `--help` listing them;
  add canonical list + aliases, and validate-docs.sh greps per framework id.
- [ ] **P4.5 testing.md completeness** — name `make test-tui-e2e` and
  `make test-vault-e2e` (CI-load-bearing, currently undocumented); document
  the P2.6 e2e split.
- [ ] **P4.6 Mechanical doc-coverage gates** — script asserting (a) every vault
  subcommand match-arm appears in docs/, (b) every GUI `on_*` callback name is
  documented; wire into `make docs-check`.
- [ ] **P4.7 CLAUDE.md accuracy** (depends on P2.4) — replace the "GUI
  scaffold" framing: native desktop GUI callbacks are implemented; real
  widget-event coverage lands with P2.4 (state whichever is true when this
  item executes). Only the WASM path is intentionally gated (align with P0.6
  wording).

## P5 — Extensibility & contributor experience (branch: extensibility)

- [ ] **P5.1 Data-driven framework/charset registries** — convert `FRAMEWORKS`
  (`paranoid-core/src/lib.rs:177-291`) and named charsets to build-validated
  data manifests (TOML under `crates/paranoid-core/data/`) so adding a
  framework/preset is a data PR; crypto-invariant math stays in Rust.
  Accept: existing FrameworkId tests pass unchanged; new framework addable
  without touching enum dispatch sites.
- [ ] **P5.2 Seal-provider trait seam** — define the provider trait in
  `paranoid-seal` (probe/evidence/kind) that existing kinds implement, giving
  contributors one place to add a provider (coordinates with P1.1).
- [ ] **P5.3 CONTRIBUTING.md + docs/reference/extending.md** — dev setup
  (`make bootstrap-local`/`configure`/`ci`), crate boundary rules, how to add
  tests at each layer, PR conventions, and the three extension points
  (frameworks, charsets, seal providers) with worked examples; link from
  README and docs/index.md.
- [ ] **P5.4 `.remember/` + `.ralph-tui/` disposition** — tracked agent-loop
  scaffolding (empty remember.md, ralph-tui setup-wizard config) with no
  documented purpose: either document in AGENTS.md tooling section or untrack
  + gitignore. **Decision**: untrack + gitignore unless the user's ralph
  workflow actively reads them from this repo.

## Review-refuted / explicitly not queued

- Rejection sampling, chi-squared, OpenSSL delegation, workspace `forbid` on
  unsafe: verified correct and test-locked — do not touch.
- Docs are otherwise unusually well-grounded; no browser-era claim leftovers
  found beyond the items above. No slop tropes beyond the monolith splits
  (P1.5) and one dead-store (fold into P1.5's touched files if trivial).

## Process notes

- 2026-07-16: a review subagent deleted 8 stale untracked browser-era
  screenshot PNGs (~2.9MB) from the repo root during a read-only review —
  mandate violation, files unrecoverable (never tracked), no repo impact.
  Executor prompts must repeat the no-delete rule verbatim.
- Review executor flake rate was nonzero (placeholder outputs, structured-
  output retry-cap failures). Orchestrator must sanity-check every executor
  result for placeholder text before acting on it.
