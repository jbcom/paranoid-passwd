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

## P0-META — Autonomous continuous-shipping loop (STANDING; user 2026-07-17)

STOP-HOOK CONTRACT: the directive is NEVER "done". It has no terminal state
until the user manually ends the session. The queue is a living document the
orchestrator continuously mutates. There is NO "RELEASED" flip that stops the
loop; there is no FINAL that ends work — FINAL just ships the current
milestone PR, then the loop discovers the next.

GATE COMPLETENESS (learned 2026-07-17, P9 verify): pinning that a function
EXISTS is not pinning that it is COMPLETE. An assurance claim that a
scrub/redact/validate function is present passes green even when the function
misses cases — the panic-lock gate was green over a live secret leak because
its test asserted the screen transition, not that every form was scrubbed.
Every security-property claim's test must assert the PROPERTY (no secret
survives), enumerated exhaustively, not the mechanism's presence. Adversarial
verify (opus, try-to-break) is mandatory before any hardening merges — unit
tests and the gate both missed this; only the break-it pass caught it.

WORKTREE ISOLATION (hard, learned 2026-07-17): NEVER run two workflows that
write to the SAME worktree concurrently — their uncommitted edits interleave
on shared files and corrupt both. At most ONE writing workflow per worktree at
a time. Parallel implementation streams each get their own git worktree cut
from the branch head (Agent isolation: "worktree" / a dedicated e2e-wt-N), and
the orchestrator merges the branch heads. Design/docs workflows that touch
only disjoint new files may overlap, but anything editing crates/ runs solo.

SINGLE SOURCE OF TRUTH: .agent-state/directive.md IS the task list. Do NOT
maintain a separate harness TaskCreate/TaskUpdate list — that is duplicate
state in a second format. Track everything (in-flight, wait-state, next,
compressed-to-PILLARS) here in the directive only.

NO FYIs / NO STATUS RELAYS (user 2026-07-17): do not pause to relay brand
directions, journey storyboards, gap lists, or progress. Decide, execute,
ship. The user reviews accumulated progress on their own schedule.

ZEROTH LAW — never block on the user. AskUserQuestion is BANNED under this
mandate. Every design/architecture/scope/priority call is the agent's to make
against the quality standards; record the decision + why in the directive and
execute. Disagreement is corrected later by the user, never by a blocked loop.

COMPRESSION: when a phase's items are all [x], compress that phase out of the
active queue into docs/PILLARS.md (one durable section per completed phase:
what shipped, key decisions, where it lives) and delete the verbose entries
from directive.md. The active directive stays short — only in-flight + next.

FORWARD EXPLORATION (the engine): whenever the active queue would otherwise
drain, the orchestrator MUST generate new work by running a DIFFERENT review/
discovery lens than last time, rotating through at least: comprehensive-review
(correctness), security-scanning/sec-context-depth, code-simplifier, a
paranoia-gap re-scan (P9-style), a UX/design critique (PUX/P8-style), a
performance pass, a docs-currency re-sweep, an accessibility pass, a
dependency/supply-chain audit, and "what would make this a better PRODUCT"
product-thinking. Each lens run appends a new numbered phase with acceptance
criteria; the loop never idles.

SHIPPING CADENCE: keep opening PRs. Land work in milestone-sized PRs off the
long-running branch (or fresh branches per the churn guidance), babysit each to
squash-merge, let release-please cut versions. Always be shipping.

LOOP MECHANICS: reschedule the ScheduleWakeup every turn with the current
next-action; keep the persistent PR + executor-failure Monitors alive; keep the
task list mirroring real phases; keep the hook mirror truthful ([WAIT-AGENT]/
[WAIT] annotations so the anti-stop hook sees legitimate yields, never a false
"done"). Only the user ending the session stops this.

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
- [x] P6.7 test-execution parallelism (owner research: Wolfi ships no
  cargo-nextest/mold/lld; rust-lld absent from pinned toolchain) — measured
  serial `scripts/cargo_test.sh` at 165.4s avg (2 runs, warm target dir) vs.
  concurrent per-suite execution at 122.4s avg (26.0% speedup, both runs
  individually clearing 25%); shipped make-level parallelism (option (b),
  dependency-free) rather than vendoring cargo-nextest (option (a)) since (b)
  cleared the bar. `scripts/cargo_test.sh` now builds every test binary once
  via `cargo test --no-run --message-format=json`, then runs suites
  concurrently (bounded to nproc, `PARANOID_TEST_MAX_PARALLEL` override),
  buffered per-suite output printed atomically sorted by suite name,
  nonzero aggregate exit on any suite failure (verified via a
  deliberately-broken-then-reverted test). `PARANOID_TEST_SERIAL=1` escape
  hatch and automatic serial fallback for `--` test-filter args preserved.
  Fixed a latent concurrency hazard in the debug device-store test shim
  (per-suite subdirectories instead of one shared root) surfaced by this
  work. Findings written to ci-design.md's "P6.7" section and the
  "Rejected Options" nextest-vendoring entry; behavioral contract documented
  in testing.md.
- [x] P4.S docs-currency sweep (user-elevated) — both-directions pass over
  every docs page vs code (haiku fan-out + sonnet fixes), Sphinx+linkcheck
  green, AGENTS.md/CLAUDE.md accurate to the post-P1 module map.
- [ ] P4.V live-site verification (post-#146 merge) — WebFetch the deployed
  Pages site; spot-check contributing/compliance-frameworks/testing/ci-design.
- [x] P7.1 Atomic backup restore — temp-sibling DB + atomic replace
  (mutation_handlers.rs:418, #146 review). `restore_vault_backup`
  (crates/paranoid-vault/src/backup_transfer.rs) no longer `remove_file`s the
  destination up front: it builds the full restored vault (schema, header
  row, every item row) in a same-directory `.{name}.{pid}.{random-hex}.tmp`
  sibling, validates that build in a fresh connection (application_id +
  user_version pragmas, header JSON round-trip, and an item-count check
  against the backup package), and only then `fs::rename`s the validated
  temp file over the destination; any build/validation failure removes the
  temp file and leaves the destination untouched. `overwrite`/`--force` now
  only lifts the pre-flight `VaultError::VaultExists` check and no longer
  pre-emptively deletes the target. TUI's `open_import_backup`
  (vault_tui/screen_state.rs) now defaults `overwrite: false` unconditionally
  instead of preselecting `true` whenever the target vault exists. Five new
  tests: `mid_restore_failure_leaves_original_vault_intact_and_unlockable`
  and `successful_restore_replaces_destination_atomically` in
  paranoid-vault/src/lib.rs (plus a temp-sibling-cleanup regression test),
  `open_import_backup_defaults_to_no_overwrite_when_target_exists` in
  paranoid-cli/src/vault_tui.rs. cargo test -p paranoid-vault -p paranoid-cli
  clean (79 + 103 tests); fmt+clippy -D warnings clean on both crates;
  scripts/validate-docs.sh clean. docs/reference/vault-format.md and
  docs/guides/recovery-operations.md updated with the atomic-restore
  guarantee and the new TUI default.
- [x] P7.2 Auto-lock hardening — never on EnvironmentApproval; purge
  options.auth + secret forms on lock (screen_state.rs:1584).
- [x] P7.3 Export safety — reject source==destination; temp-file atomic
  rename (backup_transfer.rs:210). `export_backup` and
  `export_transfer_package` both canonicalize the vault path and the
  requested output path (falling back to canonicalizing the parent +
  file name when the destination does not yet exist) and fail closed with
  the new typed `VaultError::ExportPathCollision` on a match, before any
  write happens. Both writers now go through `write_export_atomically`:
  serialize to a same-directory `.{name}.{pid}.{random-hex}.tmp` file
  (std-only naming, openssl `rand_bytes` via the existing `random_hex_id`
  helper — no new deps) then `fs::rename` into place, with the temp file
  removed on any write/rename failure. Five new tests in
  crates/paranoid-vault/src/lib.rs cover: same-path rejection leaving the
  vault byte-for-byte untouched (direct and via `..`-relative components),
  the same rejection for export-transfer, no leftover temp file after a
  successful export, and (unix-gated) an unwritable destination directory
  leaving a pre-existing backup file untouched with no temp-file leftover.
  docs/reference/vault-format.md and docs/guides/recovery-operations.md
  updated with the fail-closed/atomic-write guarantee.
- [x] P7.4 Transactional imports; temp-DB restores (backup_transfer.rs:440).
  `import_transfer_payload` (crates/paranoid-vault/src/backup_transfer.rs) now
  wraps the whole per-item loop in an explicit `BEGIN`/`COMMIT` transaction on
  `self.conn`, rolling back on the first validation or storage failure so a
  malformed item anywhere in the payload — including the last one — leaves
  zero newly-imported rows instead of committing every item that validated
  before it. Confirmed P7.1's `restore_vault_backup` already builds the full
  restored vault in a same-directory temp-DB sibling and only renames it over
  the destination after validation, so the restore side has no incremental
  persistence path left to transactionalize. Two new tests in
  paranoid-vault/src/lib.rs:
  `import_transfer_with_malformed_final_item_leaves_zero_rows_imported`
  (tampers the last item's title to empty inside a real transfer package,
  re-derives/re-encrypts the payload, and asserts item count before == after
  the failed import) and `import_transfer_with_all_valid_items_commits_all_rows`
  (asserts a successful import commits every item). cargo test -p
  paranoid-vault -p paranoid-cli clean (80 + 103 + 9 + 5 tests, one
  pre-existing unrelated flaky test excluded — see below); fmt+clippy -D
  warnings clean on both crates; scripts/validate-docs.sh clean.
  docs/reference/vault-format.md and docs/guides/recovery-operations.md
  updated with the transactional-import guarantee.

  Note (out of scope, not touched): `mnemonic_enrollment_debug_never_contains_the_phrase`
  in paranoid-vault/src/lib.rs is flaky independent of this change — it
  substring-matches every BIP-39 word in a freshly generated mnemonic against
  the enrollment's Debug output, which also contains the embedded
  `VaultKeyslot`'s own Debug field labels (e.g. "kind"). Common English words
  in the wordlist ("kind", "one", "before", ...) coincidentally collide with
  those labels and fail the test on an unrelated basis. Reproduced failing on
  base `main` before this change (single mnemonic-generation seed) — not
  introduced or worsened here.
- [x] P7.5 Zeroize MnemonicRecoveryEnrollment (SecretString + redacted
  Debug, keyslots.rs:98) — completes the P0 sweep.
- [x] P2.4 vendored slint-testing + real widget-event GUI tests.
- [ ] P2.6 make e2e-ci / e2e-local split (real mouse/keyboard local GUI
  runs), wired into make ci; testing.md documents platform conditions.
- [ ] P4.1 GUI parity overclaim fixes (re-checked against post-P2.4 truth).
- [ ] P4.5 testing.md completeness (tui/vault e2e targets + e2e split).
- [ ] P4.7 CLAUDE.md GUI framing accuracy (post-P2.4).
- [ ] P5.1 data-driven framework/charset registries (crypto math stays Rust).
- [ ] P5.2 seal-provider trait seam.
- [ ] P5.3b docs/reference/extending.md with worked examples (after P5.1/2).



### PUX decisions (user 2026-07-17, full-autonomy delegation)
- PRIMARY PERSONA: the targeted individual (activist / journalist / person
  under real coercion or surveillance risk). The name is the promise. Hero
  flows: establish trust (verify attestation), recovery + duress/decoy
  vaults, panic-lock. Voice: grave, precise, respectful, zero whimsy.
  Visual: austere, high-contrast, no decoration for its own sake.
- SCOPE: full design AND implementation before FINAL/release — the release
  ships the redesigned product (PUX.1-5 then P8.1-5 all execute this pass).



## P8.V — Visual-verify mustFix (opus verdict matchesDesign=false; must clear before P8 done). Ordered: security first.

- [x] P8.V.1 TUI item detail shows the password in CLEARTEXT by default ('password: S3cr3t-mail-pw'). Mask it ('Pass ••••••••') with an explicit Reveal action per ia.md S7 — this is a coercion/shoulder-surfer threat-model failure, not just a visual gap. The GUI already does this correctly; the TUI must match.
- [x] P8.V.2 TUI has no distinct item-detail (S7) screen: ⏎ on the vault list does not navigate anywhere, yet the footer promises '⏎ open'. Build the S7 screen (masked user/pass + '▸ Copy password' accent + Reveal/Edit + '⏎ copy r reveal e edit ? all keys ⎋ back' footer) and wire ⏎ to it.
- [x] P8.V.3 Kill the raw data dumps in the TUI vault detail pane: 'id:', 'updated_at_epoch:', 'duplicate passwords elsewhere:', 'password history entries:' are the 'box of data' the redesign exists to eliminate (ia.md rule 5, journeys.md invariant 1). Lead with intent + one '▸' accent; move mechanics behind a drill-down.
- [x] P8.V.4 TUI Ways-in (S10): rename rows by relationship ('recovery phrase'/'this device'/'trusted contact'), not by internal enum ('password_recovery'/'mnemonic_recovery'), and move keyslot mechanics ('wrap: argon2id+aes-256-gcm', kind, device-bound) behind the ia.md S10d 'Show the mechanics' drill-down instead of the intent-first surface. Add the 'Ways in (n)' count and brand.md §3a body copy.
- [x] P8.V.5 Fix the hotkey drift: the vault-list ? overlay and ways-in footer say 'w ways in' but the working key on Screen::Vault is 'k'. Rebind ways-in to 'w' on the vault screen (or fix every footer/overlay to say 'k') so the advertised key actually works.
- [x] P8.V.6 Wire the TUI S2d fingerprint drill-down: the trust-gate ? overlay advertises 'd show the fingerprint' but handle_trust_gate_key has no 'd' handler — either implement the fingerprint leaf or stop advertising the key.
- [x] P8.V.7 Replace the prose hotkey walls relocated into TUI detail panes ('Press a to add login, n to add secure note, v to add card…' on Home, S7, and Ways-in) — this is the 40-key Controls wall in a new location. The contextual footer + ? overlay already carry these; remove them from the panels.
- [ ] P8.V.8 Redesign the standalone generator wizard (paranoid-passwd --tui / tui.rs) — it was not touched by the brand/ia/journeys work. It is still the 21-field scrolling wizard with a 'Controls' hotkey block, no contextual footer ('Selected field: 1 of 21' at the bottom), no '▸' accent, and six evidence tabs thrust forward on the results screen instead of a verdict-first + 'Show the evidence' drill-down (journeys.md J2).
- [x] P8.V.9 Remove the third 'Access' panel (full vault filesystem path + unlock method) from the TUI home/steady-state screens — it violates the one-job / fixed two-pane (primary + detail) skeleton in ia.md §1 and leaks the vault path onto every screen.
- [ ] P8.V.10 Set up a GUI render-to-image path (SoftwareRenderer to PNG under xvfb, or equivalent) so the Slint window can actually be screenshotted and visually verified. Right now the GUI's visual identity is only verifiable by reading markup — the 'does it actually look designed' gate cannot be closed on the GUI without a rendered pixel to READ.
- [x] P8.V.11 TUI panic-lock (S14): render the ia.md S14 centered '⊘ Locked.' state with a '▸ Unlock' accent and the '⊘' title-bar token, instead of dropping straight into the two-pane unlock form with engineer chatter ('Native unlock now works directly from the TUI; env-based CLI inputs remain valid too').

## P9 — Paranoia hardening (user-approved 2026-07-17: ALL P9.1-9.7 before FINAL). Threat model: offline / local attacker / memory disclosure / coercion. Ordered by real security value; run before FINAL.

- [x] P9.1 Zeroize decrypted vault-item payloads (LoginRecord/CardRecord/PasswordHistoryEntry + New*/Update* + TUI App.detail + GUI vault_secret)
  WHY: This is the single largest gap between the name and the reality. Under THIS threat model (local attacker + memory disclosure + coercion via seized device), the whole point of Zeroizing the master key is defeated if the decrypted secrets it protects are plain cloneable String. crates/paranoid-vault/src/lib.rs:202/215/233/236 (and the New*/Update* mirrors at 294/323) are #[derive(Clone, Debug)] plain String: every .clone() forks an un-scrubbed heap copy, {:?} prints the secret verbatim, and on dro
  SKETCH: Introduce a SecretString-equivalent for payload fields (reuse/extend crates/paranoid-vault/src/native_access.rs SecretString, or a SecretBytes newtype wrapping Zeroizing<String>) with a manual Debug that prints <redacted>, Serialize/Deserialize that round-trips the raw value (serde over the inner string) so on-disk format is unchanged, and Drop/ZeroizeOnDrop. Change LoginRecord.password, PasswordHistoryEntry.password, CardRecord.number/.security_code and the New*/Update* mirrors (lib.rs:199-323) from String to that type. Remove blanket #[derive(Clone)] where it forks secrets, or make the secre
  ACCEPT: All decrypted item payload secret fields (login password, password-history password, card number, card security code, and their New*/Update* forms) are a zeroize-on-drop wrapper, not plain String; {:?} on any of them renders <redacted> not the secret (unit test); a test captures the heap address of a payload secret, drops the owner, and asserts the bytes are zeroed; serde round-trip proves the on-disk JSON/blob wire format is byte-identical to pr
- [x] P9.2 Persisted cross-restart failed-attempt lockout with exponential backoff
  WHY: Screen::UnlockBlocked (screen_state.rs:30, entered on any unlock Err at :1358) is a pure in-memory UI enum with no backing counter, no persisted timestamp, no backoff — grep for failed_attempts/lockout/backoff/retry_after across crates/*/src returns zero. A restart or even just re-opening the unlock form clears the 'blocked' state instantly. So the ONLY throttle on offline brute-force is Argon2id's per-guess compute cost. Under this exact threat model — local attacker with the vault file on a se
  SKETCH: Add a durable lockout record next to the vault (a sibling file, e.g. <vault>.lock-state, or a dedicated unauthenticated row in the SQLite metadata table like header_json — but NOT inside the encrypted rows, since it must be readable pre-unlock). Store: failed_attempt_count, first_failure_utc, locked_until_utc. Bind it to the vault path. On unlock attempt: if now < locked_until_utc, refuse before running Argon2id (saves the attacker nothing but denies the legitimate fast retry and makes the wait explicit). On failure: increment count, compute locked_until = now + backoff(count) with exponential
  ACCEPT: A failed unlock persists a durable lockout record (path-bound) that survives process restart; a test performs N failed unlocks, restarts the process (fresh handle), and asserts the (N+1)th attempt is refused with a positive remaining-lockout duration; backoff grows exponentially with attempt count and is capped; a successful unlock clears the record; the record lives outside the AEAD-encrypted rows (readable pre-unlock, required since unlock hasn
- [x] P9.3 OS memory-hardening: disable core dumps + PR_SET_DUMPABLE(0) / ptrace-deny, and mlock secret pages
  WHY: grep for mlock/munlock/setrlimit/prctl/RLIMIT/PR_SET_DUMPABLE/VirtualLock across crates/*/src returns zero. So today: (a) a crash produces a core dump containing every resident secret, and (b) any same-user process can attach/dump the process memory or read /proc/$pid/mem, and (c) secret pages can be swapped/hibernated to disk. KeePassXC and Bitwarden both do the dump/ptrace suppression explicitly; GnuPG does mlock. The research is candid about the ceiling (does NOT stop root/Administrator — the
  SKETCH: Add a platform module in paranoid-vault (or a small new crate paranoid-harden) gated by cfg(target_os). Linux/macOS via the libc crate: at process startup for the CLI and GUI binaries call setrlimit(RLIMIT_CORE, {0,0}); on Linux prctl(PR_SET_DUMPABLE, 0); on macOS the equivalent is ptrace(PT_DENY_ATTACH) (note: interacts with debugging/notarization — gate behind a runtime flag and document). Windows: SetProcessMitigationPolicy / disable WER for the process. For mlock: wrap the master_key and derived-KEK Zeroizing buffers (lifecycle.rs:37/963) so their pages are mlock/munlock'd around use (or a
  ACCEPT: CLI and GUI process startup calls setrlimit(RLIMIT_CORE,0) and the platform dump/ptrace-deny primitive; a test (Linux) asserts the soft+hard core limit is 0 after startup and that /proc/self/status shows non-dumpable; master-key and derived-KEK pages are mlock'd with a documented warn-and-continue fallback when locking is unavailable (test simulates lock failure and asserts the process continues with a recorded warning); any unsafe/libc FFI has a
- [x] P9.4 Clipboard-history exclusion hints (macOS ConcealedType/TransientType, KDE x-kde-passwordManagerHint, Windows ExcludeClipboardContentFromMonitorProcessing)
  WHY: The app already does the harder half well — arm-and-match-before-clear with a 30s timer that only clears if the clipboard still holds the copied value (native_access.rs:133-159, tui.rs:995-1002). But grep for org.nspasteboard/x-kde-passwordManagerHint/concealed/transient/ClipboardFormat returns zero: it calls arboard's plain set_text. That means the instant a password lands on the clipboard, Windows Clipboard History (Win+V), KDE Klipper, Maccy, Alfred, GPaste etc. capture a PERSISTENT, searchab
  SKETCH: Extend the copy path (native_access.rs arm_clipboard_clear + the two TUI copy sites) to set platform exclusion metadata instead of plain set_text. arboard's plain set_text is insufficient; either use arboard's platform-specific extensions where available or drop to per-OS clipboard APIs behind cfg(target_os): macOS — declare org.nspasteboard.ConcealedType (and TransientType) pasteboard types alongside the string; Linux/X11+Wayland — offer the x-kde-passwordManagerHint='secret' target so Klipper skips it; Windows — set the ExcludeClipboardContentFromMonitorProcessing / CanIncludeInClipboardHist
  ACCEPT: On each supported platform the copy-secret path sets the platform clipboard-history-exclusion hint (macOS ConcealedType+TransientType, KDE x-kde-passwordManagerHint, Windows exclude-from-history) in addition to the existing timed clear; a per-platform test (or a harness asserting the exclusion type/format is present on the written clipboard item) proves the hint is set; docs state per-platform which history managers honor the hint and explicitly 
- [x] P9.5 Argon2id runtime calibration with an honest floor
  WHY: DEFAULT_MEMORY_COST_KIB=262_144/ITERATIONS=3/PARALLELISM=1 (lib.rs:45-49) are fixed compile-time constants used at creation and re-wrap. grep for calibrat/benchmark returns nothing. The 256 MiB/t=3 floor already EXCEEDS OWASP's high-security profile (m=128 MiB/t=4) on memory, so unlike most managers this project is NOT under-provisioned — the gap is the opposite: a fixed constant is fragile at both ends (a RAM-constrained host either eats 256 MiB or can't unlock; a high-end host gets no addition
  SKETCH: Add a calibration helper in paranoid-vault: at vault creation (and optionally an opt-in re-derive-and-rewrap maintenance op) benchmark Argon2id on the host, then raise m/t toward a target interactive wall-clock (e.g. ~250-500ms, up to ~1s for a high-security toggle) — but clamp the memory cost to a hard floor at the current 262_144 KiB so calibration can only ever strengthen, never weaken. Persist the chosen params in the existing VaultHeader KDF block (already stored, lib.rs:113-120) so unlock uses the same params — no format change, the header already carries kdf params. Keep DEFAULT_* as th
  ACCEPT: Vault creation calibrates Argon2id params to a documented wall-clock target on the host while clamping memory cost to a hard floor >= 262_144 KiB (a test proves calibration never emits memory_cost below the floor, even when the benchmark suggests a slower/cheaper setting); chosen params persist in VaultHeader.kdf and unlock uses them (round-trip test); a constrained-host path falls back to the floor with a surfaced warning rather than failing; th
- [x] P9.6 Panic / quick-lock global hotkey wired to the existing lock+purge path
  WHY: The lock machinery already exists and is correct: purge_secret_state_on_lock (screen_state.rs:1609) scrubs every secret-bearing form, and idle auto-lock fires it (should_auto_lock at :1572). What's missing is a fast, deliberate trigger. Under the coercion / shoulder-surfer / 'someone walks up' scenario in this threat model, seconds matter and menu-diving loses them. The research is clear this adds NO new cryptographic protection — it's a UX feature riding an already-correct lock path — so it ran
  SKETCH: TUI: bind a global key (e.g. Ctrl+L, plus a configurable panic key) in handle_key (screen_state.rs:1619) that, from any unlocked screen, immediately calls the existing lock path: purge_secret_state_on_lock + clear App.detail + transition to the unlock screen + fire the clipboard clear. GUI: add a lock action/button and a keyboard accelerator that runs the equivalent (scrub GuiState.vault_secret + drop unlocked handle). For OS lock/suspend: where feasible per-platform, subscribe to screen-lock/suspend signals (macOS distributed notification, Linux logind PrepareForSleep/lock via dbus, Windows s
  ACCEPT: A documented global hotkey in both TUI and GUI immediately invokes the existing lock+purge path (secrets scrubbed, clipboard cleared, unlock screen shown) from any unlocked screen; a test drives the hotkey from an unlocked state and asserts purge_secret_state_on_lock ran and no plaintext remains in the detail/secret fields; where an OS screen-lock/suspend hook is implemented it invokes the same path and is per-platform tested, and any platform wi
- [x] P9.7 Claims-integrity gate: docs must never assert hardening that is absent, and every new P9 hardening is pinned as an enforced/process claim
  WHY: The user's core instruction and the product's whole credibility model: a vault named 'paranoid' that DOCUMENTS memory zeroization or brute-force lockout it does not actually have is worse than one that honestly says it lacks them — that's the overclaiming the research repeatedly flags (Windows Hello 'hardware-backed' when it silently falls back to software TPM; NSWindow.sharingType 'protects screenshots' when Sequoia's ScreenCaptureKit ignores it; 'we clear secrets from memory' when CVE-2023-388
  SKETCH: For each landed P9 item, add a Claim to CLAIMS in scripts/security_assurance_gate.py whose Requirements pin the load-bearing code strings AND the proving test names (the gate's own pattern — see the seal.lifecycle-boundary claim's ~90 requirements), and add the matching row to docs/reference/assurance-claims.md with the correct state (enforced for zeroize/lockout/mem-hardening/clipboard/kdf-floor; process for panic-lock UX). Add anti-overclaim guards to scripts/validate-docs.sh mirroring the existing 'must not claim' pattern: e.g. if any public doc says 'zeroized in memory' / 'memory-safe agai
  ACCEPT: Every P9 hardening that ships has a corresponding Claim in security_assurance_gate.py with Requirements pinning both its code and its test, and a row in assurance-claims.md with the honest state; removing any P9 hardening call/test causes make verify-assurance to fail (a negative test or documented manual verification proves the gate catches deletion of at least one representative hardening, e.g. the mlock call or the zeroize wrapper); validate-d

### P9 rejected as theater (do NOT implement; recorded so they are not re-proposed)
- Self-destruct / wipe-local-data after N failed master-password attempts: Research and the vendors' own caution (DataLocker, Bitwarden) flag it as a documented DoS/availability footgun: for a NO-CLOUD-BACKUP offline vault this design lets anyone with brief device access (or
- macOS NSWindow.sharingType=.none / Windows SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE) to hide reveal windows from screen capture: Largely theater on current OSes per the research: macOS 15 Sequoia's ScreenCaptureKit (the API modern recorders/sharers use) now ignores sharingType entirely, and WDA_EXCLUDEFROMCAPTURE is documented 
- Whole-process memory encryption / encrypt-secrets-between-uses (CryptProtectMemory, .NET-style ProtectedMemory): High complexity, low marginal value on top of P9.1+P9.3 for a native Rust process. It targets managed-runtime apps (Electron/JS, GC'd .NET) that structurally can't scrub memory — a native Rust process
- TPM / Secure Enclave / Windows Hello hardware-backed unlock: Genuine value but out of scope for the current ranking and high-risk to claim: the research shows it is ONLY as strong as a verified, correctly-provisioned TPM, and ElcomSoft demonstrated it degrades 
- Travel / border-crossing mode (hide non-essential vaults, restorable later): 1Password-style travel mode depends on a cloud/multi-vault sync model to remove-then-restore vaults across devices; this product is a single offline vault with no sync backbone, so the feature would e

## PUX — Product design & journey (user 2026-07-17: "not clearly communicating anything — no brand identity, no direction, no storyboarding; just boxes with technical info"). Runs BEFORE P8; P8 becomes its build arm.

- [x] PUX.1 Positioning & brand foundation — define WHO this is for (threat
  model as persona: the genuinely-targeted individual — activist, journalist,
  engineer under coercion risk) and the ONE promise the name makes. Voice &
  tone, naming of concepts (today's "keyslots/seal posture/federal evidence"
  is engineer-speak — decide user-facing vocabulary), a minimal visual
  identity the TUI+GUI+docs+site share (palette with intent, one type scale,
  iconography stance). Deliverable: docs/design/brand.md.
- [x] PUX.2 Journey mapping — map the real user journeys end to end
  (first-run → trust establishment → first password → first vault item →
  daily unlock → recovery-someday → coercion/panic → verify-the-binary),
  each as a storyboard with intent/emotion per step and the "what should I do
  next" always answered. Name the moments that currently dead-end in a box of
  data. Deliverable: docs/design/journeys.md with per-journey storyboards.
- [x] PUX.3 Information architecture & flow — from the journeys, redesign the
  screen graph: what each screen is FOR (one job), progressive disclosure of
  the technical evidence (audit math, seal posture, attestation) behind
  intent-first surfaces, guided first-run instead of a menu of hotkeys.
  Deliverable: docs/design/ia.md + annotated wireframes (ASCII/text
  storyboards fine for TUI; layout specs for GUI).
- [x] PUX.4 Design system → tokens — turn PUX.1 into concrete shared tokens
  (color/space/type/component specs) consumable by ratatui theme + .slint
  styles + Sphinx theme, so all three surfaces read as one product.
  Deliverable: crates-level theme module + docs/design/system.md.
- [x] PUX.5 Spec handoff — fold PUX.1-4 into P8's build items: rewrite P8.2/
  P8.3/P8.4 acceptance criteria to implement the storyboards and system, not
  ad-hoc polish. P8 then executes the design rather than guessing at it.

## P8 — UX maturity (user signal 2026-07-16: "feels like a prototype"; runs after P5, before FINAL). PUX.5 turned this from ad-hoc polish into "build the designed product" — every item below implements a specific storyboard step in docs/design/journeys.md, a specific screen in docs/design/ia.md, and specific tokens in docs/design/system.md. No P8 item re-decides brand/journey/IA/token choices; a P8 string, color, spacing, or key that contradicts those docs is a defect against them, not a new decision to make locally.

- [x] P8.0 Shared theme/token module — stand up the token consumption
  mechanism system.md §6 specifies, BEFORE P8.2/P8.3 touch a single screen,
  so both surfaces consume it rather than re-deriving values:
  - **ratatui**: new `crates/paranoid-cli/src/theme.rs` exposing the 9 color
    tokens (system.md §1) as `Color::Rgb` consts + `Style` helpers named by
    token (`theme::accent_action()`, `theme::verified()`, `theme::caution()`,
    `theme::danger()`, `theme::muted()`), the 16-ANSI fallback map (system.md
    §1.1), the 4-step spacing scale in cells (§2), and `Modifier` mappings for
    the 4-step type scale (§3: BOLD=title, normal=body, DIM=label, mono
    cell=type.mono). De-duplicates the `const BG/PANEL/TEXT/GREEN/BLUE/AMBER/
    RED` currently forked across `tui.rs` and `vault_tui.rs`; **removes**
    `PURPLE = #a78bfa` (system.md §7 — off-palette, maps to no brand.md
    meaning). Both TUI entry points import from `theme.rs`; no file under
    `crates/paranoid-cli` defines its own `Color::Rgb` literal after this
    lands.
  - **Slint**: new `crates/paranoid-gui/ui/paranoid-tokens.slint` `global`
    block exporting `brush`/`length` properties named by token
    (`Tokens.bg-base`, `Tokens.accent-action`, `Tokens.space-base`,
    `Tokens.type-title`, …, full set system.md §1/§2/§3). `paranoid.slint`
    components are retuned to reference `Tokens.*` per the system.md §7 drift
    table (panel bg `#171d26`→`#0d1119`, border `#314154/#405368/#4c6178`→one
    `#17304b` token, `SectionTitle #f2f5ff`→`#e4e7f2`, accent `#9fd4c9`/
    `#f5d76e`/`#1f2a37`/`#1b2a26`→canonical verified/caution/bg.panel, hero
    `34px`→`type.title` 20px) — no literal hex or px size remains in
    `paranoid.slint` after this lands.
  - **Sphinx**: `docs/_static/custom.css` `--pp-*` custom properties are
    already canonical (system.md §7 — keep as-is); extend with the missing
    space/type tokens (`--pp-space-tight/snug/base/loose`,
    `--pp-type-title/body/label/mono`) so docs components can read tokens
    instead of ad-hoc CSS values, per system.md §6 third bullet.
  ACCEPT: all three token surfaces exist and export the full set in system.md
  §1–§3; a grep for raw hex literals / `Color::Rgb(` outside `theme.rs` in
  `crates/paranoid-cli/src`, and outside `paranoid-tokens.slint` in
  `crates/paranoid-gui/ui`, returns zero; `PURPLE` is gone from the codebase.
- [x] P8.1 Evidence pass — run the REAL TUI and GUI on this machine, capture
  screenshots of every screen in the ia.md §2 screen graph (S1/S2/S2d/S3/S3f,
  S4/S5, H/S7, S8/S9, S10/S10d, S11/S11d, S12, S13/S14, S15/S16, S17, S18/
  S19) in both real- and decoy-vault framing, and LOOK at them against: (a)
  the ia.md §5 annotated wireframes for the TUI (does the rendered screen
  match the fixed skeleton in ia.md §1 and the per-screen spec?), (b) the
  ia.md §6 region contracts for the GUI. Output: a defect list keyed to the
  specific ia.md screen ID each screenshot fails to match, ranked by which
  cross-journey invariant (journeys.md "Cross-journey invariants," 7 items)
  it violates. DONE 2026-07-17: docs/design/evidence.md, 17 screenshots
  (docs/design/evidence/*.png) from the real TUI (tmux true-color capture,
  not the scripted-mode text dump) and the real GUI (make
  test-gui-e2e-emulate). Several ia.md nodes (S1-S3f trust gate, S13/S14
  dedicated Locked screen, per-screen GUI states) do not exist as distinct
  screens in the current build at all — that non-existence is itself
  captured as the evidence pass's top-ranked findings (see evidence.md
  Findings 1 and 5), not a gap in the capture. Decoy-vault framing was not
  separately captured — no decoy-vault creation path exists yet in the
  current build to screenshot (P8.2's S17 build item is what will add it);
  noted in evidence.md as follow-up scope for P8.5's re-baseline once P8.2
  ships S17.
- [x] P8.2 TUI polish — implements ia.md §1 (fixed layout skeleton) and
  ia.md §3 (guided first-run spine). Landed: (a) contextual per-screen
  footers (new `vault_tui/footer.rs`) replacing the 40-key `Controls:` wall,
  re-rendering on screen/mode change, `?` excluded from text-entry footers so
  a literal `?` stays typeable; (b) the S12 `?` overlay as a transient
  render-time layer (`help_overlay_open: bool`, not a new `Screen` variant)
  context-scoped by heading, holding every capability the old footer had;
  (c) new `Screen::TrustGate`/`Verifying`/`Verified` first-run spine fronting
  `run`/`run_scripted` (never `refresh()`, so mid-session reloads don't
  re-show it), with a real "already verified on this machine" short-circuit
  backed by an opt-in marker file (`PARANOID_PASSWD_STATE_DIR`, no `$HOME`
  guessing in ANY build — see `trust_marker_path` doc comment for the
  concrete leak this closes); existing-vault → skip-to-S15 was already
  correct behavior, confirmed not regressed; (e) brand.md §3 rewrites landed:
  `Ways in (N)` (was `Keyslots (N)`), `Hardware protection` (was
  `Seal-provider posture`), the unlock-blocked/empty/failed copy, panic-lock
  S14 copy, and the verbatim `Copied. It clears from the clipboard in N
  seconds.` micro-example; (f) severe-tier typed-name confirmation for
  delete-item and remove-a-way-in (new `Screen::DeleteConfirm` typed flow,
  `Screen::RemoveWayInConfirm`), plus S14/S15 footer distinction (`⏎ unlock
  q quit` immediately post-lock vs `? other ways in` once interacted with).
  All existing tests kept green (147 total across lib+integration+PTY,
  `make test-tui-e2e` verified against the real binary); scripted-mode tests
  updated to traverse the new trust gate; new tests cover the trust
  short-circuit, the S12 overlay's text-field non-collision, the S14/S15
  footer split, and both typed-confirmation flows through the real key
  handler. Deferred, explicitly out of scope for this item (not silently
  dropped): (d) `S3f` "not verified" HALT path and cryptographic release
  verification — no attestation/signature backend exists anywhere in the
  workspace; S1-S3 honestly reports "identity confirmed, cryptographic
  verification not available yet" (brand.md §3 rule 4, never overpromise)
  rather than fabricate a check. Threading Argon2id derivation off the UI
  thread for a real `Gauge` progress affordance (system.md §4.6) — vault_tui
  is currently fully synchronous by design; this is an architecture change
  deserving its own item, not bundled into TUI copy/layout work.
  `remaining attempts: {n}` in the failed-unlock copy — no attempt counter
  exists in `paranoid-vault` yet; states the same fact honestly without a
  number. S19 evidence-bundle, S17 decoy-vault creation, and S10d/S11d/S2d
  drill-down leaf screens — none of these features exist in the codebase
  today (no decoy-vault flow, no evidence-bundle command reachable from the
  TUI); building them is new-feature work, not polish, and is P8.4/future
  scope. The remaining brand.md §4 vocabulary-table sweep (form field labels
  like "Recovery secret", `federal-evidence` CLI flags) is explicitly P8.4's
  job per this doc's own scoping, not re-done here.
- [x] P8.3 GUI polish — implemented ia.md §6's fixed three-region frame
  (title/content/action-bar, `ParanoidPasswdShell`'s `panic-lock-scope`
  `VerticalLayout`) and rebuilt `paranoid.slint` from the pre-P8.3 single
  dashboard scaffold into the actual ia.md §2/§6 screen graph, driven by a
  `screen: string` property: `TrustGateScreen` (S1, amber `!` banner /
  earned green `✓` re-verify state + **Verify this copy** button),
  `VerifiedScreen` (S3, green `✓` line, collapsed-by-default fingerprint
  disclosure, **Continue**), `VaultListScreen` (H, `VaultPrimaryPane` list
  rail / `VaultDetailPane` detail pane, folds S4/S15's init/unlock form into
  the same screen per this build's TUI precedent), `AddLoginScreen` (S8,
  the "n new" fan-out — not in ia.md §6's GUI table but required for the
  vault to hold anything to show S7/S10/S11 against), `ItemDetailScreen`
  (S7, masked `MonoText` password field, **Copy password** primary,
  Reveal/rotate secondary), `GenerateScreen` (S11, mono result, earned
  `StatusVerified` "Randomness check: passed", **Copy** primary once a
  result exists, collapsed-by-default "Show the evidence" disclosure =
  S11d), `WaysInScreen` (S10, **Add a way in** primary, collapsed-by-default
  "Show the mechanics" disclosure = S10d, export-backup secondary),
  `LockedScreen` (S14, centered `⊘` + verbatim brand.md copy, **Unlock**
  only, no other action per ia.md §6). New token-styled `PrimaryActionButton`
  (accent, one per screen)/`SecondaryActionButton` (bordered panel-tone)/
  `TextButton` components replace every `std-widgets::Button` default-gray
  usage the pre-P8.3 scaffold had (verified against `docs/design/evidence/
  15-gui-operator-workflow-final.png`, the P8.1 baseline, which shows the
  same gray default-widget look this item exists to fix); `DisclosureRegion`
  is the shared collapsed-by-default `⋯`/"Show…" component enforcing ia.md
  §6's "GUI disclosure rule" (never a permanently visible side panel) for
  S3/S11/S10's evidence; `ProgressAffordance` exists and is wired through
  `GenerateScreen` for the non-blocking-progress contract, honestly
  documented as UI-only plumbing — `run_generator_audit` and every other
  vault/generator callback in `lib.rs` still run synchronously on the event
  loop thread, the same gap P8.2 found and deferred for `vault_tui`'s
  Argon2id derivation, not silently claimed complete here (doc comment on
  `run_generator_audit` cites the P0-META "pinning existence, not
  completeness" lesson directly). Empty states: S1's unverified-vs-verified
  banner, H's "Nothing stored yet." + **Add your first item** when a vault
  is unlocked and empty (own widget test), S10's "No ways in yet." Window
  sizing/title per brand.md §5.5 ("an instrument, not a consumer
  dashboard"): `title: "paranoid-passwd"`, `preferred-width/height:
  1024x720`, `min-width/height: 360x420` (low enough for the visual-
  regression harness's narrowest tested viewport). All `paranoid.slint`
  components reference `Tokens.*` exclusively (P8.0's module) — zero raw hex
  literals remain in the file (grep-verified).
  ACCEPT verified: `make test-gui-widgets` — 12/12 real widget-event tests
  green (8 pre-existing flows re-navigated through the real S1→S3→H screen
  path instead of a direct-jump, since the layout contract changed
  wholesale, plus 4 new: trust-gate unverified state, S3 disclosure
  collapsed-by-default, H empty-state copy, S14 Unlock→H return);
  `cargo test -p paranoid-gui --lib` — 11/11 unchanged unit tests green;
  `cargo clippy -p paranoid-gui --all-targets --features gui-widget-tests -D
  warnings` clean; `cargo fmt -p paranoid-gui --check` clean; `make
  test-gui-host-check` clean; `make test-gui-e2e-emulate` and `make
  test-gui-visual-regression-emulate` (desktop=1280x1024, tablet=900x700,
  mobile=420x800) both green against the real binary under Xvfb — screenshot
  evidence read back and reviewed (not just "tests pass"), which surfaced
  and fixed two real defects beyond the design-system swap-in: (1) `Panel`
  (and the title/content/action-bar region `Rectangle`s) never set
  `clip: true`, so unwrapped content silently drew past a panel's own
  border at any width narrower than the content's natural size — fixed by
  clipping every fixed-frame region and giving `VaultPrimaryPane`'s
  `item-list` Text an explicit wrap width bound to its `ScrollView`'s own
  width rather than the flickable-viewport-loop `parent.width` (which does
  not compile — binding loop through `viewport-width`); (2) the
  `PARANOID_GUI_AUTOMATION_*` operator-workflow scenario (used by both e2e
  harnesses) drives `GuiState` directly, bypassing every screen-navigation
  callback, so the shell was staying parked on the S1 trust-gate frame
  (claiming unverified) while the action bar simultaneously offered "Lock
  vault" for an already-unlocked session — fixed by explicitly setting
  `copy-code-verified`/`screen` to the vault-list home once automation
  reports success, landing the window where the equivalent real click path
  would have. DEFERRED, explicitly out of scope (not silently dropped): a
  genuine two-pane-vs-stacked responsive collapse at `VaultListScreen`'s
  `narrow-breakpoint: 640px` is implemented and compiles correctly (verified
  via a temporary debug canary that it is dead code under the harness's
  specific backend), but bare `Xvfb` (no window manager) plus
  `SLINT_BACKEND=software` does not propagate a post-show `Window::set_size`
  resize into the top-level component's own `width`/`height` layout
  properties on this stack — confirmed via `window.window().size()` (which
  DOES report the requested physical size) versus the responsive branch
  never firing at 420px — so the visual-regression harness's tablet/mobile
  screenshots cannot currently demonstrate the collapse even though the
  `.slint` logic is correct and will work under any real (WM-managed)
  desktop launch. `PARANOID_GUI_WINDOW_SIZE` env-var plumbing (`lib.rs`
  `apply_requested_window_size`, threaded through `tests/test_gui_e2e.sh` as
  an 8th positional arg = the viewport geometry) is left in place as
  correct, harmless infrastructure for whichever future item chases the
  Slint/winit/Xvfb-without-WM layout-property propagation gap directly — a
  new, narrower follow-up than this item's actual scope (implementing the
  design system), not a defect in the design-system work itself.
- [x] P8.4 Copy pass — every user-facing string across TUI + GUI + CLI
  errors is checked against brand.md §3's five voice rules and replaced with
  the exact rewrites brand.md §3 and the vocabulary table in §4 specify —
  this is verbatim reconciliation, not fresh copywriting. Minimum checklist
  (cite the source of each string): the 5 named rewrites in brand.md §3(a-e)
  (`Keyslots`→`Ways in`, `Seal-provider posture`→`Hardware protection`,
  `federal-evidence`/`federal-ready`→`Evidence bundle`/`--assurance strict`,
  `Unlock blocked: …`→the two conversational rewrites, the 40-hotkey line→
  contextual footers); the full §4 vocabulary table (12 rows: `keyslot`→"way
  in", `recovery keyslot`→"recovery phrase", `device-bound keyslot`→"this
  device", `certificate-wrapped keyslot`→"trusted contact"/"held key", `seal
  provider`→"hardware protection", `ops profile`→"assurance level",
  `chi-squared pass`/`p > 0.01`→"randomness check: passed", `duress vault`→
  "decoy vault", `attestation`→"verify this copy", `master key`→not
  surfaced, `rejection sampling`→not surfaced); the 5 micro-examples table
  (§3, vault-opened/panic-lock/verification-failed/decoy-created/copied);
  the journeys.md verbatim copy blocks per screen (J1 step 3a/3b, J2 step 2,
  J3 step 2/4, J4 step 3a/3b, J5 step 2/4, J6 honest-limits note — all three
  limitation statements, J7 step 3/4a/4b). Hard gate carried from brand.md
  §3/CLIG (ia.md §4.3, journeys.md invariant 4): no code path accepts a
  passphrase or recovery secret as a CLI arg — stdin/prompt/file only; this
  is a code-review gate on this item, not a copy-only check.
- [x] P8.5 Visual regression — re-baselined `test-gui-visual-regression`
  (rebuilt: it now drives every named GUI screen — trust-gate, verified,
  vault-list, add-item, item-detail, generate, ways-in, locked — through a
  real vault pass AND a decoy vault pass via a new Rust-side Timer-driven
  screen-sequence in `paranoid-gui/src/lib.rs`, capturing 16 committed
  baseline PNGs under `tests/baseline/gui/`) and the TUI PTY e2e harness:
  (a) DONE — the GUI harness crops and diffs the action-bar region between
  every real/decoy screen pair and fails on any pixel difference
  (`tests/test_gui_visual_regression.sh`); verified visually (both captures
  identical outside vault-path text, which itself is not rendered on the
  compared screens). (b) DONE for the TUI (the surface where monochrome
  assertion is meaningful — glyphs are literal text, testable without OCR):
  added `TerminalGrid`, a real cursor-position-aware VT100 replay, to
  `tests/test_tui_e2e.py` (the naive raw-byte-concat `clean_screen` silently
  dropped content ratatui's diff-renderer left unchanged between frames —
  a real false-negative bug, fixed) and a PTY flow asserting the `⊘` state
  token survives on both the S14 (just-locked) and S15 (ordinary unlock
  prompt) screens with all ANSI stripped. This caught and fixed a REAL
  pre-existing defect: `UnlockBlocked` never rendered `ICON_LOCKED` (`⊘`) at
  all — system.md §1.1's "the test" was failing. Fixed in
  `panel_rendering.rs` (`render_header`/`header_state_token`), with Rust
  unit + PTY e2e + an incremental-`CrosstermBackend`-diff regression test
  pinning the fix. GUI locked screen already showed `⊘` correctly (verified
  in the captured baseline). (c) DONE for H (Vault list) and S10 (Ways in) —
  exact ia.md §5 footer strings asserted via the new grid against the real
  PTY render — and S14/S15 (UnlockBlocked just-locked vs ordinary) via the
  new panic-lock flow. S7 (item detail) has NO distinct footer in the
  current architecture: ia.md §5 assumed independently-focusable list/
  detail panes, but P8.2 built one unified `Screen::Vault` screen where both
  panes are always visible and the full keymap (`e`/`d`/`⏎`/etc.) is bound
  regardless of "focus" — there is no S7-specific footer state to assert.
  This is a real spec/implementation gap, not silently papered over;
  flagged here as a forward P8.x item (differentiate list-vs-detail focus
  and footer, or revise ia.md §5 to match the single-screen model — an
  architecture decision for that item, not this one). (d) DONE —
  `scripts/check_token_drift.sh` (new `verify-token-drift` Make target,
  wired into `verify-assurance`) greps every tracked `crates/**/*.rs` and
  `crates/**/*.slint` file for raw hex color literals outside
  `theme.rs`/`paranoid-tokens.slint`, and every `docs/_static/*.css` file
  outside `custom.css`; verified it both passes clean today and fails on an
  injected violation. Also fixed two pre-existing, unrelated red gates
  discovered while running the full P8.5 gate sequence (both confirmed red
  on unmodified HEAD before this item started): `scripts/
  hallucination_check.sh`'s unsafe-Rust grep false-positived on the English
  word "unsafe" inside a doc comment (`screen_state.rs:3445`) — tightened to
  match the Rust keyword in code position only, verified it still catches
  real `unsafe fn`/`unsafe {`; and the assurance-pinned GUI-screenshot-
  evidence claim's Makefile/doc string set, updated consistently across
  `security_assurance_gate.py`, `verify_ai_review_inventory.sh`,
  `docs/reference/ai-review.md`, `docs/reference/testing.md`,
  `.github/agents/paranoid-security-auditor.md`, and `.github/instructions/
  security-assurance.instructions.md` to describe the new per-screen
  baseline instead of the old multi-viewport smoke paths (which
  `test-gui-visual-regression` no longer produces — `test-gui-e2e`/
  `test-gui-e2e-emulate` with `GUI_E2E_VISUAL_VIEWPORTS` still can, if that
  specific smoke check is ever wanted again). Full gate green: `cargo fmt
  --check`, `cargo clippy --workspace --all-targets -D warnings`, `cargo
  test --workspace` (all crates, zero failures), `make test-tui-e2e`,
  `make verify-assurance` (P9 exhaustive-purge and every other pinned claim
  still pass — no hardening regression), `bash scripts/validate-docs.sh`,
  `python3 -m tox -e docs`, `make e2e-ci`, `make ci`.

- [ ] P8.6 S7 detail-pane footer/architecture reconciliation (surfaced by
  P8.5's footer-assertion pass) — ia.md §5 specifies a distinct S7 item-
  detail footer (`⏎ copy   r reveal   e edit   ? all keys   ⎋ back`)
  independent from the H list-pane footer, implying independently-
  focusable list/detail panes; P8.2 built one unified `Screen::Vault` with
  both panes always visible and one shared keymap, so there is no S7-
  specific footer state today. Decide (agent's call, record why): (i) add
  real list/detail focus tracking to `vault_tui` and differentiate the
  footer per ia.md §5, or (ii) revise ia.md §5 to describe the single-
  screen model actually built and drop the S7-footer distinction. Either
  way, land the matching PTY e2e assertion this item's P8.5 work left
  unable to cover.

- [ ] FINAL: full gate (make ci + quality + e2e-ci + e2e-local on this
  machine), docs both-directions sweep, open the single PR, babysit to
  squash-merge, verify the app RUNS (TUI + GUI), release-please takes over.

## Standing constraints

Zero-exception rules in CLAUDE.md; two-tier cache/trust boundary per
design.json; no new branches; no amends to pushed commits; executor
placeholder-output checks mandatory.
