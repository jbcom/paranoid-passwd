---
title: Testing
---

# Testing

The native product line keeps generator, vault, and release behavior covered in tests while
keeping the retired browser app out of the product surface. Slint WASM and mobile targets are
treated as explicit Rust-native target surfaces with their own threat model and local checks.

The closed AI review disposition surface is tracked separately in
[AI Review Surface](./ai-review.md) and mapped to [Assurance Claims](./assurance-claims.md).
The repository enforces that inventory with `scripts/verify_ai_review_inventory.sh` and the
claim-led gate in `scripts/security_assurance_gate.py`.

## Test-Execution Parallelism

`scripts/cargo_test.sh` — the entry point behind `make test` and `make ci` — builds every
workspace test binary once with `cargo test --no-run --message-format=json` (a single
lockfile-honoring compile, `--locked --frozen --offline` preserved), then runs the resulting
per-crate/per-suite test binaries **concurrently** as separate OS processes, bounded to the
host's CPU count (`getconf _NPROCESSORS_ONLN` / `sysctl -n hw.ncpu`, override with
`PARANOID_TEST_MAX_PARALLEL`). Doc-tests (`cargo test --doc`) run as one more suite in the same
batch, since `--no-run` cannot pre-build them. Each suite's stdout/stderr is buffered to a
per-job log file and printed as one atomic block, sorted by suite name, only after that suite
finishes — no interleaved output. The aggregate exit code is nonzero if any suite fails, and
each failing suite is called out with `=== suite FAILED: <name> (exit <code>) ===` on stderr.

This is dependency-free by design — no `cargo-nextest`, `mold`, or `lld` — because the pinned
Wolfi builder image ships none of them and the workspace has no vendored path to add them
without a meaningful `vendor/` size increase (see the P6.7 section of
[CI Design](./ci-design.md#p6-7-concurrent-per-suite-test-execution-no-new-dependencies) for the
measured numbers and the rejected `cargo-nextest` vendoring alternative).

Two escape hatches:

- `PARANOID_TEST_SERIAL=1` restores the previous behavior: a single `cargo test` invocation
  running every suite serially in-process, exactly as before P6.7.
- A `--` test-name-filter argument (e.g. `cargo_test.sh -- some_test_name`) always falls back to
  the serial path automatically, since a filter has to see every suite in one process to apply
  consistently — `cargo_test.sh` detects `--` in its argument list and skips the parallel
  build/dispatch entirely in that case.

Each concurrently-running suite gets its own subdirectory under
`PARANOID_TEST_DEVICE_STORE_DIR` (job-scoped, auto-created) rather than sharing one root, because
the debug-only device-store test shim keys files by `hex(service + account)` and two suites
racing the same account inside a shared root could otherwise clobber each other now that suites
run concurrently instead of one-`cargo-test`-invocation-at-a-time. Callers that pre-set
`PARANOID_TEST_DEVICE_STORE_DIR` explicitly keep the old shared-root behavior and own that
isolation contract themselves.

Run the full assurance gate with:

```bash
make verify-assurance
```

That command verifies the hallucination checks, supply-chain checks, AI review inventory, and
security assurance protocol wiring. It also runs
[`tests/test_security_assurance_gate.py`](../../../tests/test_security_assurance_gate.py), a
negative-proof test that mirrors the small file set a P9 hardening claim's requirements touch
into an isolated temp directory, strips a load-bearing string (the zeroize wrapper's redacting
`Debug` impl for `vault.zeroized-payload-secrets`, the pre-Argon2id `check_lockout` call for
`vault.failed-unlock-lockout`), and asserts the gate actually flips that claim to `fail` —
proving the gate would catch someone deleting the hardening later, not just that its
`Requirement` strings currently happen to match.

## Local Release-Candidate Quality Gate

The Makefile remains the operator interface for local and CI workflows. Repo-owned deep checks that
need structured parsing live in the Rust-native `xtask` crate instead of ad hoc Python glue:

```bash
make verify-deep
make quality
make quality-emulate
```

- `make verify-deep` runs `cargo run -p xtask --locked --frozen --offline -- verify-deep`.
- The `xtask` gate verifies the Rust toolchain policy, locked offline Cargo metadata, workspace
  license/source policy, ShellCheck warning-or-higher results for repo-owned shell scripts, Python
  syntax for the existing docs/test harness scripts without writing bytecode, tracked-file secret
  scanning, and local visibility of security scanners.
- `make quality` runs `verify-deep`, the full `ci` target, GUI target compile checks, and the
  supported per-screen GUI visual-regression target for the host. On macOS it drives the Linux
  GUI harness through the local builder image; on Linux it uses the native `xvfb-run` harness. This
  target requires the local security scanner stack and runs the enforced local scanner subset.
- `make quality-emulate` runs the release-candidate posture through the custom Wolfi builder image:
  `verify-deep`, the builder-owned scanner subset, `ci`, and the Linux GUI visual-regression
  harness. In that mode `xtask` treats missing builder-owned scanner tools as fatal, uses the
  builder-pinned RustSec advisory DB for no-fetch cargo-audit runs, and falls back from ShellCheck
  to `bash -n` parsing because ShellCheck is still host-local.
- Optional external tools (`codeql`, `semgrep`, `cargo-deny`, `cargo-audit`, `cargo-vet`, `syft`,
  `trivy`, and `osv-scanner`) are reported when missing under `make verify-deep`; `make quality`
  sets `PARANOID_STRICT_EXTERNAL_TOOLS=1` and treats missing tools as fatal.
- `supply-chain/scanner-toolchain.env` records the scanner/tool update contract. The
  supply-chain verifier checks that Wolfi builder scanner apk versions, CodeQL action SHA pins, and
  host-local `xtask` visibility and version checks agree with that manifest. In strict host mode,
  `xtask` checks ShellCheck, cargo-deny, cargo-audit, cargo-vet, and the CodeQL CLI against their
  manifest pins before running the enforced local scanner subset.
- The enforced scanner subset is `cargo audit --no-fetch --stale`, `cargo deny check`, Semgrep
  `--config auto`, and an OSV lockfile report. `cargo-deny` allows unmaintained/unsound advisories
  as warnings only when there is no safe upgrade path; OSV findings with a fixed version remain
  blocking. The builder-owned scanner subset is `cargo audit --no-fetch --stale`, Semgrep
  `--config auto`, and an OSV lockfile report, with Syft and Trivy installed and visibility-checked
  for the next pinned evidence-output step. CodeQL, cargo-deny, cargo-vet, Syft, and Trivy remain
  host-visible or builder-visible but need pinned policies or evidence-output handling before they
  become universal blocking `make quality` steps.

Python remains in the repo only where it already owns a specific workflow: Sphinx/tox docs and the
PTY-driven TUI harness. It is not the project automation layer.

## Remote Dependency Scan

`.github/workflows/ci.yml` runs a `Dependency Scan` job on pull requests and `workflow_dispatch`
(skipped on `push`) that executes `cargo run -p xtask -- dependency-scan` inside the same Wolfi
builder image the `Rust Build + Tests` job uses. That subcommand runs `cargo audit --no-fetch
--stale` and the same OSV lockfile actionable-findings check as `make quality` /
`make quality-emulate`, and fails the job on any actionable advisory. It is a scanners-only job,
not the full `verify-deep`/`quality` gate, so it stays fast on every pull request; Semgrep,
cargo-deny, Syft, and Trivy remain local-only or `make quality-emulate`-only.

## Local Build Chain Configure

The repository owns local toolchain discovery through:

```bash
./configure
make configure
make bootstrap-local
make show-config
```

`./configure` and `make configure` generate `.config/paranoid-local.mk` for Make and
`.config/paranoid-local.env` for manual shell work. The generated config detects the host platform,
Cargo/Rustup, Docker, Xvfb/ImageMagick GUI capture tools, Android SDK/NDK paths, NDK clang/ar/ranlib,
adb, emulator, Maestro, `wasm-pack`, and installed Rust Android/WASM targets. `make bootstrap-local`
installs `aarch64-linux-android` and `wasm32-unknown-unknown` with Rustup before regenerating the
config.

GUI target checks are separate from the main CI target so platform-readiness does not hide behind
remote runners:

```bash
make test-gui-host-check
make test-gui-android-check
make test-gui-wasm-check
make test-gui-targets
```

`make test-gui-android-check` currently compile-checks the Slint GUI library through the configured
NDK while keeping the native `paranoid-core` and `paranoid-vault` path linked. `make
test-gui-wasm-check` is intentionally strict and warning-clean, but it only checks the gated
non-secret Slint WASM surface. The native vault and generator crates are not linked for
`wasm32-unknown-unknown`; target-appropriate vault storage, crypto, packaging, and runtime
validation remain product work before WASM can become a supported secret-handling surface.

## e2e Test Tiers: `make e2e-ci` and `make e2e-local`

The end-to-end suites split into two Make targets by what environment they need, not by what they
cover:

- **`make e2e-ci`** — the headless-deterministic tier. Runs on any machine with no display, no
  Accessibility permission, and no human present: `test-cli-contract`, `test-vault-e2e`,
  `test-tui-e2e` (PTY-driven, no real terminal window needed), `test-gui-e2e` when the host is
  Linux (under `xvfb-run`; empty on macOS/Windows, matching `CI_GUI_E2E_TARGET`'s existing
  Linux-only gating), and `test-gui-widgets` (the in-process real-widget-event suite from
  [Real Widget-Event Tests](#real-widget-event-tests), itself already headless with no display
  server). `make ci` calls `make e2e-ci` in place of the individual targets it used to invoke
  directly — this is a pure aggregation: the exact same commands run in the exact same order, just
  grouped under one name. Verified by diffing `make ci -n`'s full command list before and after the
  regrouping.
- **`make e2e-local`** — `make e2e-ci` plus [`tests/test_gui_e2e_local.sh`](../../../tests/test_gui_e2e_local.sh),
  which drives the real `paranoid-passwd-gui` window with real OS-level mouse clicks and keyboard
  input on a real display, gated to macOS with a real (Aqua) desktop session and Accessibility
  permission granted to the calling terminal. This is the only tier that proves the compiled GUI
  is actually operable by a human pointing a mouse and typing — every other GUI gate either drives
  the widget tree in-process (`test-gui-widgets`) or drives the binary through the
  `PARANOID_GUI_AUTOMATION_*` side-channel (`test-gui-e2e`), neither of which touches the OS input
  path at all.

### Real-Input Local GUI e2e (`make e2e-local`)

`tests/test_gui_e2e_local.sh` launches the real `paranoid-passwd-gui` binary and drives it through
the full operator workflow — generate passwords, init vault, add a login, lock, unlock, export
backup — using genuine synthetic mouse/keyboard events, then asserts every outcome through the
vault CLI (`paranoid-passwd vault --cli --path <vault> list`) against the real on-disk vault file,
not through screen text. It captures a screenshot of each stage to `dist/e2e-local/` for review.

**Why not AppleScript's `System Events` GUI scripting.** `paranoid-passwd-gui` is a winit-backed
Slint window. Probing it live shows its NSAccessibility tree exposes only titlebar chrome (close
/zoom/minimize buttons and the title text) — every `LineEdit`, `Button`, and `CheckBox` inside the
compiled `.slint` tree is invisible to the AX tree Apple's UI-scripting APIs walk. `tell
application "System Events" to click at {x,y}` and `keystroke` are silently dropped by the window
in this state: no error, no effect, the field never gets focus. This was confirmed empirically
(clicking a checkbox and a `LineEdit` at their exact on-screen coordinates through `System Events`
changed nothing; the same coordinates through a raw CGEvent post worked immediately).

**The real driver: raw CGEvents at the HID tap.** [`scripts/gui_real_input_macos.swift`](../../../scripts/gui_real_input_macos.swift)
is a small Swift CLI, compiled on demand with `swiftc` (part of the Xcode Command Line Tools this
repository's macOS builds already require — no new package install), that posts `CGEvent`s
directly at `.cghidEventTap` — the same event path a physical mouse or keyboard produces. This
bypasses the AX tree entirely and is delivered to the window exactly as real hardware input would
be, which paranoid-gui's winit event loop does receive and process. It has three subcommands:

- `click <x> <y>` — moves the cursor and posts a real left mouse down/up at an absolute screen
  point.
- `type <string>` — posts one keyDown/keyUp pair per character via CGEvent's Unicode-string path,
  so any printable character works without a virtual-keycode table.
- `keyrepeat <keycode> <count> [cmd]` — posts a virtual-keycode key event `count` times in a row,
  optionally with the Command modifier held throughout. Used to clear a `LineEdit`'s existing text
  deterministically: Right-arrow (keycode 124) ×100 to reach the true end of the field regardless
  of where the cursor started, then Backspace (keycode 51) ×150 to clear it regardless of prior
  content length. `Cmd+A` (select-all) and `Cmd+Right` (end-of-line) were tried first and are not
  reliably honored by this Slint `LineEdit` build; plain repeated navigation keys were verified to
  work deterministically instead.

**Coordinates are measured, not guessed.** Every field/button coordinate the driver clicks is a
window-relative point measured once against a real running instance of the exact compiled
`paranoid.slint` tree (screenshot the window, locate each control's pixel center, convert through
the retina scale factor). This is sound because `paranoid.slint`'s three-column operator layout is
fully static — every panel, field, and button carries a literal pixel width/height with no
data-dependent reflow — so the same relative offsets are stable across runs. The driver still reads
the window's actual position and size fresh at the start of each stage (via `System Events`, which
*can* see window-chrome-level geometry even though it cannot see or click the inner widget tree)
and rescales every reference coordinate against the window's actual granted size, so it keeps
working if a future toolchain change shifts the window's default size slightly.

**"Lock" is a real process quit, not an idle-timeout wait.** The GUI has no manual lock button —
session lock/unlock in `paranoid_vault::native_access::NativeSessionHardening` is purely
idle-timeout-driven, and waiting out that timeout in an e2e run is impractical. `test_gui_e2e_local.sh`
quits the running GUI process (via the real, AX-visible titlebar close button) and relaunches it
against the same vault path, which exercises the same on-disk persistence and Argon2id
re-derivation path a real lock/unlock cycle would — the same technique
[`tests/test_tui_e2e.py`](../../../tests/test_tui_e2e.py) already uses for its own fresh-process
restart/unlock coverage.

**Real KDF timing.** Vault init and unlock both derive against the real
`DEFAULT_MEMORY_COST_KIB` (256 MiB) Argon2id parameters on a `--profile dev` / `CARGO_PROFILE_DEV_DEBUG=0`
build — measured at roughly 9-10 seconds per derivation on Apple Silicon. The script polls the
vault CLI (not a fixed sleep) for each stage's outcome, bounded generously and scaled by
`PARANOID_E2E_TIMEOUT_SCALE` like the other e2e harnesses, so it neither races the real KDF cost
nor stalls longer than necessary on a fast machine.

**Display-feasibility gate.** The script fails fast with an actionable message, instead of hanging
or silently no-op-ing, when either precondition is missing:

- `launchctl managername` must report `Aqua` (a real logged-in WindowServer session). A headless
  SSH session or CI runner reports something else and the script exits `64` immediately.
- `System Events`'s "UI elements enabled" must be `true` — the calling terminal (Terminal.app,
  iTerm2, etc.) needs Accessibility permission in System Settings > Privacy & Security >
  Accessibility for its synthetic `CGEvent`s to be delivered to another application, and on current
  macOS may also need Input Monitoring if clicks/keystrokes still do not land after granting
  Accessibility. Without this grant, every synthetic event is silently dropped by the OS rather
  than erroring, so this check is the only way to fail loud instead of hanging on a GUI that never
  receives any input.

Run it directly (after granting the permissions above) with:

```bash
CARGO_PROFILE_DEV_DEBUG=0 cargo build -p paranoid-cli -p paranoid-gui --locked --frozen --offline
bash tests/test_gui_e2e_local.sh target/debug/paranoid-passwd target/debug/paranoid-passwd-gui dist/e2e-local
```

or through the aggregate target:

```bash
make e2e-local
```

Current GUI platform coverage is explicit:

| GUI surface | Current gate | What it proves |
| --- | --- | --- |
| Widget-event unit coverage | `make test-gui-widgets` | Drives the real compiled `paranoid.slint` widget tree in-process through synthetic pointer/accessible-value events (see below) and asserts on window property state. No display server, no `SLINT_BACKEND`, no `xvfb-run`. |
| Desktop Slint | `make test-gui-e2e` or `make test-gui-e2e-emulate` | Runs the real GUI binary through the operator workflow (see below), validates durable audit evidence, and captures a rendered screenshot. |
| Per-screen visual regression | `make test-gui-visual-regression` or `make test-gui-visual-regression-emulate` | Drives every named screen in `paranoid.slint`'s screen graph (ia.md §2/§6) through a real vault pass and a decoy vault pass, capturing one screenshot per screen into `tests/baseline/gui/`, and asserts the real/decoy action-bar region is pixel-identical (journeys.md invariant 5). |
| Real-input local e2e | `make e2e-local` (macOS, real display + Accessibility permission) | Drives the real GUI binary with genuine OS-level mouse clicks and keyboard input (see [Real-Input Local GUI e2e](#real-input-local-gui-e2e-make-e2e-local) above), the only GUI gate that exercises the actual OS input path end to end. |
| Android Slint | `make test-gui-android-check` | Compile-checks the Rust-native Slint library against the configured Android NDK while preserving native core/vault linkage. Runtime emulator/Maestro coverage remains the next Android gate. |
| WASM Slint | `make test-gui-wasm-check` | Compile-checks the gated non-secret Slint WASM surface. Secret-handling WASM is not supported until target storage, crypto, and runtime validation are threat-modeled. |

### Real Widget-Event Tests

`make test-gui-widgets` is the in-process counterpart to the `test-gui-e2e` process harness below:
instead of launching the compiled `paranoid-passwd-gui` binary and driving it through the
`PARANOID_GUI_AUTOMATION_*` side-channel under `xvfb-run`, it links the `slint_shell` module
directly into a `paranoid-gui` test binary and drives the real generated
`ParanoidPasswdShell` widget tree with `i-slint-backend-testing`'s synthetic pointer and
accessible-value events — the same code paths a real mouse click or keystroke exercises. A
`LineEdit`'s compiled `accessible-action-set-value` handler assigns `text-input.text` and fires
`edited`, exactly as a real keystroke would; a `Button`'s synthetic pointer press/release exercises
the same `TouchArea` a real mouse click would.

`i_slint_backend_testing::init_no_event_loop()` installs a null-rendering testing platform with
real Slint layout math but no actual pixel rendering, so element positions used by
`single_click`/`mock_single_click` are geometrically accurate against the compiled `.slint` tree
without any display server. This is why the target needs no `SLINT_BACKEND` and no `xvfb-run`,
unlike `test-gui-e2e`.

The vendored `slint` crate (`1.16.1`) does not carry its own testing module; the synthetic-event
API lives in the separate `i-slint-backend-testing` crate (same pinned `=1.16.1` version,
default features only — no `mcp`/`system-testing`/`internal`), added as a `paranoid-gui`
dev-dependency and vendored under `vendor/i-slint-backend-testing`. `ElementHandle::find_by_element_id`
requires the Slint compiler to have emitted element debug info, so `paranoid-gui`'s test tree only
compiles the `widget_event_tests` module behind the `gui-widget-tests` Cargo feature, and `make
test-gui-widgets` builds with `SLINT_EMIT_DEBUG_INFO=1 --features gui-widget-tests`; plain `make
test` / `cargo test --workspace` never sets either, so the ordinary test build stays unaffected.

Coverage, asserting on window property state (status text, item/keyslot counts, vault-items and
selected-item summaries) rather than the automation side-channel:

- init-vault: types a vault path and recovery secret into the real `vault-path-input`/
  `vault-secret` inputs and clicks the real "Init" button; asserts the vault file exists and the
  status/vault-items properties reflect an unlocked, empty vault
- add-login: types a title/username/password/folder/tags into the real Operations panel inputs
  and clicks the real "Add login" button; asserts the vault-items property gains exactly one entry
  and never echoes the typed password
- generate-and-rotate: types a rotate length into the real input and clicks the real "Rotate"
  button; asserts the status confirms rotation and the selected item's password-history grew
- enroll-mnemonic: types a mnemonic label into the real input and clicks the real "Enroll
  mnemonic" button; asserts the keyslot-summary property gains a mnemonic entry and the
  selected-item pane surfaces the recovery phrase
- export-backup: types a backup output path into the real input and clicks the real "Export
  backup" button; asserts the backup file was written and the status reflects the export

Run directly with:

```bash
SLINT_EMIT_DEBUG_INFO=1 cargo test -p paranoid-gui --locked --frozen --offline --features gui-widget-tests --lib widget_event_tests::
```

### GUI Automation Environment Variables

The desktop GUI e2e and visual-regression gates drive the real `paranoid-passwd-gui` binary
headlessly through four environment variables, read once at startup on non-WASM builds:

- `PARANOID_GUI_AUTOMATION_SCENARIO` — the scenario to run. Only `operator` and
  `operator-workflow` are accepted (both select the same operator-workflow scenario); any other
  value fails startup with an "unknown GUI automation scenario" error.
- `PARANOID_GUI_AUTOMATION_VAULT_PATH` — path to the vault the scenario operates against. Required
  whenever the scenario variable is set.
- `PARANOID_GUI_AUTOMATION_BACKUP_PATH` — path the scenario exports an encrypted backup to.
  Required whenever the scenario variable is set.
- `PARANOID_GUI_AUTOMATION_OUTPUT_PATH` — path the scenario writes its outcome file to. Required
  whenever the scenario variable is set.

`PARANOID_GUI_AUTOMATION_SCENARIO` unset means the GUI runs normally with no automation. When set,
the scenario runs and writes a plain-text outcome file to `PARANOID_GUI_AUTOMATION_OUTPUT_PATH`
with one `key=value` line per field: `status` (`pass` or `fail`), `scenario`, `vault`, `backup`,
and `message`. The GUI e2e and visual-regression harnesses parse this file to assert the operator
workflow actually completed rather than just checking the process exit code.

### Android and WASM Checks Are Local-Only

Neither `make test-gui-android-check` nor `make test-gui-wasm-check` runs in GitHub Actions. The
`.github/actions/builder` Wolfi image installs a single pinned `rust-1.95` apk package that ships
only the host `aarch64-unknown-linux-gnu` std rlib. It has no `rustup` (the only tool that installs
additional target std components) and no Android NDK apk — the Wolfi package index does not carry
one. `rustc` recognizes the `wasm32-unknown-unknown` target triple, but `cargo check --target
wasm32-unknown-unknown` fails with `error[E0463]: can't find crate for core` there because that
target's std is not installed, and linking the pinned system `rustc` into `rustup` cannot add
components (`rustup` only manages components for toolchains it installed itself). Making either
check pass in CI would require replacing the pinned-apk, offline-first builder trust model with a
network-fetched, rustup-managed Rust toolchain, which is out of scope for a compile-check gate.
Both checks stay local-only, gated on `make bootstrap-local` (installs `aarch64-linux-android` and
`wasm32-unknown-unknown` through a locally installed `rustup`), until that trust-model trade-off is
revisited.

## Ops, Audit, and Federal Profile Tests

The ops/audit/seal layer now has dedicated `paranoid-ops`, `paranoid-audit`, and `paranoid-seal`
crates. Current coverage proves that:

- generator automation runs through the ops boundary
- JSON reports include policy request/response audit events
- `--audit-jsonl` writes a local append-oriented JSONL audit sink
- configured audit sinks must pass a writable health check before policy treats them as available
- headless vault CLI subcommands and native vault TUI actions emit typed ops request/response events
  when an audit sink is configured
- native GUI vault operations emit typed ops request/response policy events to both in-memory
  automation evidence and configured durable JSONL sinks without copying plaintext secrets into audit
  metadata
- ops unit tests prove caller-supplied envelopes cannot downgrade the authoritative policy context
  profile, and that CLI/TUI/GUI vault-operation surfaces preserve the same operation/access metadata
- `--federal-ready` fails closed without confirmed approved-provider evidence
- federal startup evidence is emitted as JSON
- federal startup evidence includes external audit-device posture without treating configured-only
  mTLS evidence or TCP reachability as an available sink
- audit unit tests cover disabled probes, live TCP reachability probes, and the explicit ready-ack
  path required before an external audit device can satisfy required audit policy
- a stable denied federal startup fixture and an external-device-ready fixture are checked against
  the serialized evidence schema; the external audit-device and recovery-disposition wire shape is
  versioned as federal startup evidence schema `3`
- stable CLI/TUI/GUI vault operation trace fixtures pin typed ops envelopes, request/response audit
  events, and JSONL rendering for automation compatibility
- a stable mTLS process-boundary vault operation fixture pins authenticated transport evidence,
  service-account actor context, and non-secret request/response audit attributes, including
  channel-binding evidence
- live mTLS JSONL ops transport tests prove a loopback OpenSSL mTLS command exchange returns the
  same typed trace to client and server, replaces client-claimed transport evidence with
  server-observed peer-certificate evidence, and rejects an untrusted client certificate before
  policy can allow the command; the transport also rejects oversized peer-controlled JSONL frames
  instead of reading unbounded input
- audit unit tests cover the mTLS JSONL write-ack probe, including matching acknowledgement and
  mismatched challenge rejection
- typed allow/challenge/deny decisions cover sensitive vault unlock methods
- ops policy tests require seal posture evidence for federal certificate unlock, require seal
  posture evidence for device-bound unlock, and require confirmed device-bound provider
  availability before device-bound unlock can proceed; password, mnemonic, device-bound, and
  certificate unlocks are checked against their matching provider kinds instead of generic recovery
  or auto-unseal flags
- the seal state machine covers unlock, idle-lock, timeout, and relock transitions
- seal posture reports configured recovery, certificate, and auto-unseal providers without claiming
  provider availability before a health check confirms it, and helper tests keep availability
  method-specific
- headless `vault seal-status` output includes the same seal posture payload, and
  `vault seal-status --probe-providers` is covered by the vault CLI e2e script to prove
  device-bound providers become `available` only after an explicit secure-storage check
- redaction removes sensitive attributes instead of copying or hashing secrets
- hash-chain verification detects tampered event streams

Future non-blocking test expansion is now narrower:

- keyed correlation hashes only after the approved primitive and low-entropy secret risk are
  dispositioned
- broader PTY e2e coverage for each TUI vault mutation routed through typed ops envelopes

## Core Tests

`paranoid-core` includes unit coverage for:

- SHA-256 known-answer vectors
- rejection-sampling boundaries
- charset validation
- constrained generation
- chi-squared known answers
- serial-correlation known answers
- pattern detection
- full audit pipeline output
- multi-password `GeneratedPassword` inspection and `AuditSummary` roll-up

Run them with:

```bash
cargo test -p paranoid-core --locked --frozen --offline
```

## CLI and TUI

`paranoid-cli` includes:

- TUI reducer / rendering smoke tests
- real PTY-driven binary TUI workflow coverage in
  [`tests/test_tui_e2e.py`](../../../tests/test_tui_e2e.py), proving the
  generator wizard and vault TUI can be driven end to end with actual
  terminal keystrokes: the base vault flow (add-login, mnemonic-keyslot
  enrollment, backup export) plus a second PTY session against the same
  vault path proving login items and keyslots survive a fresh-process
  restart/unlock; a wrong-`PARANOID_MASTER_PASSWORD` unlock attempt that
  renders the seal's `UnlockBlocked` posture screen and is then recovered
  with the correct password in the same session; and a recovery-secret
  rotation flow (through the P2.3 environment-approval screen for the fresh
  vault it inits) that proves the rotated secret unlocks a fresh CLI-mode
  process while the pre-rotation secret no longer does
- a deterministic scripted TUI driving surface (`PARANOID_TUI_SCRIPT`, see
  [Scripted TUI mode](#scripted-tui-mode) below) exercising the real `App`
  reducers, including the generator wizard's background worker thread,
  against an in-memory backend instead of a PTY
- a Linux GUI-binary workflow harness in
  [`tests/test_gui_e2e.sh`](../../../tests/test_gui_e2e.sh), proving the native
  Slint desktop app can run an operator workflow end to end under `xvfb-run`
  and leave a screenshot artifact for review
- a per-screen GUI visual-regression harness
  ([`tests/test_gui_visual_regression.sh`](../../../tests/test_gui_visual_regression.sh)) that
  drives every named screen in `paranoid.slint`'s screen graph through a real vault pass and a
  decoy vault pass, capturing one screenshot per screen into `tests/baseline/gui/` (the committed
  baseline), and asserts the real/decoy action-bar region is pixel-identical between passes so the
  two vaults stay visually indistinguishable outside the content the owner's passphrase unlocked
- vault TUI rendering and launch-policy smoke tests
- headless CLI end-to-end coverage for the documented vault workflows in
  [`tests/test_vault_cli.sh`](../../../tests/test_vault_cli.sh), including
  real binary CRUD, structured filtering, `generate-store` create and rotate
  flows, encrypted backup restore plus `--force` overwrite behavior,
  transfer-package import/export plus remap and `--replace-existing` conflict
  handling, mnemonic recovery, device-bound unlock, certificate-backed unlock,
  recovery-secret rotation, and keyslot removal guards
- vault TUI add, edit, delete, generate-and-store, generate-and-rotate, `SecureNote`, `Card`, `Identity`, folder, tag, password-history, duplicate-password visibility, native direct unlock for recovery-secret, mnemonic, device-bound, and certificate-backed paths, keyslot-enrollment, mnemonic-slot rotation, certificate-slot rewrap, keyslot-relabel, recovery-secret rotation, keyslot-removal, device-slot rebind, and structured `/` filter workflow tests
- vault TUI encrypted backup export/import round-trip tests, invalid backup restore fail-closed coverage, transfer-package export/import round-trip tests, invalid transfer import fail-closed coverage, and backup/transfer summary preview coverage
- headless encrypted transfer-package export/import coverage for recovery-secret unwrap, certificate unwrap, and conflict remapping
- vault TUI idle auto-lock regression coverage
- vault CLI coverage through the shared workspace tests
- CLI contract coverage through the shell script in [`tests/test_cli.sh`](../../../tests/test_cli.sh)
- repository verification via `scripts/hallucination_check.sh` and `scripts/supply_chain_verify.sh`
- the [Recovery Operations](../guides/recovery-operations.md) runbook is checked by
  `scripts/validate-docs.sh` and the assurance gate so lifecycle docs keep covering mnemonic
  rotation, certificate rollover, device rebind, backup/restore, transfer packages, daily
  passwordless unlock, and disaster recovery

Run them with:

```bash
cargo test -p paranoid-cli --locked --frozen --offline
cargo build -p paranoid-cli --locked --frozen --offline
tests/test_cli.sh target/debug/paranoid-passwd
tests/test_tui_e2e.py target/debug/paranoid-passwd
tests/test_gui_e2e.sh target/debug/paranoid-passwd target/debug/paranoid-passwd-gui dist/gui-e2e.png
tests/test_gui_visual_regression.sh target/debug/paranoid-passwd target/debug/paranoid-passwd-gui tests/baseline/gui
tests/test_vault_cli.sh target/debug/paranoid-passwd
bash scripts/hallucination_check.sh
bash scripts/supply_chain_verify.sh
```

The headless vault e2e suite uses a debug-only file-backed device-store override
when `PARANOID_TEST_DEVICE_STORE_DIR` is set. Release builds do not include that
test backend.

### Scripted TUI mode

`tests/test_tui_e2e.py` forks a real PTY to prove the compiled binary works
with actual terminal I/O, but that layer is comparatively slow and its
assertions have to tolerate ANSI/terminal-emulation noise. `paranoid-cli` also
ships as a library crate (`paranoid_cli`, `crates/paranoid-cli/src/lib.rs`) so
tests — and, longer term, agentic control surfaces — can drive the real
generator wizard and vault manager `App` reducers directly against an
in-memory `ratatui::backend::TestBackend`, with no PTY and no ANSI parsing.

Setting `PARANOID_TUI_SCRIPT=<path>` before launching either TUI (the
generator wizard's `tui::run()` or the vault manager's `vault_tui::run()`,
including through `paranoid-passwd` and `paranoid-passwd vault`) activates
scripted mode: the app runs against a `TestBackend`, reads newline-delimited
key tokens from the script file, feeds them through the same `App::handle_key`
step function the real event loop uses, and on exit prints the final rendered
frame as plain text to stdout. Setting the variable also forces TUI launch
regardless of TTY auto-detection, since a script is by definition a
deliberate non-interactive drive.

Token grammar (one token per line, whitespace-trimmed):

- a single printable character — sent as its own literal `KeyCode::Char` key
  event (multi-character text is one character per line; there is no inline
  string literal)
- `<enter>`, `<esc>`, `<tab>`, `<backspace>`, `<up>`, `<down>` — the matching
  `KeyCode` variant
- `<ctrl-u>` — `KeyCode::Char('u')` with `KeyModifiers::CONTROL` (the
  custom-charset / form "clear field" shortcut)
- `<wait-idle>` — sends no key event; polls the app (worker and hardening
  polling) until any background worker thread has drained, up to a 10-second
  timeout, before continuing. Use it after an action that spawns a worker
  thread (for example launching the generator audit) before scripting further
  keys or ending the run.
- blank lines and lines starting with `#` are ignored

`crates/paranoid-cli/tests/tui_scripted.rs` covers both applications end to
end: a full generator wizard run from `Configure` through a completed audit to
the `Results` screen, and a vault init + add-login flow that unlocks a
tempdir-backed vault, drives the `Add Login` form by key events, and confirms
the item was actually persisted (not just reflected in-memory) by reopening
the vault afterward. Run them with:

```bash
cargo test -p paranoid-cli --locked --frozen --offline --test tui_scripted
```

`paranoid-vault` includes:

- vault init/unlock round trips
- CRUD coverage for `Login`, `SecureNote`, `Card`, and `Identity` items, including folder persistence, tag persistence, typed kind/folder/tag/query filtering, login password-history retention on rotation, and duplicate-password detection for login items
- wrong-password fail-closed coverage
- mnemonic recovery keyslot add/unlock coverage, including generated 24-word phrase shape and
  recovered 256-bit entropy checks
- mnemonic recovery keyslot rotation coverage, including fail-closed invalidation of the previous phrase
- multi-mnemonic-slot explicit-selection coverage
- mnemonic recovery fail-closed coverage for malformed phrase length, tampered keyslot metadata, and
  backup packages that omit the phrase and raw entropy
- device-bound keyslot add/unlock coverage, including missing provider material, tampered
  secure-storage material, wrong-length secure-storage material, removal cleanup, and same-device
  backup semantics that omit the provider secret
- multi-device-slot explicit-selection coverage
- certificate-wrapped keyslot add/unlock coverage, including explicit validation of supported
  algorithms, certificate metadata, and AES-GCM field shape before unwrap
- certificate-wrapped keyslot rewrap coverage, including persisted public metadata updates for fingerprint, subject, and validity, plus native session continuity when a live certificate-authenticated surface rewraps its active slot
- public certificate preview coverage for headless inspection before enrollment or rewrap
- headless keyslot-inspection parser coverage
- certificate keyslot health coverage for expired-recipient detection
- encrypted private-key certificate unlock coverage
- certificate backup coverage proving packages preserve the CMS-wrapped transport key and public
  metadata without exporting the private key or raw transport key
- password recovery-slot rotation coverage
- keyslot relabel persistence coverage
- recovery-posture summary coverage
- keyslot removal-impact analysis coverage
- non-recovery keyslot removal coverage
- device-bound keyslot rebind coverage
- generator-to-vault `generate-store` create and rotate coverage
- decrypted local summary filter coverage
- encrypted backup export/import round-trip coverage and backup-summary inspection coverage, including keyslot detail and certificate metadata
- encrypted transfer-package inspection and import coverage, including selective filters, certificate unwrap, and id remapping on conflict
- invalid-backup and tampered-ciphertext fail-closed coverage
- shared session-hardening coverage for clipboard auto-clear timing and idle-lock timing
- clipboard-history-exclusion hint coverage (`clipboard_hardening` module): proves the hardened copy path writes plain-text readable back, overwrites prior clipboard contents, and (macOS/Linux/Windows-specific) exercises each platform's `arboard` exclusion-hint builder; gated behind a real, addressable system clipboard and serialized against a process-local mutex since concurrent OS-clipboard access from multiple threads is unsafe on some platforms

`paranoid-gui` includes:

- shared generator request/result model coverage
- a checked-in Slint shell compiled by `build.rs` from `crates/paranoid-gui/ui/paranoid.slint`,
  with a focused Rust test that verifies the generated component bindings under locked,
  frozen, offline Cargo
- a comprehensive operator workflow test that crosses the generator and vault
  surfaces in one run, covering audit completion, vault CRUD, generate-and-rotate,
  keyslot navigation, mnemonic enrollment, backup export, and transfer export/import
- real widget-event tests (`make test-gui-widgets`, gated behind the `gui-widget-tests`
  Cargo feature) that drive the compiled `ParanoidPasswdShell` widget tree in-process
  through `i-slint-backend-testing` synthetic pointer/accessible-value events — typing
  into the real `LineEdit`s and clicking the real `Button`s — covering init-vault,
  add-login, generate-and-rotate, enroll-mnemonic, and export-backup against window
  property state, headless with no display server
- a real GUI-binary operator harness that launches the desktop app under Xvfb,
  drives the same native update path used by interactive controls, attests the
  workflow result to disk, and captures a rendered screenshot artifact
- a real GUI-binary per-screen visual-regression harness that captures one screenshot per named
  screen in the screen graph, for both a real vault pass and a decoy vault pass, and asserts the
  two passes' action-bar regions are pixel-identical
- vault refresh, CRUD, `SecureNote`, `Card`, `Identity`, folder, tag, password-history, duplicate-password visibility, structured filtering, generate-and-rotate, encrypted backup export/import, invalid backup restore fail-closed coverage, encrypted transfer export/import, invalid transfer import fail-closed coverage, and backup/transfer summary preview coverage
- native GUI keyslot inspection, mnemonic-slot rotation, certificate-slot rewrap, relabel, recovery-secret rotation, enrollment, posture-aware removal, device-slot rebind coverage, and active-session continuity after device rebind
- native GUI direct unlock coverage for recovery-secret, mnemonic, device-bound, and certificate-backed flows
- native GUI idle auto-lock coverage
- GUI launch-policy coverage for `--version` and `--help` without creating a window

The GUI crate permits Slint-generated Rust and exact Rust 2024 platform ABI export attributes to
lower the unsafe-code lint, but handwritten unsafe blocks, functions, and impls are still scanned by
`scripts/hallucination_check.sh`; security-sensitive crates remain under the workspace
`unsafe_code = "forbid"` lint.

## Docs

The docs site is part of the build:

```bash
python3 -m tox -e docs
python3 -m tox -e docs-linkcheck
```

That validates the docs tree, builds the Sphinx output under `docs/_build/html`, and checks outbound documentation links without coupling CI to the live Pages deployment.

## Release Validation

The local release path now has two explicit entry points:

```bash
make smoke-release
make release-emulate
```

- `make smoke-release` builds and smoke-tests the host-native CLI and GUI artifacts, including Linux `.deb` packages on Linux hosts, the GUI `.dmg` image on macOS hosts, and the GUI `.msi` installer on Windows hosts. DMG smoke validation mounts the image for layout inspection and stages the `.app` bundle before executable checks. MSI smoke validation uses Windows Installer administrative extraction before executable checks. Exit code 137 is retried with a bounded retry count to keep transient macOS process kills from weakening the release gate.
- `make release-emulate` drives the Linux release packaging path through the custom builder image, including `.deb` outputs.
- Linux GUI smoke validation now includes an Xvfb-backed screenshot capture of the packaged
  GUI window so the release path proves a real frame renders instead of only checking
  `--help`.
- `make test-gui-e2e` runs the actionable GUI workflow harness on Linux hosts, while
  `make test-gui-e2e-emulate` drives the same path through the custom builder image on macOS.
- `make test-gui-visual-regression` re-baselines the per-screen GUI screenshots (real + decoy
  passes) into `tests/baseline/gui/` on Linux hosts; `make test-gui-visual-regression-emulate` runs
  the same capture through the builder image on macOS.
- `scripts/release_validate.sh` is used in CI after the full matrix build to verify all CLI and GUI artifacts, Linux `.deb` packages, the Windows GUI `.msi`, package-manager manifests, and `install.sh`. Linux aggregation explicitly defers MSI payload extraction to the paired Windows published-release verifier.
- The release download verification matrix also includes the Windows GUI `.msi` as its own
  Windows-host asset so checksum, attestation, platform-signing, and administrative-extraction smoke
  checks are repeated outside the aggregate release-surface verifier.
- `make verify-branch-protection` checks that GitHub branch protection still matches the active Rust-native required checks.
