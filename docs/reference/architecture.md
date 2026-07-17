---
title: Architecture
---

# Architecture

`paranoid-passwd` now uses a Cargo workspace:

- `crates/paranoid-core`
- `crates/paranoid-audit`
- `crates/paranoid-ops`
- `crates/paranoid-seal`
- `crates/paranoid-cli`
- `crates/paranoid-gui`
- `crates/paranoid-vault`

The shared crate split is deliberate: security-sensitive generation and vault mechanics stay in the
core and vault crates, operation orchestration starts in `paranoid-ops`, seal lifecycle posture
starts in `paranoid-seal`, and structured evidence starts in `paranoid-audit` instead of UI-local
logging.

## Core

`paranoid-core` is the single source of truth for:

- charset resolution and validation
- OpenSSL-backed CSPRNG access
- rejection sampling
- constrained generation
- SHA-256 hashing
- chi-squared distribution checks via `statrs`
- serial correlation
- collision counting
- pattern detection
- compliance evaluation against the built-in `--framework` presets — see
  [Supported Compliance Frameworks](./compliance-frameworks.md)

The old raw-memory WASM result struct is gone. Application surfaces now pass typed Rust data structures between layers.
Future Slint WASM/mobile targets must keep that typed Rust boundary and cannot revive the retired JavaScript browser app.

The shared report model is split between:

- `GeneratedPassword` for per-password counts, pattern checks, hashes, and framework verdicts
- `AuditSummary` for batch-level chi-squared, serial correlation, collision, and entropy reporting

## CLI and TUI

`paranoid-passwd` is the primary user binary.

- On an interactive TTY with no mode-forcing or operational flags, it launches the TUI.
- In automation or with `--cli`, it keeps the scriptable stdout/stderr contract.
- That launch policy is treated as the standard product contract: default TUI, explicit or implied headless CLI when operational flags are present, dedicated GUI app when the GUI surface is launched.
- The TUI uses `ratatui` plus `crossterm` to keep the current three-step product flow.
- `paranoid-passwd vault` follows the same contract: interactive TTY with no vault subcommand opens the native vault TUI, explicit subcommands stay headless.
- The `vault` namespace adds encrypted local retention without changing the generator root behavior.
- Vault filtering is standardized across modes: `vault list --query ... --kind ... --folder ... --tag ...`, the vault TUI `/` filter editor, and the GUI vault filter controls all call the same typed decrypted local summary filter in `paranoid-vault`, including kind, folder, and tag metadata stored inside encrypted payloads.
- Duplicate-password detection for `Login` items is also standardized at the vault layer and surfaced consistently in CLI, TUI, and GUI views without adding new persisted state.
- The vault TUI and GUI now both include native keyslot inspection, recovery-posture reporting, mnemonic/device-bound/certificate enrollment flows, in-place mnemonic rotation, certificate rewrap, non-destructive keyslot relabeling, password recovery-secret rotation, selected non-recovery slot removal, and device-slot rebind operations. Certificate-backed slots now persist public lifecycle metadata such as subject and validity window so CLI, TUI, and GUI can surface rotation pressure without shelling out to external tooling. Both interactive surfaces support direct native unlock input for recovery-secret, mnemonic, device-slot, and certificate-backed access when shell env setup is unavailable, and all three native surfaces expose the same encrypted backup and selective transfer export/import model. CLI remains the headless administration surface for scripting and automation, not the sole vault-exchange surface.
- Certificate lifecycle admin is now standardized before mutation as well as after: CLI can preview a PEM with `inspect-certificate`, inspect a persisted slot with `inspect-keyslot`, and the TUI/GUI certificate enrollment and rewrap forms parse the candidate PEM and show public metadata before changing vault state.
- Certificate lifecycle interpretation is also centralized now: `paranoid-vault` computes shared health warnings for not-yet-valid, expired, or near-expiry certificate slots, and the CLI/TUI/GUI consume that same assessment instead of inventing UI-local rules.
- Backup administration is standardized across surfaces as well: the engine now exposes a typed backup summary over item-kind counts, keyslot posture, and format compatibility; CLI exposes that via `vault inspect-backup`, and the TUI/GUI import-export screens render the same summary before restore. Separate item-level transfer packages use the same engine model and are now available across CLI, TUI, and GUI, while still remaining distinct from full-vault restore flows because they carry selected decrypted item payloads under fresh unwrap material instead of the source vault header and ciphertext rows.
- Keyslot removal policy is now standardized across surfaces: `VaultHeader::assess_keyslot_removal()` computes the same before/after posture and warning set for CLI, TUI, and GUI; headless removal requires `--force` for posture-downgrading removals, while TUI and GUI arm a native confirmation step before proceeding.
- Native interactive surfaces share a small session-hardening layer from `paranoid-vault`: copied secrets are cleared from the clipboard after 30 seconds if unchanged, and unlocked vault views auto-lock after 5 minutes of inactivity while clearing cached decrypted state. Every copy also sets a platform clipboard-history-exclusion hint via `paranoid_vault::set_clipboard_text_excluded` (`org.nspasteboard.ConcealedType` on macOS, `x-kde-passwordManagerHint` on Linux, `ExcludeClipboardContentFromMonitorProcessing` on Windows) so cooperating history managers never store the secret; see `docs/guides/tui.md` for the per-platform table and its honest limit (a non-cooperating history manager still captures it — the timed clear remains the real backstop).
- CLI and GUI process startup both call `paranoid_vault::harden_process_memory()` (`crates/paranoid-vault/src/mem_hardening.rs`), which disables core dumps (`setrlimit(RLIMIT_CORE, {0, 0})` on Linux/macOS) and denies same-user debugger/crash-dump attachment (`prctl(PR_SET_DUMPABLE, 0)` on Linux, `ptrace(PT_DENY_ATTACH)` on macOS, `WerSetFlags(..NOHEAP)` on Windows). The vault master key and the Argon2id-derived KEK are held in `LockedSecretBuffer`, which `mlock`s its backing pages on construction (Linux/macOS) so the kernel never swaps or hibernates them to disk, and `munlock`s plus zeroizes them on drop. Every primitive is warn-and-continue: a sandboxed environment that refuses `mlock`/`prctl`/`setrlimit` still runs, with the outcome recorded in a `ProcessHardeningReport`/`HardeningOutcome` rather than silently ignored. This does not stop a root/Administrator-level attacker or a kernel-level memory dump; it closes the same-user core-dump/ptrace/swap exposure that KeePassXC, Bitwarden, and GnuPG treat the same way.

## Ops, Audit, and Seal Lifecycle

The ops/audit layer is now a typed local control plane, not UI-local logging. CLI `--json` runs
through `paranoid-ops`, returns a stable operation report, and carries `paranoid-audit` events with
an operation id shared by every event in the report. Current operation ids are process-local
correlation identifiers, not authentication tokens or cryptographic nonces.

`paranoid-ops` owns:

- command envelopes with request ids, actor context, session surface, transport, profile, and
  command identity
- authenticated mTLS transport evidence for commands that cross a process boundary, including
  non-secret peer identity, certificate fingerprint, channel-binding, and warning evidence
- an OpenSSL-backed mTLS JSONL command transport that accepts typed command envelopes across a
  process boundary, replaces client-supplied transport claims with server-observed peer-certificate
  evidence, and returns the same typed command trace used by local adapters. This transport lives
  behind the `mtls-transport` Cargo feature on `paranoid-ops` (default off): CLI, TUI, and GUI ship
  without it because none of them cross a process boundary today, and it stays out of the default
  dependency graph rather than shipping as dead public API. Its integration tests
  (`crates/paranoid-ops/tests/mtls_transport.rs`) run under `make test`/`make ci` via
  `make test-ops-mtls-transport`, which invokes
  `bash scripts/cargo_test.sh -p paranoid-ops --locked --frozen --offline --features mtls-transport`
  so the transport keeps full coverage without adding runtime surface to a shipped binary. The
  intended consumer is a future remote-ops surface: a headless agent or service endpoint that
  accepts typed `OpsCommandEnvelope`s over mTLS from a separately authenticated operator or
  automation client, for deployments where the vault or generator must be operated from outside the
  local process (for example a federal-ready fleet-management or assessor tooling integration).
  Wiring a concrete binary target onto `OpsMtlsServer`/`OpsMtlsClient` happens when that consumer
  ships; until then the feature keeps the transport building, tested, and reviewable without
  pretending it is already load-bearing production surface.
- fail-closed profile validation so externally supplied envelopes cannot downgrade the
  authoritative `OpsPolicyContext`
- an explicit `allow`, `challenge`, and `deny` policy decision model
- federal-ready startup evidence over build id, platform, audit schema, configured audit-sink
  health, and OpenSSL provider evidence
- a fail-closed federal policy that requires an audit sink and confirmed approved-provider evidence
  before security-relevant operations can run
- request/response audit event helpers so every command that reaches policy evaluation can be
  paired by request id

`paranoid-seal` owns:

- a vault seal state machine covering `sealed`, `challenge_pending`, `unsealed`,
  `idle_lock_pending`, `sealed_after_timeout`, and `recovery_required`
- non-secret seal provider evidence for password recovery, mnemonic recovery, device-bound,
  certificate-wrapped, and future external auto-unseal paths
- a seal posture report that distinguishes configured auto-unseal from confirmed provider
  availability

This is challenge/response in the security sense, not prompt-engineering in the LLM sense. Sensitive
operations declare the command, surface, profile, and preconditions; policy returns a typed
challenge when fresh proof is required, or a typed denial when controls are missing.

`paranoid-audit` owns:

- structured audit events with per-operation sequence ids
- append-only JSONL file sinks through `--audit-jsonl`
- JSONL sink health evidence covering configured, writable, unavailable, and not-configured states
- external audit-device probe boundaries, including TCP reachability evidence that remains
  `unverified` and an mTLS JSONL write-ack probe that requires a matching challenge before `ready`
- stable typed ops trace fixtures for CLI, TUI, GUI, and mTLS process-boundary vault operation
  automation
- strict redaction markers for sensitive attributes
- SHA-256 hash-chain evidence generated through the `paranoid-core` OpenSSL-backed hash path
- fail-closed integration when a required audit sink is unavailable

Audit events are evidence metadata only. They must not contain plaintext passwords, recovery
phrases, private keys, or unwrapped vault material. Generated passwords remain in the typed
generation report and are not copied into audit messages or attributes.

The CLI exposes the first automation surface:

- `--audit-jsonl PATH` appends policy and operation audit events to a JSONL sink after the path
  passes a local writable health check
- `--require-audit-sink` fails closed unless the sink is writable
- `--profile federal-ready` and `--federal-ready` enforce the federal-ready startup policy
- `--federal-evidence` emits assessor-readable startup evidence as JSON
- `--detect-environment` emits first-run capability evidence as JSON: OS keychain (`keyring`) and
  clipboard (`arboard`) availability, display server detection, and configured seal-provider
  evidence reused from `vault seal-status`
- `vault --audit-jsonl PATH <subcommand>` wraps headless vault subcommands in typed ops
  request/response audit events
- `vault seal-status` reports the local vault seal posture without decrypting item payloads
- `vault seal-status --probe-providers` performs explicit provider availability checks before
  marking an auto-unseal provider available; device-bound probes verify the secure-storage unwrap
  material against the keyslot check blob without decrypting vault items
- `vault federal-evidence` emits the same federal startup evidence from the vault namespace

The native TUI and GUI now evaluate local vault actions through the same typed ops protocol before
calling `paranoid-vault`, and their tests record non-secret request/response policy events for read,
mutate, keyslot, and export flows. TUI launches inherit `vault --audit-jsonl` / `--require-audit-sink`
policy, and the GUI exposes the same durable local JSONL sink controls for deterministic automation.
The mTLS process-boundary path now has a live JSONL command transport in `paranoid-ops`; the server
side evaluates the received envelope only after binding the session to the observed mTLS peer
certificate, not to client-asserted evidence. The seal-provider health path now distinguishes
metadata-only posture from explicit provider probes: configured device-bound slots remain
`configured` until a probe verifies secure-storage availability, and only then can posture claim
`auto_unseal_available=true`. Ops policy consumes the same posture with method-specific checks:
mnemonic unlock requires mnemonic provider evidence, device-bound unlock requires an available
device-bound provider rather than generic auto-unseal availability, and certificate unlock requires
certificate provider evidence. The remaining implementation work is broader PTY coverage over those
same command envelopes and release-grade packaging evidence.

The seal model stays local-first but borrows the operational shape of Vault: a sealed vault can read
metadata needed to decide how to unlock, but it cannot decrypt stored item payloads. Auto-unseal
providers are convenience paths for retrieving unwrap material under policy; they do not remove the
need for recovery coverage. If a seal provider is rotated, disabled, or becomes unavailable, the ops
and seal layers should expose that as posture and state, and the vault layer should only perform
rewraps through typed, audited operations. The ops policy context now accepts non-secret seal
posture evidence: federal certificate unlock requires that posture to be present, and device-bound
unlock fails closed without seal posture evidence or confirmed device-bound provider availability.

This split keeps the trust boundaries narrow:

- `paranoid-core` remains responsible for generation, hashing, audit math, and compliance checks.
- `paranoid-vault` remains responsible for encrypted storage, keyslots, and unwrap/rewrap
  mechanics.
- `paranoid-ops` becomes the command, policy, and automation boundary.
- `paranoid-seal` becomes the vault seal-state and auto-unseal posture boundary.
- `paranoid-audit` becomes the durable security-event boundary.
- CLI, TUI, and GUI become presentation adapters over the shared protocol.

This same split is the path toward a federal-ready profile. FedRAMP High, GovCloud, and DoD IL5
customers need evidence and enforceable operating modes, not UI-local logging. The ops/audit crates
should therefore emit stable JSON/JSONL evidence, support SIEM ingestion, report external
audit-device posture without overstating health, prove required audit sinks are healthy, separate
TCP reachability from durable audit ingestion, and expose FIPS-provider and policy-profile evidence
without claiming authorization for an unassessed boundary.
See [Federal Readiness](./federal-readiness.md).

## GUI

`paranoid-passwd-gui` is the dedicated GUI surface. The project is now Slint-native under the GPLv3
licensing path, and it shares the same core request/result model, native vault `Login`,
`SecureNote`, `Card`, and `Identity` CRUD/filter flows plus
folder-plus-tag organization, login password-history visibility, duplicate-password visibility,
native keyslot management, recovery-posture reporting, direct native unlock, encrypted backup
export/import, clipboard auto-clear, and vault idle auto-lock.

The checked-in Slint surface lives under `crates/paranoid-gui/ui/` and is compiled by the GUI crate
build script. Desktop remains the primary release target. Android and WASM are now explicit local
build-chain targets through `make configure`, `make test-gui-android-check`, and
`make test-gui-wasm-check`. Android compile-checks through the configured NDK with the native
`paranoid-core` and `paranoid-vault` crates linked. WASM compile-checks a gated non-secret Slint
surface that does not link the native vault or generator crates; storage, crypto, release packaging,
and runtime validation for `wasm32-unknown-unknown` remain separate threat-model work and cannot
revive JavaScript secret-handling logic or the retired DOM app.

`crates/paranoid-gui` uses a crate-local `unsafe_code = "deny"` lint instead of the workspace
`forbid` because Slint's generated Rust and Rust 2024 platform ABI export attributes need to lower
that lint internally. The handwritten GUI sources are still checked by
`scripts/hallucination_check.sh`; only exact `#[unsafe(no_mangle)]` ABI attributes are allowed
there, and all security-sensitive crates retain the workspace `forbid` policy.

`wire_callbacks()` in `crates/paranoid-gui/src/lib.rs` binds the Slint UI's `callback` declarations
to native Rust handlers. The desktop (`#[cfg(not(target_arch = "wasm32"))]`) build wires each
callback to a real vault/generator operation; the WASM (`#[cfg(target_arch = "wasm32")]`) build
wires the same callback names to gated no-op handlers that surface the compile-checked-only
message instead of touching secrets. Both builds wire the same callback set:

- `on_run_audit` — runs the compliance-framework audit for the current length/count/framework selection
- `on_init_vault` — creates a new vault at the given path with the given recovery secret
- `on_unlock_vault` — unlocks an existing vault for the session
- `on_add_login` — adds a new `Login` item to the unlocked vault
- `on_generate_rotate` — generates a password and either stores a new login or rotates an existing one in place
- `on_enroll_mnemonic` — adds a mnemonic recovery keyslot to the unlocked vault
- `on_export_backup` — writes an encrypted vault backup to the given output path
- `on_copy_primary` — copies the primary generated/stored secret to the clipboard with auto-clear
- `on_lock_vault` — panic / quick-lock (P9.6): drops the cached unlocked-vault handle and scrubs every secret/decrypted-derived `GuiState` field; wired to both the "Lock vault" button and the window-level `Control+L` accelerator (`docs/guides/tui.md#panic--quick-lock-hotkey`)

Every named widget in `crates/paranoid-gui/ui/paranoid.slint` (every `LineEdit` input and
`Button`) is directly addressable by real widget-event tests: `make test-gui-widgets` links the
compiled `ParanoidPasswdShell` widget tree into a `paranoid-gui` test binary and drives it through
`i-slint-backend-testing`'s synthetic pointer/accessible-value events — the init-vault,
add-login, generate-and-rotate, enroll-mnemonic, and export-backup flows are each exercised
through the real inputs and the real `clicked` callbacks, asserting on window property state
rather than the `PARANOID_GUI_AUTOMATION_*` side-channel. See
[Real Widget-Event Tests](./testing.md#real-widget-event-tests) for the mechanism and coverage
list.

## Local Vault

`paranoid-vault` is the encrypted local vault crate boundary.

- SQLite is the explicit vault file format, not a temporary backend choice.
- The vault stays local-device only and uses rollback-journal SQLite rather than a persistent WAL profile.
- A random master key encrypts vault items.
- Keyslots unwrap that master key:
  - `password_recovery` is the current recovery path
  - `mnemonic_recovery` is the current wallet-style recovery phrase path
  - `certificate_wrapped` is the current certificate-based unwrap path
  - `device_bound` is the current passwordless local-unlock path via platform secure storage
- Argon2id derives the recovery KEK.
- BIP39 encodes vault-generated 256-bit recovery entropy as a 24-word phrase for mnemonic recovery slots.
- OpenSSL-backed AES-256-GCM encrypts item payloads.
- OpenSSL CMS envelope encryption wraps the master key for certificate slots.
- Device-bound slots store the unwrap secret in OS secure storage and keep only verification metadata in SQLite; the unlock path requires an exact 256-bit secure-storage value to satisfy the AES-GCM check blob, and backup packages do not export that provider secret.
- Keyslot lifecycle operations are now part of the native product surface: mnemonic recovery slots can be rotated in place to a replacement phrase without changing the slot id, certificate-wrapped slots can be rewrapped in place to a replacement recipient certificate, the native TUI/GUI rewrap flows can optionally update the active certificate key path and passphrase when the live session is using that slot, keyslot labels can be updated in place, the password recovery slot can be rewrapped in place, non-recovery slots can be removed, device-bound slots can be rebound to a fresh secure-storage account, and the unlock layer keeps explicit slot selection stable when multiple device or mnemonic slots exist.
- `VaultHeader::recovery_posture()` gives every surface the same policy view over whether the vault currently has recovery coverage, certificate coverage, and the recommended combination of both.
- `VaultHeader::recovery_recommendations()` and `VaultHeader::assess_keyslot_removal()` extend that into actionable policy: the product can now tell the operator what coverage is still missing and when a keyslot removal would weaken the vault’s access posture.
- The current item model supports `Login`, `SecureNote`, `Card`, and `Identity` entries, CRUD operations, folder-plus-tag metadata, encrypted password history for `Login` items, duplicate-password detection across unlocked `Login` items, generate-and-store flows for `Login` that can either create a new item or rotate an existing login in place, encrypted backup export/import, and native vault TUI/GUI surfaces with unlocked local filtering.
- `VaultBackupPackage` remains the portable encrypted backup format, and `VaultBackupSummary` is the read-only inspection model used to preview recovery packages before import.
- `VaultTransferPackage` is now the separate portable encrypted item-exchange format. It carries selected decrypted item payloads under a fresh AES-256-GCM data key, and that data key can be wrapped by a recovery secret, a recipient certificate, or both. Import happens into an already unlocked local vault and can remap conflicting ids safely instead of overwriting by default.
- Decrypted item payload secrets (login passwords, password-history entries, card numbers, card security codes, and their `New*`/`Update*` mirrors) are the `SecretBytes` zeroize-on-drop wrapper, not plain `String`: `{:?}` renders `<redacted>`, every clone owns an independent zeroizing buffer, and the wrapper's `Serialize`/`Deserialize` is transparent so the on-disk vault item format is unchanged.
- Failed unlock attempts are throttled by a durable, path-bound lockout record (`<vault-file-name>.lock-state`, a plaintext sibling of the vault file, never inside the AEAD-encrypted `items` rows) that survives process restart: `unlock_vault`, `unlock_vault_with_certificate`, `unlock_vault_with_mnemonic`, and `unlock_vault_with_device` all check it before running Argon2id and refuse with `VaultError::LockedOut` while a lockout is in force, record a failed attempt with exponential backoff (capped) on any credential failure, and clear the record on a successful unlock.

See [Vault Format](./vault-format.md) for the storage-engine decision and on-disk layout.

## Public Website

The public website is documentation only. GitHub Pages publishes the repository `docs/` tree, including:

- installation instructions
- TUI walkthrough
- architecture and testing notes
- release verification guidance
- generated Rust API docs via `sphinx-rust`

## Release Path

Release packaging is driven by checked-in scripts instead of workflow-only shell:

- `scripts/build_release_artifact.sh`
- `scripts/smoke_test_release_artifact.sh`
- `scripts/release_validate.sh`

Linux release builds run inside the repository-owned builder action. Native macOS and Windows archives use the same repo-owned packaging and smoke-test scripts on platform runners. Linux now also emits `.deb` packages through the same checked-in packaging scripts instead of a separate external packaging pipeline.

The release surface now includes both:

- `paranoid-passwd` for CLI/TUI and headless automation
- `paranoid-passwd-gui` for the dedicated desktop app surface

`install.sh` and package-manager publication remain intentionally scoped to the CLI/TUI artifact.
