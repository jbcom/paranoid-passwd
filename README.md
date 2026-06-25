---
title: paranoid-passwd
updated: 2026-04-15
status: current
domain: product
---

# paranoid-passwd

## Local Secrets. Verifiable Trust.

`paranoid-passwd` is a **Rust-native password manager and generator** for people who want
their secrets to stay local and their security story to be inspectable.

It gives you:

- a scriptable password generator CLI
- a full-screen terminal wizard
- a dedicated Slint-native desktop GUI
- an encrypted local vault for `Login`, `SecureNote`, `Card`, and `Identity` records
- explicit recovery paths through recovery secrets, mnemonic slots, device-bound unlock,
  and certificate-wrapped keyslots
- verifiable release artifacts, checksums, attestations, and repo-owned validation scripts

The mission is simple: keep secrets out of unnecessary runtimes, make recovery visible before
it fails, and make the release pipeline something operators can verify. The old interactive
HTML/CSS/JavaScript GitHub Pages app is retired. `paranoid-passwd.com` now serves documentation,
installation instructions, and release links. Future Slint WASM or mobile artifacts must stay
Rust/Slint-native and pass their own threat model before they become a supported product surface.

Launch behavior is standardized:

- `paranoid-passwd` defaults to the TUI on an interactive terminal with no operational flags
- `paranoid-passwd` stays headless when generation or vault flags are passed, or when stdin/stdout are not interactive
- `paranoid-passwd vault` defaults to a native vault CRUD TUI on an interactive terminal when no explicit vault subcommand is passed
- `paranoid-passwd-gui` is the dedicated native app surface and ships as a separate direct-download artifact, with macOS shipping both direct archives and native `.dmg` disk images, and Linux shipping both direct archives and `.deb` packages with desktop metadata

## Workspace

- [`crates/paranoid-core`](crates/paranoid-core/src/lib.rs)
- [`crates/paranoid-audit`](crates/paranoid-audit/src/lib.rs)
- [`crates/paranoid-ops`](crates/paranoid-ops/src/lib.rs)
- [`crates/paranoid-seal`](crates/paranoid-seal/src/lib.rs)
- [`crates/paranoid-cli`](crates/paranoid-cli/src/main.rs)
- [`crates/paranoid-gui`](crates/paranoid-gui/src/main.rs)
- [`crates/paranoid-vault`](crates/paranoid-vault/src/lib.rs)

`paranoid-core` owns generation, rejection sampling, OpenSSL-backed RNG and hashing, statistical audit math, pattern detection, and compliance checks. `paranoid-ops` is the typed operation boundary for automation-facing workflows, `paranoid-seal` owns vault seal state and non-secret provider posture, and `paranoid-audit` owns redacted structured audit events. The CLI, TUI, GUI, and vault flows consume typed Rust results instead of the old raw-memory WASM bridge.

## Quick Start

Interactive:

```bash
cargo run -p paranoid-cli
```

Scriptable CLI:

```bash
cargo run -p paranoid-cli -- --cli --length 24 --count 3 --framework nist,pci_dss
```

Structured automation report:

```bash
cargo run -p paranoid-cli -- --cli --json --length 24 --count 1 --framework nist
```

Structured audit evidence:

```bash
cargo run -p paranoid-cli -- --cli --json --audit-jsonl audit.jsonl --length 24 --framework nist
cargo run -p paranoid-cli -- --federal-evidence
cargo run -p paranoid-cli -- --cli --federal-ready --audit-jsonl audit.jsonl --length 24
```

`--audit-jsonl` and `--federal-ready` fail closed unless a required audit sink has explicit ready
health. Federal-ready evidence reports both local JSONL health and configured external audit-device
posture. `PARANOID_AUDIT_DEVICE_PROBE=tcp-connect` can add live endpoint reachability evidence, but
reachability is still not treated as ready audit ingestion. `PARANOID_AUDIT_DEVICE_PROBE=mtls-jsonl-ack`
uses the configured mTLS certificate, key, and CA paths to send a versioned JSONL challenge and
reports `ready` only when the endpoint returns a matching schema, probe, challenge, and
`status=ready` acknowledgement. Federal-ready mode also requires runtime evidence confirming an
approved cryptographic provider mode. The default vendored OpenSSL build reports provider evidence
but does not claim approved mode.

Local vault:

```bash
export PARANOID_MASTER_PASSWORD='correct horse battery staple'
cargo run -p paranoid-cli -- vault init
cargo run -p paranoid-cli -- vault seal-status
cargo run -p paranoid-cli -- vault seal-status --probe-providers
cargo run -p paranoid-cli -- vault federal-evidence
cargo run -p paranoid-cli -- vault --audit-jsonl vault-audit.jsonl keyslots
cargo run -p paranoid-cli -- vault generate-store --title GitHub --username jon@example.com --length 24
cargo run -p paranoid-cli -- vault keyslots
cargo run -p paranoid-cli -- vault inspect-keyslot --id device-0123456789abcdef
cargo run -p paranoid-cli -- vault inspect-certificate --cert recipient-cert.pem
cargo run -p paranoid-cli -- vault add-mnemonic-slot --label paper-backup
cargo run -p paranoid-cli -- vault rotate-mnemonic-slot --id mnemonic-0123456789abcdef
cargo run -p paranoid-cli -- vault add-device-slot --label daily
cargo run -p paranoid-cli -- vault add-cert-slot --cert recipient-cert.pem --label laptop
cargo run -p paranoid-cli -- vault rewrap-cert-slot --id cert-0123456789abcdef --cert recipient-cert-next.pem
cargo run -p paranoid-cli -- vault rename-keyslot --id device-0123456789abcdef --label laptop-daily
cargo run -p paranoid-cli -- vault rotate-recovery-secret --new-password-env PARANOID_NEXT_MASTER_PASSWORD
cargo run -p paranoid-cli -- vault rebind-device-slot --id device-0123456789abcdef
cargo run -p paranoid-cli -- vault remove-keyslot --id cert-0123456789abcdef --force
cargo run -p paranoid-cli -- vault add-note --title "API seed" --content "Rotate after migration cutover." --folder Recovery --tags recovery,ops
cargo run -p paranoid-cli -- vault add --title GitHub --username jon@example.com --password 'Sup3r$ecret!' --folder Work --tags work,code
cargo run -p paranoid-cli -- vault generate-store --id login-0123456789abcdef --length 24 --framework nist
cargo run -p paranoid-cli -- vault        # interactive vault CRUD view
cargo run -p paranoid-cli -- vault export-backup --output ./vault.backup.json
cargo run -p paranoid-cli -- vault inspect-backup --input ./vault.backup.json
cargo run -p paranoid-cli -- vault import-backup --input ./vault.backup.json --force
cargo run -p paranoid-cli -- vault export-transfer --output ./work-logins.ppvt.json --kind login --folder Work --package-password-env PARANOID_TRANSFER_PASSWORD --package-cert recipient-cert.pem
cargo run -p paranoid-cli -- vault inspect-transfer --input ./work-logins.ppvt.json
cargo run -p paranoid-cli -- vault import-transfer --input ./work-logins.ppvt.json --package-password-env PARANOID_TRANSFER_PASSWORD
cargo run -p paranoid-cli -- vault --recovery-phrase-env PARANOID_RECOVERY_PHRASE list
cargo run -p paranoid-cli -- vault list   # falls back to the sole device slot if PARANOID_MASTER_PASSWORD is unset
cargo run -p paranoid-cli -- vault list --query octo
cargo run -p paranoid-cli -- vault list --kind login --folder Work --tag code
cargo run -p paranoid-cli -- vault --device-slot device-0123456789abcdef list
cargo run -p paranoid-cli -- vault --cert recipient-cert.pem --key recipient-key.pem list
```

Docs site:

```bash
python3 -m tox -e docs
open docs/_build/html/index.html
```

## Build and Test

```bash
make configure
make build
make test
make lint
make verify-assurance
make docs-build
make smoke-release
```

`make configure` writes `.config/paranoid-local.mk` and `.config/paranoid-local.env` with the
detected local Rust, Android SDK/NDK, WASM, Docker, Xvfb, adb, emulator, and Maestro paths. All
Cargo commands use the vendored dependency tree through `.cargo/config.toml`.

Target-gated GUI checks are explicit:

```bash
make test-gui-host-check
make test-gui-android-check
make test-gui-wasm-check
make test-gui-e2e-emulate
```

The Android check is a strict Slint GUI library compile through the configured NDK and keeps the
native `paranoid-core`/`paranoid-vault` path linked. The WASM check is strict too, but intentionally
compiles only a gated non-secret Slint surface; native vault and generator operations are disabled
there until storage and crypto are threat-modeled for `wasm32-unknown-unknown`.

To emulate the repository CI flow through the custom builder image:

```bash
make ci-emulate
```

To exercise the release packaging path:

```bash
make smoke-release
make release-emulate
make verify-published-release TAG=paranoid-passwd-v3.7.0
```

## Releases

Release archives are published on [GitHub Releases](https://github.com/jbcom/paranoid-passwd/releases). The docs site also hosts:

- [`https://paranoid-passwd.com/install.sh`](https://paranoid-passwd.com/install.sh)
- install and verification guides
- generated Rust API docs via `sphinxcontrib-rust`

The shipped release surface now has two native binaries, each published through direct archives, with Linux also shipping `.deb` packages for both:

- `paranoid-passwd`, which contains the scriptable CLI, the generator wizard TUI, and the native vault TUI with `Login`, `SecureNote`, `Card`, and `Identity` CRUD, folder-plus-tag local organization, encrypted password history for login rotation, duplicate-password detection for login items, native keyslot inspection, recovery-posture reporting, enrollment, certificate rewrap, relabeling, recovery-secret rotation, removal, and device-slot rebind, direct native unlock input for recovery-secret, mnemonic, device-slot, and certificate-backed access, encrypted backup export/import flows, and generate-and-store flows that can either create a new login or rotate an existing one in place
- `paranoid-passwd-gui`, which ships the dedicated desktop surface over the same generator and vault model, including native keyslot management, backup inspection/import, and the full local vault CRUD flow

`install.sh` and package-manager flows remain intentionally focused on `paranoid-passwd`. The GUI is distributed as direct archives, native macOS `.dmg` images, and Linux `.deb` packages until native installer work is complete on every platform.

## License

`paranoid-passwd` is licensed under the GNU General Public License v3.0 only
(`GPL-3.0-only`). This keeps the product open source under a reciprocal license
and permits using Slint under Slint's GPLv3 open-source licensing path. The GUI
surface is Slint-native.

## Security Posture

- RNG is delegated to OpenSSL through Rust bindings.
- Hashing uses OpenSSL-backed SHA-256.
- Rejection sampling still uses the critical boundary `(256 / N) * N - 1`.
- Chi-squared tail probabilities use `statrs` instead of the old handwritten approximation.
- Vault encryption uses Argon2id plus OpenSSL-backed AES-256-GCM.
- Vault storage is standardized on a local SQLite file with application-layer encryption and multiple master-key keyslots for password recovery, wallet-style mnemonic recovery, device-bound unlock, and certificate wrapping.
- Vault filtering is standardized across CLI, TUI, and GUI through the same typed filter model, including free-text query plus explicit `kind`, `folder`, and `tag` filters over decrypted local summaries.
- Native surfaces now expose the current recovery posture directly so it is visible when a vault still lacks certificate coverage or has not enrolled additional recovery paths beyond the required password slot.
- `vault keyslots` now emits explicit recovery recommendations when the vault still lacks mnemonic, device-bound, or certificate coverage.
- `vault inspect-keyslot --id ...` now exposes the full headless keyslot detail view, including removal impact and cert/device/mnemonic metadata, so recovery admin no longer depends on the native UI.
- Certificate-backed keyslots now have shared health assessment in the vault engine. CLI/TUI/GUI surface the same warnings for not-yet-valid, expired, or near-expiry recipient certs instead of leaving lifecycle pressure implicit.
- Certificate-wrapped slots can now be rewrapped in place to a replacement recipient certificate through `rewrap-cert-slot`, and the native TUI/GUI rewrap flows can optionally update the active certificate key path and passphrase at the same time so a live certificate-authenticated session does not retain stale unlock material after rotation.
- Certificate enrollment and rewrap now support native preview: CLI exposes `inspect-certificate`, and the TUI/GUI cert forms parse the PEM path and show fingerprint, subject, and validity before writing a new slot or rewrapping an existing one.
- Mnemonic recovery slots can now be rotated in place without changing the keyslot id or label. The headless CLI exposes `rotate-mnemonic-slot --id ...`, and the TUI/GUI require an explicit native confirmation before showing the replacement phrase once.
- Keyslot labels are now maintainable without destructive re-enrollment: CLI exposes `rename-keyslot`, and the TUI/GUI keyslot views expose the same relabel flow natively.
- Headless keyslot removal now requires `--force` when removing a slot would weaken certificate coverage, wallet-style recovery, or passwordless daily unlock; the TUI and GUI mirror that with native two-step confirmation.
- The password recovery slot can be rewrapped in place through `rotate-recovery-secret` without invalidating mnemonic, device-bound, or certificate slots.
- Backup export/import serializes the same encrypted vault header and ciphertext rows into a portable JSON package instead of inventing a second crypto format.
- Backup inspection is now a first-class read-only flow: CLI, TUI, and GUI can summarize a backup package before restore, including item counts, keyslot posture, the first keyslot details and certificate lifecycle metadata, and whether the current build can restore it directly.
- Encrypted transfer packages are now a distinct exchange path for selected vault items across CLI, TUI, and GUI. `export-transfer` encrypts decrypted item payloads under a fresh data key that can be unwrapped by a recovery secret, a certificate recipient, or both; `import-transfer` brings those items into an already unlocked vault while either preserving ids, replacing matching ids, or remapping conflicts safely.
- Native interactive surfaces now auto-clear copied secrets from the clipboard after 30 seconds if the clipboard contents are unchanged.
- Native interactive vault surfaces now auto-lock after 5 minutes of inactivity and clear cached decrypted state before returning to the unlock screen.
- The crypto disposition surface is mapped to explicit assurance claims in
  `docs/reference/assurance-claims.md`, and `scripts/verify_ai_review_inventory.sh`
  proves there are no untracked source `TODO: AI_REVIEW` markers.
- Cargo dependencies are vendored and CI runs Cargo in locked, frozen, offline mode.
- Security verification scripts assert the Rust-native invariants, workflow pinning, and
  security assurance protocol wiring.
- The retired browser/JavaScript runtime path is gone from the product surface.
- Slint WASM and mobile targets are allowed only as explicit Rust/Slint surfaces with
  separate threat models, release gates, and no JavaScript secret-handling logic.

The closed in-repo assurance claims are not external cryptographic approval. They are explicit
release claims with deterministic gates, written evidence, and no hidden trust in an LLM author.
