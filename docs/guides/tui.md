---
title: TUI Guide
---

# TUI Guide

The TUI is the default terminal experience for the native generator. It keeps the product
flow direct:

1. Configure
2. Generate & Audit
3. Results

## Configure

The left column exposes the generation inputs:

- password length
- password count
- audit batch size
- lowercase / uppercase / digits / symbols toggles
- extended printable ASCII toggle
- ambiguous-character exclusion
- compliance framework selection
- minimum lowercase / uppercase / digit / symbol requirements
- custom charset override

The right column shows the current validation state, effective charset size, and framework constraints.

## Render Capture

The TUI keeps the same branded three-step flow, but it now runs entirely on the native Rust core. A typical configure screen looks like this:

```text
paranoid-passwd · Configure
Configure the local generator and audit before any password is shown.

Wizard                                  Audit Preview
› Password length: 32                  Mission  local secrets, verifiable trust.
  Number of passwords: 1
  Audit batch size: 500                Effective charset: 72 characters
  Lowercase [a-z]: ON                  Manual requirements: 4 total constrained characters
  Uppercase [A-Z]: ON                  Frameworks: nist, pci_dss
  Digits [0-9]: ON
  Symbols: ON                          Ready: 72 chars, 1 passwords, 197.18 bits of entropy...
  ...                                  Controls: Up/Down move, Left/Right adjust, Enter run
```

The results screen keeps the generator-wide audit separate from per-password verdicts:

```text
paranoid-passwd · Results
Native generation complete. Review the verdict and derived details.

Primary Password
••••••••••••••••••••••••q7$A
SHA-256: <hex>
Additional passwords: 2
Verdict: PASS
```

## Controls

- `↑ / ↓`: move between fields
- `← / →`: adjust values
- `Space`: toggle the current boolean or framework
- `Enter`: edit the custom charset or start the audit
- `q`: quit

On the results screen:

- `← / →`: switch detail tabs
- `c`: copy the generated password to the system clipboard
- `r`: return to configuration
- `q`: quit

Clipboard copies from the generator and vault views are cleared automatically after 30 seconds if the clipboard contents have not changed.

Every secret copy also sets the platform clipboard-history-exclusion hint alongside the timed clear, so a *cooperating* history manager never stores it in the first place:

| Platform | Hint set | Honored by |
|---|---|---|
| macOS | `org.nspasteboard.ConcealedType` (the [nspasteboard.org](http://nspasteboard.org/) community convention) | Maccy, Alfred, Raycast, and other nspasteboard-aware clipboard managers |
| Linux (X11 and Wayland) | `x-kde-passwordManagerHint` MIME type set to `secret` | KDE Klipper and other cooperating managers that check the same convention |
| Windows | `ExcludeClipboardContentFromMonitorProcessing` clipboard format | Windows Clipboard History (Win+V) and cloud clipboard sync |

This is a hint, not an OS-enforced control: a history manager that does not check for it — an older Klipper version, a non-cooperating third-party tool, or anything that polls the clipboard directly instead of reading the documented API — still records the secret. The 30-second timed clear above is the actual backstop for every clipboard consumer, cooperating or not; the exclusion hint only reduces exposure to tools that respect it.

## Audit Model

The audit still runs seven layers:

1. password generation
2. chi-squared uniformity
3. serial correlation
4. collision detection
5. entropy and uniqueness proofs
6. pattern detection
7. threat assessment / compliance roll-up

The TUI shows stage progression in real time while the background worker runs the native Rust core.

One important change from the old implementation: the results view now keeps per-password checks and generator-wide statistical checks visibly separate. A password can fail its selected framework or pattern review even when the generator-wide batch statistics pass.

## Vault View

The same binary also exposes a native vault TUI:

```bash
paranoid-passwd vault
```

On an interactive terminal, that opens a native vault CRUD view backed by the same unlock policy as the headless vault CLI:

- password recovery via `PARANOID_MASTER_PASSWORD` or `--password-env`
- wallet-style mnemonic recovery via `--recovery-phrase-env`
- passwordless device-bound unlock when a sole device slot exists, or via `--device-slot`
- certificate-backed unlock via `--cert` and `--key`

If those shell-level inputs are unavailable, the blocked screen now includes a native unlock form for the same recovery-secret, mnemonic, device-slot, and certificate-backed paths.

### First-run environment approval

When no vault exists yet at the configured path, the vault TUI's first screen is an environment approval view instead of the unlock form. It collects the same `CapabilityReport` evidence exposed by `--detect-environment` and renders it before any secret is entered:

- OS keychain status (backend name, available/unavailable, error detail when unavailable)
- clipboard status (available/unavailable, error detail when unavailable)
- display server kind (Quartz, Wayland, X11, Windows, or headless)
- configured seal-provider posture (empty on a fresh path, since nothing is configured yet)
- the suggested initial configuration this evidence implies — a password recovery keyslot always (the only vault-init path), plus a device-bound keyslot offered only when the OS keychain probe reports available

Two choices are offered:

- **Accept suggested configuration** — proceeds to the recovery-secret entry form with Password mode preselected. Submitting initializes the vault, and when the keychain was available and accepted, a device-bound keyslot is enrolled automatically right after init.
- **Adjust manually** — proceeds to the same recovery-secret entry form, but skips the automatic device-bound keyslot enrollment; add keyslots afterward from the Keyslots view (`k`) instead.

Since the only way to create a vault is through this password-recovery init path, both choices end up entering a recovery secret; the difference is only whether the suggested device-bound keyslot gets enrolled automatically.

This screen is first-run-only: "already approved" is derived from vault existence itself (no separate state file), so it only appears again while the configured path still has no vault. It also stays reachable at any time from the vault main screen via `E`, to re-review the current environment's capabilities; `Esc` returns to the vault view from there.

The current vault TUI supports the first native vault workflows:

- item list navigation
- in-memory filtering of unlocked items via `/`, with explicit query, kind, folder, and tag fields
- selected-item detail
- add-login form
- add-note form
- add-card form
- add-identity form
- edit-login form
- edit-note form
- edit-card form
- edit-identity form
- optional folder field on login, secure-note, card, identity, and generate-and-store forms
- tag editing on login, secure-note, card, identity, and generate-and-store forms
- generate-and-store can now rotate the selected login in place instead of always creating a second entry
- selected-login detail now shows encrypted password-history retention after rotations
- login list/detail views now flag duplicate current passwords elsewhere in the unlocked vault
- selected-card detail shows masked payment-card metadata and billing notes
- selected-identity detail shows preferred contact metadata and profile notes
- dedicated keyslot view via `k`
- first-run environment approval screen with capability evidence and a suggested initial configuration, reachable again anytime via `E`
- mnemonic recovery-slot enrollment via `m`, with one-time phrase reveal
- device-bound keyslot enrollment via `b`
- certificate-wrapped keyslot enrollment via `c` (keyslot view only) from a PEM path
- selected certificate-slot rewrap to a replacement PEM via `w`, with optional replacement key path and passphrase fields to keep an active certificate-authenticated session aligned after rotation
- certificate-slot detail now includes subject and validity so cert rotation pressure is visible without leaving the native UI
- the add/rewrap certificate forms now preview the PEM path before mutation so a wrong recipient certificate can be caught before enrollment or rewrap
- certificate-backed keyslot detail now surfaces shared health warnings for not-yet-valid, expired, or near-expiry recipient certs
- selected keyslot relabeling via `l`
- selected mnemonic-slot rotation via `o`, with a dedicated confirmation screen before the replacement phrase is shown once
- recovery-secret rotation from the keyslot view via `p`
- selected non-recovery keyslot removal via `d`, with a second confirmation press when the removal would weaken recovery, certificate, or passwordless-unlock coverage
- selected device-slot rebind via `r`
- encrypted backup export via `x`
- encrypted backup import via `u`
- encrypted transfer export via `t`
- encrypted transfer import via `p`
- backup package summary preview on export and import panels before writing or restoring
- transfer-package summary preview on export and import panels before writing or importing
- delete confirmation
- generate-and-store form
- clipboard copy of the selected password, note, card number, or preferred identity contact value
- native unlock form on the blocked screen
- unlock retry / refresh

Vault filter controls:

- `/`: open the structured vault filter editor
- `Tab / Shift-Tab`: move between query, kind, folder, and tag fields
- `Left / Right / Space`: cycle the selected item kind when the kind field is active
- `Ctrl-U`: clear the selected vault filter field
- `Enter / Esc`: leave filter edit mode while keeping the active filters applied

The backup flows follow the same pattern as the rest of the vault TUI: `x` opens an export form that writes a portable JSON package containing the current encrypted header and ciphertext rows, and `u` opens an import form that restores that package back into the current vault path with explicit overwrite confirmation.

Selective transfer flows now live beside backup/restore in the same native vault surface: `t` opens an export form that writes only the currently filtered decrypted item payloads into a separate encrypted transfer package, and `p` opens an import form that brings one of those packages into the unlocked local vault using either the package recovery secret or a certificate keypair.

When the vault is unlocked in either native interactive surface, inactivity now triggers an automatic lock after 5 minutes: it clears the cached decrypted list/detail state, resets vault auth to a non-secret placeholder that forces re-entry on the next unlock attempt, clears any loaded mnemonic phrase, and resets the unlock, recovery-secret rotation, certificate rewrap, export-transfer, and import-transfer forms to their zeroizing defaults, before returning to the unlock view.

The GUI now mirrors the same native keyslot inspection, recovery-posture reporting, shared keyslot recommendations, enrollment, mnemonic rotation, certificate rewrap, relabel, recovery-secret rotation, posture-aware removal confirmation, and rebind flows, direct unlock model, folder-plus-tag organization model, backup and transfer export/import flows, clipboard auto-clear, and idle auto-lock behavior, so mnemonic, device-bound, certificate-wrapped recovery, and encrypted vault exchange no longer depend on CLI-only administration.
