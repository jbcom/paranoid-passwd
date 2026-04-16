---
title: TUI Guide
---

# TUI Guide

The TUI is the phase-1 replacement for the old browser wizard. It keeps the same three-step flow:

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
Tune the same flow the old web wizard exposed.

Wizard                                  Audit Preview
› Password length: 32                  Branding  deep navy + emerald, monospace-heavy, fail-closed.
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
- mnemonic recovery-slot enrollment with one-time phrase reveal
- device-bound keyslot enrollment
- certificate-wrapped keyslot enrollment from a PEM path
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

When the vault is unlocked in either native interactive surface, inactivity now triggers an automatic lock after 5 minutes and clears the cached decrypted list/detail state before returning to the unlock view.

The GUI now mirrors the same native keyslot inspection, recovery-posture reporting, shared keyslot recommendations, enrollment, mnemonic rotation, certificate rewrap, relabel, recovery-secret rotation, posture-aware removal confirmation, and rebind flows, direct unlock model, folder-plus-tag organization model, backup and transfer export/import flows, clipboard auto-clear, and idle auto-lock behavior, so mnemonic, device-bound, certificate-wrapped recovery, and encrypted vault exchange no longer depend on CLI-only administration.
