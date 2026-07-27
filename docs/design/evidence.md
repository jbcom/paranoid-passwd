# paranoid-passwd — P8.1 evidence pass

This document is the output of P8.1: running the **real** TUI (vault TUI and
generator wizard) and the **real** GUI on this machine, capturing screenshots
of the actual rendered output, and reading them against
[`ia.md`](./ia.md)'s wireframes and [`journeys.md`](./journeys.md)'s
storyboards. It does not implement anything — it is the punch-list P8.2
(TUI), P8.3 (GUI), and P8.4 (copy) execute against.

## How the evidence was captured

- **TUI** — the real `paranoid-passwd` debug binary, run inside a `tmux`
  pseudo-terminal (true-color 24-bit ANSI, the actual `ratatui` render — not
  `PARANOID_TUI_SCRIPT`'s deterministic `TestBackend` text dump, which has no
  color/glyph fidelity to review visually). `tmux capture-pane -e` captures
  the SGR-tagged buffer; a small ANSI-to-PNG renderer replays those
  true-color codes onto a monospace grid and rasterizes to PNG, so every
  screenshot below is the exact color/character output the binary produced,
  not a reconstruction. (Capture scripts are scratch tooling, not committed
  to the repo — see Finding T0 below for the one reusable lesson from
  building them.)
- **GUI** — the existing `make test-gui-e2e-emulate` harness (Linux + Xvfb
  under the repo's builder Docker image), which runs the real Slint desktop
  build through the `operator-workflow` automation scenario end-to-end and
  captures the live X11 window with `import -window root`. This is the
  **only** screenshot capability the GUI currently has (see Finding G0
  below) — it produces exactly one screenshot, of the final state after the
  whole scripted scenario completes, not one per screen.
- All screenshots are real renders of this build (branch
  `directive-completion`), not mockups.

Screenshot index (`docs/design/evidence/`):

| # | File | What it shows |
|---|---|---|
| 1 | `01-firstrun-environment-approval.png` | First run, no vault at path yet |
| 2 | `02-accept-config-unlock-form.png` | After accepting suggested config |
| 3 | `02b-vault-created-empty-home.png` | Vault created, empty home |
| 4 | `03-home-vault-list.png` | H — vault list with 2 items |
| 5 | `04-item-selected-detail-pane.png` | H with an item selected (detail pane) |
| 6 | `05-copy-status-line.png` | After `c` (copy) from the selected item |
| 7 | `06-add-login-form.png` | `a` — Add Login form |
| 8 | `07-generate-store-form.png` | `g` — Generate & Store form |
| 9 | `08-keyslots-ways-in.png` | `k` — Keyslots panel |
| 10 | `09-delete-confirm.png` | `d` — Delete confirmation |
| 11 | `10-environment-approval-again.png` | `E` — Environment approval re-opened |
| 12 | `11-panic-lock-result.png` | `Ctrl+L` — panic lock result |
| 13 | `12-unlock-prompt-blank.png` | Fresh unlock prompt, no `PARANOID_MASTER_PASSWORD` set |
| 14 | `12b-unlock-blocked-error.png` | After attempting to type a passphrase (see Finding 2) |
| 15 | `13-generator-wizard-config.png` | Generator wizard TUI — config screen |
| 16 | `14-generator-wizard-result.png` | Generator wizard TUI — after one `Enter` |
| 17 | `15-gui-operator-workflow-final.png` | GUI — real Xvfb render, end of `operator-workflow` |

---

## Ranked defect list

Ranked by which [journeys.md cross-journey invariant](./journeys.md#cross-journey-invariants-carried-from-brandmd-restated-as-journey-rules)
(1–7) it violates, most severe first. Each item cites the screenshot(s) it is
read from and the exact `ia.md` node it fails to match.

### 1. Panic-lock has no dedicated Locked screen at all — invariants 1, 5, 6

**Screenshot:** `11-panic-lock-result.png`. **ia.md node:** S13→S14.

`Ctrl+L` is supposed to transition to a full-screen `⊘ Locked.` state (ia.md
§5: centered glyph, one line, `▸ Unlock` action, footer collapsed to
`⏎ unlock  q quit`). What actually renders is the **ordinary unlock form**
(`Screen::UnlockBlocked`, the same screen shown for a plain wrong-password
error) with:

- the title bar still reading `paranoid-passwd · Vault` — no `⊘` state
  token, no visual distinction from a normal locked-out session;
- a status line that says **`Panic lock: vault locked immediately and the
  clipboard was cleared.`** — the literal word "Panic" rendered in red text
  on screen. For a persona whose threat model is a shoulder-surfer or a
  coercive third party physically present at the moment they trigger this
  hotkey, the product printing "Panic lock" is a direct information leak
  about *why* the screen just changed — the opposite of invariant 5 (real
  and decoy indistinguishable) and a new failure mode invariant 5 didn't
  even anticipate (panic vs. ordinary-error indistinguishable);
- the unlock form defaulting into whatever auth mode was last selected
  (`Recovery Secret` / `Mnemonic` in the captures), not a clean reset;
- the full L0 unlock footer (`p/m/b/c pick mode; Up/Down...`) rather than
  the ia.md-specified minimal `⏎ unlock  q quit`.

This is the single highest-severity finding: the one screen ia.md calls out
as load-bearing for the coercion journey (J6b, "speed is the safety
property") does not exist as a distinct screen in the current build.

### 2. Unlock-form mode hotkeys (`p`/`m`/`b`/`c`) are matched globally, not scoped to focus — invariant 1, and a functional correctness bug

**Screenshots:** `12-unlock-prompt-blank.png`, `12b-unlock-blocked-error.png`.
**Code:** `crates/paranoid-cli/src/vault_tui/screen_state.rs`,
`handle_unlock_blocked_key` (~line 1811-1845).

`KeyCode::Char('p'|'m'|'b'|'c')` on the unlock-blocked screen switches the
auth mode **unconditionally**, before falling through to the text-input
handler — regardless of which field currently has focus. Concretely: a
persona with focus on the `Recovery secret:` text field who types a
passphrase containing the letter `p`, `m`, `b`, or `c` does not get that
character inserted; the keystroke is consumed to silently change the unlock
mode instead (confirmed by direct code read and reproduced live — see
capture note below). There is no error, no beep, no visual signal that the
character was dropped; the field simply doesn't grow. This is not a
copy/IA problem, it's a **input-handling correctness bug**: any passphrase
containing those four letters cannot be typed into this form as designed,
silently and invisibly. It should be reported and fixed as its own item,
ahead of any P8.2 copy/footer work, since P8.2's contextual-footer rewrite
(`⏎ unlock  ? other ways in  ⎋ back`) will otherwise ship on top of a
still-broken text field.

*(Capture note: `12b` shows a stale "Unlock blocked: set
PARANOID_MASTER_PASSWORD..." status line and a Mnemonic-mode form because
the scripted passphrase `"definitely wrong passphrase"` — containing `m`,
`b`, `c`, `p` — triggered exactly this bug during capture, which is how it
was found. It is reproducible directly: unlock screen -> focus Recovery
secret field -> type any string containing `p`/`m`/`b`/`c` -> those
characters vanish and the mode field changes instead.)*

### 3. Item detail is a raw field dump, not ia.md's S7 masked-password card — invariants 1, 2

**Screenshots:** `04-item-selected-detail-pane.png`, `05-copy-status-line.png`,
`08-keyslots-ways-in.png` (detail pane), `09-delete-confirm.png`.
**ia.md node:** S7.

ia.md's S7 wireframe is four lines (`User`, masked `Pass ••••••••`, `▸ Copy
password`, `Reveal`/`Edit`) with a footer of `⏎ copy  r reveal  e edit  ?
all keys  ⎋ back`. The current detail pane instead renders, unconditionally
and un-maskable:

```
id: a32fe46aca157ef780aeef1a97d9a51e
title: bank
username: activist
password: hunter3
duplicate passwords elsewhere: 0
url:
notes:
folder:
tags:
password history entries: 0
recent history:

updated_at_epoch: 1784279090
```

— a raw internal UUID (`id:`), a raw Unix epoch (`updated_at_epoch:`), empty
field labels shown even when unset (`url:`, `notes:`, `folder:`, `tags:`),
and the **password shown in cleartext by default**, with no mask/reveal
distinction at all. This is the exact "box of data with no answer to what do
I do next" antipattern journeys.md's reading guide names as the defect PUX
exists to fix. `duplicate passwords elsewhere: 0` and `password history
entries: 0` are real, useful signals per ia.md rule 2 ("progressive
disclosure of evidence") but belong one drill-level down, not inline on the
intent-first surface.

### 4. The 40-key `Controls:` wall is fully intact — invariant 3

**Screenshots:** every TUI screenshot's footer row.
**ia.md node:** §1 region contract "Footer", §5 "This is where the old
40-key Controls: line goes to live" (i.e. it should be *behind* `?`, not on
screen by default).

Every screen's footer is the full un-scoped capability list, verbatim, e.g.
(`03-home-vault-list.png`):

> `Controls: Up/Down select items, / filters, a adds login, n adds secure
> note, v adds card, i adds identity, e edits, d deletes, g generates and
> stores one password, x exports backup, t exports transfer, u imports
> backup, p imports transfer, k opens keyslots, E reviews environment
> approval, c copies the selected value, r refreshes, q quits. Ctrl+L
> panic-locks the vault immediately.`

That's 17 bindings on one line, wrapping to 3 terminal rows out of 40 — this
is the literal defect ia.md rule 3 and brand.md §3e name, present unchanged
on every single screen captured (Vault, Keyslots, AddLogin, GenerateStore,
DeleteConfirm, EnvironmentApproval, UnlockBlocked all have their own
full-wall variant — see `panel_rendering.rs` lines ~187-231, all prefixed
`Controls:`). None of it is scoped to the focused pane; none of it is a `?`
overlay — it is the only help surface that exists today. This is the P8.2
footer-and-`?`-overlay work's exact target.

### 5. No S1/S2/S3 trust-gate ("verify this copy") screen exists at all — invariant 1 (J1's hero flow)

**Screenshot:** `01-firstrun-environment-approval.png`.
**ia.md nodes:** S1, S2, S2d, S3, S3f (entirely absent).

First run does not land on a trust gate. It lands directly on
`Screen::EnvironmentApproval` — a capability/posture report (`OS keychain:
available`, `Clipboard: available`, `Display server: quartz`, `Seal-provider
posture`) with an `Accept suggested configuration` / `Adjust manually`
choice. There is no verification step, no fingerprint/signature check
surfaced anywhere in the TUI, and no `!`/`✓`/`✗` trust state token in the
title bar at any point in the captured flow (title bar is static
`paranoid-passwd · Environment Approval` / `· Vault` throughout — compare
ia.md §1's "right-aligned: trust/lock state" contract, which nothing in the
current build populates). This matches journeys.md J1's documented current
state exactly ("The persona runs the binary... there is no first-run moment
that says 'here is how to confirm this copy is genuine'") and confirms it is
still true verbatim. `--federal-evidence`/`--detect-environment` exist only
as CLI flags outside the TUI's first-run spine.

### 6. Generate & Store (S11 stand-in) is a raw 10+ field parameter form, not a verdict — invariants 1, 2

**Screenshots:** `07-generate-store-form.png`, `13-generator-wizard-config.png`,
`14-generator-wizard-result.png`. **ia.md node:** S11.

ia.md's S11 job is "produce a strong password and show it is strong," one
`⏎ copy` action, evidence one level down at S11d. The vault TUI's `g`
screen instead opens directly onto a configuration form (`Password length:
32`, `Framework IDs (csv):`, `Min lowercase: 0`, `Min uppercase: 0`, `Min
digits: 0`, `Min symbols: 0`) with a live "Generation preview" showing
`Effective charset size: 94`, `Manual minima: lower=0 upper=0 digits=0
symbols=0` — engineer-speak (`charset size`, `minima`) with no generated
password or verdict visible until the persona separately navigates to
`Generate + Rotate Login` and submits. The standalone generator wizard TUI
(`--tui`, `13`/`14`) is worse: a **21-field** capability-list config screen
(`Selected field: 1 of 21`) mixing generation params, all six compliance
framework toggles, and constraint minima on one undifferentiated list, whose
only next action is `Generate + Run 7-Layer Audit` — "7-Layer Audit" is
itself unexplained internal terminology on the primary surface. Pressing
`Enter` on the first field in this capture only advanced/adjusted that
field's value (`32`→`33`) rather than producing anything — there is no
one-`⏎` path to a result at all.

### 7. Keyslot mechanics shown at the intent-first level, not behind a drill-down — invariant 2

**Screenshot:** `08-keyslots-ways-in.png`. **ia.md node:** S10/S10d.

ia.md places `keyslot` mechanics (slot indices, wrap types, cipher params)
strictly behind `⋯ Show the mechanics` (S10d), with S10 itself showing rows
"named by relationship" (e.g. "your phone," "printed backup"). The current
Keyslots screen shows, on the primary (non-drill-down) surface:

```
id: recovery
kind: password_recovery
label: password-recovery
wrap: argon2id+aes-256-gcm
device-bound: no
healthy: true
```

`wrap: argon2id+aes-256-gcm` is exactly the cipher-parameter detail ia.md
§4's placement table assigns to S10d, not S10. There is also no
relationship-based label at all — the list item name is the internal
`kind` (`password_recovery`), not "your phone" / "printed backup" /
"recovery phrase," so even the vocabulary substitution from brand.md §4
(row: `recovery keyslot` → "recovery phrase") has not been applied here.

### 8. Delete confirmation is y/N, not the ia.md §7 severe-tier typed-name confirm — invariant 1, and a duty-of-care gap

**Screenshot:** `09-delete-confirm.png`. **ia.md node:** §7 confirmation
tiering table.

ia.md §7 requires "must type the item/vault **name** or an explicit phrase —
not `y/N`" for delete item / remove a way in / delete vault / delete decoy
(the "severe" tier). The current delete-item screen reads:

> `Delete confirmation is active. Press y or Enter to remove the selected
> item.` ... `Press y or Enter to delete, or n / Esc to cancel.`

This is the exact anti-pattern ia.md §7 cites research against ("make it
hard to confirm by accident... type the name of the thing you're deleting")
— a single `y`/Enter keypress permanently deletes an encrypted vault record.
The same `y`/Enter pattern is very likely shared by remove-keyslot (not
separately captured here, but `panel_rendering.rs` line 231 shows the
identical `y or Enter confirms deletion` string is reused for keyslot
removal) — i.e. "remove a way in," ia.md's other named severe-tier action,
almost certainly has the same gap.

### 9. Copy action produces no visible status feedback within the captured frame — invariant 6 (unconfirmed, needs re-check under P8.2)

**Screenshots:** `04-item-selected-detail-pane.png` vs
`05-copy-status-line.png` (byte-identical rendered frames).

Pressing `c` on a selected item is supposed to update the status line to the
brand.md §3 micro-example (`Copied. It clears from the clipboard in 30
seconds.` — actual current string per `mutation_handlers.rs::copy_selected_secret`
is `Copied the selected vault secret to the clipboard. It will be cleared in
{n} seconds if unchanged.`, the wording P8.4 needs to reconcile against the
brand.md micro-example verbatim). In this evidence pass's headless-tmux
capture environment the status line did not visibly change after `c` at a
2-second capture delay. This is flagged as **unconfirmed** rather than a
confirmed defect: `Clipboard::new()` inside a display-less `tmux` session on
macOS (no X11/Wayland/quartz session attached to the pty) is a plausible
environment-specific failure unrelated to the real desktop TUI's behavior,
and the status-line *string* itself is confirmed correct by direct code
read. P8.2/P8.5 should re-verify this specific interaction in a real
attached terminal (not headless tmux) before treating it as fixed or broken.

### 10. GUI: no fixed three-region frame; every evidence panel is permanently visible; off-palette light theme — invariants 1, 2, 3

**Screenshot:** `15-gui-operator-workflow-final.png`. **ia.md node:** §6
(entire section).

The captured GUI render — the real Slint desktop build, real Xvfb X11
window, `operator-workflow` automation scenario run to completion — shows
none of ia.md §6's contract:

- **No title/content/action-bar three-region frame.** The window is a
  6-panel dashboard grid (`Generator`, `Vault Access`, `Operations`, `Audit
  Evidence`, `Vault Records`, `Assurance`) all visible simultaneously, no
  single-job screen, no primary/secondary action-bar pattern.
- **Every technical-evidence panel is permanently visible**, not a
  collapsed-by-default disclosure: the `Audit Evidence` panel shows raw
  `sha256=...` lines and `pass=true` inline; the `Assurance` panel shows raw
  `Recovery=true Cert=false Device=0` posture flags and a raw keyslot
  listing (`password_recovery | recovery | password-recovery`,
  `mnemonic_recovery | mnemonic-108a381741eec3ee | paper-backup`) with no
  "Show the mechanics" gating at all — the exact "stacks evidence panels
  visibly" failure system.md §7 and ia.md §6 both describe by name.
- **Off-palette light theme**, not the near-black austere palette:
  light-gray input fields and buttons on a dark-navy card background is a
  hybrid that matches neither the documented dark ground (`color.bg.base`)
  nor a coherent light theme; the buttons read as generic OS-default gray,
  not `accent.action` blue.
- **Raw field labels throughout**: `TYPED OPS POLICY`, `Password history
  entries: 1`, `SURFACE / Slint GUI`, `POSTURE` — all-caps engineer labels,
  not brand.md §3/§4 vocabulary.

This single screenshot is the GUI's *entire* evidence contribution to this
pass — see Finding G0 below for why.

---

## Tooling/process findings (not product defects, but blocking future evidence passes)

### Finding G0 — the GUI has no per-screen screenshot capability

`make test-gui-e2e-emulate` (`tests/test_gui_e2e.sh`) runs the
`operator-workflow` `PARANOID_GUI_AUTOMATION_SCENARIO` end-to-end inside one
GUI process and takes exactly **one** `import -window root` screenshot after
the whole scenario (generate, unlock, add login, filter, keyslot, backup
export) has already completed. There is no scenario granularity, no
per-region capture, and no way to see the GUI mid-flow (e.g. the trust gate,
an in-progress verify, a locked state, a delete confirmation) without adding
new automation scenarios and screenshot hooks. **P8.5's re-baselining item
cannot assert "skeleton geometry occupies the same fixed positions across
every captured mode" (its own acceptance criterion) against a harness that
only ever captures one mode.** P8.3/P8.5 should treat "GUI automation needs
per-screen/per-scenario screenshot points, not just one end-of-run capture"
as an in-scope prerequisite, not a nice-to-have.

### Finding T0 — `tmux send-keys` swallows bare literal single-character keys

Reproduced directly: `tmux send-keys -t <session> a` (no `-l`) does **not**
deliver a literal `a` keystroke to the child process on this tmux build —
it appears to consult tmux's key-name table first and silently drop the
key. `tmux send-keys -l a` (literal flag) works correctly. This cost a full
debugging cycle during capture (several early screenshots were corrupted —
"g" leaking into an Add Login title field two screens later — until traced
to this). Any future scripted-tmux capture tooling for this repo must use
`-l` for every single-character literal key; documented here so the next
evidence pass doesn't rediscover it.

---

## Summary table

| # | Finding | Screens | Invariant(s) violated | Severity |
|---|---|---|---|---|
| 1 | No dedicated Locked (S13/S14) screen; "Panic lock" text leaks on screen | S13→S14 | 1, 5, 6 | Critical |
| 2 | Unlock-form mode hotkeys eat passphrase characters unconditionally | S15 | 1 (+ correctness bug) | Critical |
| 3 | Item detail is a raw field dump (UUID, epoch, cleartext password) | S7 | 1, 2 | High |
| 4 | 40-key `Controls:` wall present unchanged on every screen | all | 3 | High |
| 5 | No trust-gate (S1/S2/S3) screen exists | S1-S3f | 1 | High |
| 6 | Generate & Store is a raw param form, no verdict | S11 | 1, 2 | High |
| 7 | Keyslot mechanics shown inline, not behind drill-down | S10/S10d | 2 | Medium |
| 8 | Delete confirm is y/N, not typed-name | §7 tiering | 1 | Medium |
| 9 | Copy status feedback unconfirmed in headless capture | S7 | 6 (unconfirmed) | Needs re-check |
| 10 | GUI: no 3-region frame, evidence panels always visible, off-palette | §6 (all) | 1, 2, 3 | Critical |

This is the punch-list P8.2 (TUI: findings 1, 2, 3, 4, 5, 6, 7, 8), P8.3
(GUI: finding 10, plus Finding G0's harness gap), and P8.4 (copy pass across
every string surfaced in every screenshot above) implement.

---

## P8.5 addendum — re-baseline against the redesigned output

The GUI harness gap this doc originally flagged ("the GUI e2e harness only
ever captures one end-of-run screenshot") is fixed: `tests/
test_gui_visual_regression.sh` now captures one screenshot per named GUI
screen (trust-gate, verified, vault-list, add-item, item-detail, generate,
ways-in, locked), for both a real vault pass and a decoy vault pass, into
`tests/baseline/gui/` — the new committed baseline, superseding the
single end-of-run frame this doc's finding 10/G0 was working around. See
`.agent-state/directive.md`'s P8.5 entry for the full acceptance-criteria
breakdown, including a real pre-P8.5 defect it caught and fixed (S14/S15's
missing `⊘` state token in the TUI) and a real spec/implementation gap it
surfaced but did not silently resolve (ia.md §5's S7 distinct detail-pane
footer has no counterpart in the single-screen `Screen::Vault` architecture
P8.2 actually built).
