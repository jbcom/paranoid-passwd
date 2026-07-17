# paranoid-passwd — Information Architecture & Flow

This document turns the seven journeys in [`journeys.md`](./journeys.md) into a
concrete **screen graph** for the CLI/TUI and the GUI scaffold. It inherits every
decision from [`brand.md`](./brand.md) — the persona (§1), the promise (§2), the
grave/precise voice (§3), the user-facing vocabulary (§4), and the austere visual
identity (§5) — and does not re-decide any of them. Where a screen shows a string,
it is the string brand.md or journeys.md already fixed.

Downstream, [`system.md`](./system.md) (PUX.4) supplies the tokens and component
specs that render these screens; PUX.5 folds both into P8's build items.

---

## 0. The four governing rules (from research + brand)

Every screen in this document obeys four rules. They are stated once here and are
not repeated per screen.

1. **One job per screen, named in the title.** No screen is a panel dump. The
   title states the single thing the screen is *for* (brand.md §5.5). If a screen
   needs two jobs, it is two screens joined by a drill-down. (Research lens 0:
   k9s/lazygit spatial + drill-down; "each level shows only what's relevant to the
   current drill depth.")

2. **Progressive disclosure of evidence.** Audit math, seal/hardware internals,
   attestation fingerprints, and keyslot mechanics live **one drill-level down**,
   reached by an explicit *Show the evidence / Show the details* action — real,
   reachable, never thrust forward, never deleted (brand.md §4 "Depth is reachable,
   never deleted"; research lens 0: "technical/engineer vocabulary stays real but
   moves to the bottom of the drill stack").

3. **Contextual footer, not a hotkey wall.** The footer shows only the **3–5 keys
   valid for the currently focused pane** and re-renders when focus moves. The
   full keymap lives behind `?`. This replaces the single 40-key `Controls:` line
   (brand.md §3e). (Research lens 0: the four-layer keyboard architecture — L0/L1
   in footer, L2 behind `?`, L3 documented only; footer re-renders per focused
   pane as in k9s.)

4. **Fixed layout skeleton.** Panels hold the same screen positions across every
   mode — including decoy vaults — and never rearrange without an explicit user
   action (brand.md §5.5; research lens 0: spatial consistency is "the
   difference-maker"). A shoulder-surfer sees identical framing regardless of which
   vault is open, which is itself a duress property (research lens 0).

A fifth rule is structural rather than per-screen and governs the whole graph:

5. **No screen is a dead-end.** Every terminal state (success, failure, empty)
   carries exactly one `accent.action` next move and a way up (`⎋`). This is the
   single defect PUX exists to fix (journeys.md cross-journey invariant 1).

---

## 1. The stable layout skeleton (TUI)

Every TUI screen is composed from **one fixed skeleton**. Modes change *what fills*
the regions; they never change *where the regions are*. This is rule 4 made
concrete, and it is the mechanism that makes real and decoy vaults
indistinguishable in framing (journeys.md J6 step 3; brand.md §4 rule 1).

```
┌──────────────────────────────────────────────────────────────────────┐
│ TITLE BAR         one job, stated  ·  right-aligned: trust/lock state  │  ← fixed row
├───────────────────────────┬──────────────────────────────────────────┤
│                           │                                          │
│   PRIMARY PANE            │   DETAIL / ACTION PANE                    │  ← fixed columns
│   (list, prompt, or       │   (selected item, verdict, or the one    │
│    guided step)           │    next action; empty when nothing sel.) │
│                           │                                          │
├───────────────────────────┴──────────────────────────────────────────┤
│ STATUS LINE       last state-change, plainly stated (brand.md §3.1)   │  ← fixed row
├──────────────────────────────────────────────────────────────────────┤
│ FOOTER            3–5 keys valid for the FOCUSED pane  ·  ? all keys   │  ← fixed row, re-renders
└──────────────────────────────────────────────────────────────────────┘
```

Region contracts:

- **Title bar** — always present, always one job. The right-aligned slot carries a
  single global state token: `!` unverified copy, `✓` verified copy, `⊘` locked.
  Never more than one; each pairs a symbol with a word on hover/expand (brand.md
  §5.4 — symbol first, color second).
- **Primary pane** — the thing the persona is acting *on* (a list, a prompt, a
  guided step). Holds focus by default.
- **Detail / action pane** — the thing selected, or the verdict, or the one next
  action. On single-purpose screens (unlock, verify) the two panes may merge into
  one centered column, but the *title / status / footer* rows never move.
- **Status line** — reports the last state change in the grave voice
  (`Vault open. 12 items.`). Empty until something changes; never a scrolling log.
- **Footer** — L0/L1 keys for the focused pane only; `? all keys` always present as
  the door to the L2 overlay.

The GUI mirrors this skeleton as a fixed three-region frame (title / content /
action-bar) — see §6.

---

## 2. The screen graph

Nodes are screens; edges are the explicit action that traverses them. `▸` marks the
single `accent.action` on each screen. Dashed edges (`⋯`) are drill-downs into
evidence (rule 2) and always have `⎋` back up. The graph has exactly one
first-run entry and one steady-state home.

```
                         ┌──────────────────────┐
   FIRST RUN  ─────────▶ │  S1  Trust gate      │  (J1)  one job: verify this copy first
                         └──────────┬───────────┘
                            ▸Verify │  Skip for now
                                    ▼
                         ┌──────────────────────┐        ⋯ Show the details
                         │  S2  Verifying…      │ ─ ⋯ ─▶  S2d  Fingerprint / signature
                         │      (non-blocking)  │         (raw hash, release metadata)
                         └───┬──────────────┬───┘
                     verified│              │not verified
                             ▼              ▼
                  ┌────────────────┐  ┌────────────────────────┐
                  │ S3  Verified   │  │ S3f  Not verified (RED) │  (J1.3b)
                  │  ▸Continue     │  │  ▸Where to re-download  │  → HALT, no vault
                  └───────┬────────┘  └────────────────────────┘
                          ▼
              ┌───────────────────────┐
   NO VAULT?  │  S4  Create vault     │  (J3)   one job: make the container + way to open
              │   ▸Create vault       │
              └───────────┬───────────┘
                          ▼
              ┌───────────────────────┐
              │  S5  Vault created    │  (J3.2)  states truth + honest caveat (amber)
              │   ▸Add your first item│          ⋯ Set up hardware protection
              └───────────┬───────────┘
                          ▼
   ┌──────────────────────────────────────────────────────────────────┐
   │                          STEADY STATE                              │
   │                                                                    │
   │   ┌────────────────┐   ⏎ open    ┌────────────────────┐           │
   │   │ H  Vault list  │ ──────────▶ │ S7  Item detail    │  (J4 home)│
   │   │  (HOME)        │ ◀────── ⎋   │  ▸Copy             │           │
   │   │  ▸(context)    │             │   ⋯ Reveal / Edit  │           │
   │   └───┬───┬───┬────┘             └────────────────────┘           │
   │       │   │   │                                                    │
   │   n new│  /find│ w ways-in   g generate   ? overlay   panic-key    │
   │       ▼   ▼    ▼        ▼          ▼           ▼           ▼        │
   │  ┌──────┐ ┌──────┐ ┌─────────┐ ┌─────────┐ ┌───────┐ ┌──────────┐ │
   │  │S8 New│ │S9    │ │S10 Ways │ │S11 Gen  │ │S12 ?  │ │S13 PANIC │ │
   │  │ item │ │Search│ │ in (J5) │ │ (J2)    │ │overlay│ │ LOCK     │ │
   │  └──────┘ └──────┘ └────┬────┘ └────┬────┘ └───────┘ └────┬─────┘ │
   │                         │⋯          │⋯                     ▼       │
   │                  S10d Keyslot   S11d Randomness      ┌──────────┐  │
   │                  mechanics      evidence (chi²)      │S14 Locked│  │
   │                                                      └────┬─────┘  │
   └───────────────────────────────────────────────────────────┼──────┘
                                                                ▼
                                                   ┌────────────────────┐
   RECOVERY (new machine, lost pass) ─▶ S1 trust ─▶│ S15 Unlock prompt  │  (J4)
                                                    │  = home entry loop │
                                        ┌───────────┴────────────────────┘
                                        │ "I need to recover"  (J7)
                                        ▼
                            ┌────────────────────────┐
                            │ S16 Recover a vault    │  (J7) guided, not slot mgmt
                            │  ▸(choose a way in)    │
                            └────────────────────────┘

   SETUP (calm, in advance):  H ─ w ─▶ S10 Ways in ─▶ S17 Create decoy vault (J6a)
```

Key structural facts the graph encodes:

- **Trust precedes everything.** There is no path to a vault — first run *or*
  recovery — that does not pass through S1/S2 (journeys.md J1, J7 step 1). Recovery
  on a new machine re-enters at S1, not at a bypass.
- **One home.** The steady state has a single home (`H`, the vault list). Every
  action fans out from it and returns to it with `⎋`. There is no second "dashboard"
  competing for the persona's orientation.
- **Panic is a global edge.** The panic key traverses from *any* steady-state
  screen straight to S13→S14 with no confirmation (journeys.md J6b; brand.md §2.3
  "speed is the safety property"). It is the only edge that skips confirmation.
- **Evidence is always a leaf.** S2d, S10d, S11d are drill-down leaves reached by
  `⋯ Show…` and exited by `⎋`. They never sit inline on the intent-first screen.

---

## 3. Guided first-run (replaces the hotkey menu)

The current product drops the persona into a TUI (or straight into an unlock
prompt) whose only orientation is the 40-key `Controls:` line — a menu of hotkeys,
not a path (journeys.md J1 current state). The redesigned first-run is a **short
guided spine**: S1 → S2 → S3 → S4 → S5 → H. Each node has one job and one next
action; the persona is never asked to read a keymap to know what to do.

First-run spine, annotated:

| # | Screen | The one job | The one next action (`▸`) | Evidence one level down |
|---|--------|-------------|---------------------------|-------------------------|
| S1 | Trust gate | Decide whether this copy can be trusted | **Verify this copy** | — |
| S2 | Verifying | Watch the check without being trapped | *(wait; `⎋` live)* | ⋯ Show the details → S2d |
| S3 | Verified | Confirm genuine, proceed | **Continue** | (fingerprint stays at S2d) |
| S4 | Create vault | Make the container + way to open | **Create vault** | *(hardware protection deferred)* |
| S5 | Vault created | Know it exists + one honest caveat | **Add your first item** | ⋯ Set up hardware protection |

Why this is not a menu: at no point does the persona choose from a list of
capabilities. Each screen presents **the single act that this moment is for**, with
everything else (types of items, keyslots, hardware protection, evidence) deferred
to the moment it becomes relevant. Capability is not removed — it is *sequenced*.

First-run detects state and short-circuits correctly:

- **Copy already verified on this machine** → S1 still shows, but the title-bar
  token reads `✓` and S1's body reads *This copy was verified on this machine.* The
  persona may re-verify or Continue. Trust is re-affirmable, never assumed away.
- **A vault already exists** → the spine ends at S15 (unlock), not S4. First-run is
  only "first" when there is nothing to open.

---

## 4. Progressive disclosure — where each piece of evidence lives

This table is the authoritative placement of every technical surface the current
product thrusts forward. **Left column: what the persona sees first. Right column:
the drill-down leaf it lives in, reached by an explicit action.** Nothing is
deleted; everything is relocated (brand.md §4 hard rule 2; rule 2 above).

| Evidence (internal) | Intent-first surface (what leads) | Lives behind | Reached by |
|---|---|---|---|
| `attestation` signature / hash / release metadata | S3 verdict: `✓ This copy matches the published release.` | **S2d** Fingerprint & signature | `⋯ Show the details` |
| `chi-squared pass`, `p > 0.01`, DoF `N−1`, entropy, rejection-sampling note | S11 verdict: `✓ Randomness check: passed` | **S11d** Randomness evidence | `⋯ Show the evidence` |
| `keyslot` mechanics (slot indices, wrap types, cipher params) | S10 `Ways in (n)` — rows named by relationship | **S10d** Keyslot mechanics | select a way in → `⋯ Show the mechanics` |
| `seal provider` / `seal posture` internals | S5 / item detail: `Hardware protection` state, one sentence | **S18** Hardware protection detail | `⋯ Set up / inspect hardware protection` |
| `federal evidence` / `federal-ready` | *(not on primary flow at all)* — offered as **Evidence bundle** action | **S19** Evidence bundle | vault menu → `Produce an evidence bundle` |
| `assurance level` (`ops profile`) | a labeled choice at S19, plain description | *(inline at S19; it is a deliberate choice, not hidden evidence)* | — |

Two placement rules bind this table:

- **A verdict is never shown without a way to the math**, and **the math is never
  shown without first showing the verdict.** S11 and S2 always pair a one-line
  verdict with a `⋯` door; S11d/S2d always open under that door, never above it.
- **`federal-evidence` is demoted twice**: renamed to *Evidence bundle* (brand.md
  §3c) *and* moved off the primary flow entirely into an on-demand vault action
  (S19). It is a deliverable the persona occasionally produces, not a mode they
  operate in, and never government-branded framing on a screen.

---

## 5. Per-screen specs (TUI) — annotated wireframes

Each screen below names its **job**, its **focused-pane footer** (rule 3), and its
**drill-downs**. Screens already storyboarded in journeys.md reuse those wireframes
verbatim; this section adds the screens the graph requires but the journeys did not
draw, and fixes the footer per pane.

### H — Vault list (HOME)

**Job:** orient the persona and let them reach any item or action. This is the one
home; all fan-out returns here.

```
┌─ Vault ─────────────────────────────────────────────────────── ✓ ──┐
│  Logins ────────────────────────────────                            │
│  ▸ mail.example                       ⏎ open                         │
│    bank                                                             │
│    forum                              (primary pane: the item list)  │
│  Notes ─────────────────────────────────                            │
│    recovery-notes                                                   │
│                                       (detail pane: empty until sel.)│
├─────────────────────────────────────────────────────────────────────┤
│ Vault open. 12 items.                                    (status)    │
├─────────────────────────────────────────────────────────────────────┤
│ ↑↓ move   ⏎ open   n new   / find   ? all keys   q quit             │  ← list-pane footer
└─────────────────────────────────────────────────────────────────────┘
```

- **Footer (list pane focused):** `↑↓ move  ⏎ open  n new  / find  ? all keys  q quit`
  (brand.md §3e verbatim). The remaining ~30 capabilities (add note/card/identity,
  edit, delete, generate, export/import backup/transfer, ways-in, environment
  approval, refresh) live behind `?` (S12), scoped by context.
- **Drill-downs:** none from the list itself; `⏎` navigates to S7 (item detail),
  which is a screen change, not an inline expansion.

### S7 — Item detail

**Job:** show one item and let the persona use it safely.

```
┌─ mail.example ──────────────────────────────────────────────── ✓ ──┐
│  User    activist@example.org                                       │
│  Pass    ••••••••••••••••                                           │
│                                                                     │
│  ▸ Copy password                              ← accent.action       │
│    Reveal                                                           │
│    Edit                                                             │
├─────────────────────────────────────────────────────────────────────┤
│ Copied. It clears from the clipboard in 30 seconds.      (status)   │
├─────────────────────────────────────────────────────────────────────┤
│ ⏎ copy   r reveal   e edit   ? all keys   ⎋ back                    │  ← detail-pane footer
└─────────────────────────────────────────────────────────────────────┘
```

- **Footer (detail pane focused):** `⏎ copy  r reveal  e edit  ? all keys  ⎋ back`.
  Note it differs from the list footer — the footer re-renders on focus change
  (rule 3). Destructive actions (delete) are **not** in this footer; they live in
  `?` and require typed confirmation (see §7).
- **Copy status** is the verbatim brand.md §3 micro-example — the clipboard-clear
  fact is a real consequence, stated plainly.

### S10 — Ways in (J5)

**Job:** answer the audit question *who or what can open this vault.* Reuses
journeys.md J5 step 1 verbatim (`Ways in (n)`, rows named by relationship).

- **Footer (ways-in pane focused):** `↑↓ move  a add  x remove  ? all keys  ⎋ back`.
- **Drill-down S10d — Keyslot mechanics:** select a way in → `⋯ Show the mechanics`
  reveals slot index, wrap type, and cipher params. `⎋` back to the relationship
  view. This is where the internal `keyslot` vocabulary is allowed to appear
  (brand.md §4 "reachable, never deleted").
- **`x remove` is destructive-tiered:** removing a way in is consequential
  (locking yourself out is possible); it requires typed confirmation (§7), unlike a
  copy.

### S11 — Generate (J2)

**Job:** produce a strong password and show it is strong. Reuses journeys.md J2
wireframe verbatim.

- **Footer (result pane focused):** `⏎ copy  g regenerate  ? help  ⎋ back`
  (journeys.md J2 verbatim).
- **Drill-down S11d — Randomness evidence:** `⋯ Show the evidence` reveals the exact
  chi-squared statistic, DoF `N−1`, the `p > 0.01` threshold, entropy, and the
  rejection-sampling note (crypto invariants unchanged — CLAUDE.md §3–4). `⎋` back
  to the verdict.

### S13 → S14 — Panic lock (J6b)

**Job (S13):** make everything unreadable *now*. There is **no S13 screen the
persona reads** — the panic key fires and the product transitions directly to S14.
This is the only edge in the graph with no confirmation (brand.md §2.3).

```
┌─ Locked ──────────────────────────────────────────────────── ⊘ ──┐
│                                                                   │
│              ⊘  Locked.                                           │
│                 Nothing is readable until you unlock again.        │
│                                                                   │
│              ▸ Unlock                          ← accent.action     │
│                                                                   │
├───────────────────────────────────────────────────────────────────┤
│ (status: cleared)                                                 │
├───────────────────────────────────────────────────────────────────┤
│ ⏎ unlock   q quit                                                 │  ← minimal footer
└───────────────────────────────────────────────────────────────────┘
```

- **S14 copy** is the verbatim brand.md §3 micro-example. The product does **not**
  say "you're safe" (brand.md §3 rule 4).
- **Footer collapses to the minimum** — in a locked state the only valid acts are
  unlock or quit. Every other key is absent (rule 3: help shows only what's
  available now; research lens 0 "contextual intelligence").
- **`⎋` to unlock loops back to S15**, identical framing to a daily unlock.

### S15 — Unlock prompt (J4) & S16 — Recover (J7)

**S15 job:** open the vault. Reuses journeys.md J4 wireframe; identical framing for
real and decoy (rule 4; brand.md §4 rule 1). Empty-state copy verbatim from brand.md
§3d.

- **Footer (unlock focused):** `⏎ unlock   ? other ways in   ⎋ back`. The `?` here
  is scoped — it opens *ways to get in* (recovery phrase, this device, held key),
  not the global keymap, because that is the only relevant help at a locked prompt
  (research lens 0: help shows only what's available in context).
- **S16 (Recover)** is reached from S15's `? → I need to recover`. It is a **guided
  path**, not slot management (journeys.md J7 current-state defect): it asks *which
  way in do you have* and walks that one method. Copy verbatim from J7 step 2.

### S17 — Create decoy vault (J6a)

**Job:** create something safe to surrender, calmly and in advance. Reached from
S10 (Ways in) or a vault menu — **never** offered only at the moment of duress
(journeys.md J6 current-state defect).

- **Honest-limits screen precedes creation** (journeys.md J6 honest-limits note,
  non-negotiable): the three limitation statements are shown *before* the persona
  can create a decoy, in the grave voice, not as fine print.
- **Invariant:** S17's output vault is byte-for-byte indistinguishable in framing
  from a real vault — identical skeleton (§1), palette, footer, and vocabulary. The
  decoy is not a special screen; it re-enters the *same* H/S15 loop (rule 4;
  journeys.md J6 step 3).

### S12 — The `?` overlay (the L2 layer)

**Job:** hold every capability not in the current footer, scoped to the current
context. This is the L2 layer of the four-layer keyboard architecture (research
lens 0). It is a transient overlay over the fixed skeleton — it does not become a
new screen, so the skeleton geometry is preserved beneath it.

```
┌─ Keys · Vault list ─────────────────────────────────────────────────┐
│  Move & open        ↑↓ move    ⏎ open      / find                    │
│  Add                n new      (login · note · card · identity)      │
│  Item               e edit     c copy      d delete  (typed confirm) │
│  Vault              w ways in  E approvals                           │
│  Backup             x export   u import    t transfer  p receive     │
│  Generate           g generate one and store it                      │
│  System             r refresh  q quit                                │
├─────────────────────────────────────────────────────────────────────┤
│ ⎋ close                                                             │
└─────────────────────────────────────────────────────────────────────┘
```

- **The overlay is context-scoped:** its heading names the pane it was opened from
  (`Keys · Vault list` vs `Keys · Item` vs `Keys · Ways in`), and it lists only the
  keys valid there (research lens 0: k9s "the hotkey list is never a static global
  wall, it's always scoped to what's selected"). Opening `?` from S7 shows the item
  keys, not the vault-backup keys.
- **This is where the old 40-key `Controls:` line goes to live** — every capability
  preserved, none thrust at the persona in the primary flow.

---

## 6. GUI layout specs (Slint scaffold)

The GUI mirrors the TUI skeleton as a fixed three-region frame. It is not a
different product; it is the same screen graph rendered with the same tokens
(system.md). Layout is expressed as region contracts a `.slint` window implements.

```
┌───────────────────────────────────────────────────────────────────────┐
│  TITLE REGION   (fixed height)                                         │
│  ├ screen title (type: title, one job)          ├ state token: ✓ ! ⊘   │
├───────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  CONTENT REGION  (flex)                                                │
│  ├ single centered column on single-purpose screens (S1,S2,S15,S16)   │
│  ├ two-pane list│detail on browse screens (H, S7)                      │
│                                                                       │
├───────────────────────────────────────────────────────────────────────┤
│  ACTION BAR      (fixed height)                                        │
│  ├ status text (last state-change, grave voice)                       │
│  ├ ▸ primary action button (accent.action) ── right-aligned           │
│  └ secondary actions as text buttons, left of primary                 │
└───────────────────────────────────────────────────────────────────────┘
```

GUI-specific specs, mapped to journeys:

| GUI screen | Region content | Primary action (`accent.action`) | Progressive disclosure |
|---|---|---|---|
| Trust gate (S1) | centered column; amber `!` banner if unverified | **Verify this copy** button | "Show the details" reveals a fingerprint panel (S2d) inline-collapsed |
| Verified (S3) | centered column; green `✓` line | **Continue** button | fingerprint panel stays collapsed under a disclosure triangle |
| Vault list (H) | left list rail / right detail pane | *(contextual)* | none |
| Item detail (S7) | detail pane; masked field | **Copy password** button | "Reveal" toggles mask; "Edit" opens form |
| Generate (S11) | result panel, mono password | **Copy** button | "Show the evidence" expands a collapsible stats panel (S11d) |
| Ways in (S10) | list of relationships | **Add a way in** button | per-row "Show the mechanics" disclosure (S10d) |
| Locked (S14) | centered `⊘` + one line | **Unlock** button | none — locked state shows only unlock |

GUI disclosure rule: technical evidence uses a **collapsible disclosure region**
(collapsed by default, a triangle/"Show…" affordance), never a permanently visible
side panel. This is the GUI analogue of the TUI `⋯` drill-down and enforces rule 2
in a windowed surface. The current `paranoid.slint` scaffold — which stacks
evidence panels visibly and drifts from the palette (see system.md §7) — is exactly
what this replaces.

Non-blocking is a GUI contract too: Verify (S2), key derivation (S15), and evidence
bundle production (S19) run off the UI thread with a visible progress affordance and
a live cancel/Esc, never freezing the window (brand.md §5.5; research lens 0 "never
freeze the UI").

---

## 7. Confirmation tiering (applied across the graph)

Research (CLIG severity-tiering) and brand.md §2.3 give a principled rule for which
actions get friction. Applied to this graph:

| Tier | Actions | Friction |
|---|---|---|
| **None** | copy, reveal, open item, navigate, generate, **panic-lock** | none — for panic, *speed is the safety property* (brand.md §2.3); for the rest, the act names itself and is non-destructive |
| **Standard** | edit item, add a way in, set hardware protection | a plain confirm; state what changed afterward (brand.md §3.1) |
| **Severe** | delete item, **remove a way in**, delete a vault, delete a decoy | must type the item/vault **name** or an explicit phrase — not `y/N` (research: "make it hard to confirm by accident… type the name of the thing you're deleting") |

The asymmetry is the point: **panic-lock has the least friction and permanent
destruction has the most.** A persona under duress must be able to lock in one
keystroke; a persona must be unable to *destroy a way in by accident* and lock
themselves out. This asymmetry is a direct discharge of the promise (brand.md §2).

---

## 8. Traceability — every journey lands on a screen

| Journey (journeys.md) | Screens (this doc) | Hero flow (brand.md §2) |
|---|---|---|
| J1 First contact / establish trust | S1, S2, S2d, S3, S3f | Trust earned in front of the user (§2.1) |
| J2 First password / evidence not dump | S11, S11d | — |
| J3 Create vault + first item | S4, S5, S8, S18 | — |
| J4 Daily unlock | S15, H, S7 | — |
| J5 Recovery without a backdoor | S10, S10d | — |
| J6 Coercion: decoy + panic + limits | S17, S13, S14 | Surrender supported (§2.2); speed = safety (§2.3) |
| J7 Someday-recovery | S1→S15, S16 | Trust re-earned on new machine (§2.1) |

Every journey has a home in the graph; every screen traces to a journey; every
screen obeys the five governing rules. Nothing in the current product's capability
set is removed — the 40-key `Controls:` wall is redistributed into contextual
footers (rule 3) and the `?` overlay (S12); every technical panel is relocated one
drill-level down (§4), not deleted. The persona is served by direction, at the
depth they are capable of, exactly as brand.md §1 requires.
