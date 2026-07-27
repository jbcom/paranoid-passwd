# paranoid-passwd — Design System & Tokens

This document turns [`brand.md`](./brand.md) §5 (palette, type scale, iconography,
layout) into **concrete, named tokens** and **component specs** that three
surfaces consume so they read as one product:

- the **ratatui** theme module (CLI/TUI — `crates/paranoid-cli`),
- the **Slint** styles (GUI — `crates/paranoid-gui/ui/paranoid.slint`),
- the **Sphinx** theme (docs/download site — `docs/_static/custom.css`).

It is the single source of truth for *values*. [`brand.md`](./brand.md) owns the
*meaning* of each value; [`ia.md`](./ia.md) owns *where* each component appears.
Nothing here is re-decided against brand.md — every token traces to brand.md §5,
cited inline. Every token is **named by intent, not by appearance** (brand.md §5.2;
research lens 0: "semantic color slots are named by function, not appearance").

> **Consumption rule.** A surface never hard-codes a hex, a size, or a spacing
> step. It reads the token. When a value must change, it changes here once and all
> three surfaces move together. The current drift (§7) — where the TUI, Slint, and
> CSS carry three slightly different palettes — is exactly the failure this rule
> exists to prevent.

---

## 1. Color tokens

The canonical values are the ones already correct in `docs/_static/custom.css` and
the ratatui constants, promoted here as authoritative (brand.md §5.2). Each token
has **one meaning** and is used only for that meaning. A color never carries meaning
alone — it always doubles a symbol or label so the monochrome layer works (brand.md
§5.1, §5.4).

| Token | Value | Meaning (brand.md §5.2) — used ONLY for this |
|---|---|---|
| `color.bg.base` | `#080c14` · `rgb(8,12,20)` | The ground. Near-black, low-glare; the whole surface. |
| `color.bg.panel` | `#0d1119` · `rgb(13,17,25)` | A raised panel or focused region. |
| `color.border` | `#17304b` · `rgb(23,48,75)` | Structure and separation between regions. |
| `color.text.primary` | `#e4e7f2` · `rgb(228,231,242)` | Primary reading text. |
| `color.text.muted` | `#95a0b8` · `rgb(149,160,184)` | Secondary text, labels, footer keys, hints. |
| `color.status.verified` | `#34d399` · `rgb(52,211,153)` | **Verified / safe / passed.** Earned only after a real check. |
| `color.accent.action` | `#60a5fa` · `rgb(96,165,250)` | **The one next thing to do.** One per screen, used sparingly. |
| `color.status.danger` | `#f87171` · `rgb(248,113,113)` | **Danger / failure / irreversible.** A stop, never decoration. |
| `color.status.caution` | `#fbbf24` · `rgb(251,191,36)` | **Attention / unverified / in-between** — a state to resolve. |

Two hard disciplines from brand.md §5.2, encoded as token-usage rules:

- **`color.status.verified` is earned.** No surface may use it as a default "all
  fine" wash; it appears only after an actual verification (binary matches release,
  randomness check passed, vault opened and trusted).
- **`color.status.danger` is reserved.** Only real danger — verification failed,
  unlock failed, irreversible destruction. Overuse trains the persona to ignore it.

There is **no `accent.secondary` and no decorative color.** The current TUI defines
a `PURPLE`/`#a78bfa` constant and the Slint scaffold uses off-palette shades
(`#f5d76e`, `#9fd4c9`, `#171d26`); none of these map to a brand.md meaning and all
are removed in favor of the nine tokens above (see §7).

### 1.1 Monochrome + 16-ANSI fallbacks (mandatory, brand.md §5.1)

Because a locked-down or remote terminal may render no truecolor — and because the
real/decoy distinction must never depend on color — every color token declares a
**16-ANSI fallback** and every meaning declares a **monochrome carrier** (the
symbol/weight that conveys it with zero color). This is the L0 (monochrome) and L1
(16-color) of brand.md's three-layer discipline.

| Token | 16-ANSI fallback | Monochrome carrier (the thing that still works with no color) |
|---|---|---|
| `color.bg.base` / `bg.panel` | default bg / reverse | panel = bordered box vs. unbordered ground |
| `color.text.primary` | default fg | normal weight |
| `color.text.muted` | bright-black (8) | dim modifier |
| `color.status.verified` | green (2) | `✓` glyph + the word *verified/passed* |
| `color.accent.action` | bright-blue (12) | `▸` marker + bold on the single next action |
| `color.status.danger` | red (1) | `✗` glyph + the word *failed/danger* |
| `color.status.caution` | yellow (3) | `!` glyph + the word *unverified/not set* |

**Test (brand.md §5.1):** strip all color — the product must remain fully usable and
the real/decoy vaults must remain indistinguishable. If a state reads *only* by its
color, that is a defect: fix the carrier, not the palette.

---

## 2. Spacing scale

One geometric-ish scale, four steps, so all three surfaces share rhythm. Named by
role. In the TUI, `space.*` maps to **cells** (ratatui `Margin`/`Layout`
constraints); in the GUI/docs, to **pixels/rem** (brand.md §5.5 "spatial
consistency").

| Token | TUI (cells) | GUI (px) | Docs (rem) | Role |
|---|---|---|---|---|
| `space.tight` | 1 | 6 | 0.375 | Between a label and its value; intra-row. |
| `space.snug` | 1 | 8 | 0.5 | Between stacked lines in a group. |
| `space.base` | 2 | 14 | 0.875 | Between groups; default panel padding. |
| `space.loose` | 3 | 22 | 1.375 | Between major regions; around the primary action. |

Panel padding is `space.base`; the gap between the two panes of a browse screen is
`space.base`; the gap around the single `accent.action` is `space.loose` so the one
next move has breathing room (ia.md §1, "the next action is singular and visible").

---

## 3. Type scale

Four steps, from brand.md §5.3. Hierarchy comes from **weight and spacing more than
size** (an austere instrument does not shout). The TUI expresses steps as
bold/normal/dim modifiers; the GUI/docs as sizes. Monospace is mandatory for
anything read character-by-character.

| Token | GUI/docs | TUI modifier | Role (brand.md §5.3) |
|---|---|---|---|
| `type.title` | 20px / 1.25rem, semibold | `BOLD` | Screen title — one per screen, states its one job. |
| `type.body` | 15px / 1rem, regular | *(normal)* | Primary content and reading text. |
| `type.label` | 13px / 0.85rem, medium, `text.muted` | `DIM` | Field labels, footer keys, hints. |
| `type.mono` | 15px / 1rem **monospace** | *(normal, mono cell)* | Secrets, hashes, phrases, generated passwords — anything read or copied character-by-character. |

Font families:

- **CLI/TUI:** monospace everywhere (the terminal's cell font).
- **GUI/docs:** a neutral sans for prose (`type.title/body/label`) paired with a
  monospace for values (`type.mono`). The docs Sphinx theme and the Slint GUI must
  pick the *same* monospace so a hash reads identically across surfaces.

`type.mono` is not merely a font choice — it is a safety property. A generated
password or recovery phrase shown in a proportional font can render `l/1/I` or `O/0`
ambiguously; `type.mono` guarantees every character is unambiguous (brand.md §5.3).

---

## 4. Component specs

Each component is defined once, in intent terms, then mapped to the primitive each
surface uses. This is the "note which token maps to which surface primitive"
requirement made explicit.

### 4.1 Panel

A raised, bordered region. The fixed layout skeleton (ia.md §1) is built from
panels.

| Property | Token | ratatui primitive | Slint primitive | Sphinx primitive |
|---|---|---|---|---|
| background | `color.bg.panel` | `Block.style(bg)` | `Rectangle.background` | `.pp-panel { background }` |
| border | `color.border`, 1 | `Borders::ALL` + `border_style` | `border-color` + `border-width:1px` | `border: 1px solid` |
| radius | (GUI/docs only) 6px / 0.5rem | *(n/a — cells)* | `border-radius:6px` | `border-radius` |
| padding | `space.base` | `Margin` | `padding` | `padding` |

The **focused** panel borders in `color.accent.action`; unfocused panels border in
`color.border`. This is how the eye finds the active region without the layout
moving (ia.md §1, rule 4).

### 4.2 Primary action (the one next move)

Exactly one per screen (ia.md §0 rule 5). It is the only element that may use
`color.accent.action`.

| Property | Token | ratatui | Slint | Sphinx |
|---|---|---|---|---|
| marker | `▸` glyph | prefix `▸ ` on the line | leading `▸` Text | `::before { content:"▸" }` |
| color | `color.accent.action` | `fg(BLUE)` | button accent color | `.pp-action { color }` |
| weight | bold | `Modifier::BOLD` | `font-weight:600` | `font-weight:600` |
| space around | `space.loose` | `Margin` | `padding`/`spacing` | `margin` |

Secondary actions render in `type.body` / `color.text.primary` with **no** accent —
so the single blue target is unmistakable (brand.md §5.2 "if everything is blue,
nothing is").

### 4.3 Input / secret field

For passphrase entry and item fields.

| Property | Token | ratatui | Slint | Sphinx (docs demos only) |
|---|---|---|---|---|
| text | `type.mono`, `color.text.primary` | mono line, `fg(TEXT)` | `TextInput` mono | `input[type=password]` mono |
| label | `type.label`, `color.text.muted` | `DIM` line above | `FieldLabel` | `<label class=pp-label>` |
| masked state | `••••` glyphs | masked string | `input-type: password` | native |

**Hard gate (brand.md §3 / CLIG, ia.md §3):** a secret field's value is *never*
sourced from a CLI argument — stdin/prompt/file only. This is a code contract the
input component enforces, not a styling note.

### 4.4 Status / danger states

Status is a symbol + word + color triple. The symbol and word are the monochrome
carriers; color reinforces (brand.md §5.4, §1.1 above).

| State | Symbol | Token | Where (ia.md) |
|---|---|---|---|
| verified / passed | `✓` | `color.status.verified` | S3, S11 verdicts; title-bar `✓` |
| failed / danger | `✗` | `color.status.danger` | S3f; unlock failure |
| attention / unverified | `!` | `color.status.caution` | S1 unverified; S5 no-hardware caveat |
| locked | `⊘` | `color.text.muted` (not danger — locking is safe) | S14; title-bar `⊘` |

`⊘` (locked) deliberately uses `color.text.muted`, **not** danger red: a locked
vault is the *safe* state, not a failure (brand.md §5.2 "red is a stop, never
decoration"). Coloring lock-state red would be a voice violation.

### 4.5 Footer (contextual keymap)

The footer is `type.label` / `color.text.muted`, one row, re-rendered per focused
pane (ia.md §3 rule; brand.md §3e). Keys render with their glyph (`↑↓ ⏎ ⎋`) from the
fixed icon set (brand.md §5.4). The footer never uses accent or status color — it is
chrome, not content.

### 4.6 Progress affordance (non-blocking ops)

Verify (S2), key derivation (S15), evidence-bundle (S19). A determinate or
indeterminate indicator in `color.accent.action` on `color.bg.panel`, with `⎋`
always live (brand.md §5.5; research lens 0 "never freeze the UI").

| Surface | Primitive |
|---|---|
| ratatui | `Gauge` with `gauge_style(fg(BLUE), bg(PANEL))` |
| Slint | a progress `Rectangle` / spinner off the UI thread |
| Sphinx | *(n/a — docs are static)* |

---

## 5. Iconography set (shared, brand.md §5.4)

A small fixed set, each a plain-text glyph that survives monochrome. No emoji, no
illustration, no mascots (brand.md §5.4 — "a celebration icon on a security event is
a voice violation").

| Glyph | Meaning | Pairs with | Where |
|---|---|---|---|
| `✓` | verified / passed | `color.status.verified` + a word | status, title bar |
| `✗` | failed / danger | `color.status.danger` + a word | status |
| `!` | attention / unverified | `color.status.caution` + a word | status, caveats |
| `⊘` | locked | `color.text.muted` + a word | title bar, S14 |
| `▸` | the one next action | `color.accent.action` + bold | primary action |
| `↑ ↓ ⏎ ⎋` | navigation | `color.text.muted` | footers only |
| `⋯` | drill into evidence | `color.text.muted` | `⋯ Show the details/evidence/mechanics` |

`⋯` is the shared affordance for progressive disclosure (ia.md §2, §4): the same
glyph means "there is real depth one level down here" on every surface — a TUI
drill-down, a GUI disclosure triangle, a docs collapsible.

---

## 6. The shared token module (how each surface consumes it)

The tokens above are authored **once** and consumed three ways. The mechanism:

- **ratatui theme module** — `crates/paranoid-cli/src/theme.rs` (new; consolidates
  the duplicated `const BG/PANEL/…` currently in both `tui.rs` and `vault_tui.rs`).
  Exposes `Color` constants and `Style` helpers named by token
  (`theme::accent_action()`, `theme::verified()`), plus the 16-ANSI fallback map for
  terminals without truecolor. Both TUIs import from it; no file defines its own
  colors.
- **Slint styles** — a `paranoid-tokens.slint` `global` block exporting `brush` and
  `length` properties named by token (`Tokens.accent-action`, `Tokens.space-base`).
  `paranoid.slint` components reference `Tokens.*`, never literal hexes.
- **Sphinx theme** — the `:root` custom properties in `docs/_static/custom.css`
  (`--pp-*`), already the canonical source, extended to cover spacing/type tokens
  (`--pp-space-base`, `--pp-type-title`) so docs components read tokens too.

Because all three read the same nine colors, four spaces, four type steps, and one
icon set, a persona moving from the download page to the GUI to the TUI sees **one
product** (directive PUX.4; brand.md §6).

### 6.1 Token → primitive quick map

| Token | ratatui | Slint | Sphinx |
|---|---|---|---|
| `color.*` | `Color::Rgb` const in `theme.rs` | `Tokens.<name>: brush` | `--pp-<name>` |
| `space.*` | cells in `Layout`/`Margin` | `Tokens.<name>: length` | `--pp-space-<name>` |
| `type.title/body/label` | `Modifier` (BOLD/DIM) | `font-size`/`font-weight` | `--pp-type-<name>` |
| `type.mono` | cell font (implicit) | monospace `font-family` | `font-family: monospace` |
| icons | literal glyph in strings | literal glyph in `Text` | literal glyph / `::before` |

---

## 7. Drift to reconcile (current-state audit)

The three surfaces have **diverged** from the canonical palette. This section
records the drift so P8 fixes it against the tokens above, not against whichever
value each file happens to hold. This is the concrete instance of the consumption
rule (§0) being currently violated.

| Surface | Current value | Canonical token | Action |
|---|---|---|---|
| `custom.css` `--pp-*` | matches brand.md §5.2 exactly | — | **authoritative**, keep; extend with space/type tokens |
| ratatui `BG/PANEL/TEXT/GREEN/BLUE/AMBER/RED` | match brand.md §5.2 exactly | — | keep values; move into `theme.rs`, de-duplicate across the two TUI files |
| ratatui `PURPLE = #a78bfa` | *(no brand.md meaning)* | — | **remove** — off-palette, maps to no intent |
| Slint `Panel background #171d26` | `color.bg.panel #0d1119` | `color.bg.panel` | **retune** to `#0d1119` |
| Slint `border #314154 / #405368 / #4c6178` | `color.border #17304b` | `color.border` | **retune** to `#17304b` (one border token, not three) |
| Slint `SectionTitle #f2f5ff` | `color.text.primary #e4e7f2` | `color.text.primary` | **retune** |
| Slint accent `#9fd4c9`, `#f5d76e`, `#1f2a37`, `#1b2a26` | verified/caution/panel intents | map to `verified/caution/bg.panel` | **retune** to canonical status tokens |
| Slint `font-size 34px` hero, `18px/16px` | `type.title 20px` | `type.title` | **retune** to the four-step scale (no 34px) |

The reconciliation is not cosmetic: the drifted Slint palette makes the GUI read as
a *different* product than the TUI and docs, which directly violates brand.md §6 and
the PUX.4 mandate that all three "read as one product." After §6's token module
lands, no surface carries its own literal values and this drift cannot recur.

---

## 8. What this binds

- **ratatui theme** (`theme.rs`) consumes §1–§5 and eliminates the duplicated
  per-file color constants (§7).
- **Slint styles** (`paranoid-tokens.slint`) consume §1–§5 and retune off the
  drifted values (§7) onto the canonical tokens.
- **Sphinx theme** (`custom.css`) is the already-canonical color source, extended
  to carry space/type tokens.
- **ia.md** components (panels, primary action, footer, status, drill-down `⋯`) are
  rendered from §4's specs on every surface, so a screen in the TUI, the GUI, and a
  docs mockup are visibly the same component.
- **P8 build items** implement these tokens and specs rather than re-picking values;
  any P8 color, size, or spacing that contradicts this document is a defect against
  the system (mirrors brand.md §6).
