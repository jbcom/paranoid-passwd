# paranoid-passwd — Brand Foundation

This document binds every surface: the CLI, the TUI, the GUI scaffold, and the
docs/download site. It is the source of truth for what the product is *for*,
how it speaks, and how it looks. Downstream work — journeys (PUX.2), information
architecture (PUX.3), and tokens (PUX.4) — inherits from here and does not
re-decide it.

Every choice below is anchored to one person and one threat model. When a
design question arises that this document does not answer, resolve it by asking:
*does this serve the targeted individual under coercion, offline, with a local
adversary?* — not *does this look finished?*

---

## 1. Who this is for

**The primary persona is the targeted individual.** An activist, a journalist,
a source, a person under real coercion or surveillance risk. Not the security
hobbyist, not the enterprise admin, not the engineer evaluating crypto. Those
people can use the product, but they are not who it is *designed for*, and when
their needs conflict with the persona's, the persona wins.

What is true of this person:

- **They are capable, not naive.** They understand that they are a target. They
  do not need concepts dumbed down — they need them *directed*. The failure of
  the product today is not that it is too technical; it is that it dumps
  technical data with no narrative and no answer to "what do I do next."
  (Research lens 0: the persona "is capable, just not served by undirected
  data.")
- **Their threat model is offline, local, and coercive** — a seized device, a
  border stop, a raid, someone standing over their shoulder, someone with
  physical access and time. It is **not** a network threat model. The product
  makes no promises about, and asks for no trust in, a network it never touches.
- **The stakes are real.** A wrong turn is not an inconvenience; it can be a
  disclosure that costs someone their safety. The product must never offer false
  comfort, never bury a consequence, and never let a destructive action feel
  routine.
- **They may be operating under duress right now.** Any screen may be viewed by
  a coercer. Any keystroke may be watched. The interface must behave the same
  whether the real vault or a decoy is open, so that the framing itself reveals
  nothing (research lens 0: consistent framing across real/decoy vaults "is
  itself a duress-relevant property").

---

## 2. The one promise the name makes

> **paranoid-passwd assumes the person you are hiding from is already here —
> with your device, with time, and with leverage over you — and it is still on
> your side.**

The name is not a mood or a marketing adjective. "Paranoid" is a *specification*.
It commits the product to designing for the adversary who has already won every
advantage a network-threat tool assumes away: physical possession, patience, and
the ability to compel. Everything the product does — verifying its own binary
before you trust it, offering a decoy vault you can surrender, locking instantly
on a panic key — is the discharge of that one promise.

This promise governs three consequences that appear everywhere downstream:

1. **Trust is earned in front of the user, not assumed.** Before the product
   asks the persona to rely on it, it gives them the means to verify it is the
   real, unmodified binary. (Hero flow: establish trust.)
2. **Surrender is a supported operation.** Recovery, duress, and decoy vaults
   exist so that a person who is compelled has something safe to give up. The
   product plans for the moment the persona loses.
3. **Speed is the safety property for panic.** Panic-lock is instant and
   low-friction *because* being fast is what protects — the opposite of the
   high-friction confirmation that guards permanent destruction. (Research:
   CLIG severity-tiering — "panic-lock (fast, reversible-by-design) can be
   low-friction/instant since speed is the safety property.")

---

## 3. Voice & tone

The voice is **grave, precise, and respectful**. It speaks to a competent adult
who is in a serious situation. Zero whimsy. No marketing gloss. No false comfort.
No exclamation points, no reassurance the product cannot honestly give.

### Rules

1. **State what is true and what changed.** After any state change, say plainly
   what happened. (Research: CLIG — "if you change state, tell the user.")
   Never leave the persona guessing whether an action took effect.
2. **Errors are guidance, not crash dumps.** Rewrite every failure as one calm
   sentence that tells the person what to do next. Never surface a raw crypto
   error code, an enum name, or a stack detail in the primary flow. (Research:
   CLIG — "Catch errors and rewrite them for humans… think of it like a
   conversation.")
3. **Name the consequence before the action, in proportion to its weight.** A
   copy is silent. A deletion states what is lost. An irreversible action states
   it is irreversible *and* makes the person type the thing's name.
4. **Never overpromise.** The product does not say "you are safe." It says what
   it did and what remains true. Safety is the persona's to judge; the product's
   job is to report accurately.
5. **Respect capability.** Do not explain what the persona already knows, and do
   not hide depth they may want. Lead with intent; keep the technical evidence
   real and reachable one level down (progressive disclosure), never deleted and
   never thrust forward.
6. **One voice across every surface.** A string in the TUI footer, a Sphinx page
   heading, and a GUI dialog are the same product speaking. No surface gets a
   lighter or breezier register.

### Rewrites — five current strings into the product's voice

These are real strings from the current surfaces. Internal names stay in code
(see §4); only the presentation changes.

**(a) The "keyslot" concept** — internal `keyslot`, currently surfaced verbatim.

> Current: `Keyslots (3)` / "Inspect and enroll recovery or unlock keyslots
> without leaving the native TUI."
>
> Voice: **`Ways in (3)`** / "The keys and phrases that can open this vault. Add
> a recovery phrase, bind a device, or remove a way in you no longer trust."

Rationale: the persona thinks in "how can this vault be opened, and by whom,"
not in cryptographic slot mechanics. "Ways in" names the security-relevant
question — *who or what can unlock me* — which is exactly the question a targeted
person needs to audit.

**(b) "Seal-provider posture"** — internal `seal posture` / `Seal-provider
posture`.

> Current: `Seal-provider posture` / "No seal providers configured yet (expected
> before vault init)."
>
> Voice: **`Hardware protection`** / "This vault is not yet tied to this
> device's secure hardware. Once it is set up, an attacker who copies the vault
> file to another machine cannot open it there."

Rationale: "seal-provider posture" is three engineer nouns stacked; it tells the
persona nothing about the protection it represents. The rewrite names the actual
guarantee in threat-model terms the persona cares about: *can my vault be opened
on a machine that isn't mine.*

**(c) "Federal evidence" / "federal-ready"** — internal `federal-evidence`,
`FederalReady`, an ops/compliance profile.

> Current: `--federal-evidence`, `federal-ready`, "US federal digital identity
> guidance."
>
> Voice (user-facing surface): **`Evidence bundle`** / "Produce a signed,
> timestamped record of this vault's integrity you can hand to a lawyer,
> auditor, or court." The compliance-profile flag becomes **`--assurance
> strict`** with the plain description "Apply the strictest audit and evidence
> rules."

Rationale: "federal" and "federal evidence" read as US-government branding on a
tool whose persona is often *adversarial to* a government, and it buries the
actual function: producing a defensible integrity record. The rewrite names the
deliverable and its use, without geopolitical framing the persona may find
alarming or irrelevant. (Internal profile name `FederalReady` stays in code.)

**(d) "Unlock blocked: no secret"** — internal status string in `screen_state`.

> Current: `Unlock blocked: no secret` / `Unlock blocked: {error}`
>
> Voice: **`Nothing entered yet — type your passphrase, or press ? for other
> ways in.`** For a real failure: **`That didn't open the vault. Check your
> passphrase and try again — remaining attempts: {n}.`**

Rationale: "blocked" reads as the product refusing the person; "no secret" is
implementation vocabulary. The rewrite treats a failed unlock as a calm
conversation, states the remaining-attempts fact plainly (a real consequence the
persona must know), and points to recovery paths without lecturing. (Research:
CLIG error-as-conversation; "if you change state, tell the user.")

**(e) The 40-hotkey controls line** — the single flat string listing every key.

> Current: "Controls: Up/Down select items, / filters, a adds login, n adds
> secure note, v adds card, i adds identity, e edits, d deletes, g generates and
> stores one password, x exports backup, t exports transfer, u imports backup,
> p imports transfer, k opens keyslots, E reviews environment approval, c copies
> the selected value, r refreshes, q quits."
>
> Voice (footer, scoped to the item list — L0/L1 only): **`↑↓ move   ⏎ open
> a new   / find   ? all keys   q quit`** with everything else moved behind `?`.

Rationale: the flat 40-key line is the "hotkey wall" the research names directly.
Best-in-class TUIs (lazygit, k9s) show only 3–5 keys in the footer, scoped to the
focused pane, and move the rest to a `?` overlay (research lens 0: the four-layer
keyboard architecture, footer re-rendering per pane). The rewrite keeps every
capability — nothing is removed — but stops thrusting all of it at a person who
is trying to do one thing. The footer must re-render per focused pane; the item
list, the "ways in" view, and a decoy vault each get their own minimal footer.

### Micro-examples (register calibration)

| Situation | Wrong (whimsy / gloss / dump) | Right (grave, precise) |
|---|---|---|
| Vault opened | "You're in! 🎉" | "Vault open. 12 items." |
| Panic-lock fired | "Locked down tight!" | "Locked. Nothing is readable until you unlock again." |
| Verification failed | "Signature mismatch: E_SIG_0x2" | "This copy does not match the published release. Do not trust it — re-download and verify before using." |
| Decoy vault created | "Decoy ready to fool 'em!" | "Decoy vault created. It opens with its own passphrase and looks identical to a real vault." |
| Copied a password | "Copied to clipboard!" | "Copied. It clears from the clipboard in 30 seconds." |

---

## 4. User-facing vocabulary

Internal names stay in code — this is a *presentation* mapping, not a rename of
types, fields, flags-in-source, or APIs. Only what the persona reads changes.
The right column is the only vocabulary that appears on a user-facing surface.

| Internal term (stays in code) | What the user sees | Why |
|---|---|---|
| `keyslot` | **way in** | Names *who/what can open the vault* — the question the persona audits. |
| `recovery keyslot` | **recovery phrase** | It is a phrase you write down; say so. |
| `device-bound keyslot` | **this device** | It is "this machine can open it without a phrase." |
| `certificate-wrapped keyslot` | **trusted contact** / **held key** | A key someone else holds; name the relationship, not the wrapping. |
| `seal provider` / `seal posture` | **hardware protection** | Names the guarantee (bound to this device's secure hardware), not the mechanism. |
| `federal evidence` / `federal-ready` | **evidence bundle** / **strict assurance** | Names the deliverable and its use; drops government branding. |
| `ops profile` | **assurance level** | The persona chooses how strict, not an "ops" mode. |
| `unlock blocked` | *(rewritten inline — see §3d)* | "Blocked" reframes the product as the obstacle; it isn't. |
| `chi-squared pass` / `p > 0.01` | **randomness check: passed** | The math stays exact internally; the persona sees the verdict, with the math one level down. |
| `rejection sampling` | *(not surfaced)* | Implementation detail; belongs in docs, never in the primary flow. |
| `duress vault` | **decoy vault** | "Decoy" names its purpose to the persona: the thing you safely give up. |
| `panic-lock` | **panic lock** *(kept)* | Already plain and correct; the persona's own word. |
| `attestation` | **verify this copy** | Names the action the persona takes, not the cryptographic noun. |
| `master key` / `vault master key` | *(not surfaced)* | Internal; the persona never handles it directly. |

Two hard rules bind this table:

- **The real vs. decoy distinction must survive with zero vocabulary or color
  cues.** A shoulder-surfer must not be able to tell which is open from any label
  or shade. Whatever distinguishes them for the *owner* must be something only
  the owner knows (which passphrase they typed), never something on screen.
  (Research lens 0: "Never rely on color alone to distinguish the real vault
  from a decoy — that distinction must survive monochrome.")
- **Depth is reachable, never deleted.** Every internal term above still exists
  one drill-level down for the persona who wants it (research lens 0: k9s-style
  drill-down; "technical/engineer vocabulary stays real but moves to the bottom
  of the drill stack, reachable but not thrust at the user"). Progressive
  disclosure hides depth by default; it never removes it.

---

## 5. Visual identity

The direction is **austere, high-contrast, and deliberate**. Nothing decorative.
Every visual element earns its place by carrying meaning. The look should feel
like an instrument, not an app — closer to a cockpit gauge than a consumer
dashboard.

### 5.1 The three-layer discipline (non-negotiable)

Design is verified in three enforced layers, in order (research lens 0):

1. **Monochrome baseline** — the interface must be *fully usable and
   directionally clear with zero color*. Hierarchy comes from layout, weight,
   spacing, and symbols first. This is not an accessibility nicety for this
   persona: a locked-down, remote, or minimal terminal may not render color at
   all, and the real/decoy distinction must never depend on color.
2. **16-ANSI-color pass** — verify hierarchy still reads under a plain terminal
   theme; color only *reinforces* status meaning already established by layout.
3. **True-color / GUI beauty layer** — the palette below applies here as polish,
   never as the thing that makes the design work.

The test: *if you stripped all color, the product must remain fully usable.* If
it doesn't, the design is broken — fix the layout, not the palette.

### 5.2 Palette, with intent

These values are the existing product palette (docs `custom.css`, GUI
`paranoid.slint`), promoted here as the canonical set. Each has a single meaning;
color is a **semantic slot named by function, not appearance** (research lens 0).
A color never carries meaning alone — it always doubles a symbol or label so the
monochrome layer still works.

| Slot | Value | Meaning — used ONLY for this |
|---|---|---|
| `bg.base` | `#080c14` | The ground. Near-black, low-glare. The whole surface sits here. |
| `bg.panel` | `#0d1119` | A raised panel or focused region. |
| `border` | `#17304b` | Structure and separation between regions. |
| `text.primary` | `#e4e7f2` | Primary reading text. |
| `text.muted` | `#95a0b8` | Secondary/supporting text, labels, hints. |
| `status.verified` | `#34d399` (green) | **Verified / safe / passed.** Binary matches the release; randomness check passed; vault open and trusted. Nothing "good" that is not *verified* may use this. |
| `accent.action` | `#60a5fa` (blue) | **The one thing to do next.** The single primary action or focus target on a screen. Used sparingly — if everything is blue, nothing is. |
| `status.danger` | `#f87171` (red) | **Danger / failure / irreversible.** Verification failed, unlock failed, and irreversible destruction. Red is a stop, never decoration. |
| `status.caution` | `#fbbf24` (amber) | **Attention / unverified / in-between.** Not yet verified, hardware protection not set, recovery not configured — states the persona should resolve but that are not failures. |

Discipline for this persona:

- **Red is reserved for real danger.** Overusing red trains the persona to
  ignore it; when it appears, it must mean stop.
- **Verified-green is *earned*.** It appears only after an actual verification,
  never as a default "everything's fine" wash. The persona must never see green
  for a state that was merely assumed rather than checked.
- **The decoy vault uses the identical palette.** No shade, tint, or accent
  distinguishes real from decoy — the surrender operation depends on them being
  visually indistinguishable.

### 5.3 Type scale

One scale, four steps. Hierarchy comes from *weight and spacing more than size* —
an austere instrument does not shout with large type. In the TUI this maps to
bold / normal / dim; in the GUI and docs to the point sizes below (monospace
everywhere for the CLI/TUI; the GUI and docs may pair a neutral sans for prose
with a monospace for values/secrets/hashes).

| Step | GUI/docs size | TUI equivalent | Use |
|---|---|---|---|
| `title` | 20 px / 1.25rem, semibold | bold | Screen title — one per screen, states its single job. |
| `body` | 15 px / 1rem, regular | normal | Primary content and reading text. |
| `label` | 13 px / 0.85rem, medium, `text.muted` | dim | Field labels, footer keys, supporting hints. |
| `mono` | 15 px / 1rem monospace | normal mono | Secrets, hashes, phrases, generated passwords — anything the persona reads character-by-character or copies. Always monospace so no character is ambiguous. |

### 5.4 Iconography stance

**Restraint.** Icons are functional glyphs, never illustration and never
personality. Prefer a small, fixed set of unambiguous symbols that also read in
plain text:

- `✓` verified / passed — always paired with `status.verified` and a word.
- `✗` failed / danger — always paired with `status.danger` and a word.
- `!` attention / unverified — always paired with `status.caution` and a word.
- `↑ ↓ ⏎ ⎋` navigation, in footers only.
- **No emoji anywhere.** No mascots, no celebratory marks, no decorative flair.
  A celebration icon on a security event is a voice violation, not just a visual
  one.

Every icon must survive the monochrome layer — a symbol first, a color second.
An icon that only reads because of its color is a defect.

### 5.5 Layout stance

Downstream (PUX.3) owns the screen graph, but the visual identity fixes these
invariants now:

- **Spatial consistency.** Panels hold fixed positions and never rearrange
  without an explicit user action (research lens 0). The persona's eyes learn
  the geometry; a decoy vault and a real vault present the identical skeleton.
- **One job per screen, stated in the title.** No screen is a dumping ground of
  panels. Technical evidence lives one drill-level down, reached deliberately.
- **The next action is always visible and singular.** Every screen answers "what
  do I do next" with one blue `accent.action` target; the footer shows only the
  3–5 keys valid right now.
- **Nothing blocks.** Derivation, verification, and unlock run without freezing
  the interface, with a visible progress affordance, and `⎋` always returns to a
  responsive state (research lens 0: "Never freeze the UI… the user should always
  be able to press Esc"). A coerced persona must never be trapped in a frozen
  screen.

---

## 6. What this binds

- **PUX.2 (journeys)** storyboards the hero flows named in §2 — establish trust,
  recovery + duress/decoy, panic-lock — in this voice, with this vocabulary.
- **PUX.3 (IA)** builds the drill-down screen graph on §5.5's invariants and
  §4's progressive-disclosure rule.
- **PUX.4 (tokens)** turns §5's palette, type scale, and icon set into shared
  tokens consumed by the ratatui theme, the `.slint` styles, and the Sphinx
  theme, so all three surfaces are visibly one product.
- **P8 (build)** implements the above rather than re-deciding it. Any P8 string,
  color, or key that contradicts this document is a defect against the brand.
