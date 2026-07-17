# paranoid-passwd — User Journeys

This document storyboards the real end-to-end journeys of the **primary persona**
— the targeted individual (activist, journalist, source, person under coercion or
surveillance risk) — as defined in [`brand.md`](brand.md) §1. It inherits every
decision made there: the one promise (§2), the grave/precise/respectful voice
(§3), the user-facing vocabulary (§4), and the austere high-contrast visual
identity (§5). It does not re-decide any of them; where a phrase appears here it
is the phrase brand.md already fixed.

Downstream, [`ia.md`](ia.md) (PUX.3) turns these storyboards into the screen graph
and the drill-down structure; the journeys are the *why* the screens exist.

## How to read a storyboard

Each journey is told twice:

- **Current state** — where the product actually leaves the persona today, and the
  exact moment it dead-ends in "a box of data with no answer to *what do I do
  next*." These are grounded in the real surfaces named in brand.md §3 (the
  verbatim `Keyslots (3)`, `Seal-provider posture`, `--federal-evidence`,
  `Unlock blocked: no secret`, and the 40-key `Controls:` line).
- **Designed state** — a step-by-step storyboard. Every step names three things:
  1. **Intent** — what the persona is trying to accomplish at this step.
  2. **Emotion** — the felt state (calibrated to the register in brand.md §3:
     graveness earned, never manufactured anxiety, never false comfort).
  3. **What do I do next** — the single answer the screen must give. Per brand.md
     §5.5, every screen answers this with one `accent.action` target and a footer
     of only the 3–5 keys valid right now. **No step ends in a box of data.**

The design principle that governs all seven journeys, stated once:

> **A screen may present depth, but it must never present *only* depth.** Every
> surface leads with intent and offers exactly one next move; the technical
> evidence the persona is capable of reading sits one drill-level down, reachable
> and real, never thrust forward and never deleted (brand.md §4, "Depth is
> reachable, never deleted"; research lens 0, k9s drill-down).

---

## Journey 1 — First contact: establish trust before trusting it

**The hero flow that discharges promise-consequence #1** (brand.md §2.1): *trust
is earned in front of the user, not assumed.* The persona has just obtained the
binary. They are a target; they assume a supply-chain or on-device tamper is
plausible. The product must let them verify it is the real, unmodified release
**before** it asks for a single secret.

### Current state

The persona runs the binary. It drops them into a TUI (or, worse, straight into a
vault-unlock prompt) with the 40-key `Controls:` line at the bottom. Verification
exists only as the engineer noun `attestation` and the `--federal-evidence` /
`federal-ready` flags — vocabulary that reads as US-government branding to a
persona often adversarial to a government (brand.md §3c). **Dead-end:** there is
no first-run moment that says "here is how to confirm this copy is genuine before
you rely on it." The single most important act for this persona — verifying trust
*first* — is buried behind a compliance flag and never offered as a step.

### Designed state

```
┌─ Step 1 · First run ─────────────────────────────────────────────┐
│ TITLE:  paranoid-passwd                                           │
│                                                                   │
│   Before you trust this program with anything, confirm it is the  │
│   genuine, unmodified release.                                    │
│                                                                   │
│   [!] This copy has not been verified on this machine yet.        │
│                                                                   │
│   ▸ Verify this copy                            ← accent.action   │
│     Skip for now                                                  │
│                                                                   │
│ FOOTER:  ↑↓ move   ⏎ select   ? help   q quit                     │
└───────────────────────────────────────────────────────────────────┘
```

- **Step 1 — Land on the trust screen.**
  - *Intent:* find out whether this program can be trusted at all.
  - *Emotion:* alert, appropriately wary — the product meets the wariness instead
    of papering over it. The amber `[!]` (brand.md §5.4) names an unresolved
    state, not a failure.
  - *What do I do next:* one primary action, **Verify this copy** (the §4 rename
    of `attestation`). "Skip for now" exists but is not the accent target — the
    product's posture is *verify first*.

- **Step 2 — Verification runs (non-blocking).**
  - *Intent:* watch the check happen without being trapped.
  - *Emotion:* engaged, in control. A determinate/indeterminate progress
    affordance shows; `⎋` stays live the whole time (brand.md §5.5, "Nothing
    blocks"). The persona is never frozen — a property that matters even here,
    because a coerced user must never be stuck.
  - *What do I do next:* wait, or press `⎋` to return. Nothing else competes.

- **Step 3a — Verified.**
  - *Intent:* confirm the copy is genuine and proceed.
  - *Emotion:* earned reassurance — the first legitimate use of
    `status.verified` green (brand.md §5.2, "Verified-green is *earned*"; it
    appears only after an actual check).
  - *Copy:* `✓ This copy matches the published release. Its fingerprint is
    shown below.` The raw signature / hash / release metadata sits one drill-level
    down under **Show the details** — real, reachable, not thrust forward.
  - *What do I do next:* one action, **Continue** → sets up the first vault
    (Journey 3). Trust established; now the product may ask for secrets.

- **Step 3b — Not verified.**
  - *Intent:* understand the failure and not proceed on a tampered copy.
  - *Emotion:* grave — this is exactly when red must mean *stop* (brand.md §5.2).
  - *Copy (brand.md §3 micro-example, verbatim):* `✗ This copy does not match the
    published release. Do not trust it — re-download and verify before using.`
    No raw `E_SIG_0x2` in the primary flow (brand.md §3 rule 2).
  - *What do I do next:* **Where to re-download safely** (guidance, not a
    dead-end error). The product refuses to walk the persona into a compromised
    binary and tells them the one safe next move.

---

## Journey 2 — First password generated: evidence as reassurance, not a dump

The persona generates their first password. The audit math is the product's proof
that the output is genuinely unpredictable — but the persona needs the *verdict*
first, with the math reachable, never a wall of statistics thrust at them
(brand.md §4: `chi-squared pass` / `p > 0.01` → **randomness check: passed**, "the
math stays exact internally; the persona sees the verdict, with the math one level
down").

### Current state

Generation produces the password plus a panel of audit output that surfaces
`chi-squared pass`, `p > 0.01`, entropy figures, and rejection-sampling framing as
raw engineer data. **Dead-end:** the persona is handed a correct, valuable result
wrapped in statistics with no sentence telling them *this means your password is
sound, here is how to use it.* The evidence is present but undirected — the exact
failure brand.md §1 names.

### Designed state

```
┌─ Password generated ─────────────────────────────────────────────┐
│ TITLE:  Your new password                                        │
│                                                                   │
│   ▏ 4mK$w9!qL2vT· ·rX7@nB               (mono, char-by-char)     │
│                                                                   │
│   ✓ Randomness check: passed                                     │
│     This password is drawn from a verified-uniform source.        │
│                                                                   │
│   ▸ Copy                                        ← accent.action   │
│     Generate another                                             │
│     Show the evidence                                            │
│                                                                   │
│ FOOTER:  ⏎ copy   g regenerate   ? help   ⎋ back                  │
└───────────────────────────────────────────────────────────────────┘
```

- **Step 1 — See the password and the verdict together.**
  - *Intent:* get a strong password and know it is strong.
  - *Emotion:* quiet confidence. The password renders in `mono` so no character is
    ambiguous (brand.md §5.3). The green `✓ Randomness check: passed` is the
    reassurance — a *verdict*, one line, earned by a real check.
  - *What do I do next:* **Copy** is the single accent action.

- **Step 2 — Copy, and be told what happens next.**
  - *Intent:* use the password without leaving it exposed.
  - *Emotion:* reassured by precision, not by cheer.
  - *Copy (brand.md §3 micro-example, verbatim):* `Copied. It clears from the
    clipboard in 30 seconds.` The product states the consequence plainly (§3 rule
    1, "if you change state, tell the user") — a real safety fact, not "Copied!".
  - *What do I do next:* return to the vault, or generate another.

- **Step 3 — (Optional) Show the evidence.**
  - *Intent:* for the capable persona who *wants* the math — audit it.
  - *Emotion:* respected. Depth is offered, not imposed (brand.md §4).
  - *Content one level down:* the exact chi-squared statistic, degrees of freedom
    `N − 1`, the `p > 0.01` pass threshold, entropy, and the rejection-sampling
    note. The math is unchanged and honest; it simply is not the first thing the
    persona must read.
  - *What do I do next:* `⎋` back to the verdict. The drill-down has a clear way
    up (research lens 0).

---

## Journey 3 — Create the vault and its first item

Trust is established (Journey 1). Now the persona needs somewhere to keep secrets.
This journey creates the vault and lands the first item, without front-loading
keyslot mechanics or seal-provider vocabulary.

### Current state

Vault setup exposes `Seal-provider posture` ("No seal providers configured yet
(expected before vault init)") and `Keyslots (3)` immediately — the persona is
asked to reason about seal-provider posture and cryptographic slots before they
have stored a single password. **Dead-end:** the setup screen is a panel of
engineer state (`Seal-provider posture`, keyslot counts) with no narrative path
from "I have nothing" to "my first secret is safely stored."

### Designed state

- **Step 1 — Name the vault and set the passphrase.**
  - *Intent:* create the container and the way to open it.
  - *Emotion:* deliberate. This is the root of everything; the product is calm and
    unhurried.
  - *Guardrail:* the passphrase is entered via stdin/prompt only — **never** as a
    CLI arg (brand.md §3 references CLIG "never accept secrets via flags";
    process-list/shell-history leakage). This is a hard code-review gate, not a
    suggestion.
  - *What do I do next:* one action, **Create vault**. Keyslots and hardware
    protection are *not* on this screen.

- **Step 2 — Vault created; state what is true.**
  - *Intent:* know the vault exists and what protects it right now.
  - *Emotion:* grounded, with one honest caveat surfaced, not buried.
  - *Copy:* `Vault created. It opens with your passphrase.` Then, in amber (a
    state to resolve, not a failure): `[!] Hardware protection is not set. An
    attacker who copies this vault file to another machine could try to open it
    there.` — the §4 rename of `seal posture`, stated as the actual guarantee
    (brand.md §3b), and honest about what is *not* yet true.
  - *What do I do next:* **Add your first item** (accent) — the caveat offers
    **Set up hardware protection** as a secondary, reachable path, but the primary
    story continues toward using the vault.

- **Step 3 — Add the first item.**
  - *Intent:* store something real.
  - *Emotion:* the product becoming useful; low ceremony.
  - *What do I do next:* choose a type (login / note / card / identity — the
    capabilities from the old `Controls:` line, now scoped to *this* screen's
    footer, not a global wall), fill it, **Save**.

- **Step 4 — Item saved; vault has a purpose now.**
  - *Intent:* confirm it landed and see the vault populated.
  - *Emotion:* settled.
  - *Copy:* `Saved. Your vault has 1 item.` (§3 rule 1.)
  - *What do I do next:* the vault list (Journey 4's home). The footer re-renders
    to the item-list context: `↑↓ move   ⏎ open   n new   / find   ? all keys   q
    quit` (brand.md §3e).

---

## Journey 4 — Daily unlock

The most-repeated journey. It must be fast, calm, and never punish the persona for
a mistyped passphrase with implementation vocabulary. It also carries a
duress-relevant invariant: the unlock screen looks identical whether the real or a
decoy vault is behind it.

### Current state

The unlock path can emit `Unlock blocked: no secret` and `Unlock blocked:
{error}` — "blocked" frames the product as the obstacle, "no secret" is
implementation vocabulary, and a real failure risks surfacing a raw error
(brand.md §3d). **Dead-end:** a failed unlock leaves the persona staring at a
status string that neither guides them nor tells them the one fact they must know
— how many attempts remain.

### Designed state

- **Step 1 — Unlock prompt.**
  - *Intent:* open the vault.
  - *Emotion:* routine, unhurried. Identical framing for real and decoy (brand.md
    §4 hard rule 1; research lens 0: consistent framing is itself a duress
    property). Nothing on screen betrays which vault this passphrase will open.
  - *What do I do next:* type the passphrase. Empty-state copy (brand.md §3d,
    verbatim): `Nothing entered yet — type your passphrase, or press ? for other
    ways in.`

- **Step 2 — Derivation runs (non-blocking).**
  - *Intent:* wait for the key derivation without being trapped.
  - *Emotion:* patient; in control because `⎋` is live.
  - *What do I do next:* wait, or `⎋`. Argon2/scrypt-class derivation runs as a
    background task with a progress affordance (brand.md §5.5; research lens 0:
    "never freeze the UI").

- **Step 3a — Opened.**
  - *Intent:* get to the items.
  - *Emotion:* neutral competence — not celebration.
  - *Copy (brand.md §3 micro-example, verbatim):* `Vault open. 12 items.`
  - *What do I do next:* the item list.

- **Step 3b — Wrong passphrase.**
  - *Intent:* understand the failure and know the stakes.
  - *Emotion:* corrected, not scolded; aware of the consequence.
  - *Copy (brand.md §3d, verbatim):* `That didn't open the vault. Check your
    passphrase and try again — remaining attempts: {n}.` The remaining-attempts
    count is a real consequence stated plainly (§3 rule 3).
  - *What do I do next:* try again, or open **other ways in** (`?`) — recovery
    phrase, this device, a held key (brand.md §4). Never a dead-end string.

---

## Journey 5 — Set up recovery without creating a backdoor

The persona must be able to recover if they lose the passphrase — but recovery is
the exact feature that, done wrong, *is* the backdoor an adversary exploits. The
product must be honest that every added way in is also a way in for someone who
compels it. This is the §4 `keyslot` → **way in** rename doing its most important
work: naming *who or what can open this vault* so the persona can audit it.

### Current state

`Keyslots (3)` and "Inspect and enroll recovery or unlock keyslots without leaving
the native TUI." The persona is presented cryptographic slot mechanics with no
framing of the security *question* — who can open this vault. **Dead-end:** the
keyslots panel lists slots as data; it never says "each of these is a way someone
could open your vault; here is what you are trading when you add one."

### Designed state

- **Step 1 — Ways in, framed as the audit question.**
  - *Intent:* see exactly who or what can open this vault today.
  - *Emotion:* clear-eyed. The screen title states its one job.
  - *Copy (brand.md §3a, verbatim):* `Ways in (3)` / "The keys and phrases that
    can open this vault. Add a recovery phrase, bind a device, or remove a way in
    you no longer trust." Each row names the *relationship*, not the wrapping
    (brand.md §4): **recovery phrase**, **this device**, **trusted contact / held
    key**.
  - *What do I do next:* **Add a way in**, or select one to inspect/remove.

- **Step 2 — Choose a recovery method, told the honest trade.**
  - *Intent:* add recovery without opening a hole they don't understand.
  - *Emotion:* soberly informed. No false comfort (brand.md §3 rule 4).
  - *Copy:* for a **recovery phrase** — `This is a phrase you write down. Anyone
    who reads it can open this vault. Store it somewhere only you can reach.` The
    product states plainly that recovery is also exposure — it never pretends a
    recovery method is risk-free.
  - *What do I do next:* **Generate the phrase** (accent).

- **Step 3 — The phrase, shown once, in mono.**
  - *Intent:* capture the phrase correctly.
  - *Emotion:* focused; aware this is load-bearing.
  - *Content:* the phrase renders in `mono` (brand.md §5.3) so no word is
    ambiguous. Guidance: write it down now; the product will not show it again.
  - *What do I do next:* **I've written it down** → a confirmation step (type back
    a word or two) so a mis-transcribed phrase fails here, not in a real recovery.

- **Step 4 — Way in added; the audit list updated.**
  - *Intent:* confirm the new way in exists and re-see the full set.
  - *Emotion:* settled, and slightly more exposed — which the product does not
    hide.
  - *Copy:* `Recovery phrase added. This vault now has 4 ways in.` (§3 rule 1;
    stating the new count *is* the honest reminder that exposure grew.)
  - *What do I do next:* back to **Ways in (4)**, where the persona can remove a
    way in they no longer trust — auditing is a first-class, repeatable action.

- **Not-a-backdoor invariant (design note).** Recovery methods only ever wrap the
  vault key with a secret the *persona* holds (a phrase they wrote, a device they
  control, a key a chosen contact holds). The product surfaces no method that
  places a way in with the vendor, a network service, or any party the persona did
  not explicitly choose — consistent with the offline/local threat model (brand.md
  §1) and the promise (§2). "Recovery without a backdoor" means: every way in is
  one the persona can name, audit, and remove.

---

## Journey 6 — Coercion / panic: duress, decoy, and panic-lock, with honest limits

The journey the name exists for (brand.md §2, promise-consequence #2: *surrender
is a supported operation*; #3: *speed is the safety property for panic*). Someone
is compelling the persona, or is about to see their screen. The product's job is
to give them something safe to surrender and a way to lock instantly — and to be
brutally honest about what these can and cannot protect.

### Current state

`duress vault` and `panic-lock` exist as internal features. **Dead-end (two
kinds):** (1) there is no calm, discoverable setup that walks the persona through
creating a decoy *before* they are under duress — the moment they need it is the
worst moment to discover it; (2) nothing states the honest limitations, so the
product risks the worst possible failure for this persona — *false comfort* that
gets someone hurt (brand.md §1: "never offer false comfort").

### Designed state — 6a: Set up a decoy vault (done calmly, in advance)

- **Step 1 — Understand what a decoy is and is not.**
  - *Intent:* decide whether to create something safe to surrender.
  - *Emotion:* grave, thinking about a real future moment.
  - *Copy (brand.md §3 micro-example, verbatim):* `Decoy vault created. It opens
    with its own passphrase and looks identical to a real vault.` Preceded by the
    honest-limits statement (see the limits note below) *before* creation, not
    after.
  - *What do I do next:* **Create a decoy vault** (accent), or read the limits
    first.

- **Step 2 — Set the decoy's own passphrase and seed it plausibly.**
  - *Intent:* make the decoy convincing — a vault worth surrendering.
  - *Emotion:* deliberate, almost rehearsing.
  - *What do I do next:* add a few believable items to the decoy. Guidance: a
    decoy that is obviously empty is not a decoy.

- **Step 3 — Decoy ready; the invariant restated.**
  - *Intent:* trust that surrendering the decoy reveals nothing about the real
    vault.
  - *Emotion:* soberly prepared.
  - *Design invariant (brand.md §4 hard rule 1 + §5.2):* the decoy uses the
    *identical* palette, layout skeleton, and vocabulary. No shade, label, footer,
    or geometry distinguishes real from decoy — the distinction survives even in
    monochrome, because the *only* thing that differs is which passphrase the owner
    typed (brand.md §5.1). A shoulder-surfer watching either vault open sees the
    same product.

### Designed state — 6b: Panic-lock (instant, low-friction)

- **Step 1 — Fire the panic key.**
  - *Intent:* make everything unreadable *now*.
  - *Emotion:* urgent — and the product matches urgency with speed, not a
    confirmation dialog. Panic-lock is deliberately low-friction because *speed is
    the safety property* (brand.md §2.3; research: CLIG severity-tiering — panic
    is fast and reversible-by-design, the opposite of high-friction destruction).
  - *What do I do next:* nothing — it already happened. This is the one action
    with no confirmation, by design.

- **Step 2 — Locked; state exactly what is true.**
  - *Intent:* know the vault is closed and nothing readable remains on screen.
  - *Emotion:* momentarily safe, with no overclaim.
  - *Copy (brand.md §3 micro-example, verbatim):* `Locked. Nothing is readable
    until you unlock again.` The product does *not* say "you're safe" (brand.md §3
    rule 4) — it reports what it did, and lets the persona judge their safety.
  - *What do I do next:* re-enter through the normal unlock (Journey 4), identical
    framing.

### Honest-limits note (stated in-product, before reliance — non-negotiable)

Per brand.md §1 ("never offer false comfort, never bury a consequence") and §2
(the promise plans for the moment the persona *loses*), the product states these
limitations plainly, in the grave voice, at setup time — not in fine print:

- **A decoy protects against being *compelled to open a vault*, not against
  forensic analysis of the device.** A determined adversary with the disk and time
  may find evidence that a second vault exists. The product does not promise
  deniability it cannot guarantee.
- **Panic-lock protects what is *at rest*, not what already left.** Anything
  already copied, displayed, or exported is outside the vault's control. Panic-lock
  closes the vault; it cannot recall a password already on someone else's screen or
  clipboard.
- **Neither feature protects against a coercer who watches you type.** If the
  adversary sees which passphrase opens the real vault, no decoy helps. The
  product says so.

These statements are the product keeping its one promise honestly: it is on the
persona's side precisely because it refuses to lie to them about what it can do.

---

## Journey 7 — Someday-recovery

Months later, on a new machine, after losing the passphrase — the persona returns
to recover. This journey validates that Journey 5's honesty paid off: the recovery
method they chose actually works, calmly, without a backdoor having been needed.

### Current state

Recovery is reachable only through the same keyslot mechanics (`Keyslots`) with no
guided "I have lost my passphrase, walk me through recovery" entry point.
**Dead-end:** a persona in a recovery situation — often stressed, on unfamiliar
hardware — is handed slot management, not a path. The one journey where calm
guidance matters most is the one most exposed to raw mechanics.

### Designed state

- **Step 1 — Re-establish trust first (loop back to Journey 1).**
  - *Intent:* confirm *this* copy, on *this* new machine, is genuine before
    recovering into it.
  - *Emotion:* wary again — correctly. New machine, same discipline.
  - *What do I do next:* **Verify this copy** (Journey 1). Recovery never bypasses
    trust establishment.

- **Step 2 — Choose "I need to recover."**
  - *Intent:* declare the situation and get a guided path, not slot management.
  - *Emotion:* stressed but met with calm.
  - *Copy:* `Recover a vault` / "Open a vault using a way in other than its
    passphrase — a recovery phrase, this device, or a key a trusted contact
    holds." Framed as the persona's situation, in §4 vocabulary.
  - *What do I do next:* pick the recovery method they set up in Journey 5.

- **Step 3 — Recover with the phrase (or device, or held key).**
  - *Intent:* enter the recovery secret and open the vault.
  - *Emotion:* hopeful, focused.
  - *Guardrail:* the recovery phrase is entered via stdin/prompt only, never a CLI
    arg (same hard gate as Journey 3, brand.md §3/CLIG).
  - *What do I do next:* on success, the vault opens with the same `Vault open. {n}
    items.` framing as a daily unlock — recovery lands the persona in the exact
    same place, no special-cased screen.

- **Step 4a — Recovered.**
  - *Intent:* get back in and re-secure.
  - *Emotion:* relief, earned honestly.
  - *Copy:* `Vault open. Set a new passphrase to keep using it day to day.` The
    product guides the persona to re-establish a daily way in and to review **Ways
    in** (Journey 5) — including removing any way in they no longer trust after the
    loss event.
  - *What do I do next:* **Set a new passphrase** (accent), then a prompted audit
    of Ways in.

- **Step 4b — Recovery secret rejected.**
  - *Intent:* understand why and what remains possible.
  - *Emotion:* anxious — met with guidance, never a raw error.
  - *Copy:* `That didn't match a way in for this vault. Check the phrase — a
    mistyped or reordered word is the usual cause.` If other ways in exist, the
    product points to them; it never dead-ends on a rejection.
  - *What do I do next:* try again, or switch to another way in they set up.

---

## Cross-journey invariants (carried from brand.md, restated as journey rules)

1. **No step ends in a box of data.** Every storyboard step above answers "what do
   I do next" with one action. This is the single defect PUX exists to fix
   (brand.md §1; directive PUX.2).
2. **Depth is one drill-level down, always reachable, never thrust forward.** Audit
   math (J2), keyslot mechanics (J5), verification fingerprints (J1), seal
   internals (J3) all live behind a deliberate "show the details / evidence" step.
3. **The next action is singular and visible;** the footer shows only the 3–5 keys
   valid in the current context and re-renders per pane (brand.md §3e, §5.5).
4. **Secrets are never accepted as CLI args** — stdin/prompt/file only (J3, J7;
   brand.md §3/CLIG). Hard code-review gate.
5. **Real and decoy are visually identical in every layer including monochrome**
   (J4, J6; brand.md §4 rule 1, §5.1–5.2). The only differentiator is the
   passphrase the owner knows.
6. **State changes are always reported plainly** (J2, J3, J4, J5, J6; brand.md §3
   rule 1). The persona never guesses whether an action took effect.
7. **The product never offers safety it cannot guarantee** (J1, J6; brand.md §3
   rule 4). Limits are stated before reliance, in the grave voice — false comfort
   is the one failure this persona cannot afford.
```
