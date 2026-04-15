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
