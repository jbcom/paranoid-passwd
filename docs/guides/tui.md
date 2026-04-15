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

