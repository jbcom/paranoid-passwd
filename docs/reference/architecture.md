---
title: Architecture
---

# Architecture

`paranoid-passwd` now uses a Cargo workspace:

- `crates/paranoid-core`
- `crates/paranoid-cli`
- `crates/paranoid-gui`
- `crates/paranoid-vault`

## Core

`paranoid-core` is the single source of truth for:

- charset resolution and validation
- OpenSSL-backed CSPRNG access
- rejection sampling
- constrained generation
- SHA-256 hashing
- chi-squared distribution checks via `statrs`
- serial correlation
- collision counting
- pattern detection
- compliance evaluation

The old raw-memory WASM result struct is gone. The native application surface now passes typed Rust data structures between layers.

The shared report model is split between:

- `GeneratedPassword` for per-password counts, pattern checks, hashes, and framework verdicts
- `AuditSummary` for batch-level chi-squared, serial correlation, collision, and entropy reporting

## CLI and TUI

`paranoid-passwd` is the primary user binary.

- On an interactive TTY with no mode-forcing or operational flags, it launches the TUI.
- In automation or with `--cli`, it keeps the scriptable stdout/stderr contract.
- The TUI uses `ratatui` plus `crossterm` to keep the current three-step product flow.
- The `vault` namespace adds encrypted local retention without changing the generator root behavior.

## GUI

`paranoid-passwd-gui` is the follow-on desktop surface. It uses `Iced` and shares the same core request/result model.

## Vault Foundation

`paranoid-vault` is the first password-manager crate boundary.

- SQLite stores vault metadata and encrypted item blobs.
- Argon2id derives the master unlock key.
- OpenSSL-backed AES-256-GCM wraps the vault master key and item payloads.
- The current item model supports `Login` entries, CRUD operations, and generate-and-store flows.

## Public Website

The public website is documentation only. GitHub Pages publishes the repository `docs/` tree, including:

- installation instructions
- TUI walkthrough
- architecture and testing notes
- release verification guidance
- generated Rust API docs via `sphinx-rust`

## Release Path

Release packaging is driven by checked-in scripts instead of workflow-only shell:

- `scripts/build_release_artifact.sh`
- `scripts/smoke_test_release_artifact.sh`
- `scripts/release_validate.sh`

Linux release builds run inside the repository-owned builder action. Native macOS and Windows archives use the same repo-owned packaging and smoke-test scripts on platform runners.
