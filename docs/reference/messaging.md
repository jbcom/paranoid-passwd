---
title: Messaging
---

# Messaging

This page keeps the public voice consistent across docs, release notes, UI copy, and PR
descriptions.

## Product Promise

Local secrets. Verifiable trust.

`paranoid-passwd` is a local-first password manager and generator. It keeps secrets out of
unnecessary runtimes, makes recovery posture visible, and makes release integrity something
operators can check instead of assume.

## One-Sentence Description

`paranoid-passwd` is a Rust-native password manager and generator with a scriptable CLI,
terminal TUI, desktop GUI, encrypted local vault, explicit recovery paths, and verifiable
release artifacts.

## Voice

- Direct: explain what the tool does and what it does not do.
- Evidence-led: prefer checks, artifacts, and named assurance claims over confidence language.
- Local-first: emphasize that secrets stay on the user's machine.
- Calmly paranoid: reduce trust boundaries without sounding theatrical.
- Operator-friendly: make recovery, backups, transfer, and release verification easy to find.

## Preferred Terms

| Use | Avoid |
|-----|-------|
| local-first password manager and generator | password generator only |
| encrypted local vault | vault foundation |
| security assurance protocol | vague human review process |
| tracked-open assurance claim | approved crypto/statistics review |
| federal-ready operating profile | FedRAMP certified |
| DoD IL5-compatible evidence package | DoD authorized |
| FIPS-validated crypto module path | OpenSSL means FIPS |
| typed ops protocol | GUI talks to TUI |
| structured audit event | primitive log line |
| seal / auto-unseal lifecycle | unlock helper |
| native CLI/TUI/GUI surfaces | web app replacement |
| docs and downloads site | application website |
| verifiable release artifacts | trust us |

## Standard Bullets

Use these when a short product summary is needed:

- native CLI, terminal TUI, and desktop GUI
- OpenSSL-backed generation, hashing, and vault encryption paths
- encrypted local vault for `Login`, `SecureNote`, `Card`, and `Identity` records
- recovery through password, mnemonic, device-bound, and certificate-wrapped keyslots
- backup, restore, and selected-item transfer packages
- vendored offline builds, pinned workflows, checksums, attestations, and payload inspection
- claim-led security assurance with deterministic gates

## Claims To Avoid

Do not claim:

- "unbreakable" security
- "military-grade" encryption
- independent cryptographic approval without a linked disposition
- production approval for `tracked-open` assurance claims
- FedRAMP authorization or DoD IL5 authorization without an actual assessed boundary
- FIPS-compliant product behavior without a validated module, approved mode, and configuration
  evidence
- cloud sync, browser extension, autofill, or multi-user collaboration

The strongest brand position is not hype. It is that the project exposes its trust boundaries
clearly and keeps them small.
