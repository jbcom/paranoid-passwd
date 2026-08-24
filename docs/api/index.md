---
title: API
---

# Rust API and crate boundaries

`paranoid-passwd` is primarily a native application rather than a general-purpose Rust SDK. Its
supported automation contract is the `paranoid-passwd --cli` command and its documented JSON
output. The crate entry points below are provided for maintainers, security reviewers, and
integrators who need to inspect the source boundary directly.

| Crate | Stable responsibility | Source entry point |
| --- | --- | --- |
| `paranoid-core` | OpenSSL-backed RNG and SHA-256 delegation, password generation, compliance checks, and statistical audit math | [`lib.rs`](https://github.com/jbcom/paranoid-passwd/blob/main/crates/paranoid-core/src/lib.rs) |
| `paranoid-audit` | Redacted audit events and JSON/JSONL evidence primitives | [`lib.rs`](https://github.com/jbcom/paranoid-passwd/blob/main/crates/paranoid-audit/src/lib.rs) |
| `paranoid-ops` | Typed operation orchestration and policy-bound automation reports | [`lib.rs`](https://github.com/jbcom/paranoid-passwd/blob/main/crates/paranoid-ops/src/lib.rs) |
| `paranoid-seal` | Vault seal state and non-secret provider-posture evidence | [`lib.rs`](https://github.com/jbcom/paranoid-passwd/blob/main/crates/paranoid-seal/src/lib.rs) |
| `paranoid-vault` | Encrypted local storage, keyslots, transfer packages, and recovery posture | [`lib.rs`](https://github.com/jbcom/paranoid-passwd/blob/main/crates/paranoid-vault/src/lib.rs) |
| `paranoid-cli` | Scriptable CLI and interactive terminal workflows | [`main.rs`](https://github.com/jbcom/paranoid-passwd/blob/main/crates/paranoid-cli/src/main.rs) |
| `paranoid-gui` | Slint-native desktop application | [`main.rs`](https://github.com/jbcom/paranoid-passwd/blob/main/crates/paranoid-gui/src/main.rs) |

The public command reference lives in the [TUI guide](../guides/tui.md),
[recovery operations guide](../guides/recovery-operations.md), and the command's built-in
`--help` output. Security-sensitive logic intentionally remains in `paranoid-core`; CLI, TUI,
GUI, and documentation layers consume typed results rather than duplicating it.

## Generated-reference status

Sourcey's current Rust adapter requires a nightly rustdoc JSON format that matches the adapter's
bundled converter. This repository's Rust 1.95+ workspace currently produces a newer format, so
the site deliberately publishes this maintained source-boundary reference rather than rendering
stale Sphinx directives as API content. The compatibility boundary and regeneration check are
tracked in the release and documentation validation workflow.
