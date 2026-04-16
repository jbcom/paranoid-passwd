---
title: paranoid-passwd
---

# paranoid-passwd

## The Password Generator That Trusts No One

`paranoid-passwd` is now a **Rust-native local application** with a scriptable CLI, a full-screen wizard TUI, a dedicated desktop GUI, and an encrypted local vault. The public website is a **docs and downloads surface only**. There is no browser generator, no WASM runtime, and no JavaScript trust boundary in the product anymore.

The current release line focuses on reproducing the existing generator and audit behavior in a more maintainable stack:

- `paranoid-core` owns password generation, rejection sampling, OpenSSL-backed hashing and RNG, compliance policy, and the 7-layer audit.
- `paranoid-passwd` is the user-facing binary. It defaults to the TUI on an interactive terminal and keeps the scriptable CLI for automation.
- `paranoid-passwd-gui` follows the same three-screen flow and shared view models as the CLI/TUI and now ships as a separate direct-download artifact, with macOS releases publishing both direct archives and native `.dmg` images, and Linux releases publishing both direct archives and `.deb` packages that include desktop metadata.
- `paranoid-vault` provides the encrypted local vault foundation built on SQLite, Argon2id, and OpenSSL-backed AEAD.
- the remaining human cryptography/statistics review surface is tracked explicitly in the reference docs instead of being left as scattered source comments

```{toctree}
:maxdepth: 2
:caption: Docs

getting-started/index
guides/tui
reference/index
api/index
```

## Download Channels

- [GitHub Releases](https://github.com/jbcom/paranoid-passwd/releases) ship the signed native archives, macOS `.dmg` images for the GUI, Linux `.deb` packages, and checksums.
- `install.sh` is hosted at the docs site root and resolves the latest GitHub Release.
- Package-manager metadata is still generated from the release workflow for Homebrew, Scoop, and Chocolatey.
- The release pipeline now validates archive, `.dmg`, and Debian package payloads, manifest generation, and the installer surface before attesting assets.
- The current release line ships both the CLI/TUI binary and a separate GUI binary through direct archives, with Linux `.deb` packages for both.
- `install.sh` and package-manager flows remain focused on the CLI/TUI binary; the GUI uses direct-download artifacts until native installer work lands on every supported platform.

## What Changed

- The interactive GitHub Pages app is retired.
- GitHub Pages now publishes documentation built from the repository `docs/` tree with Sphinx.
- The builder image still owns the CI/docs build path, but it now installs Rust and Sphinx tooling instead of the old C/WASM toolchain.
- Release packaging is driven by checked-in scripts: `build_release_artifact.sh`, `smoke_test_release_artifact.sh`, and `release_validate.sh`.
- The public product surface is native-first: local secrets never need a browser runtime.
