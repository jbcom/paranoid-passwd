---
title: Supply Chain
---

# Supply Chain

The supply-chain model is still builder-first, but the toolchain has changed.

## What the Builder Owns Now

The custom GitHub Action builder image is the repository trust root for:

- a digest-pinned Wolfi base image
- pinned Rust `1.88.x` and pinned `tox`
- Rust toolchain installation
- OpenSSL development headers
- Sphinx and Python docs tooling
- `cargo` build / test / clippy / fmt runs
- docs-site builds from the repository root
- vendored Cargo dependency resolution

## What It No Longer Builds

- the retired interactive browser app
- WebAssembly artifacts
- GitHub Pages site zips pulled from releases

## Release Outputs

The release pipeline now focuses on:

- native CLI and GUI archives
- macOS GUI `.dmg` packages
- Linux `.deb` packages for both binaries
- checksums
- provenance / attestations
- package-manager metadata
- optional Wolfi packaging

Before attestation, the release workflow now validates:

- per-platform archive smoke tests
- macOS GUI `.dmg` payload validation and host smoke tests
- Debian package payload validation and Linux host smoke tests for `.deb` artifacts
- aggregate checksums
- Homebrew / Scoop / Chocolatey manifest generation
- the docs-hosted `install.sh` flow against a local artifact server
- the checked-in release-validation scripts instead of workflow-only inline shell

GitHub Pages is rebuilt directly from `main` using the Sphinx docs tree instead of downloading a site zip from a release artifact.

## Branch Protection Discipline

The repository now carries `scripts/verify_branch_protection.sh` plus `make verify-branch-protection` so operators can detect stale required-check policies before they block a merge. This is a manual or authenticated check because branch protection lives in GitHub configuration rather than the Git tree.

## Cargo Dependency Discipline

- `Cargo.lock` is committed and release-aware.
- Cargo dependencies are vendored under `vendor/`.
- Workspace Cargo commands run with `--locked --frozen --offline` in `make` and CI.
- `scripts/hallucination_check.sh` verifies math/security invariants in `paranoid-core`.
- `scripts/supply_chain_verify.sh` verifies vendoring, workflow pinning, and release prerequisites.
- Release packaging lives in repo-owned scripts instead of workflow-only inline shell.
