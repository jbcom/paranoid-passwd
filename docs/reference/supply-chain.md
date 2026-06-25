---
title: Supply Chain
---

# Supply Chain

The supply-chain model is builder-first, and the CI/CD toolchain is explicitly
back on Wolfi.

## What the Builder Owns Now

The custom GitHub Action builder image is the repository trust root for:

- a digest-pinned Chainguard Wolfi base image
- Wolfi `rust-1.95=1.95.0-r0`
- pinned `tox` and `sphinx-rustdocgen`
- Rust toolchain installation, including `rustfmt` and Clippy from Wolfi packages
- OpenSSL development headers from Wolfi packages
- Xvfb and the Xlib runtime libraries required for GUI screenshot smoke tests
- Sphinx and Python docs tooling
- local scanner CLIs used by the deeper release-candidate gates, including `semgrep`,
  `osv-scanner`, `syft`, and `trivy`
- `cargo` build / test / clippy / fmt runs
- docs-site builds from the repository root
- vendored Cargo dependency resolution

Remote Rust CI invokes the same `make ci` target used locally, inside this builder.
Linux release validation, published-release surface verification, and downloaded
asset smoke verification also run through the same builder instead of installing
ad hoc packages onto the Ubuntu runner.

## Historical CI Rigor Baseline

The older C/WASM GitHub Pages line carried a stricter release discipline than the
Rust-native branch had drifted into: native CMake/CTest, WASM validation and
export/import checks, Playwright E2E, CodeQL, SonarCloud, ShellCheck,
hallucination checks, supply-chain verification, and a Wolfi/melange/apko release
path.

The Rust-native product no longer ships the browser app or JavaScript
secret-handling surface, so those exact gates are not copied forward blindly. The
replacement standard is that remote CI must be at least as strict for the current
surface: full local `make ci` in Wolfi, docs and link validation, GUI/TUI/vault
e2e coverage, release payload inspection, published-release verification,
attestation checks, and repo-owned supply-chain scripts.

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
- repo-owned package metadata

Before attestation, the release workflow now validates:

- per-platform archive smoke tests
- macOS GUI `.dmg` payload validation and host smoke tests
- Debian package payload validation and Linux smoke tests for `.deb` artifacts in the Wolfi builder
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
- Dependabot remains enabled for GitHub Actions only. Cargo dependency PRs are not automated
  through Dependabot because the repository's `.cargo/config.toml` replaces `crates.io` with the
  checked-in `vendor/` tree, and Dependabot's Cargo updater does not maintain vendored Cargo
  source directories. Cargo dependency updates must therefore be maintainer-driven: update
  `Cargo.toml` / `Cargo.lock`, refresh the affected vendored crates, preserve
  `.cargo-checksum.json`, and prove the result with locked/frozen/offline Cargo gates before PR.
- `make verify-deep` runs Rust-native `xtask` checks for offline metadata, dependency source and
  license policy, repo-owned shell linting, Python syntax checks for the existing docs/test harness
  scripts, and tracked-file secret scanning.
- `make quality` is the local release-candidate gate: it runs `verify-deep`, the enforced local
  scanner subset, `ci`, and the host-supported GUI e2e harness before remote CI is treated as
  confirmation. It also requires the local security scanner stack to be installed.
- `deny.toml` records the local dependency license/source policy for `cargo-deny`.
- `scripts/hallucination_check.sh` verifies math/security invariants in `paranoid-core`.
- `scripts/supply_chain_verify.sh` verifies vendoring, workflow pinning, and release prerequisites.
- `scripts/security_assurance_gate.py` verifies the claim-led PR assurance protocol wiring.
- Release packaging lives in repo-owned scripts instead of workflow-only inline shell.

## Scanner Toolchain Pin Manifest

Scanner and tooling updates are tracked in `supply-chain/scanner-toolchain.env`. That manifest is
the source of truth for:

- Wolfi apk scanner versions installed into the repository builder (`semgrep`, `osv-scanner`,
  `syft`, and `trivy`)
- the pinned `github/codeql-action` version and commit SHA used by workflow CodeQL jobs
- host-local scanner tools that `xtask` must continue to discover for `make verify-deep` /
  `make quality`
- host-local scanner versions for ShellCheck, cargo-deny, cargo-audit, cargo-vet, and the CodeQL CLI
  when `make quality` enables strict local-tool checking

`scripts/supply_chain_verify.sh` sources the manifest and fails if the Dockerfile, workflow CodeQL
references, or `xtask` local-tool visibility checks drift from it. Updating a scanner therefore
requires changing the manifest, updating the corresponding builder, workflow reference, or host
version check, and rerunning the assurance gate plus `make quality` rather than letting the runner
or workstation resolve a new scanner version implicitly.
