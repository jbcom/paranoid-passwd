---
title: Getting Started
---

# Getting Started

```{toctree}
:maxdepth: 1

downloads
install-and-verify
```

## Download

The canonical binaries are published through [GitHub Releases](https://github.com/jbcom/paranoid-passwd/releases). Release assets keep the existing naming pattern:

- `paranoid-passwd-<version>-linux-amd64.tar.gz`
- `paranoid-passwd-<version>-linux-arm64.tar.gz`
- `paranoid-passwd-<version>-darwin-amd64.tar.gz`
- `paranoid-passwd-<version>-darwin-arm64.tar.gz`
- `paranoid-passwd-<version>-windows-amd64.zip`

The docs site also serves [`/install.sh`](https://paranoid-passwd.com/install.sh), which downloads the correct release archive for the current platform.

Today’s published release artifact is `paranoid-passwd`, which includes the CLI and TUI entrypoint. The GUI crate is present in the workspace, but GUI packaging is a later phase.

## Install With `install.sh`

```bash
curl -sSL https://paranoid-passwd.com/install.sh | sh
```

You can pin a version or install into a custom directory:

```bash
curl -sSL https://paranoid-passwd.com/install.sh | sh -s -- --version paranoid-passwd-v3.5.1
curl -sSL https://paranoid-passwd.com/install.sh | sh -s -- --install-dir "$HOME/.local/bin"
```

## Package Managers

- `brew tap jbcom/tap && brew install paranoid-passwd`
- `scoop bucket add jbcom https://github.com/jbcom/pkgs && scoop install paranoid-passwd`
- `choco install paranoid-passwd`

## First Run

Interactive terminal:

```bash
paranoid-passwd
```

That launches the TUI wizard by default.

Non-interactive / scriptable usage:

```bash
paranoid-passwd --cli --length 20 --count 3 --framework nist,pci_dss
paranoid-passwd --cli --charset hex --length 64 --no-audit --quiet
```

Vault foundation:

```bash
export PARANOID_MASTER_PASSWORD='correct horse battery staple'
paranoid-passwd vault init
paranoid-passwd vault generate-store --title GitHub --username jon@example.com --length 24 --framework nist
paranoid-passwd vault list
```

## Build Locally

```bash
cargo build --workspace --locked --frozen --offline
cargo test --workspace --locked --frozen --offline
cargo build -p paranoid-cli --locked --frozen --offline
bash tests/test_cli.sh target/debug/paranoid-passwd
python3 -m tox -e docs
```

If you want to reproduce the CI environment from the repository root:

```bash
make ci-emulate
```

If you want to exercise the checked-in release packaging path locally:

```bash
make smoke-release
make release-emulate
```

If you are validating the release process itself instead of installing the tool, use the release checklist in [Reference → Release Checklist](../reference/release-checklist.md).
