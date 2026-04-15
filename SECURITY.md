# Security Policy

## Supported Versions

| Version | Supported | Notes |
| ------- | --------- | ----- |
| 3.5.x   | Yes       | Rust-native CLI/TUI/docs distribution line |
| < 3.5   | No        | Legacy browser/C/WASM architecture |

## Reporting

Report vulnerabilities privately through GitHub Security Advisories or by contacting the maintainer directly. Do not file public issues for exploitable bugs, supply-chain problems, or weaknesses in password generation/audit behavior.

Include:
- impact and affected version
- reproduction steps
- whether the issue affects generation, audit, packaging, or release verification

## Current Security Boundary

The active product is:
- Rust-native local application code in `crates/`
- OpenSSL-backed RNG and SHA-256 in `paranoid-core`
- vendored Cargo dependency tree
- Sphinx docs/download site

The retired browser/WASM surface is no longer part of the supported product.

## What Counts As A Security Issue

- biased or predictable password generation
- incorrect rejection-sampling boundaries
- audit math that produces false passes or false negatives
- packaging or release-verification tampering
- dependency/provenance drift that breaks locked offline builds
- install-script or package-manager delivery compromise

## Verification Expectations

Before release, the repository should pass:

```bash
make ci
```

That includes:
- locked/frozen/offline Cargo builds
- CLI contract tests
- docs build
- `scripts/hallucination_check.sh`
- `scripts/supply_chain_verify.sh`
