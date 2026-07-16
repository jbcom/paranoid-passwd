---
title: Supported Compliance Frameworks
---

# Supported Compliance Frameworks

`--framework ID` (repeatable or comma-separated) checks generated passwords against one or more
built-in policy presets. Each preset is a fixed set of length, entropy, and character-class
requirements defined in `crates/paranoid-core/src/lib.rs` (`FrameworkId`, `ComplianceFramework`,
`FRAMEWORKS`). Selecting a framework does not change how passwords are generated; it adds a
per-password and batch-level pass/fail check against that preset's requirements.

## Frameworks

| Id | Aliases | Display name | Min length | Min entropy (bits) | Mixed case | Digits | Symbols |
|---|---|---|---|---|---|---|---|
| `nist` | — | NIST SP 800-63B | 8 | 30.0 | no | no | no |
| `pci_dss` | `pci`, `pci-dss` | PCI DSS 4.0 | 12 | 60.0 | yes | yes | no |
| `hipaa` | — | HIPAA | 8 | 50.0 | yes | yes | yes |
| `soc2` | `soc_2`, `soc-2` | SOC 2 | 8 | 50.0 | yes | yes | no |
| `gdpr` | — | GDPR / ENISA | 10 | 80.0 | yes | yes | yes |
| `iso27001` | `iso-27001`, `iso_27001` | ISO 27001 | 12 | 90.0 | yes | yes | yes |

The `Id` column is the canonical string accepted by `--framework` and returned by
`FrameworkId::as_str()`. The `Aliases` column lists additional strings `FrameworkId::parse()`
accepts for the same id; the CLI's `--help` text advertises only the canonical ids.

Each row's requirements come directly from that framework's entry in `FRAMEWORKS`:

- **Min length** — minimum accepted password length.
- **Min entropy (bits)** — minimum accepted Shannon entropy for the password.
- **Mixed case** — whether both uppercase and lowercase characters are required.
- **Digits** — whether at least one digit is required.
- **Symbols** — whether at least one symbol character is required.

## Usage

```bash
paranoid-passwd --cli --length 20 --count 3 --framework nist,pci_dss
paranoid-passwd vault generate-store --title GitHub --username jon@example.com --length 24 --framework nist
```

Passing multiple frameworks requires the generated password to satisfy every selected framework's
requirements, not just one. `--json` and `--audit-jsonl` output report per-framework and combined
`selected_frameworks_pass` results alongside the rest of the audit.

None of these presets are an authorization, certification, or compliance claim for the named
standard — they are password-strength policy presets modeled on each standard's published password
guidance. See [Federal Control Mapping](./control-mapping.md) for the separate NIST SP 800-53
control-family evidence map used for FedRAMP/GovCloud/DoD IL5 evaluation.
