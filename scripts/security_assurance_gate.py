#!/usr/bin/env python3
"""Deterministic security assurance protocol gate for paranoid-passwd."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Requirement:
    path: str
    pattern: str
    description: str
    regex: bool = False


@dataclass(frozen=True)
class Claim:
    claim_id: str
    title: str
    surface: str
    requirements: tuple[Requirement, ...]


CLAIMS: tuple[Claim, ...] = (
    Claim(
        "rng.openssl-delegation",
        "OpenSSL-backed RNG and SHA-256 delegation",
        "core-security",
        (
            Requirement(
                "crates/paranoid-core/src/lib.rs",
                r"^use openssl::\{(?=[^}]*" + "rand" + r"::rand_bytes)(?=[^}]*sha::sha256)[^}]*\};",
                "paranoid-core imports OpenSSL RNG and SHA-256",
                True,
            ),
            Requirement(
                "scripts/hallucination_check.sh",
                "core still delegates RNG and SHA-256 to OpenSSL",
                "hallucination check enforces OpenSSL delegation",
            ),
        ),
    ),
    Claim(
        "rng.rejection-sampling-boundary",
        "Rejection sampling boundary",
        "core-security",
        (
            Requirement(
                "crates/paranoid-core/src/lib.rs",
                "let max_valid = (256 / charset_bytes.len()) * charset_bytes.len() - 1;",
                "generation path keeps the inclusive -1 boundary",
            ),
            Requirement(
                "crates/paranoid-core/src/lib.rs",
                "let rejection_max_valid = (256 / charset_len) * charset_len - 1;",
                "audit summary reports the same inclusive -1 boundary",
            ),
        ),
    ),
    Claim(
        "audit.chi-squared-tail",
        "Chi-squared tail interpretation",
        "core-security",
        (
            Requirement(
                "crates/paranoid-core/src/lib.rs",
                r"^use statrs::distribution::\{ChiSquared, ContinuousCDF\};",
                "chi-squared probability comes from statrs",
                True,
            ),
            Requirement(
                "crates/paranoid-core/src/lib.rs",
                "let chi2_pass = chi2_p_value > 0.01;",
                "pass logic rejects only low p-values",
            ),
            Requirement(
                "crates/paranoid-core/src/lib.rs",
                "let df = charset_bytes.len().saturating_sub(1);",
                "degrees of freedom remain N - 1",
            ),
        ),
    ),
    Claim(
        "audit.serial-correlation-estimator",
        "Serial-correlation estimator tracking",
        "core-security",
        (
            Requirement(
                "docs/reference/human-review.md",
                "Serial correlation audit",
                "open serial-correlation disposition remains tracked",
            ),
            Requirement(
                "scripts/verify_human_review_inventory.sh",
                "verify the serial-correlation coefficient matches the intended estimator",
                "inventory check tracks the serial-correlation TODO",
            ),
        ),
    ),
    Claim(
        "surface.no-browser-runtime",
        "No retired browser/runtime product surface",
        "product-surface",
        (
            Requirement(
                "scripts/hallucination_check.sh",
                "retired browser/C surfaces are gone",
                "hallucination check verifies retired runtime paths are absent",
            ),
            Requirement(
                ".github/copilot-instructions.md",
                "Do not reintroduce the retired browser app, JavaScript secret-handling logic, DOM UI, or webview runtime paths.",
                "Copilot repository instructions preserve the retired browser/runtime rule",
            ),
            Requirement(
                ".github/copilot-instructions.md",
                "Treat any Slint WASM or mobile work as a separately gated Rust-native surface with an explicit threat model.",
                "Copilot repository instructions gate future Slint WASM/mobile surfaces",
            ),
        ),
    ),
    Claim(
        "vault.device-bound-keyslot",
        "Device-bound keyslot tracking",
        "vault-security",
        (
            Requirement(
                "docs/reference/human-review.md",
                "Device-bound keyslot design",
                "open device-bound keyslot disposition remains tracked",
            ),
            Requirement(
                "scripts/verify_human_review_inventory.sh",
                "device-bound keyslot design",
                "inventory check tracks the device-bound keyslot TODO",
            ),
        ),
    ),
    Claim(
        "vault.mnemonic-recovery-keyslot",
        "Mnemonic recovery keyslot tracking",
        "vault-security",
        (
            Requirement(
                "docs/reference/human-review.md",
                "Mnemonic recovery construction",
                "open mnemonic recovery disposition remains tracked",
            ),
            Requirement(
                "scripts/verify_human_review_inventory.sh",
                "24-word BIP39 entropy",
                "inventory check tracks the mnemonic recovery TODO",
            ),
        ),
    ),
    Claim(
        "vault.certificate-wrapped-keyslot",
        "Certificate-wrapped keyslot tracking",
        "vault-security",
        (
            Requirement(
                "docs/reference/human-review.md",
                "Certificate-wrapped keyslots",
                "open certificate-wrapped keyslot disposition remains tracked",
            ),
            Requirement(
                "scripts/verify_human_review_inventory.sh",
                "CMS recipient selection",
                "inventory check tracks the certificate-wrapped keyslot TODO",
            ),
        ),
    ),
    Claim(
        "ops.shared-policy-boundary",
        "Shared ops policy boundary tracking",
        "ops-security",
        (
            Requirement(
                "crates/paranoid-ops/src/lib.rs",
                "TODO: HUMAN_REVIEW - centralized policy boundary for ops/vault authorization and audit evidence across adapters.",
                "shared ops policy boundary remains tracked for human review",
            ),
            Requirement(
                "crates/paranoid-ops/src/lib.rs",
                "let envelope = OpsCommandEnvelope::local(surface, context.profile, command);",
                "ops command envelopes derive profile from the authoritative policy context",
            ),
            Requirement(
                "crates/paranoid-ops/src/lib.rs",
                '"session_surface".to_string()',
                "ops request/response events preserve adapter session surface metadata",
            ),
            Requirement(
                "crates/paranoid-cli/src/vault_tui.rs",
                "evaluate_vault_operation(AuditSurface::Tui",
                "TUI vault adapter routes covered operations through the shared ops evaluator",
            ),
            Requirement(
                "crates/paranoid-gui/src/lib.rs",
                "write_events_jsonl(path, evaluation.audit_events.as_slice())",
                "native GUI persists durable ops audit events when JSONL is configured",
            ),
            Requirement(
                "docs/reference/human-review.md",
                "Ops policy boundary",
                "open ops policy boundary disposition remains tracked",
            ),
            Requirement(
                "scripts/verify_human_review_inventory.sh",
                "centralized policy boundary for ops/vault authorization and audit evidence across adapters",
                "inventory check tracks the ops policy boundary TODO",
            ),
        ),
    ),
    Claim(
        "seal.lifecycle-boundary",
        "Seal lifecycle boundary",
        "seal-security",
        (
            Requirement(
                "crates/paranoid-seal/src/lib.rs",
                r"#\[derive\([^\n]*Serialize[^\n]*Deserialize[^\n]*\)\]\n#\[serde\([^\n]*\)\]\npub enum VaultSealState",
                "paranoid-seal owns a serializable seal state enum",
                True,
            ),
            Requirement(
                "crates/paranoid-seal/src/lib.rs",
                r"#\[derive\([^\n]*Serialize[^\n]*Deserialize[^\n]*\)\]\npub struct VaultSealPosture",
                "paranoid-seal owns a serializable non-secret seal posture model",
                True,
            ),
            Requirement(
                "crates/paranoid-seal/src/lib.rs",
                r"#\[derive\([^\n]*Serialize[^\n]*Deserialize[^\n]*\)\]\n#\[serde\([^\n]*\)\]\npub enum VaultSealProviderKind",
                "paranoid-seal models serializable seal provider kinds",
                True,
            ),
            Requirement(
                "crates/paranoid-seal/src/lib.rs",
                "TODO: HUMAN_REVIEW - confirm the seal/posture model correctly represents unlock and recovery posture without overstating provider availability.",
                "seal posture model remains tracked for human review",
            ),
            Requirement(
                "crates/paranoid-ops/src/lib.rs",
                "pub use paranoid_seal::{",
                "paranoid-ops re-exports seal types for adapter stability",
            ),
            Requirement(
                "crates/paranoid-cli/src/vault_cli.rs",
                "let (vault_exists, posture) = seal_posture_for_path(&invocation.open_options.path);",
                "vault seal-status command evaluates seal posture",
            ),
            Requirement(
                "crates/paranoid-cli/src/vault_cli.rs",
                '"seal": posture',
                "vault seal-status command includes posture in JSON output",
            ),
            Requirement(
                "crates/paranoid-cli/src/vault_cli.rs",
                "serde_json::to_writer_pretty(io::stdout(), &report)",
                "vault seal-status command serializes the posture report",
            ),
            Requirement(
                "tests/test_vault_cli.sh",
                "seal_status=\"$(source_vault seal-status)\"",
                "headless vault e2e exercises seal-status output",
            ),
            Requirement(
                "tests/test_vault_cli.sh",
                'seal = data["seal"]',
                "headless vault e2e asserts the seal posture payload",
            ),
            Requirement(
                "scripts/verify_human_review_inventory.sh",
                "seal/posture model correctly represents unlock and recovery posture",
                "inventory check tracks the seal posture TODO",
            ),
            Requirement(
                "docs/reference/human-review.md",
                "Seal lifecycle posture model",
                "open seal posture disposition remains tracked",
            ),
            Requirement(
                "docs/reference/assurance-claims.md",
                "`seal.lifecycle-boundary` | `tracked-open`",
                "assurance claim tracks the open seal posture review",
            ),
            Requirement(
                "docs/reference/testing.md",
                "`vault seal-status` output",
                "testing docs cover seal-status posture output",
            ),
            Requirement(
                "docs/reference/architecture.md",
                "`paranoid-seal` owns:",
                "architecture docs name the seal lifecycle boundary",
            ),
            Requirement(
                "docs/reference/architecture.md",
                "distinguishes configured auto-unseal from confirmed provider",
                "architecture docs document provider availability semantics",
            ),
            Requirement(
                "docs/reference/federal-readiness.md",
                "so evidence does not overstate what the local process has actually checked",
                "federal readiness docs document provider availability evidence semantics",
            ),
            Requirement(
                "crates/paranoid-cli/src/vault_cli.rs",
                "VaultSealPosture::from_providers(VaultSealState::RecoveryRequired, Vec::new())",
                "unreadable vault headers do not synthesize recovery providers",
            ),
            Requirement(
                "crates/paranoid-cli/src/vault_cli.rs",
                "seal_posture_for_unreadable_vault_does_not_synthesize_provider",
                "CLI tests cover unreadable header posture behavior",
            ),
            Requirement(
                "crates/paranoid-cli/src/vault_cli.rs",
                "seal_posture_for_initialized_vault_reports_header_providers_only",
                "CLI tests cover initialized vault posture behavior",
            ),
            Requirement(
                "crates/paranoid-seal/src/lib.rs",
                "posture_reports_configured_recovery_and_auto_unseal_without_claiming_availability",
                "seal crate tests cover configured versus available provider posture",
            ),
            Requirement(
                "crates/paranoid-seal/src/lib.rs",
                "posture_requires_operator_recovery_when_only_auto_unseal_exists",
                "seal crate tests require operator recovery coverage",
            ),
            Requirement(
                "crates/paranoid-seal/src/lib.rs",
                "posture_reports_confirmed_auto_unseal_availability",
                "seal crate tests cover confirmed auto-unseal availability",
            ),
            Requirement(
                "docs/reference/remaining-work-prd.md",
                "seal-state transitions and seal-provider posture have unit tests and e2e coverage",
                "remaining-work PRD tracks seal posture acceptance criteria",
            ),
            Requirement(
                "README.md",
                "`paranoid-seal` owns vault seal state and non-secret provider posture",
                "README names the seal lifecycle boundary",
            ),
            Requirement(
                "docs/conf.py",
                '"paranoid_seal": str(repo_root / "crates" / "paranoid-seal")',
                "docs build includes generated Rust API docs for paranoid-seal",
            ),
            Requirement(
                "docs/api/index.md",
                "crates/paranoid_seal/lib",
                "Rust API index links the paranoid-seal crate docs",
            ),
            Requirement(
                "Cargo.toml",
                '"crates/paranoid-seal"',
                "workspace includes the paranoid-seal crate",
            ),
            Requirement(
                "Cargo.toml",
                'paranoid-seal = { path = "crates/paranoid-seal" }',
                "workspace dependency exposes the paranoid-seal crate",
            ),
            Requirement(
                "crates/paranoid-ops/Cargo.toml",
                "paranoid-seal.workspace = true",
                "paranoid-ops depends on paranoid-seal through workspace dependency",
            ),
            Requirement(
                "crates/paranoid-seal/Cargo.toml",
                'name = "paranoid-seal"',
                "paranoid-seal crate manifest exists",
            ),
            Requirement(
                "crates/paranoid-seal/Cargo.toml",
                "serde.workspace = true",
                "paranoid-seal depends on serde through the workspace",
            ),
            Requirement(
                "crates/paranoid-seal/Cargo.toml",
                "thiserror.workspace = true",
                "paranoid-seal depends on thiserror through the workspace",
            ),
            Requirement(
                "crates/paranoid-seal/Cargo.toml",
                "[lints]",
                "paranoid-seal inherits workspace lints",
            ),
            Requirement(
                "crates/paranoid-seal/src/lib.rs",
                "pub const SEAL_SCHEMA_VERSION: u16 = 1;",
                "seal posture schema version is explicit",
            ),
            Requirement(
                "crates/paranoid-ops/src/lib.rs",
                "SEAL_SCHEMA_VERSION",
                "ops re-exports the seal schema version",
            ),
            Requirement(
                "crates/paranoid-cli/src/vault_cli.rs",
                '"schema_version": SEAL_SCHEMA_VERSION',
                "seal-status JSON uses the seal schema version",
            ),
            Requirement(
                "crates/paranoid-seal/src/lib.rs",
                "pub fn is_auto_unseal(self) -> bool",
                "seal provider kind exposes auto-unseal classification",
            ),
            Requirement(
                "crates/paranoid-seal/src/lib.rs",
                "pub fn is_operator_recovery(self) -> bool",
                "seal provider kind exposes operator recovery classification",
            ),
            Requirement(
                "crates/paranoid-seal/src/lib.rs",
                "pub fn is_certificate_unseal(self) -> bool",
                "seal provider kind exposes certificate unwrap classification",
            ),
            Requirement(
                "crates/paranoid-seal/src/lib.rs",
                "pub fn is_available(self) -> bool",
                "seal provider status exposes confirmed availability classification",
            ),
            Requirement(
                "crates/paranoid-seal/src/lib.rs",
                "pub fn from_providers(",
                "seal posture aggregates provider evidence",
            ),
            Requirement(
                "crates/paranoid-seal/src/lib.rs",
                "recovery_required: state == VaultSealState::RecoveryRequired",
                "seal posture marks recovery-required state explicitly",
            ),
            Requirement(
                "crates/paranoid-seal/src/lib.rs",
                "|| !operator_recovery_configured",
                "seal posture requires an operator recovery path",
            ),
            Requirement(
                "crates/paranoid-seal/src/lib.rs",
                "provider.status.is_available()",
                "seal posture only marks auto-unseal available after provider availability is confirmed",
            ),
            Requirement(
                "docs/reference/architecture.md",
                "`paranoid-seal` owns:",
                "architecture docs name the seal lifecycle boundary",
            ),
        ),
    ),
    Claim(
        "supply-chain.locked-offline-cargo",
        "Locked offline Cargo policy",
        "supply-chain",
        (
            Requirement(
                ".cargo/config.toml",
                'replace-with = "vendored-sources"',
                "Cargo is configured to use vendored sources",
            ),
            Requirement(
                "Makefile",
                "--locked --frozen --offline",
                "Makefile exposes locked/frozen/offline Cargo gates",
            ),
        ),
    ),
    Claim(
        "supply-chain.sha-pinned-actions",
        "SHA-pinned GitHub Actions",
        "supply-chain",
        (
            Requirement(
                "scripts/supply_chain_verify.sh",
                "@[a-f0-9]{40}",
                "supply-chain verifier rejects unpinned external actions",
            ),
            Requirement(
                ".github/dependabot.yml",
                "github-actions",
                "Dependabot tracks GitHub Actions updates",
            ),
        ),
    ),
    Claim(
        "release.payload-verification",
        "Release payload verification",
        "release",
        (
            Requirement(
                "scripts/release_validate.sh",
                "validate_archive_payload",
                "release validation inspects packaged payloads",
            ),
            Requirement(
                "scripts/verify_published_release.sh",
                "gh attestation verify",
                "published release verification checks GitHub attestations",
            ),
        ),
    ),
    Claim(
        "assurance.pr-neutral-auditor",
        "Neutral PR assurance reviewer",
        "assurance-process",
        (
            Requirement(
                ".github/agents/paranoid-security-auditor.md",
                "You do not approve cryptography",
                "custom auditor profile limits model authority",
            ),
            Requirement(
                ".github/instructions/security-assurance.instructions.md",
                "make verify-assurance",
                "path-scoped Copilot instructions require the assurance gate",
            ),
            Requirement(
                ".github/workflows/security-assurance.yml",
                "make verify-assurance",
                "dedicated workflow runs the assurance gate",
            ),
        ),
    ),
)


GLOBAL_REQUIREMENTS: tuple[Requirement, ...] = (
    Requirement(
        "docs/reference/security-assurance.md",
        "Security Assurance Protocol",
        "security assurance protocol reference exists",
    ),
    Requirement(
        "docs/reference/assurance-claims.md",
        "Assurance Claims",
        "assurance claim inventory exists",
    ),
    Requirement(
        "docs/reference/index.md",
        "security-assurance",
        "security assurance docs are in the reference toctree",
    ),
    Requirement(
        "docs/reference/index.md",
        "assurance-claims",
        "assurance claims docs are in the reference toctree",
    ),
    Requirement(
        "Makefile",
        "verify-assurance:",
        "Makefile exposes the assurance gate",
    ),
)


SURFACE_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("core-security", ("crates/paranoid-core/",)),
    ("vault-security", ("crates/paranoid-vault/",)),
    ("ops-security", ("crates/paranoid-audit/", "crates/paranoid-ops/")),
    ("seal-security", ("crates/paranoid-seal/",)),
    ("supply-chain", (".cargo/", "Cargo.lock", "vendor/", ".github/", "scripts/", "Makefile")),
    ("security-docs", ("AGENTS.md", "SECURITY.md", "docs/reference/")),
)


def read_text(path: str) -> str:
    full_path = REPO_ROOT / path
    if not full_path.exists():
        raise FileNotFoundError(path)
    return full_path.read_text(encoding="utf-8")


def requirement_passes(requirement: Requirement) -> tuple[bool, str]:
    try:
        content = read_text(requirement.path)
    except FileNotFoundError:
        return False, f"{requirement.path}: missing file"

    if requirement.regex:
        if re.search(requirement.pattern, content, flags=re.MULTILINE):
            return True, f"{requirement.path}: {requirement.description}"
        return False, f"{requirement.path}: missing regex {requirement.pattern!r}"

    if requirement.pattern in content:
        return True, f"{requirement.path}: {requirement.description}"
    return False, f"{requirement.path}: missing text {requirement.pattern!r}"


def run_git(args: Iterable[str]) -> list[str]:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=REPO_ROOT,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return []
    if result.returncode != 0:
        return []
    return [line for line in result.stdout.splitlines() if line]


def collect_changed_files(base_ref: str | None) -> list[str]:
    files: list[str] = []
    if base_ref:
        files.extend(run_git(["diff", "--name-only", f"{base_ref}...HEAD"]))
    else:
        files.extend(run_git(["diff", "--name-only", "HEAD"]))
        files.extend(run_git(["diff", "--name-only", "--cached"]))
        files.extend(run_git(["ls-files", "--others", "--exclude-standard"]))
    return sorted(set(files))


def summarize_changed_files(changed_files: list[str]) -> tuple[list[str], int]:
    vendor_count = sum(1 for path in changed_files if path.startswith("vendor/"))
    summarized = [path for path in changed_files if not path.startswith("vendor/")]
    if vendor_count:
        summarized.append(f"vendor/ ({vendor_count} changed files)")
    return summarized, vendor_count


def classify_surfaces(changed_files: list[str]) -> list[str]:
    surfaces = set()
    for path in changed_files:
        for surface, prefixes in SURFACE_RULES:
            if any(path == prefix.rstrip("/") or path.startswith(prefix) for prefix in prefixes):
                surfaces.add(surface)
    return sorted(surfaces)


def evaluate_claims() -> tuple[list[dict[str, object]], list[str]]:
    failures: list[str] = []
    claims_doc = read_text("docs/reference/assurance-claims.md")
    results: list[dict[str, object]] = []

    for claim in CLAIMS:
        evidence: list[str] = []
        claim_failures: list[str] = []

        if claim.claim_id not in claims_doc:
            claim_failures.append(f"docs/reference/assurance-claims.md: missing {claim.claim_id}")

        for requirement in claim.requirements:
            ok, message = requirement_passes(requirement)
            if ok:
                evidence.append(message)
            else:
                claim_failures.append(message)

        status = "pass" if not claim_failures else "fail"
        failures.extend(f"{claim.claim_id}: {failure}" for failure in claim_failures)
        results.append(
            {
                "id": claim.claim_id,
                "title": claim.title,
                "surface": claim.surface,
                "status": status,
                "evidence": evidence,
                "failures": claim_failures,
            }
        )

    return results, failures


def evaluate_global_requirements() -> list[str]:
    failures: list[str] = []
    for requirement in GLOBAL_REQUIREMENTS:
        ok, message = requirement_passes(requirement)
        if not ok:
            failures.append(message)
    return failures


def build_report(base_ref: str | None) -> dict[str, object]:
    changed_files = collect_changed_files(base_ref)
    report_changed_files, vendor_changed_file_count = summarize_changed_files(changed_files)
    changed_surfaces = classify_surfaces(changed_files)
    claims, claim_failures = evaluate_claims()
    global_failures = evaluate_global_requirements()
    failures = [*global_failures, *claim_failures]

    return {
        "schema_version": 1,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "verdict": "pass" if not failures else "fail",
        "base_ref": base_ref,
        "changed_files": report_changed_files,
        "changed_file_count": len(changed_files),
        "vendor_changed_file_count": vendor_changed_file_count,
        "changed_surfaces": changed_surfaces,
        "claims": claims,
        "failures": failures,
        "required_commands": ["make verify-assurance", "make ci"],
    }


def write_json(path: Path, report: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_markdown(path: Path, report: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Security Assurance Report",
        "",
        f"- Verdict: `{report['verdict']}`",
        f"- Generated: `{report['generated_at_utc']}`",
        f"- Base ref: `{report['base_ref'] or 'local workspace'}`",
        "",
        "## Changed Surfaces",
        "",
    ]
    changed_surfaces = report["changed_surfaces"]
    if changed_surfaces:
        lines.extend(f"- `{surface}`" for surface in changed_surfaces)
    else:
        lines.append("- none detected")

    lines.extend(["", "## Claims", ""])
    for claim in report["claims"]:
        status = claim["status"]
        marker = "PASS" if status == "pass" else "FAIL"
        lines.append(f"- `{marker}` `{claim['id']}` - {claim['title']}")

    failures = report["failures"]
    if failures:
        lines.extend(["", "## Failures", ""])
        lines.extend(f"- {failure}" for failure in failures)

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-ref", help="Optional git base ref for changed-file detection")
    parser.add_argument("--json-out", type=Path, help="Write the assurance report as JSON")
    parser.add_argument("--markdown-out", type=Path, help="Write the assurance report as Markdown")
    args = parser.parse_args()

    report = build_report(args.base_ref)

    if args.json_out:
        write_json(args.json_out, report)
    if args.markdown_out:
        write_markdown(args.markdown_out, report)

    print(json.dumps(report, indent=2, sort_keys=True))

    if report["verdict"] != "pass":
        print("security assurance gate failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
