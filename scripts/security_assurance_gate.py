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
