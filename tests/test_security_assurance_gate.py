#!/usr/bin/env python3
"""Negative-proof harness for the security assurance gate (P9.7).

The gate (`scripts/security_assurance_gate.py`) is only worth trusting if
deleting a load-bearing piece of a shipped P9 hardening actually flips it
from `pass` to `fail`. This script proves that for one representative P9
requirement per hardening item (the zeroize wrapper's `Debug` impl for
P9.1, the `check_lockout` gate for P9.2, and the `setrlimit(RLIMIT_CORE, 0)`
call for P9.3) by mirroring just the small set of files that claim's
`Requirement`s touch into an isolated temp directory, stripping the
load-bearing string from one of them, and asserting the gate now reports
that specific claim as failed. The real repository tree is never mutated.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
GATE_SCRIPT = REPO_ROOT / "scripts" / "security_assurance_gate.py"

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import security_assurance_gate as gate  # noqa: E402


def mirror_claim_files(claim: "gate.Claim", dest_root: Path) -> None:
    """Copies every file a claim's requirements read into `dest_root`,
    preserving the same relative paths the gate expects under its own
    REPO_ROOT, plus the claims doc (checked separately below)."""
    paths = {requirement.path for requirement in claim.requirements}
    paths.add("docs/reference/assurance-claims.md")
    for relative_path in paths:
        source = REPO_ROOT / relative_path
        destination = dest_root / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def run_gate_against(dest_root: Path) -> dict:
    """Runs the gate's own evaluation logic (not a subprocess) against
    `dest_root` by monkeypatching its REPO_ROOT for the duration of the
    call, then restoring it. Using the in-process module (rather than
    shelling out to a copied script) keeps this a direct test of the same
    `evaluate_claims`/`requirement_passes` code paths the real `make
    verify-assurance` run exercises."""
    original_repo_root = gate.REPO_ROOT
    gate.REPO_ROOT = dest_root
    try:
        results, failures = gate.evaluate_claims()
    finally:
        gate.REPO_ROOT = original_repo_root
    return {result["id"]: result for result in results}, failures


def claim_by_id(claim_id: str) -> "gate.Claim":
    for claim in gate.CLAIMS:
        if claim.claim_id == claim_id:
            return claim
    raise AssertionError(f"no such claim: {claim_id}")


def assert_gate_catches_deletion(
    claim_id: str, mutate_path: str, load_bearing_text: str
) -> None:
    claim = claim_by_id(claim_id)

    import tempfile

    with tempfile.TemporaryDirectory(prefix="assurance-gate-negative-") as tmp:
        dest_root = Path(tmp)
        mirror_claim_files(claim, dest_root)

        # Baseline: the mirrored, untouched files must satisfy every
        # requirement for this claim, or the mirror itself is incomplete
        # and the negative test below would be meaningless.
        results, _ = run_gate_against(dest_root)
        baseline_status = results[claim_id]["status"]
        if baseline_status != "pass":
            raise AssertionError(
                f"{claim_id}: baseline mirror must pass before mutation, "
                f"got {baseline_status}: {results[claim_id]['failures']}"
            )

        # Mutation: strip the load-bearing string from the mirrored copy
        # only. The real repository file on disk is never touched.
        target = dest_root / mutate_path
        original = target.read_text(encoding="utf-8")
        if load_bearing_text not in original:
            raise AssertionError(
                f"{mutate_path}: expected load-bearing text not found: "
                f"{load_bearing_text!r}"
            )
        mutated = original.replace(load_bearing_text, "")
        target.write_text(mutated, encoding="utf-8")

        results, failures = run_gate_against(dest_root)
        mutated_status = results[claim_id]["status"]
        if mutated_status != "fail":
            raise AssertionError(
                f"{claim_id}: deleting {load_bearing_text!r} from "
                f"{mutate_path} must flip the claim to fail, got "
                f"{mutated_status}"
            )
        if not any(claim_id in failure for failure in failures):
            raise AssertionError(
                f"{claim_id}: mutated run must report a failure naming "
                f"the claim id, got: {failures}"
            )

    print(f"PASS {claim_id}: gate catches deletion of {mutate_path!r} evidence")


def main() -> int:
    # P9.1 representative: deleting the zeroize-on-drop wrapper's redacting
    # Debug impl must flip vault.zeroized-payload-secrets to fail.
    assert_gate_catches_deletion(
        "vault.zeroized-payload-secrets",
        "crates/paranoid-vault/src/native_access.rs",
        'f.write_str("<redacted>")',
    )

    # P9.2 representative: deleting the pre-Argon2id lockout gate call must
    # flip vault.failed-unlock-lockout to fail.
    assert_gate_catches_deletion(
        "vault.failed-unlock-lockout",
        "crates/paranoid-vault/src/lifecycle.rs",
        "check_lockout(path)?;",
    )

    # P9.3 representative: deleting the core-dump-disabling setrlimit call
    # must flip vault.memory-hardening to fail.
    assert_gate_catches_deletion(
        "vault.memory-hardening",
        "crates/paranoid-vault/src/mem_hardening.rs",
        "let result = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) };",
    )

    print("security assurance gate negative-proof: all checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
