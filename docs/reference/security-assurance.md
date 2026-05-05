---
title: Security Assurance Protocol
---

# Security Assurance Protocol

This repository uses a security assurance protocol, not a free-form "prompt engineering"
or "challenge / response" process. The model may challenge a pull request, but it does
not approve cryptography, waive tests, or replace deterministic verification.

The protocol is claim-led:

1. security-sensitive behavior is expressed as named assurance claims
2. each claim points to source locations, tests, scripts, and docs
3. CI runs deterministic gates before any model-authored review can matter
4. the AI assessor agent is a neutral reporter that cites evidence and blocks uncertainty
5. maintainers merge only when required gates pass and blocking findings are resolved

## Research Basis

The protocol is intentionally boring. It follows the direction of current public guidance
rather than relying on stronger prompts:

- GitHub documents repository custom instructions through `.github/copilot-instructions.md`
  and path-scoped `.github/instructions/*.instructions.md` files for Copilot review and
  coding agents.
- GitHub's late-2025 agent-specific instruction support allows targeted instructions for
  code review and coding-agent contexts instead of one catch-all prompt.
- OWASP's 2026 Agentic AI security guidance treats autonomous agents as a distinct risk
  class because tool use, prompt injection, goal hijacking, and trust exploitation create
  failure modes that normal code review prompts do not control.
- OpenSSF GitHub workflow guidance emphasizes least-privilege tokens, pinned actions,
  avoiding privileged workflows for untrusted code, and careful handling of attacker-
  controlled inputs.
- GitHub artifact attestations and SLSA guidance reinforce that build and release trust
  comes from verifiable provenance and verification, not assessor confidence.
- NIST AI RMF guidance frames AI governance around mapped risks, measured outcomes, and
  recorded evidence.

References:

- [GitHub repository custom instructions](https://docs.github.com/en/copilot/how-tos/copilot-on-github/customize-copilot/add-custom-instructions/add-repository-instructions)
- [GitHub agent-specific instruction support](https://github.blog/changelog/2025-11-12-copilot-code-review-and-coding-agent-now-support-agent-specific-instructions/)
- [OWASP Top 10 for Agentic Applications announcement](https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/)
- [OpenSSF GitHub workflow attack-vector guidance](https://openssf.org/blog/2024/08/12/mitigating-attack-vectors-in-github-workflows/)
- [GitHub artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations)
- [NIST AI RMF Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)

## Pull Request Protocol

Every pull request that touches a sensitive surface must be reviewed against
[assurance-claims.md](./assurance-claims.md).

Sensitive surfaces are:

- `crates/paranoid-core/**`
- `crates/paranoid-vault/**`
- `.cargo/**`, `Cargo.lock`, `vendor/**`
- `.github/**`, `scripts/**`, `Makefile`
- `AGENTS.md`, `SECURITY.md`, and `docs/reference/**`

Required steps:

1. Identify changed sensitive surfaces.
2. Run `make verify-assurance`.
3. Run `make ci` before merge when the change is not docs-only.
4. Use the security assessor instructions in
   `.github/agents/paranoid-security-auditor.md` or the path-scoped Copilot instructions
   in `.github/instructions/security-assurance.instructions.md`.
5. Treat the agent output as findings and questions, not approval.
6. Resolve every blocking finding with code, tests, docs, or an explicit claim disposition.
7. For UI-sensitive changes, cite the GUI screenshot artifact produced by `make test-gui-e2e`
   or `make test-gui-e2e-emulate`.

## Deterministic Gate

`make verify-assurance` is the required local and CI gate for this protocol. It runs:

```bash
bash scripts/hallucination_check.sh
bash scripts/supply_chain_verify.sh
bash scripts/verify_ai_review_inventory.sh
python3 scripts/security_assurance_gate.py
```

The Python gate validates that the claim inventory, Copilot instructions, custom agent
profile, workflows, and security reference docs stay wired together. It also emits a
machine-readable report when asked:

```bash
python3 scripts/security_assurance_gate.py \
  --json-out dist/security-assurance-report.json \
  --markdown-out dist/security-assurance-report.md
```

## AI Assessor Agent Contract

The neutral PR security assessor must:

- cite file paths and line numbers for findings
- distinguish deterministic evidence from model judgment
- fail closed when evidence is missing
- require GUI screenshot capture for UI-sensitive changes and cite the artifact path
- refuse to approve custom crypto, ad hoc randomness, modulo-without-rejection, browser
  runtime reintroduction, unpinned workflow actions, or loosened Cargo offline policy
- require known-answer tests for audit math changes
- require a claim disposition for any change to tracked open AI review sites

The agent must not:

- claim independent cryptographic or statistical sign-off
- accept "looks correct" as evidence
- waive CI, release, supply-chain, or inventory gates
- request secrets or privileged tokens for pull request review
- use `pull_request_target` or other privileged workflows for untrusted PR code

## Decision States

Each claim touched by a pull request ends in exactly one state:

| State | Meaning |
|------|---------|
| `pass` | Required deterministic gates passed and no blocking finding remains. |
| `blocked` | A required gate failed, a source invariant moved, or evidence is missing. |
| `needs-disposition` | The code may be implemented, but an assurance claim changed and needs a written disposition before the release claim can be strengthened. |
| `out-of-scope` | The PR did not touch a sensitive surface. |

## Stable Release Rule

A stable release can rely on this protocol only when:

1. `make ci` and `make verify-assurance` pass on the release candidate.
2. The release candidate has a generated security assurance report.
3. Every touched claim in [assurance-claims.md](./assurance-claims.md) is either enforced
   by deterministic gates or explicitly marked as open disposition.
4. No documentation claims external cryptographic approval unless an external disposition
   exists and is linked from the repo.

This preserves the security posture while removing the old dependency on vague,
unstructured review language.
