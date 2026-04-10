---
title: State
updated: 2026-04-09
status: current
domain: context
---

# Current State

## What's Done

### v3.1.0 (released 2026-02-26)

The v3.0 migration is complete. The project is in production at
https://paranoid-passwd.com deployed via GitHub Pages from signed, attested releases.

**Architecture**
- C-based computation (`src/paranoid.c`) compiled to WASM via CMake + Zig
- Platform abstraction layer separates native (OpenSSL) and WASM (compact SHA-256 + WASI)
- WASM binary: ~180KB (no OpenSSL dependency in WASM target)
- JavaScript bridge (`www/app.js`): display-only, reads struct from WASM linear memory
- CSS-only wizard navigation in `www/style.css`

**Build and CI/CD**
- CMake build system with Zig cross-compilation toolchain
- melange + apko (Wolfi) for reproducible package and container builds
- Three-workflow CI/CD: `ci.yml` (PRs), `cd.yml` (push to main), `release.yml` (tags)
- SHA-pinned GitHub Actions throughout
- release-please for automated versioning and release PRs
- Cosign keyless signing via Sigstore
- SLSA Level 3 provenance on all release artifacts

**Security**
- Fail-closed design: WASM unavailability disables generation (no JS fallback)
- SRI hashes for all assets via `BUILD_MANIFEST.json` (loaded at runtime)
- Struct offset runtime verification catches C/JS layout mismatches
- 7-layer statistical audit pipeline
- NIST CAVP SHA-256 known-answer tests
- Double compilation (Zig + Clang) as Ken Thompson defense

**Documentation**
- All standard docs present with YAML frontmatter
- `AGENTS.md` with LLM clean room protocol
- `docs/` with ARCHITECTURE, DESIGN, THREAT-MODEL, AUDIT, BUILD, SUPPLY-CHAIN,
  TESTING, STATE

## Active Issues / Known Gaps

- `docs/plans/2026-02-26-wolfi-migration-design.md` — historical plan, deleted in docs
  standardization pass (2026-04-09)
- `DEVELOPMENT.md` — deleted in docs standardization pass; content absorbed into
  `docs/TESTING.md` and `STANDARDS.md`
- WASM binary is ~180KB; target is <100KB (requires further linker optimization)
- No transparency log or public build record infrastructure

## Planned Work

### Near Term
- Reduce WASM binary size to under 100KB via dead code elimination and `wasm-opt`
- Community verification infrastructure (public build record at paranoid-project.org)
- SBOM transparency log integration

### Medium Term
- NIST SP 800-22 statistical test suite (optional deep test mode)
- Dieharder test battery integration
- Third-party cryptographer security audit

### Long Term
- Formal verification with Frama-C (ACSL annotations on `src/paranoid.c`)
- Post-quantum entropy mode (L≥39, 256-bit threshold)
- Web Workers for parallel batch generation

## Branch Status

- `main` — production, protected, all CI required
- Feature work on named branches, PR to merge

## Open PRs

Check: `gh pr list --repo jbcom/paranoid-passwd`
