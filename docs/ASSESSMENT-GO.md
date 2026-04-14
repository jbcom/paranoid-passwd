---
title: Assessment — Could Go Achieve Better Security Paranoia Than C/WASM?
updated: 2026-04-14
status: draft
domain: technical
---

# Assessment: Could a Rigid Go Codebase Achieve Better Security Paranoia?

This document evaluates whether the security and quality posture of
`paranoid-passwd` (currently C compiled to wasm32-wasi via Zig, with a
display-only JavaScript bridge) could be matched or exceeded by a strict Go
implementation.

The evaluation is grounded in the project's actual threat model
(`docs/THREAT-MODEL.md`), supply-chain framework (`docs/SUPPLY-CHAIN.md`),
and the LLM-adversary stance defined in `AGENTS.md` — *not* in language
preferences.

---

## TL;DR

**No, not for this product.** A Go rewrite would be cleaner to develop and
review, but it would *weaken* the security posture in two structural ways
the project explicitly relies on:

1. **Browser deployment.** The current product runs entirely in the user's
   browser via WebAssembly with no server. Go-to-WASM produces a runtime
   3–5× larger than the current ~100KB target, drags in a garbage
   collector and goroutine scheduler, and ships a far larger attack
   surface for the same job. The "no server" property is load-bearing —
   it's what makes "the page never sees your password" verifiable.
2. **Auditable surface area.** The crypto core is ~400 reviewable lines
   of straight-line C plus a 245-line FIPS 180-4 SHA-256. A strict Go
   version of the same logic would be longer, would route through the
   `crypto/rand`, `math/big`, and `encoding/binary` packages (each their
   own trust chain), and would not let a cryptographer eyeball the entire
   computation in one sitting. Smaller and simpler beats safer-looking
   for an LLM-adversary threat model.

A Go rewrite makes sense **only** if the product is changed to a CLI or a
server-side service. As a browser app, C/WASM is the right choice, and
the rigor in this codebase already exceeds what a Go rewrite would
deliver.

The remainder of this document walks through the comparison dimension by
dimension.

---

## 1. Deployment Model — The Decisive Factor

The product's first paragraph in `README.md` and `docs/ARCHITECTURE.md`
makes one promise: passwords are generated in the user's browser, in a
WASM sandbox, with zero network calls after the initial page load. This is
enforced via CSP, SRI, and a fail-closed JS bridge.

Anything that breaks this promise — a server round-trip, a CLI tool the
user has to install, a service worker that phones home — destroys the
threat model. The user no longer needs to trust *just* their browser; they
have to trust the operator, TLS termination, and any intermediate
infrastructure.

| Deployment | C/WASM today | Go (WASM) | Go (CLI) | Go (server) |
|---|---|---|---|---|
| User trust required | Browser only | Browser only | OS + binary distribution | Browser + operator + TLS |
| Promise: "page can't see your password" | Verifiable | Verifiable | N/A — local | Lost |
| Install friction | None | None | High | None |
| Binary on the wire | ~100KB target | 400KB–2MB | N/A | N/A |
| GC / scheduler in-process | No | Yes | Yes | Yes |

**Verdict:** If we keep the browser-only product, the choice of source
language is constrained by what compiles to small, bounded, GC-free
WASM. C, Rust, and Zig qualify. Go does not. TinyGo exists but is a
different language with its own runtime — it does not get us "rigid Go."

---

## 2. WASM Output: Size, Determinism, Surface Area

| Property | C via Zig (current) | Go (`GOOS=js GOARCH=wasm`) | TinyGo |
|---|---|---|---|
| Typical binary size | ~100KB target | 2–5 MB minimum | 200–800 KB |
| Garbage collector in binary | No | Yes (~1 MB of GC code) | Yes (smaller) |
| Goroutine scheduler | No | Yes | Yes |
| `wasm_exec.js` glue required | No (we ship a 60-line WASI shim) | Yes (Go-shipped, ~20KB JS) | Yes |
| Reproducible builds | Yes (Zig is bit-identical for same input) | Approximately | Approximately |
| Imports beyond WASI random_get | None | DOM bridge + scheduler hooks | A handful |
| Reviewability of import surface | Trivial | Non-trivial | Moderate |

The current build's import surface is one function: `wasi_snapshot_preview1.random_get`.
That is verified in CI (`ci.yml` line 138–148: any other namespace fails
the build). Go builds import a runtime-defined `go.*` namespace with
~20+ entries that the JS glue must implement, including scheduler ticks,
typed-array helpers, and DOM bridges. Each is a place an LLM-authored
glue file could go subtly wrong.

**Verdict:** The current 1-import surface is the strongest possible
reduction. Go (or TinyGo) materially regresses this.

---

## 3. The Crypto Core — Size and Auditability

What a cryptographer must read end-to-end to clear this code:

| Component | Current (C) | Hypothetical strict Go |
|---|---|---|
| RNG bridging | `platform_wasm.c`: 9 LOC | `crypto/rand` (uses `js.Global.Get("crypto").Call(...)` via syscall/js) — a stdlib black box |
| Rejection sampling | `paranoid.c:56–97`, ~40 LOC, no allocations | Equivalent length, but allocates `[]byte` slices via the Go heap |
| Chi-squared | C: ~30 LOC, all `double` arithmetic | Go: similar; Wilson-Hilferty either via `math` or via a third-party stats library |
| SHA-256 | `sha256_compact.c`: 245 LOC of FIPS 180-4 | Use `crypto/sha256` (stdlib, ~600 LOC across files), OR write our own (defeats the point of Go) |
| Total reviewable surface | ~700 LOC, single language, zero deps | Either ~700 LOC + Go runtime + stdlib trust, or 1500+ LOC if reimplementing |

The current design is deliberate: the entire computation is **400 lines of
C** plus a **245-line FIPS-traceable SHA-256**. A cryptographer can read
both in an afternoon. The platform abstraction header (`paranoid_platform.h`,
56 LOC) is the only place the codebase touches "outside."

A "rigid Go" version that uses `crypto/sha256` and `crypto/rand` is
trusting the Go cryptography team — which is reasonable but is not
*better* than trusting OpenSSL for native and FIPS 180-4 reference C for
WASM. It's a *different* trust chain, and a longer one for WASM.

A Go version that reimplements SHA-256 to avoid `crypto/sha256` is
strictly worse: it doesn't get the audited stdlib *and* it loses the
existing FIPS-traceable line-by-line annotations.

**Verdict:** The C core is at the auditability sweet spot. Go can match
the behavior; it cannot match the surface area.

---

## 4. The LLM-Adversary Threat Model

`docs/THREAT-MODEL.md` T5 ("Hallucinated Security Claims") names the
most dangerous threat: an LLM produces plausible-looking but
mathematically wrong code. The mitigations in this codebase are:

1. Every cryptographic line carries a `// VERIFIED:` or `// TODO: HUMAN_REVIEW`
   comment naming the specification it derives from.
2. Known-answer tests use NIST CAVP vectors (`tests/test_sha256.c`).
3. The code is short enough that those comments can actually be checked.
4. The `Hallucination Check` CI job scans for unverified math.
5. Type checking is replaced by deliberate, defensive integer guards
   (`charset_len <= 0 || charset_len > PARANOID_MAX_CHARSET_LEN`).

Go would change exactly two of these:

- **(+)** Go's type system catches some integer-coercion mistakes the
  current C code catches with runtime guards (`int` vs `size_t`).
- **(−)** Go's stdlib hides the math behind opaque calls. An LLM cannot
  miswrite SHA-256 if it never wrote SHA-256 — but a reviewer also
  cannot *verify* that the bytes hashed and the bytes the user typed are
  the same bytes, because the code is now `sha256.Sum256(b)` rather than
  64 explicit rounds whose constants you can check against the FIPS table.

The current design treats every line as untrusted-until-verified. Go's
design philosophy of "use the stdlib" trades *that* property for ergonomic
safety. For most products, Go's tradeoff is correct. For *this* product,
it is exactly backwards.

**Verdict:** Go's safety story is "the stdlib is fine, trust it." The
project's safety story is "trust nothing, including the LLM that wrote
this." These are incompatible philosophies.

---

## 5. Memory Safety

This is where Go *would* clearly win in a different project.

C exposes:
- Buffer overflow on the output array if `length` checks are wrong
- Use-after-free of `g_result` if exposed pointer outlives a call
- Integer overflow in `(256 / charset_len) * charset_len - 1` if `charset_len = 0`

Current mitigations: hard-coded bounds (`PARANOID_MAX_*`), defensive zero
checks, `memset` scrubbing of buffers, and CodeQL + SonarCloud + a CI
hallucination check.

Go's runtime would catch all three classes for free. But — and this is
the part that matters — the WASM sandbox already provides the same
*containment* for free, regardless of source language:

- A WASM module cannot read or write memory outside its own linear
  memory region.
- A buffer overflow in `g_result` cannot reach the browser, the JS
  bridge, or the user's filesystem. It can corrupt the audit result —
  which is then displayed as garbage, which is detectable.
- The browser kernel's process isolation is the next ring out.

So for *this* deployment, the worst case of a C bug is "the audit shows
garbage in the user's browser tab," not "remote code execution." Go's
memory-safety advantage is real but its blast radius here is small.

**Verdict:** Memory safety is a real Go advantage, partially neutered by
the WASM sandbox. Worth ~15% of a security argument, not 80%.

---

## 6. Supply Chain

The current chain (per `docs/SUPPLY-CHAIN.md`):

- Source: ~10 hand-written C/H files, 1 vendored `acutest` (SHA-pinned)
- Compiler: Zig (single binary, reproducible, SHA-pinned in CI)
- Build packaging: Wolfi (`melange.yaml` + `apko.yaml`), provenance-attested
- Distribution: GitHub Pages with SRI hashes
- Runtime imports: 1 WASI function

A Go equivalent's chain:

- Source: similar size of `.go` files
- Compiler: `go` toolchain (single binary, mostly reproducible) **plus**
  a minimum of `crypto/rand`, `crypto/sha256`, `encoding/binary`, `math`,
  `runtime` (the GC), and `syscall/js` (the browser bridge) from stdlib
- Modules: at least Go's stdlib transitively; `go.mod` pinning is good
  but a Go project that uses *no* third-party modules is unusual and
  reviewers would ask why
- Build packaging: same Wolfi flow works
- Distribution: same GH Pages
- Runtime imports: the Go `wasm_exec.js` glue calls a couple dozen
  Go-runtime hooks

Wolfi has both `go` and a bunch of Go modules pre-built, so the
*operational* supply-chain story is comparable. The *reviewable* chain
is materially longer because Go's stdlib is brought in implicitly.

**Verdict:** Roughly equivalent for operations, materially worse for
audit. Wolfi neutralizes the operational difference but cannot shrink
the stdlib's surface area for review.

---

## 7. Where a Rigid Go Codebase Would Win

Honest list:

- **Concurrency.** If the audit added a parallel batch generator that
  produced 10⁶ passwords and ran chi-squared in parallel goroutines, Go
  would be much cleaner than C threads. Not a current requirement.
- **Native CLI.** A `paranoid-passwd` CLI that takes flags and writes a
  password to stdout would be 100 lines of trivial Go. The C native
  build already exists; nobody is asking for a CLI.
- **Test harness ergonomics.** Go's `testing` package is nicer than
  acutest. Real win, but ~5% of the audit budget, not the bottleneck.
- **HTTP server (if it existed).** Go shines for a backend; we don't have
  one and adding one breaks the threat model.
- **Cross-compilation matrix.** `GOOS=...` is friendlier than CMake
  toolchain files. CMake works; this is taste.
- **Refactor velocity for non-crypto code.** Building a desktop wrapper,
  a TUI, or test fixtures would be faster in Go.

None of these touch the security paranoia axis. They are developer-
ergonomics wins, and the project already has tractable ergonomics
(CMake configures in <1s, native tests run in <1s, CI completes in <2min).

---

## 8. What a "Rigid Go" Project Would Have to Look Like To Even Approach Parity

For Go to deliver the project's stated security paranoia, a hypothetical
Go rewrite would need:

1. **Compile target:** TinyGo to wasm32-wasi (the only Go-family compiler
   that produces small enough binaries). This is *not* mainline Go.
2. **No third-party modules.** Stdlib only.
3. **No `crypto/rand` use of `syscall/js` glue** — would have to wire
   WASI `random_get` manually. TinyGo supports this; mainline Go does not.
4. **Either accept `crypto/sha256` as-is (and remove the project's
   "verify every line of crypto" stance) or reimplement SHA-256** in Go
   with the same per-line FIPS annotations the C version has — which
   means rewriting `sha256_compact.c` in Go for no functional gain.
5. **Strict linting** (`staticcheck`, `gosec`, `errcheck`) plus a custom
   linter that enforces the `// VERIFIED:` annotation rule (the C side
   has the `Hallucination Check` script for this).
6. **Reviewer-readable WASI glue** — TinyGo's runtime is smaller than
   mainline Go but still introduces dozens of import functions. Each
   needs a verified shim.

The result is *TinyGo with extra rules*, not "rigid Go." It is not
straightforwardly better than the current C build, and it is materially
harder to recruit cryptographer review for.

---

## 9. The Scenario Where Go Is The Right Call

If the product evolves into one of:

- A standalone CLI (`paranoid-passwd --length 32 --charset alnum`)
- A library imported by other Go programs (a service generating
  one-time passwords, a test fixture generator, etc.)
- A self-hosted backend (defeats the threat model — only acceptable
  if the threat model is explicitly relaxed)

…then a Go rewrite is reasonable and probably preferable to maintaining a
C codebase for those use cases. The native-only `paranoid` library
embedded in a Go program would gain memory safety, easier testing, and
much better packaging, with no WASM-related downsides because there is
no WASM.

This is a *different product*, not the current one.

---

## 10. Recommendation

Keep C compiled to wasm32-wasi as the source of truth for the
browser-deployed product. The current architecture is well matched to
the threat model and the binary-size constraint that makes the threat
model verifiable.

If a CLI variant is desired, write that *as a separate Go binary* that
links against either the existing C library (via `cgo`, accepting that
trade-off) or as an independent Go reimplementation tested against the
same NIST vectors. Do not replace the C/WASM core to gain that CLI.

The rigor that this codebase already brings — SHA-pinned actions, FIPS
180-4 line-by-line annotations, `Hallucination Check` CI, single-import
WASI surface, fail-closed bridge, CSP/SRI distribution, melange/apko
provenance — is not language-bound. Most of it would be preserved by a
Go rewrite. But the *core property* the project sells (small, audit-
in-an-afternoon, verifiable end-to-end) is C-and-Zig-bound, and a Go
rewrite would lose it.
