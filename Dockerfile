# syntax=docker/dockerfile:1.7-labs

##
## Attested Build Container — Liquibase-Style Supply Chain Security
## ==================================================================
##
## This Dockerfile implements the supply chain security practices from:
## https://www.liquibase.com/blog/docker-supply-chain-security
##
## BUILD PHILOSOPHY:
##   ALL testing runs INSIDE Docker as a condition of successful build.
##   If ANY test fails, the Docker build fails — no artifacts produced.
##
##   Tests run in order:
##     1. Native C unit tests (acutest framework)
##     2. WASM compilation with Zig
##     3. Integration tests (exports, imports, size, SRI)
##     4. Hallucination detection (LLM code safety)
##     5. Supply chain verification
##     6. (Optional) Diverse double-compilation with Clang
##
## NO SUBMODULE REQUIRED:
##   The Dockerfile clones openssl-wasm at a SHA-pinned commit.
##   The vendor/ directory and .gitmodules are NOT needed for Docker builds.
##   This makes the container fully self-contained and reproducible.
##
## BASE IMAGE RATIONALE:
##   Alpine (~3.5MB) vs Debian slim (~29MB) = 8x smaller
##   musl libc + BusyBox = minimal, auditable footprint
##   Zig static binaries compatible with musl-libc
##
## Build command (with full attestation):
##   DOCKER_BUILDKIT=1 docker build \
##     --sbom=true \
##     --provenance=mode=max \
##     -t paranoid-artifact .
##
## Verify signature (after push to registry):
##   cosign verify ghcr.io/jbcom/paranoid-passwd:latest \
##     --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
##     --certificate-identity-regexp="https://github.com/jbcom/paranoid-passwd/.*"
##
## Extract artifacts:
##   docker create --name temp paranoid-artifact
##   docker cp temp:/artifact ./artifact
##   docker rm temp
##

# ═══════════════════════════════════════════════════════════════════════════════
# ARGS — SHA-pinned dependencies (supply chain security)
# ═══════════════════════════════════════════════════════════════════════════════
ARG ALPINE_VERSION=3.21
ARG ALPINE_SHA256=25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659
ARG OPENSSL_WASM_REPO=https://github.com/jedisct1/openssl-wasm.git
ARG OPENSSL_WASM_COMMIT=fe926b5006593ad2825243f97e363823cd56599f
ARG ACUTEST_REPO=https://github.com/mity/acutest.git
ARG ACUTEST_COMMIT=31751b4089c93b46a9fd8a8183a695f772de66de
ARG ZIG_VERSION=0.14.0
ARG ZIG_SHA256=473ec26806133cf4d1918caf1a410f8403a13d979726a9045b421b685031a982

# ═══════════════════════════════════════════════════════════════════════════════
# STAGE 1: BASE — Alpine with build tools
# ═══════════════════════════════════════════════════════════════════════════════
FROM alpine:${ALPINE_VERSION}@sha256:${ALPINE_SHA256} AS base

# Install build dependencies (minimal set for C/WASM compilation + testing)
RUN apk add --no-cache \
        ca-certificates \
        curl \
        xz \
        make \
        git \
        python3 \
        openssl \
        gcc \
        musl-dev \
        bash \
    && apk add --no-cache --repository=https://dl-cdn.alpinelinux.org/alpine/edge/testing wabt

# Verify architecture
RUN ARCH=$(uname -m) && [ "$ARCH" = "x86_64" ] || \
    { echo "ERROR: Builder must be x86_64 to match bundled Zig toolchain"; exit 1; }

# ═══════════════════════════════════════════════════════════════════════════════
# STAGE 2: DEPS — Clone dependencies at pinned commits
# ═══════════════════════════════════════════════════════════════════════════════
FROM base AS deps

ARG OPENSSL_WASM_REPO
ARG OPENSSL_WASM_COMMIT
ARG ACUTEST_REPO
ARG ACUTEST_COMMIT

WORKDIR /deps

# Clone openssl-wasm at pinned commit (no submodule needed!)
RUN git clone --filter=blob:none --no-checkout ${OPENSSL_WASM_REPO} openssl-wasm && \
    cd openssl-wasm && \
    git checkout ${OPENSSL_WASM_COMMIT} && \
    ACTUAL_SHA=$(git rev-parse HEAD) && \
    [ "$ACTUAL_SHA" = "${OPENSSL_WASM_COMMIT}" ] || \
    { echo "ERROR: openssl-wasm commit SHA mismatch! Expected ${OPENSSL_WASM_COMMIT}, got $ACTUAL_SHA"; exit 1; } && \
    echo "✓ openssl-wasm pinned to ${OPENSSL_WASM_COMMIT}"

# Clone acutest at pinned commit (header-only test framework, no vendor directory needed!)
RUN git clone --filter=blob:none --no-checkout ${ACUTEST_REPO} acutest && \
    cd acutest && \
    git checkout ${ACUTEST_COMMIT} && \
    ACTUAL_SHA=$(git rev-parse HEAD) && \
    [ "$ACTUAL_SHA" = "${ACUTEST_COMMIT}" ] || \
    { echo "ERROR: acutest commit SHA mismatch! Expected ${ACUTEST_COMMIT}, got $ACTUAL_SHA"; exit 1; } && \
    echo "✓ acutest pinned to ${ACUTEST_COMMIT}"

# ═══════════════════════════════════════════════════════════════════════════════
# STAGE 3: TEST-NATIVE — Run C unit tests BEFORE WASM compilation
# ═══════════════════════════════════════════════════════════════════════════════
FROM base AS test-native

ARG ZIG_VERSION
ARG ZIG_SHA256

WORKDIR /src

# Copy source code (excluding vendor/ - we use deps stage)
COPY src/ src/
COPY include/ include/
COPY tests/ tests/
COPY Makefile .
COPY zig-linux-x86_64-${ZIG_VERSION}.tar.xz .

# Copy dependencies from deps stage
COPY --from=deps /deps/openssl-wasm /src/vendor/openssl-wasm
COPY --from=deps /deps/acutest /src/vendor/acutest

# Verify Zig tarball hash
RUN echo "${ZIG_SHA256}  zig-linux-x86_64-${ZIG_VERSION}.tar.xz" | sha256sum -c - || \
    { echo "ERROR: Zig tarball hash mismatch — supply chain compromise?"; exit 1; }

# Extract Zig
RUN mkdir -p /opt/zig && tar -xf zig-linux-x86_64-${ZIG_VERSION}.tar.xz -C /opt/zig --strip-components=1
ENV PATH=/opt/zig:${PATH}

# Build and run native C unit tests (acutest framework)
# THIS MUST PASS or Docker build fails!
RUN echo "═══════════════════════════════════════════════════════════" && \
    echo "  STAGE: Native C Unit Tests (acutest)" && \
    echo "═══════════════════════════════════════════════════════════" && \
    make test-native && \
    echo "✓ All native C tests passed"

# ═══════════════════════════════════════════════════════════════════════════════
# STAGE 4: BUILD-ZIG — Compile WASM with Zig (primary compiler)
# ═══════════════════════════════════════════════════════════════════════════════
FROM test-native AS build-zig

# Copy web assets
COPY www/ www/

# Copy scripts for verification
COPY scripts/ scripts/
RUN chmod +x scripts/*.sh

# Copy .git if present for reproducible timestamps and supply chain verification
# This is optional - CI builds will have .git, local builds may not
COPY .git* .git/
RUN if [ -d .git ]; then \
        echo "✓ .git directory present — SOURCE_DATE_EPOCH will use commit timestamp"; \
    else \
        echo "⚠ .git directory missing — using current time for SOURCE_DATE_EPOCH"; \
        mkdir -p .git && echo "ref: refs/heads/main" > .git/HEAD; \
    fi

# Build WASM and site
RUN echo "═══════════════════════════════════════════════════════════" && \
    echo "  STAGE: WASM Compilation (Zig)" && \
    echo "═══════════════════════════════════════════════════════════" && \
    make site && \
    echo "✓ WASM compilation successful"

# ═══════════════════════════════════════════════════════════════════════════════
# STAGE 5: VERIFY — Run all verification (integration, hallucination, supply chain)
# ═══════════════════════════════════════════════════════════════════════════════
FROM build-zig AS verify

# Run WASM export/import verification
RUN echo "═══════════════════════════════════════════════════════════" && \
    echo "  STAGE: WASM Verification" && \
    echo "═══════════════════════════════════════════════════════════" && \
    make verify && \
    echo "✓ WASM exports/imports verified"

# Run hallucination detection (LLM code safety)
RUN echo "═══════════════════════════════════════════════════════════" && \
    echo "  STAGE: Hallucination Detection" && \
    echo "═══════════════════════════════════════════════════════════" && \
    ./scripts/hallucination_check.sh && \
    echo "✓ No LLM hallucinations detected"

# Verify binary size is in expected range (~180KB ± 20KB per AGENTS.md)
RUN echo "═══════════════════════════════════════════════════════════" && \
    echo "  STAGE: Binary Size Verification" && \
    echo "═══════════════════════════════════════════════════════════" && \
    SIZE=$(stat -c%s build/paranoid.wasm) && \
    echo "WASM size: $SIZE bytes" && \
    [ "$SIZE" -gt 160000 ] && [ "$SIZE" -lt 200000 ] || \
    { echo "ERROR: Binary size $SIZE outside expected range (160KB-200KB)"; exit 1; } && \
    echo "✓ Binary size within expected range"

# Verify site assets exist
RUN echo "═══════════════════════════════════════════════════════════" && \
    echo "  STAGE: Site Asset Verification" && \
    echo "═══════════════════════════════════════════════════════════" && \
    test -f build/site/index.html && \
    test -f build/site/app.js && \
    test -f build/site/style.css && \
    test -f build/site/paranoid.wasm && \
    test -f build/site/BUILD_MANIFEST.json && \
    echo "✓ All site assets present"

# Verify SRI hashes were injected (check explicit placeholder names)
RUN echo "═══════════════════════════════════════════════════════════" && \
    echo "  STAGE: SRI Hash Verification" && \
    echo "═══════════════════════════════════════════════════════════" && \
    grep -q 'sha384-' build/site/index.html && \
    ! grep -qE '__(WASM|CSS|JS)_SRI__' build/site/index.html && \
    ! grep -q '__WASM_SHA256__' build/site/index.html && \
    ! grep -q '__VERSION__' build/site/index.html && \
    echo "✓ SRI hashes properly injected"

# Print build summary
RUN echo "" && \
    echo "═══════════════════════════════════════════════════════════" && \
    echo "  BUILD COMPLETE — All Tests Passed" && \
    echo "═══════════════════════════════════════════════════════════" && \
    echo "" && \
    echo "WASM Hash: $(sha256sum build/paranoid.wasm | cut -d' ' -f1)" && \
    echo "WASM Size: $(stat -c%s build/paranoid.wasm) bytes" && \
    echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# STAGE 6: ARTIFACT — Collect verified artifacts
# ═══════════════════════════════════════════════════════════════════════════════
FROM verify AS artifact-collector

RUN mkdir -p /artifact && \
    cp -r build/site /artifact/site && \
    cp build/paranoid.wasm /artifact/paranoid.wasm && \
    sha256sum /artifact/paranoid.wasm > /artifact/paranoid.wasm.sha256 && \
    cat build/site/BUILD_MANIFEST.json > /artifact/BUILD_MANIFEST.json

# ═══════════════════════════════════════════════════════════════════════════════
# FINAL IMAGE — Scratch (zero attack surface, Liquibase approach)
# ═══════════════════════════════════════════════════════════════════════════════
FROM scratch AS artifact

# OCI annotations for SBOM and provenance tooling
LABEL org.opencontainers.image.title="paranoid-artifact" \
      org.opencontainers.image.source="https://github.com/jbcom/paranoid-passwd" \
      org.opencontainers.image.description="Cryptographic password generator WASM artifacts — scratch image, zero runtime, all tests passed" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="paranoid-passwd" \
      org.opencontainers.image.documentation="https://github.com/jbcom/paranoid-passwd/blob/main/docs/SUPPLY-CHAIN.md"

COPY --from=artifact-collector /artifact/ /artifact/
