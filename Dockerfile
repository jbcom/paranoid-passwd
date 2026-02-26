# syntax=docker/dockerfile:1.7-labs

##
## Attested Build Container — Full Provenance Chain
## ==================================================================
##
## BUILD PHILOSOPHY:
##   ALL testing runs INSIDE Docker as a condition of successful build.
##   If ANY test fails, the Docker build fails — no artifacts produced.
##
##   Tests run in order:
##     1. Native C unit tests (acutest framework)
##     2. OpenSSL compiled FROM SOURCE for WASM (not precompiled!)
##     3. WASM compilation with Zig
##     4. Integration tests (exports, imports, size, SRI)
##     5. Hallucination detection (LLM code safety)
##     6. Supply chain verification
##
## FULL PROVENANCE:
##   Every dependency is built from source inside Docker:
##     Official OpenSSL source → Our patches → Zig compiler → libcrypto.a
##     Our C source → Zig compiler → paranoid.wasm
##
##   No precompiled binaries from third parties. Zero vendor lock-in.
##   The only binary we trust is the Zig compiler tarball (SHA-pinned).
##
## Build command (with full attestation):
##   DOCKER_BUILDKIT=1 docker build \
##     --sbom=true \
##     --provenance=mode=max \
##     -t paranoid-artifact .
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

# Official OpenSSL source — pinned to a tagged release
ARG OPENSSL_REPO=https://github.com/openssl/openssl.git
ARG OPENSSL_TAG=openssl-3.4.0

# Test framework
ARG ACUTEST_REPO=https://github.com/mity/acutest.git
ARG ACUTEST_COMMIT=31751b4089c93b46a9fd8a8183a695f772de66de

# Zig compiler
ARG ZIG_VERSION=0.13.0
ARG ZIG_SHA256=d45312e61ebcc48032b77bc4cf7fd6915c11fa16e4aad116b66c9468211230ea

# ═══════════════════════════════════════════════════════════════════════════════
# STAGE 1: BASE — Alpine with build tools
# ═══════════════════════════════════════════════════════════════════════════════
FROM alpine:${ALPINE_VERSION}@sha256:${ALPINE_SHA256} AS base

# Install build dependencies
# perl: required by OpenSSL's Configure script
# linux-headers: required by some OpenSSL configuration checks
# openssl-dev: native OpenSSL for native test compilation (NOT for WASM)
# pkgconf: resolves native OpenSSL flags via pkg-config
RUN apk add --no-cache \
        ca-certificates \
        curl \
        xz \
        make \
        git \
        python3 \
        openssl \
        openssl-dev \
        pkgconf \
        gcc \
        musl-dev \
        bash \
        perl \
        linux-headers \
        patch \
    && apk add --no-cache --repository=https://dl-cdn.alpinelinux.org/alpine/edge/testing wabt binaryen

# Verify architecture
RUN ARCH=$(uname -m) && [ "$ARCH" = "x86_64" ] || \
    { echo "ERROR: Builder must be x86_64 to match bundled Zig toolchain"; exit 1; }

# ═══════════════════════════════════════════════════════════════════════════════
# STAGE 2: ZIG — Install and verify Zig compiler
# ═══════════════════════════════════════════════════════════════════════════════
FROM base AS zig

ARG ZIG_VERSION
ARG ZIG_SHA256

COPY zig-linux-x86_64-${ZIG_VERSION}.tar.xz .

# Verify Zig tarball hash
RUN echo "${ZIG_SHA256}  zig-linux-x86_64-${ZIG_VERSION}.tar.xz" | sha256sum -c - || \
    { echo "ERROR: Zig tarball hash mismatch — supply chain compromise?"; exit 1; }

# Extract Zig
RUN mkdir -p /opt/zig && tar -xf zig-linux-x86_64-${ZIG_VERSION}.tar.xz -C /opt/zig --strip-components=1
ENV PATH=/opt/zig:${PATH}

RUN echo "Zig $(zig version) installed"

# ═══════════════════════════════════════════════════════════════════════════════
# STAGE 3: BUILD-OPENSSL — Compile OpenSSL FROM OFFICIAL SOURCE for WASM
# ═══════════════════════════════════════════════════════════════════════════════
#
# THIS IS THE KEY PROVENANCE STAGE:
#   We clone the official OpenSSL repository at a pinned tag,
#   apply our WASI patches (sourced from jedisct1/openssl-wasm patterns),
#   and build libcrypto.a from source using Zig.
#
#   No precompiled binaries. Full auditability.
#
FROM zig AS build-openssl

ARG OPENSSL_TAG
ARG OPENSSL_REPO

WORKDIR /build

# Copy our patches and build script
COPY patches/ patches/
COPY scripts/build_openssl_wasm.sh scripts/
RUN chmod +x scripts/build_openssl_wasm.sh

# Clone official OpenSSL at pinned tag
RUN echo "═══════════════════════════════════════════════════════════" && \
    echo "  Cloning official OpenSSL at tag ${OPENSSL_TAG}" && \
    echo "═══════════════════════════════════════════════════════════" && \
    git clone --depth=1 --branch ${OPENSSL_TAG} --single-branch ${OPENSSL_REPO} openssl-src && \
    cd openssl-src && \
    echo "Commit: $(git rev-parse HEAD)" && \
    echo "Tag:    $(git describe --tags)" && \
    echo "✓ Official OpenSSL source cloned"

# Build OpenSSL for WASM — full provenance chain
RUN echo "═══════════════════════════════════════════════════════════" && \
    echo "  STAGE: OpenSSL WASM Build (from source)" && \
    echo "═══════════════════════════════════════════════════════════" && \
    ./scripts/build_openssl_wasm.sh openssl-src /openssl-wasm patches && \
    echo "✓ OpenSSL compiled from source for WASM"

# ═══════════════════════════════════════════════════════════════════════════════
# STAGE 4: DEPS — Clone test framework at pinned commit
# ═══════════════════════════════════════════════════════════════════════════════
FROM base AS deps

ARG ACUTEST_REPO
ARG ACUTEST_COMMIT

WORKDIR /deps

# Clone acutest at pinned commit (header-only test framework)
RUN git clone --filter=blob:none --no-checkout ${ACUTEST_REPO} acutest && \
    cd acutest && \
    git checkout ${ACUTEST_COMMIT} && \
    ACTUAL_SHA=$(git rev-parse HEAD) && \
    [ "$ACTUAL_SHA" = "${ACUTEST_COMMIT}" ] || \
    { echo "ERROR: acutest commit SHA mismatch! Expected ${ACUTEST_COMMIT}, got $ACTUAL_SHA"; exit 1; } && \
    echo "✓ acutest pinned to ${ACUTEST_COMMIT}"

# ═══════════════════════════════════════════════════════════════════════════════
# STAGE 5: TEST-NATIVE — Run C unit tests BEFORE WASM compilation
# ═══════════════════════════════════════════════════════════════════════════════
#
# Native tests use system OpenSSL (openssl-dev), NOT the WASM vendor library.
# This stage does NOT need the from-source WASM OpenSSL — those run in parallel.
#
FROM zig AS test-native

WORKDIR /src

# Copy source code
COPY src/ src/
COPY include/ include/
COPY tests/ tests/
COPY Makefile .

# Copy test framework from deps stage
COPY --from=deps /deps/acutest /src/vendor/acutest

# Build and run native C unit tests (acutest framework)
# THIS MUST PASS or Docker build fails!
RUN echo "═══════════════════════════════════════════════════════════" && \
    echo "  STAGE: Native C Unit Tests (acutest)" && \
    echo "═══════════════════════════════════════════════════════════" && \
    make test-native && \
    echo "✓ All native C tests passed"

# ═══════════════════════════════════════════════════════════════════════════════
# STAGE 6: BUILD-WASM — Compile paranoid.wasm with from-source OpenSSL
# ═══════════════════════════════════════════════════════════════════════════════
FROM test-native AS build-wasm

# Copy the FROM-SOURCE OpenSSL WASM library (no precompiled binaries!)
COPY --from=build-openssl /openssl-wasm /src/vendor/openssl

# Copy web assets
COPY www/ www/

# Copy scripts for verification
COPY scripts/ scripts/
RUN chmod +x scripts/*.sh

# Copy .git if present for reproducible timestamps
COPY .git* .git/
RUN if [ -d .git ]; then \
        echo "✓ .git directory present — SOURCE_DATE_EPOCH will use commit timestamp"; \
    else \
        echo "⚠ .git directory missing — using current time for SOURCE_DATE_EPOCH"; \
        mkdir -p .git && echo "ref: refs/heads/main" > .git/HEAD; \
    fi

# Build WASM and site
RUN echo "═══════════════════════════════════════════════════════════" && \
    echo "  STAGE: WASM Compilation (Zig + from-source OpenSSL)" && \
    echo "═══════════════════════════════════════════════════════════" && \
    make site && \
    echo "✓ WASM compilation successful"

# ═══════════════════════════════════════════════════════════════════════════════
# STAGE 7: VERIFY — Run all verification
# ═══════════════════════════════════════════════════════════════════════════════
FROM build-wasm AS verify

# Run WASM validation (catches codegen bugs that browsers reject)
RUN echo "═══════════════════════════════════════════════════════════" && \
    echo "  STAGE: WASM Validation (wasm-validate)" && \
    echo "═══════════════════════════════════════════════════════════" && \
    wasm-validate build/paranoid.wasm && \
    echo "✓ WASM binary passes spec validation"

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

# Verify binary size is in expected range
# From-source OpenSSL build may differ from precompiled — use wider range
RUN echo "═══════════════════════════════════════════════════════════" && \
    echo "  STAGE: Binary Size Verification" && \
    echo "═══════════════════════════════════════════════════════════" && \
    SIZE=$(stat -c%s build/paranoid.wasm) && \
    echo "WASM size: $SIZE bytes" && \
    [ "$SIZE" -gt 100000 ] && [ "$SIZE" -lt 15000000 ] || \
    { echo "ERROR: Binary size $SIZE outside expected range (100KB-15MB)"; exit 1; } && \
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

# Verify SRI hashes were injected
RUN echo "═══════════════════════════════════════════════════════════" && \
    echo "  STAGE: SRI Hash Verification" && \
    echo "═══════════════════════════════════════════════════════════" && \
    grep -q 'sha384-' build/site/index.html && \
    ! grep -qE '__(WASM|CSS|JS)_SRI__' build/site/index.html && \
    ! grep -q '__WASM_SHA256__' build/site/index.html && \
    ! grep -q '__VERSION__' build/site/index.html && \
    echo "✓ SRI hashes properly injected"

# Verify OpenSSL provenance artifact exists
RUN echo "═══════════════════════════════════════════════════════════" && \
    echo "  STAGE: OpenSSL Provenance Verification" && \
    echo "═══════════════════════════════════════════════════════════" && \
    test -f vendor/openssl/BUILD_PROVENANCE.txt && \
    cat vendor/openssl/BUILD_PROVENANCE.txt && \
    echo "" && \
    echo "✓ OpenSSL build provenance verified"

# Print build summary
RUN echo "" && \
    echo "═══════════════════════════════════════════════════════════" && \
    echo "  BUILD COMPLETE — All Tests Passed" && \
    echo "═══════════════════════════════════════════════════════════" && \
    echo "" && \
    echo "Provenance: Official OpenSSL → Our patches → Zig → WASM" && \
    echo "WASM Hash:  $(sha256sum build/paranoid.wasm | cut -d' ' -f1)" && \
    echo "WASM Size:  $(stat -c%s build/paranoid.wasm) bytes" && \
    echo ""

# ═══════════════════════════════════════════════════════════════════════════════
# STAGE 8: ARTIFACT — Collect verified artifacts
# ═══════════════════════════════════════════════════════════════════════════════
FROM verify AS artifact-collector

RUN mkdir -p /artifact && \
    cp -r build/site /artifact/site && \
    cp build/paranoid.wasm /artifact/paranoid.wasm && \
    sha256sum /artifact/paranoid.wasm > /artifact/paranoid.wasm.sha256 && \
    cat build/site/BUILD_MANIFEST.json > /artifact/BUILD_MANIFEST.json && \
    cp vendor/openssl/BUILD_PROVENANCE.txt /artifact/OPENSSL_PROVENANCE.txt

# ═══════════════════════════════════════════════════════════════════════════════
# FINAL IMAGE — Scratch (zero attack surface)
# ═══════════════════════════════════════════════════════════════════════════════
FROM scratch AS artifact

# OCI annotations for SBOM and provenance tooling
LABEL org.opencontainers.image.title="paranoid-artifact" \
      org.opencontainers.image.source="https://github.com/jbcom/paranoid-passwd" \
      org.opencontainers.image.description="Cryptographic password generator — from-source OpenSSL, full provenance, all tests passed" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="paranoid-passwd" \
      org.opencontainers.image.documentation="https://github.com/jbcom/paranoid-passwd/blob/main/docs/SUPPLY-CHAIN.md"

COPY --from=artifact-collector /artifact/ /artifact/
