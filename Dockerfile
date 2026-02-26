# syntax=docker/dockerfile:1.7-labs

##
## Attested Build Container — Liquibase-Style Supply Chain Security
## ==================================================================
##
## This Dockerfile implements the supply chain security practices from:
## https://www.liquibase.com/blog/docker-supply-chain-security
##
## Features:
##   - SHA256-pinned base image (immutable, auditable)
##   - SBOM generation via BuildKit (--sbom=true)
##   - SLSA Level 3 provenance (--provenance=mode=max)
##   - Cosign keyless signing via GitHub OIDC
##   - Zig toolchain hash verification
##   - Reproducible builds (SOURCE_DATE_EPOCH)
##   - Scratch final image (zero attack surface)
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
## View SBOM:
##   docker buildx imagetools inspect ghcr.io/jbcom/paranoid-passwd:latest \
##     --format '{{ json .SBOM }}'
##

# ═══════════════════════════════════════════════════════════════════════════════
# BASE IMAGE — SHA256-pinned for immutability (Liquibase approach)
# ═══════════════════════════════════════════════════════════════════════════════
# Image: debian:12-slim (bookworm)
# Digest verified: 2024-02-26 via `docker pull debian:12-slim && docker inspect`
# To update: pull new image, verify signature, update digest below
# ═══════════════════════════════════════════════════════════════════════════════
FROM debian:12-slim@sha256:74d56e3931e0d5a1dd51f8c8a2466d21de84a271cd3b5a733b803aa91abf4421 AS builder

# ═══════════════════════════════════════════════════════════════════════════════
# ZIG TOOLCHAIN — SHA256-pinned (committed tarball)
# ═══════════════════════════════════════════════════════════════════════════════
ARG ZIG_VERSION=0.14.0
ARG ZIG_DIST=zig-linux-x86_64-${ZIG_VERSION}.tar.xz
ARG ZIG_SHA256=473ec26806133cf4d1918caf1a410f8403a13d979726a9045b421b685031a982

# ═══════════════════════════════════════════════════════════════════════════════
# BUILD ENVIRONMENT
# ═══════════════════════════════════════════════════════════════════════════════
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies (minimal set)
RUN --mount=type=cache,target=/var/cache/apt \
    --mount=type=cache,target=/var/lib/apt \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        xz-utils \
        make \
        git \
        python3 \
        openssl \
        wabt \
    && rm -rf /var/lib/apt/lists/*

# Verify architecture matches bundled Zig toolchain
RUN dpkg --print-architecture | grep -q "^amd64$" || \
    { echo "ERROR: Builder must be amd64/x86_64 to match bundled Zig toolchain"; exit 1; }

# ═══════════════════════════════════════════════════════════════════════════════
# SOURCE VERIFICATION
# ═══════════════════════════════════════════════════════════════════════════════
WORKDIR /src
COPY . .

# Require git metadata for submodule verification and reproducible timestamps
RUN test -d .git || \
    { echo "ERROR: .git directory missing; required for submodule verification"; exit 1; }

# Initialize submodules (fails closed if missing)
RUN git submodule update --init --recursive

# ═══════════════════════════════════════════════════════════════════════════════
# ZIG TOOLCHAIN VERIFICATION
# ═══════════════════════════════════════════════════════════════════════════════
# Verify tarball exists and hash matches before extraction
RUN test -f ${ZIG_DIST} || \
    { echo "ERROR: Zig tarball missing (${ZIG_DIST})"; exit 1; }
RUN echo "${ZIG_SHA256}  ${ZIG_DIST}" | sha256sum -c - || \
    { echo "ERROR: Zig tarball hash mismatch — supply chain compromise?"; exit 1; }

RUN mkdir -p /opt/zig && tar -xf ${ZIG_DIST} -C /opt/zig --strip-components=1
ENV PATH=/opt/zig:${PATH}

# ═══════════════════════════════════════════════════════════════════════════════
# REPRODUCIBLE BUILD
# ═══════════════════════════════════════════════════════════════════════════════
# SOURCE_DATE_EPOCH from git commit timestamp ensures bit-for-bit reproducibility
RUN ts=$(git log -1 --format=%ct 2>/dev/null) && [ -n "$ts" ] || \
    { echo "ERROR: git metadata required for reproducible SOURCE_DATE_EPOCH"; exit 1; } && \
    echo "$ts" > /tmp/source_date_epoch && \
    echo "SOURCE_DATE_EPOCH=$ts"

# Build with deterministic timestamp
RUN SOURCE_DATE_EPOCH=$(cat /tmp/source_date_epoch) make clean
RUN SOURCE_DATE_EPOCH=$(cat /tmp/source_date_epoch) make site

# ═══════════════════════════════════════════════════════════════════════════════
# ARTIFACT COLLECTION
# ═══════════════════════════════════════════════════════════════════════════════
RUN mkdir -p /artifact && \
    cp -r build/site /artifact/site && \
    cp build/paranoid.wasm /artifact/paranoid.wasm

# ═══════════════════════════════════════════════════════════════════════════════
# FINAL IMAGE — Scratch (zero attack surface, Liquibase approach)
# ═══════════════════════════════════════════════════════════════════════════════
FROM scratch AS artifact

# OCI annotations for SBOM and provenance tooling
LABEL org.opencontainers.image.title="paranoid-artifact" \
      org.opencontainers.image.source="https://github.com/jbcom/paranoid-passwd" \
      org.opencontainers.image.description="Cryptographic password generator WASM artifacts — scratch image, no runtime" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="paranoid-passwd" \
      org.opencontainers.image.documentation="https://github.com/jbcom/paranoid-passwd/blob/main/docs/SUPPLY-CHAIN.md"

COPY --from=builder /artifact/ /artifact/
