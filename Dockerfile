# syntax=docker/dockerfile:1.7-labs

##
## Attested build container
## -------------------------
## - Final image: scratch (artifacts only, no OS)
## - Builder image: must be provided with a trusted digest at build time
## - Zig toolchain hash is verified before use
## - Uses BuildKit features; enable with DOCKER_BUILDKIT=1
##

# MUST be overridden with a verified digest (build fails closed if left as-is)
ARG DEBIAN_IMAGE=debian:12-slim@sha256:REQUIRE_TRUSTED_DIGEST
FROM ${DEBIAN_IMAGE} AS builder

# Validate DEBIAN_IMAGE shape (format-only; actual digest trust must be verified upstream)
RUN case "$DEBIAN_IMAGE" in \
    *REQUIRE_TRUSTED_DIGEST*) echo "ERROR: DEBIAN_IMAGE placeholder rejected."; echo "Set --build-arg DEBIAN_IMAGE=debian:12-slim@sha256:<verified-digest>"; exit 1 ;; \
    *@sha256:*) \
        digest=${DEBIAN_IMAGE##*@sha256:}; \
        digest_norm=$(echo "$digest" | tr 'A-F' 'a-f'); \
        echo "$digest_norm" | grep -Eq '^[a-f0-9]{64}$' || { echo "ERROR: DEBIAN_IMAGE digest must be 64 hex chars"; exit 1; } ;; \
    *) echo "ERROR: DEBIAN_IMAGE must include @sha256:<digest>"; exit 1 ;; \
    esac

ARG ZIG_VERSION=0.14.0
ARG ZIG_DIST=zig-linux-x86_64-${ZIG_VERSION}.tar.xz
# Pinned to the checked-in tarball (zig-linux-x86_64-0.14.0.tar.xz)
ARG ZIG_SHA256=473ec26806133cf4d1918caf1a410f8403a13d979726a9045b421b685031a982

ENV DEBIAN_FRONTEND=noninteractive

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

RUN dpkg --print-architecture | grep -q "^amd64$" || { echo "ERROR: Builder must be amd64/x86_64 to match bundled Zig toolchain"; exit 1; }

WORKDIR /src
COPY . .

# Ensure git metadata is present for submodule verification
RUN test -d .git || { echo "ERROR: .git directory missing; required for submodule verification"; exit 1; }

# Ensure submodule is present (fails closed if missing)
RUN git submodule update --init --recursive

# Verify the Zig toolchain hash before extracting (tarball is committed to the repo)
RUN test -f ${ZIG_DIST} || { echo "ERROR: Zig tarball missing (${ZIG_DIST})"; exit 1; }
RUN echo "${ZIG_SHA256}  ${ZIG_DIST}" | sha256sum -c - || { echo "ERROR: Zig tarball hash mismatch"; exit 1; }

RUN mkdir -p /opt/zig && tar -xf ${ZIG_DIST} -C /opt/zig --strip-components=1
ENV PATH=/opt/zig:${PATH}

# Deterministic timestamp for reproducible builds; fail if git metadata is absent
RUN ts=$(git log -1 --format=%ct 2>/dev/null) && [ -n "$ts" ] || { echo "ERROR: git metadata required for reproducible SOURCE_DATE_EPOCH"; exit 1; } && \
    echo "$ts" > /tmp/source_date_epoch && \
    echo "SOURCE_DATE_EPOCH=$ts"
RUN SOURCE_DATE_EPOCH=$(cat /tmp/source_date_epoch) make clean
RUN SOURCE_DATE_EPOCH=$(cat /tmp/source_date_epoch) make site

# Collect artifacts for the minimal final image
RUN mkdir -p /artifact && \
    cp -r build/site /artifact/site && \
    cp build/paranoid.wasm /artifact/paranoid.wasm

FROM scratch AS artifact
LABEL org.opencontainers.image.title="paranoid-artifact" \
      org.opencontainers.image.source="https://github.com/jbcom/paranoid-passwd" \
      org.opencontainers.image.description="Scratch image containing paranoid build artifacts with no runtime" \
      org.opencontainers.image.licenses="MIT"

COPY --from=builder /artifact/ /artifact/
