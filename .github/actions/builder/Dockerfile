# =================================================================
# paranoid-passwd builder image (Docker container action)
#
# Single trust root for every CI/CD job: Wolfi (+ pinned Zig 0.13.0).
#
# This Dockerfile lives in-repo. GitHub Actions builds it per-job
# from action.yml's `runs.using: docker` + `image: Dockerfile`.
# No registry, no signing, no digest pinning. The PR that touches
# this file IS the PR that adopts the new toolchain — atomically.
#
# Replaces in every consuming workflow:
#   - GitHub-managed ubuntu-24.04 toolchain layer
#   - apt-get install cmake / wabt / etc.
#   - curl https://ziglang.org/download/...
#
# All Wolfi packages come from packages.wolfi.dev, signed by
# wolfi-signing.rsa.pub, with locked source SHAs in their melange recipes.
# Zig comes from ziglang.org with a pinned SHA-256.
#
# Why vendor Zig instead of using Wolfi's zig package:
#   Wolfi's `zig` tracks the latest upstream (currently 0.15.x), which
#   has WASM codegen/export-naming changes that break our wasm-objdump
#   validation step. See memory/zig-bug.md — we pin 0.13.0 until 0.15
#   WASM backend is verified. curl+SHA is the same pattern the
#   workflows used before this Docker action existed, so the trust
#   chain is unchanged.
# =================================================================

FROM cgr.dev/chainguard/wolfi-base:latest

# Wolfi toolchain packages.
# Notes on package names (Wolfi-specific):
#   - `ninja-build` (not `ninja`) is the package name in Wolfi.
#   - `tar` and `gzip` are provided by the busybox in wolfi-base.
#   - `coreutils` provides GNU sha256sum/stat/install used by build scripts.
#   - `make` is needed for the default cmake generator (Unix Makefiles).
#   - `build-base` provides gcc + binutils + libc headers so CMake's
#     native C compiler detection succeeds inside the image.
RUN apk add --no-cache \
        bash \
        binaryen \
        build-base \
        cmake \
        coreutils \
        curl \
        git \
        make \
        ninja-build \
        openssl-dev \
        wabt

# Vendor Zig 0.13.0 with SHA-256 pin (same chain of trust as the
# previous curl-on-ubuntu workflow step it replaces).
ARG ZIG_VERSION=0.13.0
ARG ZIG_SHA256=d45312e61ebcc48032b77bc4cf7fd6915c11fa16e4aad116b66c9468211230ea
RUN archive="zig-linux-x86_64-${ZIG_VERSION}.tar.xz" \
 && curl -sSLO "https://ziglang.org/download/${ZIG_VERSION}/${archive}" \
 && echo "${ZIG_SHA256}  ${archive}" | sha256sum -c - \
 && tar -xJf "${archive}" -C /opt/ \
 && ln -sf "/opt/zig-linux-x86_64-${ZIG_VERSION}/zig" /usr/local/bin/zig \
 && rm "${archive}"

# Sanity check at image-build time — fail fast if any tool is missing.
RUN bash --version >/dev/null \
 && cc --version >/dev/null \
 && cmake --version >/dev/null \
 && zig version | grep -q "^0\.13\." \
 && wasm-validate --version >/dev/null \
 && wasm-opt --version >/dev/null \
 && echo "builder image OK"

# Action entrypoint: run whatever bash code the caller passes via INPUT_RUN.
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
