# =================================================================
# paranoid-passwd builder image (Docker container action)
#
# Single trust root for every CI/CD job: Wolfi.
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
# All packages come from packages.wolfi.dev, signed by
# wolfi-signing.rsa.pub, with locked source SHAs in their melange recipes.
# =================================================================

FROM cgr.dev/chainguard/wolfi-base:latest

# Install all toolchain packages from Wolfi in one layer.
# Notes on package names (Wolfi-specific):
#   - `ninja-build` (not `ninja`) is the package name in Wolfi.
#   - `tar` and `gzip` are provided by the busybox already in wolfi-base.
#     Only added explicitly when GNU coreutils-tar is needed.
#   - `coreutils` provides GNU sha256sum/stat/install used by build scripts.
#   - `make` is needed for the default cmake generator (Unix Makefiles).
RUN apk add --no-cache \
        bash \
        binaryen \
        cmake \
        coreutils \
        curl \
        git \
        make \
        ninja-build \
        openssl-dev \
        wabt \
        zig

# Sanity check at image-build time — fail fast if any tool is missing.
RUN bash --version >/dev/null \
 && cmake --version >/dev/null \
 && zig version >/dev/null \
 && wasm-validate --version >/dev/null \
 && wasm-opt --version >/dev/null \
 && echo "builder image OK"

# Action entrypoint: run whatever bash code the caller passes via INPUT_RUN.
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
