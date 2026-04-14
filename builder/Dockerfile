# =================================================================
# paranoid-passwd builder image
#
# Single trust root for every CI/CD job: Wolfi.
#
# Replaces:
#   - GitHub-managed ubuntu-24.04 runner image (toolchain side)
#   - apt-get install cmake / wabt / etc.
#   - curl https://ziglang.org/download/...
#
# All packages come from packages.wolfi.dev, signed by
# wolfi-signing.rsa.pub, with locked source SHAs in their melange recipes.
#
# Image is built and pushed by .github/workflows/builder.yml on changes
# to builder/**, signed via cosign keyless (sigstore OIDC), and pinned
# in consuming workflows by sha256 digest.
# =================================================================

# Pin Wolfi base by digest (set by dependabot once it tracks Docker tags).
# wolfi-base ships only apk-tools, libc, and ca-certificates -- nothing else.
FROM cgr.dev/chainguard/wolfi-base:latest

# Install all toolchain packages from Wolfi in one layer.
# Versions are determined by Wolfi at image-build time. The image SHA we
# publish locks the exact set; consumers pin by digest.
RUN apk add --no-cache \
        bash \
        binaryen \
        cmake \
        coreutils \
        curl \
        git \
        gzip \
        ninja \
        openssl-dev \
        tar \
        wabt \
        zig

# Sanity check at build time -- fail the image build if anything's missing.
RUN bash --version >/dev/null \
 && cmake --version >/dev/null \
 && zig version >/dev/null \
 && wasm-validate --version >/dev/null \
 && wasm-opt --version >/dev/null \
 && echo "builder image OK"

LABEL org.opencontainers.image.source="https://github.com/jbcom/paranoid-passwd"
LABEL org.opencontainers.image.description="Wolfi-based builder for paranoid-passwd CI/CD"
LABEL org.opencontainers.image.licenses="MIT"
