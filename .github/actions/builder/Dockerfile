# syntax=docker/dockerfile:1.7
# =================================================================
# paranoid-passwd builder — Wolfi Docker container action
#
# Single trust root for CI/CD toolchain packages: Wolfi.
#
# This image is built per workflow job from the in-repository Dockerfile.
# External GitHub Actions remain SHA-pinned, and this base image is digest
# pinned so the builder cannot drift silently back to a general-purpose distro.
# =================================================================

FROM cgr.dev/chainguard/wolfi-base@sha256:1af610c4a70668dad46159ee178b20378c79a49b554f76405670fc442d30183a

ARG RUST_APK_PACKAGE=rust-1.95
ARG RUST_APK_VERSION=1.95.0-r0
ARG SEMGREP_APK_VERSION=1.165.0-r0
ARG OSV_SCANNER_APK_VERSION=2.4.0-r0
ARG SYFT_APK_VERSION=1.45.1-r1
ARG TRIVY_APK_VERSION=0.70.0-r5
ARG SPHINX_RUSTDOCGEN_VERSION=1.1.0
ARG TOX_VERSION=4.53.0

ENV PATH="/usr/local/bin:${PATH}" \
    CARGO_HOME=/tmp/cargo \
    CARGO_TARGET_DIR=/tmp/cargo-target \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN --mount=type=cache,target=/var/cache/apk,sharing=locked \
    apk add \
        bash \
        build-base \
        ca-certificates \
        coreutils \
        curl \
        dbus \
        dbus-dev \
        dbus-x11 \
        font-liberation \
        fontconfig \
        fontconfig-dev \
        gh \
        git \
        imagemagick-7 \
        libx11 \
        libx11-dev \
        libxcb \
        libxcb-dev \
        libxcursor \
        libxcursor-dev \
        libxfixes \
        libxfixes-dev \
        libxi \
        libxi-dev \
        libxinerama \
        libxinerama-dev \
        libxkbcommon \
        libxkbcommon-dev \
        libxss \
        libxss-dev \
        make \
        openssl \
        openssl-dev \
        osv-scanner="${OSV_SCANNER_APK_VERSION}" \
        perl \
        pkgconf \
        py3-pip \
        python3 \
        ripgrep \
        semgrep="${SEMGREP_APK_VERSION}" \
        shadow \
        syft="${SYFT_APK_VERSION}" \
        trivy="${TRIVY_APK_VERSION}" \
        wayland \
        wayland-dev \
        xauth \
        xkeyboard-config \
        xorg-server \
        xorg-server-common \
        xvfb-run \
        "${RUST_APK_PACKAGE}=${RUST_APK_VERSION}"

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN --mount=type=cache,target=/root/.cache/pip \
    python3 -m pip install --break-system-packages "tox==${TOX_VERSION}"

RUN --mount=type=cache,target=/tmp/cargo/registry \
    --mount=type=cache,target=/tmp/cargo/git \
    CARGO_HOME=/tmp/cargo \
    CARGO_TARGET_DIR=/tmp/cargo-target \
    cargo install --locked --root /usr/local "sphinx-rustdocgen@${SPHINX_RUSTDOCGEN_VERSION}" \
 && rm -rf /tmp/cargo-target /tmp/cargo/bin /tmp/cargo/.crates.toml /tmp/cargo/.crates2.json

RUN bash --version >/dev/null \
 && cargo --version >/dev/null \
 && cargo clippy --version >/dev/null \
 && cargo fmt --version >/dev/null \
 && fc-cache -f >/dev/null \
 && fc-match sans >/dev/null \
 && command -v dbus-run-session >/dev/null \
 && command -v gh >/dev/null \
 && command -v identify >/dev/null \
 && command -v import >/dev/null \
 && command -v openssl >/dev/null \
 && command -v osv-scanner >/dev/null \
 && command -v semgrep >/dev/null \
 && command -v sphinx-rustdocgen >/dev/null \
 && command -v syft >/dev/null \
 && command -v trivy >/dev/null \
 && command -v xvfb-run >/dev/null \
 && pkgconf --modversion fontconfig >/dev/null \
 && pkgconf --modversion openssl >/dev/null \
 && python3 --version >/dev/null \
 && rg --version >/dev/null \
 && rustc --version >/dev/null \
 && rustc --version | grep -F "1.95.0" >/dev/null \
 && tox --version | grep -F "${TOX_VERSION}" >/dev/null \
 && echo "Wolfi builder image OK"

RUN groupadd --gid 1001 builder \
 && useradd --uid 1001 --gid builder --create-home --shell /bin/bash builder \
 && mkdir -p /github/workspace /tmp/cargo /tmp/cargo-target \
 && chown -R builder:builder /github /tmp/cargo /tmp/cargo-target

COPY --chmod=0755 entrypoint.sh /entrypoint.sh
USER builder
ENTRYPOINT ["/entrypoint.sh"]
