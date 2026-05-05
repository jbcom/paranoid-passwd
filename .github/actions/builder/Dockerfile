# syntax=docker/dockerfile:1.7
FROM cgr.dev/chainguard/wolfi-base:latest@sha256:1af610c4a70668dad46159ee178b20378c79a49b554f76405670fc442d30183a

ARG RUST_APK_PACKAGE=rust-1.95
ARG RUST_APK_VERSION=1.95.0-r0
ARG SPHINX_RUSTDOCGEN_VERSION=1.1.0
ARG TOX_VERSION=4.53.0

ENV PATH="/usr/local/bin:${PATH}" \
    CARGO_HOME=/tmp/cargo \
    CARGO_TARGET_DIR=/tmp/cargo-target \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN --mount=type=cache,target=/var/cache/apk \
    apk add --no-cache \
        bash \
        build-base \
        coreutils \
        curl \
        dbus \
        dbus-dev \
        fontconfig-dev \
        git \
        imagemagick \
        make \
        openssl \
        openssl-dev \
        perl \
        pkgconf \
        py3-pip \
        python3 \
        ripgrep \
        xkbcomp \
        xkeyboard-config \
        xvfb-run \
        ${RUST_APK_PACKAGE}=${RUST_APK_VERSION}

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
 && command -v sphinx-rustdocgen >/dev/null \
 && command -v dbus-run-session >/dev/null \
 && command -v identify >/dev/null \
 && command -v import >/dev/null \
 && command -v openssl >/dev/null \
 && command -v xvfb-run >/dev/null \
 && rustc --version >/dev/null \
 && pkgconf --modversion fontconfig >/dev/null \
 && pkgconf --modversion openssl >/dev/null \
 && python3 --version >/dev/null \
 && rg --version >/dev/null \
 && tox --version >/dev/null \
 && rustc --version | grep -F "1.95.0" >/dev/null \
 && tox --version | grep -F "${TOX_VERSION}" >/dev/null \
 && echo "builder image OK"

RUN addgroup -g 1001 builder \
 && adduser -D -u 1001 -G builder builder \
 && mkdir -p /github/workspace /tmp/cargo /tmp/cargo-target \
 && chown -R builder:builder /github /tmp/cargo /tmp/cargo-target

COPY --chmod=0755 entrypoint.sh /entrypoint.sh
USER builder
ENTRYPOINT ["/entrypoint.sh"]
