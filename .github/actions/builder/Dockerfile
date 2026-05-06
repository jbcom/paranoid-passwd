# syntax=docker/dockerfile:1.7
FROM rust:1.95.0-slim-bookworm@sha256:caaf9ca7acd474892186860307d6f28e51fdbc1a4eada459fcff81517cf46a36

ARG SPHINX_RUSTDOCGEN_VERSION=1.1.0
ARG TOX_VERSION=4.53.0

ENV PATH="/usr/local/bin:${PATH}" \
    CARGO_HOME=/tmp/cargo \
    CARGO_TARGET_DIR=/tmp/cargo-target \
    PIP_DISABLE_PIP_VERSION_CHECK=1

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        bash \
        build-essential \
        ca-certificates \
        coreutils \
        curl \
        dbus \
        dbus-x11 \
        fontconfig \
        fonts-liberation \
        git \
        imagemagick \
        libdbus-1-3 \
        libdbus-1-dev \
        libfontconfig1-dev \
        libssl-dev \
        libwayland-client0 \
        libwayland-dev \
        libx11-6 \
        libx11-dev \
        libxcursor1 \
        libxcb-render0 \
        libxcb-render0-dev \
        libxcb-shape0 \
        libxcb-shape0-dev \
        libxcb-xfixes0 \
        libxcb-xfixes0-dev \
        libxcb1 \
        libxcb1-dev \
        libxi6 \
        libxinerama1 \
        libxkbcommon-dev \
        libxkbcommon-x11-0 \
        libxkbcommon-x11-dev \
        libxkbcommon0 \
        libxss1 \
        make \
        openssl \
        perl \
        pkg-config \
        pkgconf \
        python3-pip \
        python3 \
        ripgrep \
        x11-xkb-utils \
        xauth \
        xkb-data \
        xvfb \
 && rm -rf /var/lib/apt/lists/*

RUN --mount=type=cache,target=/root/.cache/pip \
    python3 -m pip install --break-system-packages "tox==${TOX_VERSION}"

RUN --mount=type=cache,target=/tmp/cargo/registry \
    --mount=type=cache,target=/tmp/cargo/git \
    CARGO_HOME=/tmp/cargo \
    CARGO_TARGET_DIR=/tmp/cargo-target \
    cargo install --locked --root /usr/local "sphinx-rustdocgen@${SPHINX_RUSTDOCGEN_VERSION}" \
 && rm -rf /tmp/cargo-target /tmp/cargo/bin /tmp/cargo/.crates.toml /tmp/cargo/.crates2.json

RUN rustup component add rustfmt clippy

RUN toolchain_bin="$(rustc --print sysroot)/bin" \
 && for tool in cargo rustc rustdoc rustfmt cargo-fmt cargo-clippy clippy-driver; do \
      if [ -x "${toolchain_bin}/${tool}" ]; then \
        ln -sf "${toolchain_bin}/${tool}" "/usr/local/bin/${tool}"; \
      fi; \
    done

RUN bash --version >/dev/null \
 && cargo --version >/dev/null \
 && cargo clippy --version >/dev/null \
 && cargo fmt --version >/dev/null \
 && fc-cache -f >/dev/null \
 && fc-match sans >/dev/null \
 && command -v sphinx-rustdocgen >/dev/null \
 && command -v dbus-run-session >/dev/null \
 && command -v identify >/dev/null \
 && command -v import >/dev/null \
 && command -v openssl >/dev/null \
 && command -v xvfb-run >/dev/null \
 && rustc --version >/dev/null \
 && pkg-config --modversion fontconfig >/dev/null \
 && pkg-config --modversion openssl >/dev/null \
 && python3 --version >/dev/null \
 && rg --version >/dev/null \
 && tox --version >/dev/null \
 && rustc --version | grep -F "1.95.0" >/dev/null \
 && tox --version | grep -F "${TOX_VERSION}" >/dev/null \
 && echo "builder image OK"

RUN groupadd --gid 1001 builder \
 && useradd --uid 1001 --gid builder --create-home --shell /bin/bash builder \
 && mkdir -p /github/workspace /tmp/cargo /tmp/cargo-target \
 && chown -R builder:builder /github /tmp/cargo /tmp/cargo-target

COPY --chmod=0755 entrypoint.sh /entrypoint.sh
USER builder
ENTRYPOINT ["/entrypoint.sh"]
