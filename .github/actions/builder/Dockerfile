FROM cgr.dev/chainguard/wolfi-base:latest@sha256:1af610c4a70668dad46159ee178b20378c79a49b554f76405670fc442d30183a

ARG RUST_APK_PACKAGE=rust-1.88
ARG RUST_APK_VERSION=1.88.0-r0
ARG TOX_VERSION=4.53.0

RUN apk add --no-cache \
        bash \
        build-base \
        coreutils \
        curl \
        git \
        make \
        openssl-dev \
        perl \
        pkgconf \
        py3-pip \
        python3 \
        ${RUST_APK_PACKAGE}=${RUST_APK_VERSION}

RUN python3 -m pip install --break-system-packages --no-cache-dir "tox==${TOX_VERSION}"

RUN bash --version >/dev/null \
 && cargo --version >/dev/null \
 && rustc --version >/dev/null \
 && python3 --version >/dev/null \
 && tox --version >/dev/null \
 && openssl version >/dev/null \
 && rustc --version | grep -F "1.88.0" >/dev/null \
 && tox --version | grep -F "${TOX_VERSION}" >/dev/null \
 && echo "builder image OK"

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
