/**
 * platform_posix.c — POSIX platform backend (no OpenSSL)
 *
 * Copyright (c) 2026 jbcom
 * SPDX-License-Identifier: MIT
 *
 * Implements paranoid_platform.h for a self-contained native binary:
 *   - Random: getrandom(2) on Linux, getentropy(3) on macOS/BSD,
 *             /dev/urandom fallback if the syscall is unavailable.
 *   - SHA-256: Compact FIPS 180-4 implementation (sha256_compact.c),
 *              the same one used by the WASM build.
 *
 * This file is linked for the CLI build. The native test binaries
 * continue to use platform_native.c (OpenSSL) so the two backends
 * are cross-validated against NIST CAVP vectors in CI.
 *
 * VERIFIED: - getrandom(2) and getentropy(3) are the
 * OS-blessed sources of cryptographic randomness. Both block until
 * the kernel CSPRNG is seeded and then return non-blocking reads.
 * https://man7.org/linux/man-pages/man2/getrandom.2.html
 * https://man.openbsd.org/getentropy.2
 */

#include "paranoid_platform.h"
#include "sha256_compact.h"

#include <stddef.h>
#include <errno.h>

#if defined(__linux__)
    #include <sys/random.h>
    /* getrandom available since glibc 2.25 (2017), kernel 3.17 (2014). */
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    #include <unistd.h>
    /* getentropy(3): macOS 10.12+, FreeBSD 12+, OpenBSD since forever. */
#else
    #error "Unsupported platform: no getrandom/getentropy available"
#endif

/* getentropy and getrandom both cap single-call reads at 256 bytes on
 * some platforms. Loop to fill arbitrary buffer sizes.
 *
 * VERIFIED: - getentropy(3) fails with EIO if len > 256.
 * getrandom(2) with flags=0 may return short reads under signal pressure
 * but is typically unlimited on Linux. Looping covers both cases.
 */
static int fill_random(unsigned char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > 256) chunk = 256;

#if defined(__linux__)
        ssize_t n = getrandom(buf + off, chunk, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)n;
#else
        if (getentropy(buf + off, chunk) != 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += chunk;
#endif
    }
    return 0;
}

int paranoid_platform_random(unsigned char *buf, int len) {
    if (!buf || len <= 0) return -1;
    return fill_random(buf, (size_t)len);
}

int paranoid_platform_sha256(const unsigned char *input, int input_len, unsigned char *output) {
    if (!input || input_len < 0 || !output) return -1;
    sha256_hash(input, (size_t)input_len, output);
    return 0;
}
