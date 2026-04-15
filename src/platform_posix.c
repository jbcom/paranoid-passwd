/**
 * platform_posix.c — POSIX platform backend (no OpenSSL)
 *
 * Copyright (c) 2026 jbcom
 * SPDX-License-Identifier: MIT
 *
 * Implements paranoid_platform.h for a self-contained native binary:
 *   - Random: getrandom(2) on Linux, getentropy(3) on macOS/BSD.
 *             No /dev/urandom fallback — if the syscall is unavailable
 *             we fail-closed, matching the project's threat-model stance
 *             that a degraded RNG is worse than no result.
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

#if defined(_WIN32) || defined(_WIN64)
    /* Windows: BCryptGenRandom from bcrypt.lib. BCRYPT_USE_SYSTEM_PREFERRED_RNG
     * reads from the OS CSPRNG without requiring an algorithm handle.
     * Available Vista+ (2007). Documented:
     * https://learn.microsoft.com/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom
     *
     * VERIFIED: BCryptGenRandom with BCRYPT_USE_SYSTEM_PREFERRED_RNG
     * is the OS-blessed CSPRNG on Windows. CryptGenRandom is deprecated.
     */
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
    #include <bcrypt.h>
    #ifndef STATUS_SUCCESS
        #define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
    #endif
#elif defined(__linux__)
    #include <sys/random.h>
    /* getrandom available since glibc 2.25 (2017), kernel 3.17 (2014). */
#elif defined(__APPLE__)
    /* macOS: getentropy is declared in <sys/random.h> as of the SDK
     * shipped with Zig's libc. <unistd.h> alone is not enough — the
     * cross-compile sysroot does not put getentropy there.
     * Documented: https://developer.apple.com/documentation/kernel/3201648-getentropy
     */
    #include <sys/random.h>
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    #include <unistd.h>
    /* getentropy(3): FreeBSD 12+, OpenBSD since forever. */
#else
    #error "Unsupported platform: no getrandom/getentropy/BCryptGenRandom available"
#endif

/* getentropy and getrandom both cap single-call reads at 256 bytes on
 * some platforms. Loop to fill arbitrary buffer sizes.
 *
 * VERIFIED: - getentropy(3) fails with EIO if len > 256.
 * getrandom(2) with flags=0 may return short reads or be interrupted by
 * a signal (errno=EINTR). getentropy(3) per POSIX/openbsd does NOT
 * report EINTR — it either fully succeeds or fails with EIO/EFAULT/ENOSYS.
 */
static int fill_random(unsigned char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > 256) chunk = 256;

#if defined(_WIN32) || defined(_WIN64)
        /* BCryptGenRandom has no documented max-read cap (unlike
         * getentropy's 256-byte limit), but we keep the chunked loop
         * for uniformity and so the failure mode matches the other
         * backends. */
        NTSTATUS rc = BCryptGenRandom(NULL, buf + off, (ULONG)chunk,
                                      BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (rc != STATUS_SUCCESS) return -1;
        off += chunk;
#elif defined(__linux__)
        ssize_t n = getrandom(buf + off, chunk, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)n;
#else
        if (getentropy(buf + off, chunk) != 0) {
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
