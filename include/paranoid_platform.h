/**
 * paranoid_platform.h — Platform abstraction interface
 *
 * Copyright (c) 2026 jbcom
 * SPDX-License-Identifier: MIT
 *
 * This header defines the platform abstraction layer for paranoid.
 * Two backends exist:
 *
 *   Native (platform_native.c):
 *     - Random: OpenSSL RAND_bytes()
 *     - SHA-256: OpenSSL EVP SHA-256
 *
 *   WASM (platform_wasm.c):
 *     - Random: WASI random_get()
 *     - SHA-256: Compact FIPS 180-4 implementation (sha256_compact.c)
 *
 * Only ONE backend is linked per build target. The Makefile/CMake
 * selects the correct .c file based on --target=wasm32-wasi vs native.
 */

#ifndef PARANOID_PLATFORM_H
#define PARANOID_PLATFORM_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Fill buffer with cryptographically secure random bytes.
 * Native: delegates to OpenSSL RAND_bytes()
 * WASM:   delegates to WASI random_get()
 *
 * @param buf  Output buffer
 * @param len  Number of bytes to generate
 * @return     0 on success, -1 on failure
 */
int paranoid_platform_random(unsigned char *buf, int len);

/**
 * Compute SHA-256 hash.
 * Native: delegates to OpenSSL EVP SHA-256
 * WASM:   uses compact FIPS 180-4 implementation
 *
 * @param input      Input bytes
 * @param input_len  Length of input
 * @param output     32-byte output buffer
 * @return           0 on success, -1 on failure
 */
int paranoid_platform_sha256(const unsigned char *input, int input_len, unsigned char *output);

#ifdef __cplusplus
}
#endif

#endif /* PARANOID_PLATFORM_H */
