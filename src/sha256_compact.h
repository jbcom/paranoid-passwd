/**
 * sha256_compact.h — Compact SHA-256 (FIPS 180-4) interface
 *
 * Copyright (c) 2026 jbcom
 * SPDX-License-Identifier: MIT
 *
 * Compact SHA-256 -- FIPS 180-4 reference implementation.
 * ~150 lines of pure C. Zero dependencies beyond stdint.h/stddef.h.
 * Zero heap allocations. Suitable for freestanding / WASM targets.
 *
 * This is the ONLY SHA-256 in the WASM binary (OpenSSL is not
 * available in the WASM build for hashing -- only for CSPRNG via
 * the WASI random_get shim).
 *
 * TODO: HUMAN_REVIEW - Verify implementation against:
 *   1. NIST CAVP test vectors (shabytetestvectors.zip)
 *   2. RFC 6234 reference implementation
 *   3. FIPS 180-4 Section 5-6 (preprocessing and hash computation)
 */

#ifndef SHA256_COMPACT_H
#define SHA256_COMPACT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * SHA-256 incremental context.
 *
 * state[8]: Working hash values (H0..H7)
 * count:    Total bytes processed (for final padding)
 * buffer:   Partial block accumulator (up to 64 bytes)
 */
typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buffer[64];
} sha256_ctx_t;

/** Initialize context with FIPS 180-4 Section 5.3.3 initial hash values. */
void sha256_init(sha256_ctx_t *ctx);

/** Feed data incrementally. Can be called multiple times. */
void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len);

/** Finalize hash and write 32-byte digest. Context is zeroed after. */
void sha256_final(sha256_ctx_t *ctx, uint8_t digest[32]);

/** One-shot convenience: hash data in a single call. */
void sha256_hash(const uint8_t *data, size_t len, uint8_t digest[32]);

#ifdef __cplusplus
}
#endif

#endif /* SHA256_COMPACT_H */
