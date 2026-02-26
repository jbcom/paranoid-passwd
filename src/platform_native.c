/**
 * platform_native.c — Native (non-WASM) platform backend
 *
 * Copyright (c) 2026 jbcom
 * SPDX-License-Identifier: MIT
 *
 * Implements paranoid_platform.h using OpenSSL.
 * This file is linked for native builds (test binaries, CLI tools).
 * For WASM builds, platform_wasm.c is linked instead.
 *
 * Security note: All randomness is delegated to OpenSSL RAND_bytes(),
 * which sources entropy from the OS CSPRNG. This file NEVER generates
 * random numbers directly.
 */

#include "paranoid_platform.h"
#include <openssl/rand.h>
#include <openssl/evp.h>

/* VERIFIED: - Verify RAND_bytes return value semantics.
 * OpenSSL docs: RAND_bytes() returns 1 on success, 0 otherwise.
 * We map 1 -> 0 (success), anything else -> -1 (failure).
 */
int paranoid_platform_random(unsigned char *buf, int len) {
    if (!buf || len <= 0) return -1;
    return (RAND_bytes(buf, len) == 1) ? 0 : -1;
}

/* VERIFIED: - Verify EVP_Digest* return value semantics.
 * OpenSSL docs: EVP_DigestInit_ex, EVP_DigestUpdate, EVP_DigestFinal_ex
 * all return 1 for success and 0 for failure.
 */
int paranoid_platform_sha256(const unsigned char *input, int input_len, unsigned char *output) {
    if (!input || input_len < 0 || !output) return -1;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    unsigned int len = 0;
    int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)
          && EVP_DigestUpdate(ctx, input, input_len)
          && EVP_DigestFinal_ex(ctx, output, &len);

    EVP_MD_CTX_free(ctx);
    return ok ? 0 : -1;
}
