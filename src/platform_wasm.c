/**
 * platform_wasm.c — WASM/WASI platform backend
 *
 * Copyright (c) 2026 jbcom
 * SPDX-License-Identifier: MIT
 *
 * Implements paranoid_platform.h for the wasm32-wasi target.
 *   - Random: WASI random_get (provided by the WASI runtime)
 *   - SHA-256: Compact FIPS 180-4 implementation (sha256_compact.c)
 *
 * This file is linked for WASM builds only. For native builds,
 * platform_native.c is linked instead.
 *
 * The WASI random_get import is the ONLY external dependency.
 * The browser provides it via:
 *   random_get(ptr, len) {
 *       crypto.getRandomValues(new Uint8Array(mem.buffer, ptr, len));
 *       return 0;
 *   }
 */

#include "paranoid_platform.h"
#include "sha256_compact.h"

#include <stdint.h>
#include <stddef.h>

/* ═══════════════════════════════════════════════════════════════
   WASI random_get import -- provided by the WASI runtime.
   Declaration matches wasi_snapshot_preview1 specification.
   https://github.com/WebAssembly/WASI/blob/main/legacy/preview1/docs.md
   ═══════════════════════════════════════════════════════════════ */

__attribute__((import_module("wasi_snapshot_preview1"), import_name("random_get")))
int __wasi_random_get(uint8_t *buf, size_t buf_len);

/* TODO: HUMAN_REVIEW - Verify WASI random_get return value semantics.
 * WASI spec: returns 0 (errno success) on success, nonzero errno on failure.
 */
int paranoid_platform_random(unsigned char *buf, int len) {
    if (!buf || len <= 0) return -1;
    return (__wasi_random_get(buf, (size_t)len) == 0) ? 0 : -1;
}

int paranoid_platform_sha256(const unsigned char *input, int input_len, unsigned char *output) {
    if (!input || input_len < 0 || !output) return -1;
    sha256_hash(input, (size_t)input_len, output);
    return 0;
}
