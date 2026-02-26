/**
 * test_sha256.c — NIST CAVP test vectors for compact SHA-256
 *
 * Copyright (c) 2026 jbcom
 * SPDX-License-Identifier: MIT
 *
 * Tests the compact FIPS 180-4 SHA-256 implementation (sha256_compact.c)
 * against official NIST Cryptographic Algorithm Validation Program vectors.
 *
 * References:
 *   - FIPS 180-4 Sections 5-6
 *   - https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip
 *   - RFC 6234 test vectors
 *
 * Build: cc -O2 -Wall -Wextra -I../include -I../vendor/acutest/include \
 *        tests/test_sha256.c src/sha256_compact.c -o build/test_sha256
 * Run:   ./build/test_sha256 [--verbose]
 *
 * TODO: HUMAN_REVIEW - Verify all expected hashes against an independent
 * source (e.g., `echo -n "abc" | openssl dgst -sha256`).
 */

#include "../vendor/acutest/include/acutest.h"
#include "../src/sha256_compact.h"
#include <string.h>
#include <stdlib.h>

/* ═══════════════════════════════════════════════════════════════
   Helper: convert 32-byte digest to 64-char hex string
   ═══════════════════════════════════════════════════════════════ */

static void digest_to_hex(const uint8_t digest[32], char hex[65]) {
    static const char hextab[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        hex[i * 2]     = hextab[digest[i] >> 4];
        hex[i * 2 + 1] = hextab[digest[i] & 0x0f];
    }
    hex[64] = '\0';
}

/* ═══════════════════════════════════════════════════════════════
   NIST CAVP SHORT MESSAGE TESTS
   ═══════════════════════════════════════════════════════════════ */

void test_sha256_compact_empty(void) {
    /*
     * NIST CAVP vector: SHA-256("")
     * Input:  (empty string, 0 bytes)
     * Expect: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
     *
     * TODO: HUMAN_REVIEW - Verified against FIPS 180-4 and
     * `echo -n "" | openssl dgst -sha256`
     */
    uint8_t digest[32];
    char hex[65];

    sha256_hash((const uint8_t *)"", 0, digest);
    digest_to_hex(digest, hex);

    TEST_CHECK(strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0);
    TEST_MSG("Expected: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    TEST_MSG("Got:      %s", hex);
}

void test_sha256_compact_abc(void) {
    /*
     * NIST CAVP vector: SHA-256("abc")
     * Input:  61 62 63 (3 bytes)
     * Expect: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
     *
     * TODO: HUMAN_REVIEW - FIPS 180-4 Appendix B.1 (SHA-256 example)
     */
    uint8_t digest[32];
    char hex[65];

    sha256_hash((const uint8_t *)"abc", 3, digest);
    digest_to_hex(digest, hex);

    TEST_CHECK(strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0);
    TEST_MSG("Expected: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    TEST_MSG("Got:      %s", hex);
}

void test_sha256_compact_448bits(void) {
    /*
     * NIST CAVP vector: SHA-256(448-bit message)
     * Input:  "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" (56 bytes)
     * Expect: 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1
     *
     * This is a critical boundary test: the input is exactly 56 bytes,
     * which is the threshold where padding requires an additional block.
     *
     * TODO: HUMAN_REVIEW - FIPS 180-4 Appendix B.2 (SHA-256 example)
     */
    const char *input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    uint8_t digest[32];
    char hex[65];

    sha256_hash((const uint8_t *)input, strlen(input), digest);
    digest_to_hex(digest, hex);

    TEST_CHECK(strcmp(hex, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") == 0);
    TEST_MSG("Expected: 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    TEST_MSG("Got:      %s", hex);
}

void test_sha256_compact_896bits(void) {
    /*
     * NIST CAVP vector: SHA-256(896-bit message)
     * Input:  "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn
     *          hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
     *         (112 bytes)
     * Expect: cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1
     *
     * TODO: HUMAN_REVIEW - FIPS 180-4 Appendix B.3 (SHA-256 example)
     */
    const char *input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
                        "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    uint8_t digest[32];
    char hex[65];

    sha256_hash((const uint8_t *)input, strlen(input), digest);
    digest_to_hex(digest, hex);

    TEST_CHECK(strcmp(hex, "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1") == 0);
    TEST_MSG("Expected: cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
    TEST_MSG("Got:      %s", hex);
}

/* ═══════════════════════════════════════════════════════════════
   NIST CAVP LONG MESSAGE TEST
   ═══════════════════════════════════════════════════════════════ */

void test_sha256_compact_million_a(void) {
    /*
     * NIST CAVP vector: SHA-256(1,000,000 x 'a')
     * Input:  'a' repeated 1,000,000 times
     * Expect: cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0
     *
     * This tests the implementation's ability to handle large inputs
     * across many block boundaries (15,625 blocks of 64 bytes).
     *
     * TODO: HUMAN_REVIEW - Verified against
     * `printf 'a%.0s' {1..1000000} | openssl dgst -sha256`
     */
    uint8_t digest[32];
    char hex[65];

    /* Feed in chunks to test the incremental update path */
    sha256_ctx_t ctx;
    sha256_init(&ctx);

    /* Use 1000-byte chunks (1000 iterations of 1000 bytes = 1,000,000) */
    uint8_t chunk[1000];
    memset(chunk, 'a', sizeof(chunk));

    for (int i = 0; i < 1000; i++) {
        sha256_update(&ctx, chunk, sizeof(chunk));
    }

    sha256_final(&ctx, digest);
    digest_to_hex(digest, hex);

    TEST_CHECK(strcmp(hex, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0") == 0);
    TEST_MSG("Expected: cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    TEST_MSG("Got:      %s", hex);
}

/* ═══════════════════════════════════════════════════════════════
   INCREMENTAL UPDATE EQUIVALENCE TESTS

   Verify that calling sha256_update() multiple times produces
   the same result as a single sha256_hash() call. This catches
   bugs in the buffer management logic.
   ═══════════════════════════════════════════════════════════════ */

void test_sha256_compact_incremental_1byte(void) {
    /*
     * Feed "abc" one byte at a time and compare against one-shot.
     * This tests the partial-block buffering path.
     */
    const uint8_t *input = (const uint8_t *)"abc";
    uint8_t digest_oneshot[32];
    uint8_t digest_incremental[32];

    /* One-shot */
    sha256_hash(input, 3, digest_oneshot);

    /* Incremental: 1 byte at a time */
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, input + 0, 1);  /* 'a' */
    sha256_update(&ctx, input + 1, 1);  /* 'b' */
    sha256_update(&ctx, input + 2, 1);  /* 'c' */
    sha256_final(&ctx, digest_incremental);

    TEST_CHECK(memcmp(digest_oneshot, digest_incremental, 32) == 0);
    TEST_MSG("One-byte incremental update produced different digest than one-shot");
}

void test_sha256_compact_incremental_split(void) {
    /*
     * Feed the 448-bit test message in various split points.
     * "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" (56 bytes)
     *
     * Split at: 7 + 49, 13 + 43, 32 + 24, 1 + 55
     * All must produce the same digest.
     */
    const uint8_t *input = (const uint8_t *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    size_t total_len = 56;
    uint8_t digest_ref[32];
    uint8_t digest_test[32];

    /* Reference: one-shot */
    sha256_hash(input, total_len, digest_ref);

    /* Split points to test */
    size_t splits[] = { 7, 13, 32, 1, 55, 63, 64 };
    int num_splits = (int)(sizeof(splits) / sizeof(splits[0]));

    for (int s = 0; s < num_splits; s++) {
        size_t split = splits[s];
        if (split >= total_len) continue;

        sha256_ctx_t ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, input, split);
        sha256_update(&ctx, input + split, total_len - split);
        sha256_final(&ctx, digest_test);

        TEST_CHECK(memcmp(digest_ref, digest_test, 32) == 0);
        if (memcmp(digest_ref, digest_test, 32) != 0) {
            TEST_MSG("Split at %zu of %zu produced different digest", split, total_len);
        }
    }
}

void test_sha256_compact_incremental_large(void) {
    /*
     * Feed the 896-bit message in 3-byte chunks to stress the
     * buffering logic across multiple block boundaries.
     */
    const uint8_t *input = (const uint8_t *)
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
        "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    size_t total_len = 112;
    uint8_t digest_ref[32];
    uint8_t digest_test[32];

    /* Reference: one-shot */
    sha256_hash(input, total_len, digest_ref);

    /* Feed in 3-byte chunks (not aligned to block size) */
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    size_t offset = 0;
    while (offset < total_len) {
        size_t chunk = 3;
        if (offset + chunk > total_len) chunk = total_len - offset;
        sha256_update(&ctx, input + offset, chunk);
        offset += chunk;
    }
    sha256_final(&ctx, digest_test);

    TEST_CHECK(memcmp(digest_ref, digest_test, 32) == 0);
    TEST_MSG("3-byte chunked incremental produced different digest than one-shot");
}

/* ═══════════════════════════════════════════════════════════════
   EDGE CASE TESTS
   ═══════════════════════════════════════════════════════════════ */

void test_sha256_compact_exactly_64bytes(void) {
    /*
     * Input that is exactly one block (64 bytes). The padding will
     * require a second block containing only the 0x80 byte, zeros,
     * and the 64-bit length.
     *
     * Input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
     *        (64 'a' characters)
     * Expected: ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb
     *
     * TODO: HUMAN_REVIEW - Verify with `printf 'a%.0s' {1..64} | openssl dgst -sha256`
     */
    uint8_t input[64];
    memset(input, 'a', 64);
    uint8_t digest[32];
    char hex[65];

    sha256_hash(input, 64, digest);
    digest_to_hex(digest, hex);

    TEST_CHECK(strcmp(hex, "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb") == 0);
    TEST_MSG("Expected: ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb");
    TEST_MSG("Got:      %s", hex);
}

void test_sha256_compact_exactly_55bytes(void) {
    /*
     * 55 bytes: exactly the maximum that fits padding + length in one block.
     * After appending 0x80 (1 byte) + length (8 bytes) = 64 bytes total.
     * This is the tightest single-block case.
     *
     * Input: 55 'a' characters
     * Expected: 9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318
     *
     * TODO: HUMAN_REVIEW - Verify with `python3 -c "print('a'*55, end='')" | openssl dgst -sha256`
     */
    uint8_t input[55];
    memset(input, 'a', 55);
    uint8_t digest[32];
    char hex[65];

    sha256_hash(input, 55, digest);
    digest_to_hex(digest, hex);

    TEST_CHECK(strcmp(hex, "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318") == 0);
    TEST_MSG("Expected: 9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318");
    TEST_MSG("Got:      %s", hex);
}

void test_sha256_compact_exactly_56bytes(void) {
    /*
     * 56 bytes: the first size that forces a second block for padding.
     * After appending 0x80 = 57 bytes, no room for 8-byte length in
     * a 64-byte block. Must pad to 128 bytes (two blocks).
     *
     * Input: 56 'a' characters
     * Expected: b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a
     *
     * TODO: HUMAN_REVIEW - Verify with `python3 -c "print('a'*56, end='')" | openssl dgst -sha256`
     */
    uint8_t input[56];
    memset(input, 'a', 56);
    uint8_t digest[32];
    char hex[65];

    sha256_hash(input, 56, digest);
    digest_to_hex(digest, hex);

    TEST_CHECK(strcmp(hex, "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a") == 0);
    TEST_MSG("Expected: b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a");
    TEST_MSG("Got:      %s", hex);
}

void test_sha256_compact_context_zeroed(void) {
    /*
     * Verify sha256_final zeroes the context (defense in depth).
     * After finalization, no hash state should remain in memory.
     */
    sha256_ctx_t ctx;
    uint8_t digest[32];

    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t *)"secret data", 11);
    sha256_final(&ctx, digest);

    /* Verify the context is zeroed */
    sha256_ctx_t zero_ctx;
    memset(&zero_ctx, 0, sizeof(zero_ctx));

    TEST_CHECK(memcmp(&ctx, &zero_ctx, sizeof(ctx)) == 0);
    TEST_MSG("Context was not zeroed after sha256_final");
}

/* ═══════════════════════════════════════════════════════════════
   TEST LIST — acutest format matching tests/test_native.c
   ═══════════════════════════════════════════════════════════════ */

TEST_LIST = {
    /* NIST CAVP Short Message Tests */
    { "sha256_compact/empty",              test_sha256_compact_empty },
    { "sha256_compact/abc",                test_sha256_compact_abc },
    { "sha256_compact/448bits",            test_sha256_compact_448bits },
    { "sha256_compact/896bits",            test_sha256_compact_896bits },

    /* NIST CAVP Long Message Test */
    { "sha256_compact/million_a",          test_sha256_compact_million_a },

    /* Incremental Update Equivalence Tests */
    { "sha256_compact/incremental_1byte",  test_sha256_compact_incremental_1byte },
    { "sha256_compact/incremental_split",  test_sha256_compact_incremental_split },
    { "sha256_compact/incremental_large",  test_sha256_compact_incremental_large },

    /* Edge Case Tests */
    { "sha256_compact/exactly_64bytes",    test_sha256_compact_exactly_64bytes },
    { "sha256_compact/exactly_55bytes",    test_sha256_compact_exactly_55bytes },
    { "sha256_compact/exactly_56bytes",    test_sha256_compact_exactly_56bytes },
    { "sha256_compact/context_zeroed",     test_sha256_compact_context_zeroed },

    { NULL, NULL }
};
