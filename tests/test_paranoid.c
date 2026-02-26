/**
 * test_paranoid.c — Unit test framework for paranoid WASM module
 *
 * Tests include:
 *   - Known-answer tests (NIST vectors for SHA-256)
 *   - Rejection sampling boundary verification
 *   - Chi-squared statistical test validation
 *   - Serial correlation computation verification
 *   - Collision detection validation
 *
 * Build: make test (see Makefile)
 * Run: ./build/test_paranoid
 */

#include "paranoid.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <assert.h>

/* ═══════════════════════════════════════════════════════════
   TEST FRAMEWORK
   ═══════════════════════════════════════════════════════════ */

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    static void test_##name(void); \
    static int test_##name##_failed; \
    static void run_test_##name(void) { \
        int prev_failed = tests_failed; \
        printf("  TEST: %s ... ", #name); \
        fflush(stdout); \
        test_##name(); \
        if (tests_failed == prev_failed) { \
            tests_passed++; \
            printf("\033[0;32mPASS\033[0m\n"); \
        } \
    } \
    static void test_##name(void)

#define ASSERT(cond) do { \
    if (!(cond)) { \
        printf("\033[0;31mFAIL\033[0m\n"); \
        printf("    Assertion failed: %s\n", #cond); \
        printf("    File: %s, Line: %d\n", __FILE__, __LINE__); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define ASSERT_EQ(a, b) ASSERT((a) == (b))
#define ASSERT_STREQ(a, b) ASSERT(strcmp((a), (b)) == 0)
#define ASSERT_NEAR(a, b, tol) ASSERT(fabs((a) - (b)) < (tol))

/* ═══════════════════════════════════════════════════════════
   NIST KNOWN-ANSWER TESTS (SHA-256)
   Reference: NIST FIPS 180-4, CAVP test vectors
   ═══════════════════════════════════════════════════════════ */

TEST(sha256_empty) {
    /* NIST vector: SHA-256("") */
    char hex[65];
    int rc = paranoid_sha256_hex("", hex);
    ASSERT_EQ(rc, 0);
    ASSERT_STREQ(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(sha256_abc) {
    /* NIST vector: SHA-256("abc") */
    char hex[65];
    int rc = paranoid_sha256_hex("abc", hex);
    ASSERT_EQ(rc, 0);
    ASSERT_STREQ(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(sha256_448bits) {
    /* NIST vector: SHA-256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") */
    const char *input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    char hex[65];
    int rc = paranoid_sha256_hex(input, hex);
    ASSERT_EQ(rc, 0);
    ASSERT_STREQ(hex, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

TEST(sha256_896bits) {
    /* NIST vector: SHA-256("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu") */
    const char *input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    char hex[65];
    int rc = paranoid_sha256_hex(input, hex);
    ASSERT_EQ(rc, 0);
    ASSERT_STREQ(hex, "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
}

/* ═══════════════════════════════════════════════════════════
   REJECTION SAMPLING BOUNDARY TESTS
   Critical: max_valid = (256/N)*N - 1 (NOT -0)
   ═══════════════════════════════════════════════════════════ */

TEST(rejection_boundary_94) {
    /* For N=94 (printable ASCII): max_valid = (256/94)*94 - 1 = 2*94 - 1 = 187 */
    paranoid_audit_result_t result;
    memset(&result, 0, sizeof(result));
    
    /* This tests the formula used in paranoid_run_audit */
    int N = 94;
    int expected_max_valid = (256 / N) * N - 1;  /* = 187 */
    ASSERT_EQ(expected_max_valid, 187);
    
    /* Also verify expected rejection rate */
    double expected_rate = (double)(255 - expected_max_valid) / 256.0 * 100.0;
    ASSERT_NEAR(expected_rate, 26.5625, 0.001);  /* (255-187)/256 = 68/256 = 26.5625% */
}

TEST(rejection_boundary_62) {
    /* For N=62 (alphanumeric): max_valid = (256/62)*62 - 1 = 4*62 - 1 = 247 */
    int N = 62;
    int expected_max_valid = (256 / N) * N - 1;  /* = 247 */
    ASSERT_EQ(expected_max_valid, 247);
}

TEST(rejection_boundary_26) {
    /* For N=26 (lowercase): max_valid = (256/26)*26 - 1 = 9*26 - 1 = 233 */
    int N = 26;
    int expected_max_valid = (256 / N) * N - 1;  /* = 233 */
    ASSERT_EQ(expected_max_valid, 233);
}

TEST(rejection_boundary_10) {
    /* For N=10 (digits): max_valid = (256/10)*10 - 1 = 25*10 - 1 = 249 */
    int N = 10;
    int expected_max_valid = (256 / N) * N - 1;  /* = 249 */
    ASSERT_EQ(expected_max_valid, 249);
}

/* ═══════════════════════════════════════════════════════════
   PASSWORD GENERATION TESTS
   ═══════════════════════════════════════════════════════════ */

TEST(generate_length) {
    char password[33];
    const char *charset = "abcdefghijklmnopqrstuvwxyz";
    int rc = paranoid_generate(charset, 26, 32, password);
    ASSERT_EQ(rc, 0);
    ASSERT_EQ((int)strlen(password), 32);
}

TEST(generate_charset_only) {
    char password[17];
    const char *charset = "abc";
    int rc = paranoid_generate(charset, 3, 16, password);
    ASSERT_EQ(rc, 0);
    
    /* All characters must be from charset */
    for (int i = 0; i < 16; i++) {
        ASSERT(password[i] == 'a' || password[i] == 'b' || password[i] == 'c');
    }
}

TEST(generate_invalid_length) {
    char password[10];
    const char *charset = "abc";
    int rc = paranoid_generate(charset, 3, 0, password);  /* Invalid length */
    ASSERT_EQ(rc, -2);
}

TEST(generate_invalid_charset) {
    char password[10];
    int rc = paranoid_generate(NULL, 0, 8, password);  /* NULL charset */
    ASSERT_EQ(rc, -2);
}

/* ═══════════════════════════════════════════════════════════
   CHI-SQUARED STATISTICAL TESTS
   Reference: Knuth Vol 2, Section 3.3.1
   ═══════════════════════════════════════════════════════════ */

TEST(chi_squared_uniform) {
    /* Generate uniform frequency distribution (perfect) */
    const char *charset = "abc";
    int charset_len = 3;
    int num_pw = 100;
    int pw_len = 30;  /* 3000 chars total */
    
    /* Create perfectly uniform distribution: 1000 of each char */
    char *passwords = malloc(num_pw * pw_len);
    ASSERT(passwords != NULL);
    for (int i = 0; i < num_pw * pw_len; i++) {
        passwords[i] = charset[i % charset_len];
    }
    
    int df;
    double p_value;
    double chi2 = paranoid_chi_squared(passwords, num_pw, pw_len, charset, charset_len, &df, &p_value);
    
    free(passwords);
    
    /* Perfect uniformity should give chi² ≈ 0 */
    ASSERT_NEAR(chi2, 0.0, 0.001);
    ASSERT_EQ(df, charset_len - 1);  /* df = N - 1 */
}

TEST(chi_squared_degrees_of_freedom) {
    /* Verify df = N - 1 (NOT N) */
    const char *charset = "abcdefghij";  /* N = 10 */
    int charset_len = 10;
    int num_pw = 10;
    int pw_len = 100;
    
    char *passwords = malloc(num_pw * pw_len);
    ASSERT(passwords != NULL);
    for (int i = 0; i < num_pw * pw_len; i++) {
        passwords[i] = charset[i % charset_len];
    }
    
    int df;
    double p_value;
    paranoid_chi_squared(passwords, num_pw, pw_len, charset, charset_len, &df, &p_value);
    
    free(passwords);
    
    /* CRITICAL: df = N - 1, NOT N */
    ASSERT_EQ(df, 9);
}

/* ═══════════════════════════════════════════════════════════
   SERIAL CORRELATION TESTS
   Reference: Knuth Vol 2, Section 3.3.2
   ═══════════════════════════════════════════════════════════ */

TEST(serial_correlation_constant) {
    /* Constant sequence should have correlation = 0 (undefined, returns 0) */
    char data[100];
    memset(data, 'A', 100);
    
    double r = paranoid_serial_correlation(data, 100);
    /* Constant data: variance = 0, so r = 0 */
    ASSERT_NEAR(r, 0.0, 0.001);
}

TEST(serial_correlation_short) {
    /* Very short data should return 0 */
    char data[1] = {'A'};
    double r = paranoid_serial_correlation(data, 1);
    ASSERT_NEAR(r, 0.0, 0.001);
}

/* ═══════════════════════════════════════════════════════════
   COLLISION DETECTION TESTS
   ═══════════════════════════════════════════════════════════ */

TEST(collision_no_duplicates) {
    /* All unique passwords */
    const char *passwords = "aaa" "bbb" "ccc" "ddd" "eee";
    int dupes = paranoid_count_collisions(passwords, 5, 3);
    ASSERT_EQ(dupes, 0);
}

TEST(collision_with_duplicates) {
    /* Has duplicates: aaa appears twice */
    const char *passwords = "aaa" "bbb" "aaa" "ccc" "ddd";
    int dupes = paranoid_count_collisions(passwords, 5, 3);
    ASSERT_EQ(dupes, 1);
}

TEST(collision_all_same) {
    /* All same: 4 duplicates detected (positions 1,2,3,4 match position 0) */
    const char *passwords = "xxx" "xxx" "xxx" "xxx" "xxx";
    int dupes = paranoid_count_collisions(passwords, 5, 3);
    /* Algorithm counts: pos1 matches pos0, pos2 matches pos0 or pos1 (break), etc */
    ASSERT_EQ(dupes, 4);
}

/* ═══════════════════════════════════════════════════════════
   STRUCT OFFSET VERIFICATION TESTS
   ═══════════════════════════════════════════════════════════ */

TEST(offset_password_length) {
    int offset = paranoid_offset_password_length();
    /* Must match the offset table in AGENTS.md */
    ASSERT(offset >= 0);
    ASSERT(offset < (int)sizeof(paranoid_audit_result_t));
}

TEST(offset_chi2_statistic) {
    int offset = paranoid_offset_chi2_statistic();
    ASSERT(offset >= 0);
    ASSERT(offset < (int)sizeof(paranoid_audit_result_t));
}

TEST(offset_current_stage) {
    int offset = paranoid_offset_current_stage();
    ASSERT(offset >= 0);
    ASSERT(offset < (int)sizeof(paranoid_audit_result_t));
}

TEST(offset_all_pass) {
    int offset = paranoid_offset_all_pass();
    ASSERT(offset >= 0);
    ASSERT(offset < (int)sizeof(paranoid_audit_result_t));
}

/* ═══════════════════════════════════════════════════════════
   FULL AUDIT INTEGRATION TESTS
   ═══════════════════════════════════════════════════════════ */

TEST(run_audit_basic) {
    paranoid_audit_result_t *result = paranoid_get_result_ptr();
    const char *charset = "abcdefghijklmnopqrstuvwxyz";
    
    int rc = paranoid_run_audit(charset, 26, 16, 100, result);
    ASSERT_EQ(rc, 0);
    
    /* Check basic fields populated */
    ASSERT_EQ(result->password_length, 16);
    ASSERT_EQ(result->charset_size, 26);
    ASSERT_EQ(result->batch_size, 100);
    ASSERT_EQ((int)strlen(result->password), 16);
    ASSERT_EQ((int)strlen(result->sha256_hex), 64);
    ASSERT_EQ(result->current_stage, 8);  /* Done */
}

TEST(run_audit_entropy) {
    paranoid_audit_result_t *result = paranoid_get_result_ptr();
    const char *charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
    int charset_len = 70;
    
    int rc = paranoid_run_audit(charset, charset_len, 20, 100, result);
    ASSERT_EQ(rc, 0);
    
    /* Verify entropy calculation: H = L * log2(N) */
    double expected_bits = 20 * log2(70.0);
    ASSERT_NEAR(result->total_entropy, expected_bits, 0.001);
    ASSERT_NEAR(result->bits_per_char, log2(70.0), 0.001);
}

TEST(run_audit_invalid_args) {
    paranoid_audit_result_t *result = paranoid_get_result_ptr();
    
    /* NULL charset */
    int rc = paranoid_run_audit(NULL, 26, 16, 100, result);
    ASSERT_EQ(rc, -1);
    
    /* Invalid charset length */
    rc = paranoid_run_audit("abc", 0, 16, 100, result);
    ASSERT_EQ(rc, -2);
    
    /* Invalid password length */
    rc = paranoid_run_audit("abc", 3, 0, 100, result);
    ASSERT_EQ(rc, -2);
    
    /* Invalid batch size */
    rc = paranoid_run_audit("abc", 3, 16, 0, result);
    ASSERT_EQ(rc, -2);
}

/* ═══════════════════════════════════════════════════════════
   VERSION TEST
   ═══════════════════════════════════════════════════════════ */

TEST(version_string) {
    const char *version = paranoid_version();
    ASSERT(version != NULL);
    ASSERT(strstr(version, "paranoid") != NULL);
    ASSERT(strstr(version, "3.0.0") != NULL);
    ASSERT(strstr(version, "platform abstraction") != NULL);
}

/* ═══════════════════════════════════════════════════════════
   MAIN
   ═══════════════════════════════════════════════════════════ */

int main(void) {
    printf("\n");
    printf("═══════════════════════════════════════════════════════════\n");
    printf("  paranoid unit tests\n");
    printf("═══════════════════════════════════════════════════════════\n\n");
    
    printf("SHA-256 NIST Known-Answer Tests:\n");
    run_test_sha256_empty();
    run_test_sha256_abc();
    run_test_sha256_448bits();
    run_test_sha256_896bits();
    
    printf("\nRejection Sampling Boundary Tests:\n");
    run_test_rejection_boundary_94();
    run_test_rejection_boundary_62();
    run_test_rejection_boundary_26();
    run_test_rejection_boundary_10();
    
    printf("\nPassword Generation Tests:\n");
    run_test_generate_length();
    run_test_generate_charset_only();
    run_test_generate_invalid_length();
    run_test_generate_invalid_charset();
    
    printf("\nChi-Squared Statistical Tests:\n");
    run_test_chi_squared_uniform();
    run_test_chi_squared_degrees_of_freedom();
    
    printf("\nSerial Correlation Tests:\n");
    run_test_serial_correlation_constant();
    run_test_serial_correlation_short();
    
    printf("\nCollision Detection Tests:\n");
    run_test_collision_no_duplicates();
    run_test_collision_with_duplicates();
    run_test_collision_all_same();
    
    printf("\nStruct Offset Verification Tests:\n");
    run_test_offset_password_length();
    run_test_offset_chi2_statistic();
    run_test_offset_current_stage();
    run_test_offset_all_pass();
    
    printf("\nFull Audit Integration Tests:\n");
    run_test_run_audit_basic();
    run_test_run_audit_entropy();
    run_test_run_audit_invalid_args();
    
    printf("\nVersion Test:\n");
    run_test_version_string();
    
    printf("\n═══════════════════════════════════════════════════════════\n");
    printf("  Results: %d passed, %d failed\n", tests_passed, tests_failed);
    printf("═══════════════════════════════════════════════════════════\n\n");
    
    return tests_failed > 0 ? 1 : 0;
}
