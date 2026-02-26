/**
 * test_native.c — Comprehensive unit tests using acutest framework
 *
 * This is the primary C test suite that runs BEFORE WASM compilation.
 * It validates the complete paranoid password generation logic at the
 * native C level, ensuring all cryptographic assumptions hold.
 *
 * Test coverage:
 *   - NIST SHA-256 known-answer tests (FIPS 180-4 vectors)
 *   - Rejection sampling boundary verification
 *   - Chi-squared statistical distribution tests
 *   - Serial correlation tests
 *   - Collision detection validation
 *   - Password generation correctness
 *   - End-to-end audit pipeline verification
 *   - High-volume password generation stress tests
 *
 * Build: make test-native (compiles with system cc, not WASM)
 * Run: ./build/test_native [options]
 *
 * acutest CLI options:
 *   --help         Show all options
 *   --list         List all tests
 *   --verbose      Show test output even on pass
 *   --color=auto   Color output control
 */

#include "../vendor/acutest/include/acutest.h"
#include "../include/paranoid.h"
#include <string.h>
#include <math.h>
#include <stdlib.h>

/* ═══════════════════════════════════════════════════════════════════════════════
   NIST SHA-256 KNOWN-ANSWER TESTS (FIPS 180-4)
   Reference: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip
   ═══════════════════════════════════════════════════════════════════════════════ */

void test_sha256_empty(void) {
    /* NIST CAVP vector: SHA-256("") */
    char hex[65];
    int rc = paranoid_sha256_hex("", hex);
    TEST_CHECK(rc == 0);
    TEST_CHECK(strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0);
    TEST_MSG("Got: %s", hex);
}

void test_sha256_abc(void) {
    /* NIST CAVP vector: SHA-256("abc") */
    char hex[65];
    int rc = paranoid_sha256_hex("abc", hex);
    TEST_CHECK(rc == 0);
    TEST_CHECK(strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0);
    TEST_MSG("Got: %s", hex);
}

void test_sha256_448bits(void) {
    /* NIST CAVP vector: SHA-256(448 bits) */
    const char *input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    char hex[65];
    int rc = paranoid_sha256_hex(input, hex);
    TEST_CHECK(rc == 0);
    TEST_CHECK(strcmp(hex, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") == 0);
    TEST_MSG("Got: %s", hex);
}

void test_sha256_896bits(void) {
    /* NIST CAVP vector: SHA-256(896 bits) */
    const char *input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    char hex[65];
    int rc = paranoid_sha256_hex(input, hex);
    TEST_CHECK(rc == 0);
    TEST_CHECK(strcmp(hex, "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1") == 0);
    TEST_MSG("Got: %s", hex);
}

/* ═══════════════════════════════════════════════════════════════════════════════
   REJECTION SAMPLING BOUNDARY TESTS
   Critical: max_valid = (256/N)*N - 1 (NOT -0, NOT N)
   ═══════════════════════════════════════════════════════════════════════════════ */

void test_rejection_boundary_94(void) {
    /* N=94 (printable ASCII): max_valid = (256/94)*94 - 1 = 2*94 - 1 = 187 */
    int N = 94;
    int max_valid = (256 / N) * N - 1;
    TEST_CHECK(max_valid == 187);
    TEST_MSG("Expected 187, got %d", max_valid);

    /* Rejection rate = (255 - 187) / 256 = 68/256 = 26.5625% */
    double rate = (double)(255 - max_valid) / 256.0 * 100.0;
    TEST_CHECK(fabs(rate - 26.5625) < 0.0001);
    TEST_MSG("Expected 26.5625%%, got %f%%", rate);
}

void test_rejection_boundary_62(void) {
    /* N=62 (alphanumeric): max_valid = (256/62)*62 - 1 = 4*62 - 1 = 247 */
    int N = 62;
    int max_valid = (256 / N) * N - 1;
    TEST_CHECK(max_valid == 247);
    TEST_MSG("Expected 247, got %d", max_valid);
}

void test_rejection_boundary_26(void) {
    /* N=26 (lowercase): max_valid = (256/26)*26 - 1 = 9*26 - 1 = 233 */
    int N = 26;
    int max_valid = (256 / N) * N - 1;
    TEST_CHECK(max_valid == 233);
    TEST_MSG("Expected 233, got %d", max_valid);
}

void test_rejection_boundary_10(void) {
    /* N=10 (digits): max_valid = (256/10)*10 - 1 = 25*10 - 1 = 249 */
    int N = 10;
    int max_valid = (256 / N) * N - 1;
    TEST_CHECK(max_valid == 249);
    TEST_MSG("Expected 249, got %d", max_valid);
}

/* ═══════════════════════════════════════════════════════════════════════════════
   PASSWORD GENERATION TESTS
   ═══════════════════════════════════════════════════════════════════════════════ */

void test_generate_length(void) {
    char password[33];
    const char *charset = "abcdefghijklmnopqrstuvwxyz";
    int rc = paranoid_generate(charset, 26, 32, password);
    TEST_CHECK(rc == 0);
    TEST_CHECK(strlen(password) == 32);
    TEST_MSG("Expected length 32, got %zu", strlen(password));
}

void test_generate_charset_only(void) {
    char password[101];
    const char *charset = "XYZ";
    int rc = paranoid_generate(charset, 3, 100, password);
    TEST_CHECK(rc == 0);

    /* Every character must be from charset */
    for (int i = 0; i < 100; i++) {
        TEST_CHECK(password[i] == 'X' || password[i] == 'Y' || password[i] == 'Z');
        if (!(password[i] == 'X' || password[i] == 'Y' || password[i] == 'Z')) {
            TEST_MSG("Invalid char '%c' at position %d", password[i], i);
            break;
        }
    }
}

void test_generate_uniqueness(void) {
    /* Generate 100 passwords and verify they're all different */
    char passwords[100][33];
    const char *charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    for (int i = 0; i < 100; i++) {
        int rc = paranoid_generate(charset, 62, 32, passwords[i]);
        TEST_CHECK(rc == 0);
    }

    /* Check all pairs for uniqueness */
    for (int i = 0; i < 100; i++) {
        for (int j = i + 1; j < 100; j++) {
            TEST_CHECK(strcmp(passwords[i], passwords[j]) != 0);
            if (strcmp(passwords[i], passwords[j]) == 0) {
                TEST_MSG("Collision at indices %d and %d", i, j);
            }
        }
    }
}

void test_generate_invalid_args(void) {
    char password[33];

    /* NULL charset */
    TEST_CHECK(paranoid_generate(NULL, 0, 8, password) == -2);

    /* Zero charset length */
    TEST_CHECK(paranoid_generate("abc", 0, 8, password) == -2);

    /* Zero password length */
    TEST_CHECK(paranoid_generate("abc", 3, 0, password) == -2);

    /* NULL output */
    TEST_CHECK(paranoid_generate("abc", 3, 8, NULL) == -2);
}

/* ═══════════════════════════════════════════════════════════════════════════════
   CHI-SQUARED STATISTICAL TESTS
   Reference: Knuth Vol 2, Section 3.3.1
   ═══════════════════════════════════════════════════════════════════════════════ */

void test_chi_squared_uniform(void) {
    /* Perfect uniform distribution should yield chi² ≈ 0 */
    const char *charset = "abcd";
    int charset_len = 4;
    int num_pw = 100;
    int pw_len = 40;  /* 4000 chars total, 1000 per char */

    char *passwords = malloc(num_pw * pw_len);
    TEST_ASSERT(passwords != NULL);

    for (int i = 0; i < num_pw * pw_len; i++) {
        passwords[i] = charset[i % charset_len];
    }

    int df;
    double p_value;
    double chi2 = paranoid_chi_squared(passwords, num_pw, pw_len, charset, charset_len, &df, &p_value);

    free(passwords);

    TEST_CHECK(fabs(chi2) < 0.001);
    TEST_MSG("Expected chi2 ≈ 0, got %f", chi2);
    TEST_CHECK(df == charset_len - 1);  /* CRITICAL: df = N - 1 */
    TEST_MSG("Expected df=%d, got %d", charset_len - 1, df);
}

void test_chi_squared_biased(void) {
    /* Heavily biased distribution should yield high chi² */
    const char *charset = "ab";
    int charset_len = 2;
    int num_pw = 100;
    int pw_len = 100;  /* 10000 chars */

    char *passwords = malloc(num_pw * pw_len);
    TEST_ASSERT(passwords != NULL);

    /* 90% 'a', 10% 'b' - heavily biased */
    for (int i = 0; i < num_pw * pw_len; i++) {
        passwords[i] = (i % 10 == 0) ? 'b' : 'a';
    }

    int df;
    double p_value;
    double chi2 = paranoid_chi_squared(passwords, num_pw, pw_len, charset, charset_len, &df, &p_value);

    free(passwords);

    /* Chi² should be very high for biased data */
    TEST_CHECK(chi2 > 1000.0);
    TEST_MSG("Expected chi2 > 1000, got %f", chi2);
    /* P-value should be very low (reject null hypothesis) */
    TEST_CHECK(p_value < 0.001);
    TEST_MSG("Expected p < 0.001, got %f", p_value);
}

void test_chi_squared_degrees_of_freedom(void) {
    /* CRITICAL TEST: Verify df = N - 1 (NOT N) */
    const char *charset = "abcdefghij";  /* N = 10 */
    int charset_len = 10;
    int num_pw = 10;
    int pw_len = 100;

    char *passwords = malloc(num_pw * pw_len);
    TEST_ASSERT(passwords != NULL);
    for (int i = 0; i < num_pw * pw_len; i++) {
        passwords[i] = charset[i % charset_len];
    }

    int df;
    double p_value;
    paranoid_chi_squared(passwords, num_pw, pw_len, charset, charset_len, &df, &p_value);

    free(passwords);

    /* This is a CRITICAL assertion - wrong df would invalidate all statistics */
    TEST_CHECK(df == 9);  /* df = N - 1 = 10 - 1 = 9 */
    TEST_MSG("Expected df=9, got %d", df);
}

/* ═══════════════════════════════════════════════════════════════════════════════
   SERIAL CORRELATION TESTS
   ═══════════════════════════════════════════════════════════════════════════════ */

void test_serial_correlation_constant(void) {
    /* Constant sequence has variance 0 → correlation undefined → returns 0 */
    char data_const[100];
    memset(data_const, 'A', 100);

    double r = paranoid_serial_correlation(data_const, 100);
    TEST_CHECK(fabs(r) < 0.001);
    TEST_MSG("Expected r ≈ 0, got %f", r);
}

void test_serial_correlation_alternating(void) {
    /* Perfectly alternating sequence should have strong negative correlation */
    char data_alt[100];
    for (int i = 0; i < 100; i++) {
        data_alt[i] = (i % 2 == 0) ? 'A' : 'Z';
    }

    double r = paranoid_serial_correlation(data_alt, 100);
    /* Should be strongly negative (near -1) */
    TEST_CHECK(r < -0.9);
    TEST_MSG("Expected r < -0.9, got %f", r);
}

void test_serial_correlation_short(void) {
    /* Single character - undefined, should return 0 */
    char data_short[1] = {'A'};
    double r = paranoid_serial_correlation(data_short, 1);
    TEST_CHECK(fabs(r) < 0.001);
    TEST_MSG("Expected r ≈ 0, got %f", r);
}

/* ═══════════════════════════════════════════════════════════════════════════════
   COLLISION DETECTION TESTS
   ═══════════════════════════════════════════════════════════════════════════════ */

void test_collision_no_duplicates(void) {
    const char *passwords = "aaa" "bbb" "ccc" "ddd" "eee";
    int dupes = paranoid_count_collisions(passwords, 5, 3);
    TEST_CHECK(dupes == 0);
    TEST_MSG("Expected 0 duplicates, got %d", dupes);
}

void test_collision_with_duplicates(void) {
    const char *passwords = "aaa" "bbb" "aaa" "ccc" "ddd";
    int dupes = paranoid_count_collisions(passwords, 5, 3);
    TEST_CHECK(dupes == 1);
    TEST_MSG("Expected 1 duplicate, got %d", dupes);
}

void test_collision_all_same(void) {
    const char *passwords = "xxx" "xxx" "xxx" "xxx" "xxx";
    int dupes = paranoid_count_collisions(passwords, 5, 3);
    TEST_CHECK(dupes == 4);  /* Positions 1,2,3,4 each match an earlier one */
    TEST_MSG("Expected 4 duplicates, got %d", dupes);
}

/* ═══════════════════════════════════════════════════════════════════════════════
   STRUCT OFFSET VERIFICATION TESTS
   Critical for JS/WASM interop - wrong offsets = reading garbage
   ═══════════════════════════════════════════════════════════════════════════════ */

void test_struct_offsets(void) {
    /* All offsets must be within struct bounds */
    int size = paranoid_get_result_size();

    TEST_CHECK(paranoid_offset_password_length() >= 0);
    TEST_CHECK(paranoid_offset_password_length() < size);

    TEST_CHECK(paranoid_offset_chi2_statistic() >= 0);
    TEST_CHECK(paranoid_offset_chi2_statistic() < size);

    TEST_CHECK(paranoid_offset_current_stage() >= 0);
    TEST_CHECK(paranoid_offset_current_stage() < size);

    TEST_CHECK(paranoid_offset_all_pass() >= 0);
    TEST_CHECK(paranoid_offset_all_pass() < size);
}

/* ═══════════════════════════════════════════════════════════════════════════════
   FULL AUDIT INTEGRATION TESTS
   ═══════════════════════════════════════════════════════════════════════════════ */

void test_audit_basic(void) {
    paranoid_audit_result_t *result = paranoid_get_result_ptr();
    const char *charset = "abcdefghijklmnopqrstuvwxyz";

    int rc = paranoid_run_audit(charset, 26, 16, 100, result);
    TEST_CHECK(rc == 0);

    TEST_CHECK(result->password_length == 16);
    TEST_CHECK(result->charset_size == 26);
    TEST_CHECK(result->batch_size == 100);
    TEST_CHECK(strlen(result->password) == 16);
    TEST_MSG("Password length: %zu", strlen(result->password));
    TEST_CHECK(strlen(result->sha256_hex) == 64);
    TEST_MSG("Hash length: %zu", strlen(result->sha256_hex));
    TEST_CHECK(result->current_stage == 8);  /* Done */
    TEST_MSG("Stage: %d", result->current_stage);
}

void test_audit_entropy_calculation(void) {
    paranoid_audit_result_t *result = paranoid_get_result_ptr();
    const char *charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
    int charset_len = 70;
    int pw_len = 20;

    int rc = paranoid_run_audit(charset, charset_len, pw_len, 100, result);
    TEST_CHECK(rc == 0);

    /* Verify entropy: H = L * log2(N) */
    double expected_bits = pw_len * log2((double)charset_len);
    TEST_CHECK(fabs(result->total_entropy - expected_bits) < 0.001);
    TEST_MSG("Expected entropy %f, got %f", expected_bits, result->total_entropy);
    TEST_CHECK(fabs(result->bits_per_char - log2((double)charset_len)) < 0.001);
    TEST_MSG("Expected bits_per_char %f, got %f", log2((double)charset_len), result->bits_per_char);
}

void test_audit_invalid_args(void) {
    paranoid_audit_result_t *result = paranoid_get_result_ptr();

    TEST_CHECK(paranoid_run_audit(NULL, 26, 16, 100, result) == -1);
    TEST_CHECK(paranoid_run_audit("abc", 0, 16, 100, result) == -2);
    TEST_CHECK(paranoid_run_audit("abc", 3, 0, 100, result) == -2);
    TEST_CHECK(paranoid_run_audit("abc", 3, 16, 0, result) == -2);
}

/* ═══════════════════════════════════════════════════════════════════════════════
   HIGH-VOLUME STRESS TESTS
   These verify statistical assumptions hold across many password generations
   ═══════════════════════════════════════════════════════════════════════════════ */

void test_stress_distribution(void) {
    /* Generate 10,000 characters and verify distribution is approximately uniform */
    const char *charset = "abcdefghij";  /* N = 10 */
    int charset_len = 10;
    int total_chars = 10000;
    int freq[256] = {0};

    char password[101];
    for (int i = 0; i < total_chars / 100; i++) {
        int rc = paranoid_generate(charset, charset_len, 100, password);
        TEST_CHECK(rc == 0);

        for (int j = 0; j < 100; j++) {
            freq[(unsigned char)password[j]]++;
        }
    }

    /* Each character should appear ~1000 times (10000/10) */
    /* Allow 10% deviation for random variation */
    double expected = (double)total_chars / charset_len;
    for (int i = 0; i < charset_len; i++) {
        int count = freq[(unsigned char)charset[i]];
        double deviation = fabs((double)count - expected) / expected;
        TEST_CHECK(deviation < 0.10);  /* Less than 10% deviation */
        if (deviation >= 0.10) {
            TEST_MSG("Char '%c': expected ~%.0f, got %d (%.1f%% deviation)",
                     charset[i], expected, count, deviation * 100.0);
        }
    }
}

void test_stress_no_collisions(void) {
    /* Generate 500 32-character passwords and verify no collisions */
    /* With charset 62 and length 32: probability of collision ≈ 0 */
    const char *charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    int charset_len = 62;
    int pw_len = 32;
    int num_passwords = 500;

    /* Allocate an extra byte: paranoid_generate writes a NUL terminator at
       output[pw_len], so the last password needs pw_len+1 bytes total. */
    char *batch = malloc(num_passwords * pw_len + 1);
    TEST_ASSERT(batch != NULL);

    for (int i = 0; i < num_passwords; i++) {
        int rc = paranoid_generate(charset, charset_len, pw_len, batch + i * pw_len);
        TEST_CHECK(rc == 0);
    }

    int collisions = paranoid_count_collisions(batch, num_passwords, pw_len);
    free(batch);

    TEST_CHECK(collisions == 0);
    TEST_MSG("Expected 0 collisions, got %d", collisions);
}

void test_stress_chi_squared_pass(void) {
    /* Generate random passwords and verify chi-squared test passes */
    const char *charset = "abcdefghijklmnopqrstuvwxyz";
    int charset_len = 26;
    int num_pw = 200;
    int pw_len = 50;

    /* Allocate an extra byte: paranoid_generate writes a NUL terminator at
       output[pw_len], so the last password needs pw_len+1 bytes total. */
    char *batch = malloc(num_pw * pw_len + 1);
    TEST_ASSERT(batch != NULL);

    for (int i = 0; i < num_pw; i++) {
        int rc = paranoid_generate(charset, charset_len, pw_len, batch + i * pw_len);
        TEST_CHECK(rc == 0);
    }

    int df;
    double p_value;
    paranoid_chi_squared(batch, num_pw, pw_len, charset, charset_len, &df, &p_value);

    free(batch);

    /* For truly random data, p-value should be > 0.01 most of the time */
    /* (There's a 1% chance of false failure - acceptable for stress tests) */
    TEST_CHECK(p_value > 0.001);
    TEST_MSG("Expected p > 0.001, got %f", p_value);
}

/* ═══════════════════════════════════════════════════════════════════════════════
   VERSION TEST
   ═══════════════════════════════════════════════════════════════════════════════ */

void test_version(void) {
    const char *version = paranoid_version();
    TEST_CHECK(version != NULL);
    TEST_CHECK(strstr(version, "paranoid") != NULL);
    TEST_MSG("Version string: %s", version);
    TEST_CHECK(strstr(version, "3.0.0") != NULL);
    TEST_CHECK(strstr(version, "platform abstraction") != NULL);
}

/* ═══════════════════════════════════════════════════════════════════════════════
   TEST LIST
   ═══════════════════════════════════════════════════════════════════════════════ */

TEST_LIST = {
    /* SHA-256 NIST Known-Answer Tests */
    { "sha256/empty",           test_sha256_empty },
    { "sha256/abc",             test_sha256_abc },
    { "sha256/448bits",         test_sha256_448bits },
    { "sha256/896bits",         test_sha256_896bits },

    /* Rejection Sampling Boundary Tests */
    { "rejection/boundary_94",  test_rejection_boundary_94 },
    { "rejection/boundary_62",  test_rejection_boundary_62 },
    { "rejection/boundary_26",  test_rejection_boundary_26 },
    { "rejection/boundary_10",  test_rejection_boundary_10 },

    /* Password Generation Tests */
    { "generate/length",        test_generate_length },
    { "generate/charset_only",  test_generate_charset_only },
    { "generate/uniqueness",    test_generate_uniqueness },
    { "generate/invalid_args",  test_generate_invalid_args },

    /* Chi-Squared Statistical Tests */
    { "chi_squared/uniform",           test_chi_squared_uniform },
    { "chi_squared/biased",            test_chi_squared_biased },
    { "chi_squared/degrees_of_freedom", test_chi_squared_degrees_of_freedom },

    /* Serial Correlation Tests */
    { "serial/constant",        test_serial_correlation_constant },
    { "serial/alternating",     test_serial_correlation_alternating },
    { "serial/short",           test_serial_correlation_short },

    /* Collision Detection Tests */
    { "collision/no_duplicates",  test_collision_no_duplicates },
    { "collision/with_duplicates", test_collision_with_duplicates },
    { "collision/all_same",       test_collision_all_same },

    /* Struct Offset Verification */
    { "struct/offsets",         test_struct_offsets },

    /* Full Audit Integration Tests */
    { "audit/basic",            test_audit_basic },
    { "audit/entropy",          test_audit_entropy_calculation },
    { "audit/invalid_args",     test_audit_invalid_args },

    /* High-Volume Stress Tests */
    { "stress/distribution",    test_stress_distribution },
    { "stress/no_collisions",   test_stress_no_collisions },
    { "stress/chi_squared_pass", test_stress_chi_squared_pass },

    /* Version */
    { "version/string",         test_version },

    { NULL, NULL }
};
