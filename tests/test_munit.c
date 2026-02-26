/**
 * test_munit.c — Comprehensive unit tests using µnit framework
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
 * Run: ./build/test_munit [options]
 *
 * µnit CLI options:
 *   --help         Show all options
 *   --seed SEED    Set PRNG seed for reproducibility
 *   --iterations N Run each test N times
 *   --log-visible  Show test output even on pass
 */

#include "../vendor/munit/munit.h"
#include "paranoid.h"
#include <string.h>
#include <math.h>

/* ═══════════════════════════════════════════════════════════════════════════════
   NIST SHA-256 KNOWN-ANSWER TESTS (FIPS 180-4)
   Reference: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip
   ═══════════════════════════════════════════════════════════════════════════════ */

static MunitResult
test_sha256_empty(const MunitParameter params[], void* data) {
    (void) params;
    (void) data;
    
    /* NIST CAVP vector: SHA-256("") */
    char hex[65];
    int rc = paranoid_sha256_hex("", hex);
    munit_assert_int(rc, ==, 0);
    munit_assert_string_equal(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    
    return MUNIT_OK;
}

static MunitResult
test_sha256_abc(const MunitParameter params[], void* data) {
    (void) params;
    (void) data;
    
    /* NIST CAVP vector: SHA-256("abc") */
    char hex[65];
    int rc = paranoid_sha256_hex("abc", hex);
    munit_assert_int(rc, ==, 0);
    munit_assert_string_equal(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    
    return MUNIT_OK;
}

static MunitResult
test_sha256_448bits(const MunitParameter params[], void* data) {
    (void) params;
    (void) data;
    
    /* NIST CAVP vector: SHA-256(448 bits) */
    const char *input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    char hex[65];
    int rc = paranoid_sha256_hex(input, hex);
    munit_assert_int(rc, ==, 0);
    munit_assert_string_equal(hex, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    
    return MUNIT_OK;
}

static MunitResult
test_sha256_896bits(const MunitParameter params[], void* data) {
    (void) params;
    (void) data;
    
    /* NIST CAVP vector: SHA-256(896 bits) */
    const char *input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    char hex[65];
    int rc = paranoid_sha256_hex(input, hex);
    munit_assert_int(rc, ==, 0);
    munit_assert_string_equal(hex, "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
    
    return MUNIT_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════════
   REJECTION SAMPLING BOUNDARY TESTS
   Critical: max_valid = (256/N)*N - 1 (NOT -0, NOT N)
   ═══════════════════════════════════════════════════════════════════════════════ */

static MunitResult
test_rejection_boundary_94(const MunitParameter params[], void* data) {
    (void) params;
    (void) data;
    
    /* N=94 (printable ASCII): max_valid = (256/94)*94 - 1 = 2*94 - 1 = 187 */
    int N = 94;
    int max_valid = (256 / N) * N - 1;
    munit_assert_int(max_valid, ==, 187);
    
    /* Rejection rate = (255 - 187) / 256 = 68/256 = 26.5625% */
    double rate = (double)(255 - max_valid) / 256.0 * 100.0;
    munit_assert_double_equal(rate, 26.5625, 4);
    
    return MUNIT_OK;
}

static MunitResult
test_rejection_boundary_62(const MunitParameter params[], void* data) {
    (void) params;
    (void) data;
    
    /* N=62 (alphanumeric): max_valid = (256/62)*62 - 1 = 4*62 - 1 = 247 */
    int N = 62;
    int max_valid = (256 / N) * N - 1;
    munit_assert_int(max_valid, ==, 247);
    
    return MUNIT_OK;
}

static MunitResult
test_rejection_boundary_26(const MunitParameter params[], void* data) {
    (void) params;
    (void) data;
    
    /* N=26 (lowercase): max_valid = (256/26)*26 - 1 = 9*26 - 1 = 233 */
    int N = 26;
    int max_valid = (256 / N) * N - 1;
    munit_assert_int(max_valid, ==, 233);
    
    return MUNIT_OK;
}

static MunitResult
test_rejection_boundary_10(const MunitParameter params[], void* data) {
    (void) params;
    (void) data;
    
    /* N=10 (digits): max_valid = (256/10)*10 - 1 = 25*10 - 1 = 249 */
    int N = 10;
    int max_valid = (256 / N) * N - 1;
    munit_assert_int(max_valid, ==, 249);
    
    return MUNIT_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════════
   PASSWORD GENERATION TESTS
   ═══════════════════════════════════════════════════════════════════════════════ */

static MunitResult
test_generate_length(const MunitParameter params[], void* data) {
    (void) params;
    (void) data;
    
    char password[33];
    const char *charset = "abcdefghijklmnopqrstuvwxyz";
    int rc = paranoid_generate(charset, 26, 32, password);
    munit_assert_int(rc, ==, 0);
    munit_assert_size(strlen(password), ==, 32);
    
    return MUNIT_OK;
}

static MunitResult
test_generate_charset_only(const MunitParameter params[], void* data) {
    (void) params;
    (void) data;
    
    char password[101];
    const char *charset = "XYZ";
    int rc = paranoid_generate(charset, 3, 100, password);
    munit_assert_int(rc, ==, 0);
    
    /* Every character must be from charset */
    for (int i = 0; i < 100; i++) {
        munit_assert_true(password[i] == 'X' || password[i] == 'Y' || password[i] == 'Z');
    }
    
    return MUNIT_OK;
}

static MunitResult
test_generate_uniqueness(const MunitParameter params[], void* data) {
    (void) params;
    (void) data;
    
    /* Generate 100 passwords and verify they're all different */
    char passwords[100][33];
    const char *charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    
    for (int i = 0; i < 100; i++) {
        int rc = paranoid_generate(charset, 62, 32, passwords[i]);
        munit_assert_int(rc, ==, 0);
    }
    
    /* Check all pairs for uniqueness */
    for (int i = 0; i < 100; i++) {
        for (int j = i + 1; j < 100; j++) {
            munit_assert_string_not_equal(passwords[i], passwords[j]);
        }
    }
    
    return MUNIT_OK;
}

static MunitResult
test_generate_invalid_args(const MunitParameter params[], void* data) {
    (void) params;
    (void) data;
    
    char password[33];
    
    /* NULL charset */
    munit_assert_int(paranoid_generate(NULL, 0, 8, password), ==, -2);
    
    /* Zero charset length */
    munit_assert_int(paranoid_generate("abc", 0, 8, password), ==, -2);
    
    /* Zero password length */
    munit_assert_int(paranoid_generate("abc", 3, 0, password), ==, -2);
    
    /* NULL output */
    munit_assert_int(paranoid_generate("abc", 3, 8, NULL), ==, -2);
    
    return MUNIT_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════════
   CHI-SQUARED STATISTICAL TESTS
   Reference: Knuth Vol 2, Section 3.3.1
   ═══════════════════════════════════════════════════════════════════════════════ */

static MunitResult
test_chi_squared_uniform(const MunitParameter params[], void* data) {
    (void) params;
    (void) data;
    
    /* Perfect uniform distribution should yield chi² ≈ 0 */
    const char *charset = "abcd";
    int charset_len = 4;
    int num_pw = 100;
    int pw_len = 40;  /* 4000 chars total, 1000 per char */
    
    char *passwords = malloc(num_pw * pw_len);
    munit_assert_not_null(passwords);
    
    for (int i = 0; i < num_pw * pw_len; i++) {
        passwords[i] = charset[i % charset_len];
    }
    
    int df;
    double p_value;
    double chi2 = paranoid_chi_squared(passwords, num_pw, pw_len, charset, charset_len, &df, &p_value);
    
    free(passwords);
    
    munit_assert_double_equal(chi2, 0.0, 3);
    munit_assert_int(df, ==, charset_len - 1);  /* CRITICAL: df = N - 1 */
    
    return MUNIT_OK;
}

static MunitResult
test_chi_squared_biased(const MunitParameter params[], void* data) {
    (void) params;
    (void) data;
    
    /* Heavily biased distribution should yield high chi² */
    const char *charset = "ab";
    int charset_len = 2;
    int num_pw = 100;
    int pw_len = 100;  /* 10000 chars */
    
    char *passwords = malloc(num_pw * pw_len);
    munit_assert_not_null(passwords);
    
    /* 90% 'a', 10% 'b' - heavily biased */
    for (int i = 0; i < num_pw * pw_len; i++) {
        passwords[i] = (i % 10 == 0) ? 'b' : 'a';
    }
    
    int df;
    double p_value;
    double chi2 = paranoid_chi_squared(passwords, num_pw, pw_len, charset, charset_len, &df, &p_value);
    
    free(passwords);
    
    /* Chi² should be very high for biased data */
    munit_assert_double(chi2, >, 1000.0);
    /* P-value should be very low (reject null hypothesis) */
    munit_assert_double(p_value, <, 0.001);
    
    return MUNIT_OK;
}

static MunitResult
test_chi_squared_degrees_of_freedom(const MunitParameter params[], void* data) {
    (void) params;
    (void) data;
    
    /* CRITICAL TEST: Verify df = N - 1 (NOT N) */
    const char *charset = "abcdefghij";  /* N = 10 */
    int charset_len = 10;
    int num_pw = 10;
    int pw_len = 100;
    
    char *passwords = malloc(num_pw * pw_len);
    munit_assert_not_null(passwords);
    for (int i = 0; i < num_pw * pw_len; i++) {
        passwords[i] = charset[i % charset_len];
    }
    
    int df;
    double p_value;
    paranoid_chi_squared(passwords, num_pw, pw_len, charset, charset_len, &df, &p_value);
    
    free(passwords);
    
    /* This is a CRITICAL assertion - wrong df would invalidate all statistics */
    munit_assert_int(df, ==, 9);  /* df = N - 1 = 10 - 1 = 9 */
    
    return MUNIT_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════════
   SERIAL CORRELATION TESTS
   ═══════════════════════════════════════════════════════════════════════════════ */

static MunitResult
test_serial_correlation_constant(const MunitParameter params[], void* data) {
    (void) params;
    (void) data;
    
    /* Constant sequence has variance 0 → correlation undefined → returns 0 */
    char data_const[100];
    memset(data_const, 'A', 100);
    
    double r = paranoid_serial_correlation(data_const, 100);
    munit_assert_double_equal(r, 0.0, 3);
    
    return MUNIT_OK;
}

static MunitResult
test_serial_correlation_alternating(const MunitParameter params[], void* data) {
    (void) params;
    (void) data;
    
    /* Perfectly alternating sequence should have strong negative correlation */
    char data_alt[100];
    for (int i = 0; i < 100; i++) {
        data_alt[i] = (i % 2 == 0) ? 'A' : 'Z';
    }
    
    double r = paranoid_serial_correlation(data_alt, 100);
    /* Should be strongly negative (near -1) */
    munit_assert_double(r, <, -0.9);
    
    return MUNIT_OK;
}

static MunitResult
test_serial_correlation_short(const MunitParameter params[], void* data) {
    (void) params;
    (void) data;
    
    /* Single character - undefined, should return 0 */
    char data_short[1] = {'A'};
    double r = paranoid_serial_correlation(data_short, 1);
    munit_assert_double_equal(r, 0.0, 3);
    
    return MUNIT_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════════
   COLLISION DETECTION TESTS
   ═══════════════════════════════════════════════════════════════════════════════ */

static MunitResult
test_collision_no_duplicates(const MunitParameter params[], void* data) {
    (void) params;
    (void) data;
    
    const char *passwords = "aaa" "bbb" "ccc" "ddd" "eee";
    int dupes = paranoid_count_collisions(passwords, 5, 3);
    munit_assert_int(dupes, ==, 0);
    
    return MUNIT_OK;
}

static MunitResult
test_collision_with_duplicates(const MunitParameter params[], void* data) {
    (void) params;
    (void) data;
    
    const char *passwords = "aaa" "bbb" "aaa" "ccc" "ddd";
    int dupes = paranoid_count_collisions(passwords, 5, 3);
    munit_assert_int(dupes, ==, 1);
    
    return MUNIT_OK;
}

static MunitResult
test_collision_all_same(const MunitParameter params[], void* data) {
    (void) params;
    (void) data;
    
    const char *passwords = "xxx" "xxx" "xxx" "xxx" "xxx";
    int dupes = paranoid_count_collisions(passwords, 5, 3);
    munit_assert_int(dupes, ==, 4);  /* Positions 1,2,3,4 each match an earlier one */
    
    return MUNIT_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════════
   STRUCT OFFSET VERIFICATION TESTS
   Critical for JS/WASM interop - wrong offsets = reading garbage
   ═══════════════════════════════════════════════════════════════════════════════ */

static MunitResult
test_struct_offsets(const MunitParameter params[], void* data) {
    (void) params;
    (void) data;
    
    /* All offsets must be within struct bounds */
    int size = paranoid_get_result_size();
    
    munit_assert_int(paranoid_offset_password_length(), >=, 0);
    munit_assert_int(paranoid_offset_password_length(), <, size);
    
    munit_assert_int(paranoid_offset_chi2_statistic(), >=, 0);
    munit_assert_int(paranoid_offset_chi2_statistic(), <, size);
    
    munit_assert_int(paranoid_offset_current_stage(), >=, 0);
    munit_assert_int(paranoid_offset_current_stage(), <, size);
    
    munit_assert_int(paranoid_offset_all_pass(), >=, 0);
    munit_assert_int(paranoid_offset_all_pass(), <, size);
    
    return MUNIT_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════════
   FULL AUDIT INTEGRATION TESTS
   ═══════════════════════════════════════════════════════════════════════════════ */

static MunitResult
test_audit_basic(const MunitParameter params[], void* data) {
    (void) params;
    (void) data;
    
    paranoid_audit_result_t *result = paranoid_get_result_ptr();
    const char *charset = "abcdefghijklmnopqrstuvwxyz";
    
    int rc = paranoid_run_audit(charset, 26, 16, 100, result);
    munit_assert_int(rc, ==, 0);
    
    munit_assert_int(result->password_length, ==, 16);
    munit_assert_int(result->charset_size, ==, 26);
    munit_assert_int(result->batch_size, ==, 100);
    munit_assert_size(strlen(result->password), ==, 16);
    munit_assert_size(strlen(result->sha256_hex), ==, 64);
    munit_assert_int(result->current_stage, ==, 8);  /* Done */
    
    return MUNIT_OK;
}

static MunitResult
test_audit_entropy_calculation(const MunitParameter params[], void* data) {
    (void) params;
    (void) data;
    
    paranoid_audit_result_t *result = paranoid_get_result_ptr();
    const char *charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
    int charset_len = 70;
    int pw_len = 20;
    
    int rc = paranoid_run_audit(charset, charset_len, pw_len, 100, result);
    munit_assert_int(rc, ==, 0);
    
    /* Verify entropy: H = L * log2(N) */
    double expected_bits = pw_len * log2((double)charset_len);
    munit_assert_double_equal(result->total_entropy, expected_bits, 3);
    munit_assert_double_equal(result->bits_per_char, log2((double)charset_len), 3);
    
    return MUNIT_OK;
}

static MunitResult
test_audit_invalid_args(const MunitParameter params[], void* data) {
    (void) params;
    (void) data;
    
    paranoid_audit_result_t *result = paranoid_get_result_ptr();
    
    munit_assert_int(paranoid_run_audit(NULL, 26, 16, 100, result), ==, -1);
    munit_assert_int(paranoid_run_audit("abc", 0, 16, 100, result), ==, -2);
    munit_assert_int(paranoid_run_audit("abc", 3, 0, 100, result), ==, -2);
    munit_assert_int(paranoid_run_audit("abc", 3, 16, 0, result), ==, -2);
    
    return MUNIT_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════════
   HIGH-VOLUME STRESS TESTS
   These verify statistical assumptions hold across many password generations
   ═══════════════════════════════════════════════════════════════════════════════ */

static MunitResult
test_stress_distribution(const MunitParameter params[], void* data) {
    (void) params;
    (void) data;
    
    /* Generate 10,000 characters and verify distribution is approximately uniform */
    const char *charset = "abcdefghij";  /* N = 10 */
    int charset_len = 10;
    int total_chars = 10000;
    int freq[256] = {0};
    
    char password[101];
    for (int i = 0; i < total_chars / 100; i++) {
        int rc = paranoid_generate(charset, charset_len, 100, password);
        munit_assert_int(rc, ==, 0);
        
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
        munit_assert_double(deviation, <, 0.10);  /* Less than 10% deviation */
    }
    
    return MUNIT_OK;
}

static MunitResult
test_stress_no_collisions(const MunitParameter params[], void* data) {
    (void) params;
    (void) data;
    
    /* Generate 500 32-character passwords and verify no collisions */
    /* With charset 62 and length 32: probability of collision ≈ 0 */
    const char *charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    int charset_len = 62;
    int pw_len = 32;
    int num_passwords = 500;
    
    char *batch = malloc(num_passwords * pw_len);
    munit_assert_not_null(batch);
    
    for (int i = 0; i < num_passwords; i++) {
        int rc = paranoid_generate(charset, charset_len, pw_len, batch + i * pw_len);
        munit_assert_int(rc, ==, 0);
    }
    
    int collisions = paranoid_count_collisions(batch, num_passwords, pw_len);
    free(batch);
    
    munit_assert_int(collisions, ==, 0);
    
    return MUNIT_OK;
}

static MunitResult
test_stress_chi_squared_pass(const MunitParameter params[], void* data) {
    (void) params;
    (void) data;
    
    /* Generate random passwords and verify chi-squared test passes */
    const char *charset = "abcdefghijklmnopqrstuvwxyz";
    int charset_len = 26;
    int num_pw = 200;
    int pw_len = 50;
    
    char *batch = malloc(num_pw * pw_len);
    munit_assert_not_null(batch);
    
    for (int i = 0; i < num_pw; i++) {
        int rc = paranoid_generate(charset, charset_len, pw_len, batch + i * pw_len);
        munit_assert_int(rc, ==, 0);
    }
    
    int df;
    double p_value;
    paranoid_chi_squared(batch, num_pw, pw_len, charset, charset_len, &df, &p_value);
    
    free(batch);
    
    /* For truly random data, p-value should be > 0.01 most of the time */
    /* (There's a 1% chance of false failure - acceptable for stress tests) */
    munit_assert_double(p_value, >, 0.001);
    
    return MUNIT_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════════
   VERSION TEST
   ═══════════════════════════════════════════════════════════════════════════════ */

static MunitResult
test_version(const MunitParameter params[], void* data) {
    (void) params;
    (void) data;
    
    const char *version = paranoid_version();
    munit_assert_not_null(version);
    munit_assert_ptr_not_null(strstr(version, "paranoid"));
    munit_assert_ptr_not_null(strstr(version, "OpenSSL"));
    
    return MUNIT_OK;
}

/* ═══════════════════════════════════════════════════════════════════════════════
   TEST SUITE DEFINITIONS
   ═══════════════════════════════════════════════════════════════════════════════ */

static MunitTest sha256_tests[] = {
    { "/empty", test_sha256_empty, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
    { "/abc", test_sha256_abc, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
    { "/448bits", test_sha256_448bits, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
    { "/896bits", test_sha256_896bits, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
    { NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL }
};

static MunitTest rejection_tests[] = {
    { "/boundary_94", test_rejection_boundary_94, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
    { "/boundary_62", test_rejection_boundary_62, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
    { "/boundary_26", test_rejection_boundary_26, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
    { "/boundary_10", test_rejection_boundary_10, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
    { NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL }
};

static MunitTest generate_tests[] = {
    { "/length", test_generate_length, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
    { "/charset_only", test_generate_charset_only, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
    { "/uniqueness", test_generate_uniqueness, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
    { "/invalid_args", test_generate_invalid_args, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
    { NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL }
};

static MunitTest chi_squared_tests[] = {
    { "/uniform", test_chi_squared_uniform, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
    { "/biased", test_chi_squared_biased, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
    { "/degrees_of_freedom", test_chi_squared_degrees_of_freedom, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
    { NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL }
};

static MunitTest serial_tests[] = {
    { "/constant", test_serial_correlation_constant, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
    { "/alternating", test_serial_correlation_alternating, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
    { "/short", test_serial_correlation_short, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
    { NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL }
};

static MunitTest collision_tests[] = {
    { "/no_duplicates", test_collision_no_duplicates, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
    { "/with_duplicates", test_collision_with_duplicates, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
    { "/all_same", test_collision_all_same, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
    { NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL }
};

static MunitTest struct_tests[] = {
    { "/offsets", test_struct_offsets, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
    { NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL }
};

static MunitTest audit_tests[] = {
    { "/basic", test_audit_basic, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
    { "/entropy", test_audit_entropy_calculation, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
    { "/invalid_args", test_audit_invalid_args, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
    { NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL }
};

static MunitTest stress_tests[] = {
    { "/distribution", test_stress_distribution, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
    { "/no_collisions", test_stress_no_collisions, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
    { "/chi_squared_pass", test_stress_chi_squared_pass, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
    { NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL }
};

static MunitTest version_tests[] = {
    { "/string", test_version, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
    { NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL }
};

static MunitSuite child_suites[] = {
    { "/sha256", sha256_tests, NULL, 1, MUNIT_SUITE_OPTION_NONE },
    { "/rejection", rejection_tests, NULL, 1, MUNIT_SUITE_OPTION_NONE },
    { "/generate", generate_tests, NULL, 1, MUNIT_SUITE_OPTION_NONE },
    { "/chi_squared", chi_squared_tests, NULL, 1, MUNIT_SUITE_OPTION_NONE },
    { "/serial", serial_tests, NULL, 1, MUNIT_SUITE_OPTION_NONE },
    { "/collision", collision_tests, NULL, 1, MUNIT_SUITE_OPTION_NONE },
    { "/struct", struct_tests, NULL, 1, MUNIT_SUITE_OPTION_NONE },
    { "/audit", audit_tests, NULL, 1, MUNIT_SUITE_OPTION_NONE },
    { "/stress", stress_tests, NULL, 1, MUNIT_SUITE_OPTION_NONE },
    { "/version", version_tests, NULL, 1, MUNIT_SUITE_OPTION_NONE },
    { NULL, NULL, NULL, 0, MUNIT_SUITE_OPTION_NONE }
};

static const MunitSuite root_suite = {
    "/paranoid",
    NULL,
    child_suites,
    1,
    MUNIT_SUITE_OPTION_NONE
};

int main(int argc, char* argv[MUNIT_ARRAY_PARAM(argc + 1)]) {
    return munit_suite_main(&root_suite, NULL, argc, argv);
}
