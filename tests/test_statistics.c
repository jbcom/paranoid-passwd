/**
 * test_statistics.c -- Known-answer tests for statistical audit functions
 *
 * Copyright (c) 2026 jbcom
 * SPDX-License-Identifier: MIT
 *
 * Tests chi-squared and serial correlation with known-distribution
 * datasets to verify the implementations match expected values.
 *
 * Build (native):
 *   cc -O2 -Wall -Wextra -I../include -I../vendor/acutest/include \
 *      tests/test_statistics.c src/paranoid.c src/platform_native.c \
 *      -lcrypto -lm -o build/test_statistics
 *
 * Run: ./build/test_statistics [--verbose]
 *
 * TODO: HUMAN_REVIEW - Verify expected chi-squared and correlation
 * values against an independent implementation (e.g., scipy.stats).
 */

#include "../vendor/acutest/include/acutest.h"
#include "../include/paranoid.h"
#include <string.h>
#include <stdlib.h>
#include <math.h>

/* ================================================================
   CHI-SQUARED KNOWN-ANSWER TESTS
   ================================================================ */

void test_chi2_perfect_uniform(void) {
    /*
     * Generate a perfectly uniform distribution over charset "abc".
     * Each character appears exactly the same number of times.
     * Expected chi-squared statistic: 0.0
     * Expected p-value: ~1.0 (perfect fit)
     * Expected df: 2 (N-1 = 3-1)
     *
     * Dataset: "abcabcabcabc..." repeated to fill 100 passwords * 30 chars
     * Total chars: 3000. Each char appears 1000 times.
     * Expected frequency: 3000/3 = 1000.
     * Observed: a=1000, b=1000, c=1000.
     * chi2 = sum((Oi-Ei)^2/Ei) = 0 + 0 + 0 = 0.0
     *
     * TODO: HUMAN_REVIEW - verify chi2 = 0 for perfect uniform
     */
    const char *charset = "abc";
    int charset_len = 3;
    int num_pw = 100;
    int pw_len = 30;

    char *passwords = (char *)malloc(num_pw * pw_len);
    TEST_ASSERT(passwords != NULL);

    for (int i = 0; i < num_pw * pw_len; i++) {
        passwords[i] = charset[i % charset_len];
    }

    int df;
    double p_value;
    double chi2 = paranoid_chi_squared(
        passwords, num_pw, pw_len, charset, charset_len, &df, &p_value
    );

    free(passwords);

    /* chi2 should be exactly 0 for perfect uniform distribution */
    TEST_CHECK(fabs(chi2 - 0.0) < 0.001);
    TEST_MSG("chi2 = %f, expected ~0.0", chi2);

    /* df = N - 1 = 2 */
    TEST_CHECK(df == 2);
    TEST_MSG("df = %d, expected 2", df);

    /* p-value should be very high (~1.0) */
    TEST_CHECK(p_value > 0.5);
    TEST_MSG("p_value = %f, expected > 0.5", p_value);
}

void test_chi2_known_biased(void) {
    /*
     * Generate a heavily biased distribution: all 'a', none of 'b' or 'c'.
     * This should produce a very large chi-squared and a very small p-value.
     *
     * Dataset: 3000 chars, all 'a'.
     * Expected frequency per char: 3000/3 = 1000.
     * Observed: a=3000, b=0, c=0.
     * chi2 = (3000-1000)^2/1000 + (0-1000)^2/1000 + (0-1000)^2/1000
     *       = 4000000/1000 + 1000000/1000 + 1000000/1000
     *       = 4000 + 1000 + 1000 = 6000.0
     *
     * TODO: HUMAN_REVIEW - verify chi2 = 6000 for all-'a' input
     */
    const char *charset = "abc";
    int charset_len = 3;
    int num_pw = 100;
    int pw_len = 30;

    char *passwords = (char *)malloc(num_pw * pw_len);
    TEST_ASSERT(passwords != NULL);

    memset(passwords, 'a', num_pw * pw_len);

    int df;
    double p_value;
    double chi2 = paranoid_chi_squared(
        passwords, num_pw, pw_len, charset, charset_len, &df, &p_value
    );

    free(passwords);

    /* chi2 should be exactly 6000 */
    TEST_CHECK(fabs(chi2 - 6000.0) < 0.1);
    TEST_MSG("chi2 = %f, expected ~6000.0", chi2);

    /* df = N - 1 = 2 */
    TEST_CHECK(df == 2);
    TEST_MSG("df = %d, expected 2", df);

    /* p-value should be extremely small (reject H0) */
    TEST_CHECK(p_value < 0.01);
    TEST_MSG("p_value = %f, expected < 0.01 (reject uniformity)", p_value);
}

void test_chi2_moderate_bias(void) {
    /*
     * Generate a moderately biased distribution over "ab".
     * 'a' appears 2000 times, 'b' appears 1000 times.
     * Total: 3000 chars across 100 passwords of length 30.
     *
     * Expected frequency per char: 3000/2 = 1500.
     * Observed: a=2000, b=1000.
     * chi2 = (2000-1500)^2/1500 + (1000-1500)^2/1500
     *       = 250000/1500 + 250000/1500
     *       = 166.667 + 166.667 = 333.333
     *
     * TODO: HUMAN_REVIEW - verify chi2 = 333.33 for 2:1 bias
     */
    const char *charset = "ab";
    int charset_len = 2;
    int num_pw = 100;
    int pw_len = 30;

    char *passwords = (char *)malloc(num_pw * pw_len);
    TEST_ASSERT(passwords != NULL);

    /* Fill: 2/3 'a', 1/3 'b' */
    for (int i = 0; i < num_pw * pw_len; i++) {
        passwords[i] = (i % 3 == 2) ? 'b' : 'a';
    }

    int df;
    double p_value;
    double chi2 = paranoid_chi_squared(
        passwords, num_pw, pw_len, charset, charset_len, &df, &p_value
    );

    free(passwords);

    /* chi2 should be ~333.33 */
    TEST_CHECK(fabs(chi2 - 333.333) < 1.0);
    TEST_MSG("chi2 = %f, expected ~333.333", chi2);

    /* df = N - 1 = 1 */
    TEST_CHECK(df == 1);
    TEST_MSG("df = %d, expected 1", df);

    /* p-value should be very small */
    TEST_CHECK(p_value < 0.01);
    TEST_MSG("p_value = %f, expected < 0.01", p_value);
}

void test_chi2_df_is_n_minus_one(void) {
    /*
     * CRITICAL: verify degrees of freedom = N - 1 (not N).
     * Test with N=10 charset.
     *
     * TODO: HUMAN_REVIEW - df = N-1 is the single most common
     * LLM hallucination in chi-squared implementations.
     */
    const char *charset = "abcdefghij";
    int charset_len = 10;
    int num_pw = 10;
    int pw_len = 100;

    char *passwords = (char *)malloc(num_pw * pw_len);
    TEST_ASSERT(passwords != NULL);

    for (int i = 0; i < num_pw * pw_len; i++) {
        passwords[i] = charset[i % charset_len];
    }

    int df;
    double p_value;
    paranoid_chi_squared(
        passwords, num_pw, pw_len, charset, charset_len, &df, &p_value
    );

    free(passwords);

    /* df MUST be 9 (N-1), NOT 10 (N) */
    TEST_CHECK(df == 9);
    TEST_MSG("df = %d, expected 9 (N-1)", df);
}

/* ================================================================
   SERIAL CORRELATION KNOWN-ANSWER TESTS
   ================================================================ */

void test_serial_constant_data(void) {
    /*
     * Constant data: all same character.
     * Variance = 0, so correlation is undefined.
     * Implementation should return 0 (safe default).
     *
     * Input: 100 x 'A'
     * Mean = 65 (ASCII 'A')
     * All deviations from mean = 0
     * Numerator = sum(0 * 0) = 0
     * Denominator = sum(0^2) = 0
     * Result: 0 (division by zero guard)
     */
    char data[100];
    memset(data, 'A', 100);

    double r = paranoid_serial_correlation(data, 100);

    TEST_CHECK(fabs(r - 0.0) < 0.001);
    TEST_MSG("r = %f, expected 0.0 (constant data)", r);
}

void test_serial_alternating_high_low(void) {
    /*
     * Alternating high-low pattern: strong negative correlation.
     * Pattern: 'A' (65), 'z' (122), 'A' (65), 'z' (122), ...
     *
     * Mean = (65 + 122) / 2 = 93.5
     * Deviations: -28.5, +28.5, -28.5, +28.5, ...
     *
     * Numerator = sum(d[i] * d[i+1]) = (-28.5)(+28.5) + (+28.5)(-28.5) + ...
     *           = -812.25 * (N-1) terms of alternating pairs
     * Denominator = sum(d[i]^2) = 812.25 * N terms (all same magnitude)
     *
     * For N=100 pairs:
     * Numerator = 99 terms: each -812.25 => total = -80392.75
     * Denominator = 100 terms: each 812.25 => total = 81225.0
     * r = -80392.75 / 81225.0 ≈ -0.9898...
     *
     * This should produce a strong negative correlation (r close to -1).
     * The serial_pass flag should FAIL (|r| > 0.05).
     *
     * TODO: HUMAN_REVIEW - verify expected correlation coefficient
     * against scipy: np.corrcoef(x[:-1], x[1:])[0,1]
     */
    char data[100];
    for (int i = 0; i < 100; i++) {
        data[i] = (i % 2 == 0) ? 'A' : 'z';
    }

    double r = paranoid_serial_correlation(data, 100);

    /* Should be strongly negative (close to -1) */
    TEST_CHECK(r < -0.9);
    TEST_MSG("r = %f, expected < -0.9 (strong negative correlation)", r);

    /* Must fail the serial_pass threshold of |r| < 0.05 */
    TEST_CHECK(fabs(r) > 0.05);
    TEST_MSG("|r| = %f, expected > 0.05 (should fail serial test)", fabs(r));
}

void test_serial_ascending_sequence(void) {
    /*
     * Ascending sequence: 'a', 'b', 'c', ..., 'z', 'a', 'b', ...
     * This is a perfectly correlated sequence (strong positive lag-1
     * correlation), though the correlation coefficient depends on
     * the wrap-around behavior.
     *
     * For a pure ascending sequence of 26 chars repeated ~4 times:
     * Within each cycle of 26, adjacent values differ by +1.
     * At the boundary (z->a), value drops by 25.
     *
     * Expected: positive correlation (each char predicts the next).
     *
     * TODO: HUMAN_REVIEW - verify expected correlation value
     */
    char data[104]; /* 4 full cycles of 26 */
    for (int i = 0; i < 104; i++) {
        data[i] = 'a' + (i % 26);
    }

    double r = paranoid_serial_correlation(data, 104);

    /* Should be noticeably positive due to ascending pattern */
    TEST_CHECK(r > 0.5);
    TEST_MSG("r = %f, expected > 0.5 (ascending sequence)", r);
}

void test_serial_single_char(void) {
    /*
     * Single character: correlation is undefined.
     * Implementation should return 0.
     */
    char data[1] = {'X'};

    double r = paranoid_serial_correlation(data, 1);

    TEST_CHECK(fabs(r - 0.0) < 0.001);
    TEST_MSG("r = %f, expected 0.0 (single char)", r);
}

void test_serial_two_chars(void) {
    /*
     * Two characters: only one lag-1 pair.
     * For 'A' (65), 'B' (66):
     * Mean = 65.5
     * d[0] = -0.5, d[1] = +0.5
     * Numerator = (-0.5)(+0.5) = -0.25 (one term only: i=0)
     * Denominator = (-0.5)^2 = 0.25 (sum over i=0 only in denominator)
     *
     * Note: the implementation sums denominator from i=0 to total_chars-2
     * (matching the numerator range), or it may sum the full range.
     * Either way, with only 2 data points the result should be
     * approximately -1.0 or near 0.
     *
     * TODO: HUMAN_REVIEW - verify boundary behavior for N=2
     */
    char data[2] = {'A', 'B'};

    double r = paranoid_serial_correlation(data, 2);

    /* With 2 data points, result is either -1.0 or 0.0 depending
     * on how the denominator is computed. Both are acceptable
     * as long as the function does not crash or return NaN. */
    TEST_CHECK(r >= -1.01 && r <= 1.01);
    TEST_MSG("r = %f, expected in [-1, 1]", r);
}

/* ================================================================
   TEST LIST
   ================================================================ */

TEST_LIST = {
    /* Chi-squared known-answer tests */
    { "chi2/perfect_uniform",       test_chi2_perfect_uniform },
    { "chi2/known_biased",          test_chi2_known_biased },
    { "chi2/moderate_bias",         test_chi2_moderate_bias },
    { "chi2/df_is_n_minus_one",     test_chi2_df_is_n_minus_one },

    /* Serial correlation known-answer tests */
    { "serial/constant_data",       test_serial_constant_data },
    { "serial/alternating_hl",      test_serial_alternating_high_low },
    { "serial/ascending_sequence",  test_serial_ascending_sequence },
    { "serial/single_char",         test_serial_single_char },
    { "serial/two_chars",           test_serial_two_chars },

    { NULL, NULL }
};
