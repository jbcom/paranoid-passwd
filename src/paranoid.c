/**
 * paranoid.c — Complete implementation
 *
 * Every function that touches random data, statistics, or math
 * runs here in WASM linear memory. The JS layer is a display-only
 * bridge that reads the result struct and sets DOM textContent.
 */

#include "paranoid.h"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <string.h>
#include <stddef.h>
#include <math.h>
#include <stdlib.h>

/* ═══════════════════════════════════════════════════════════
   STATIC RESULT — lives in WASM linear memory
   JS gets a pointer to this via paranoid_get_result_ptr()
   ═══════════════════════════════════════════════════════════ */

static paranoid_audit_result_t g_result;

paranoid_audit_result_t* paranoid_get_result_ptr(void) {
    return &g_result;
}

int paranoid_get_result_size(void) {
    return (int)sizeof(paranoid_audit_result_t);
}

/**
 * Runtime struct layout verification.
 * JS calls these at init to confirm its hardcoded offsets match
 * what the compiler actually produced. If any mismatch, JS must
 * refuse to run (wrong offsets = reading garbage from WASM memory).
 */
int paranoid_offset_password_length(void) { return (int)offsetof(paranoid_audit_result_t, password_length); }
int paranoid_offset_chi2_statistic(void)  { return (int)offsetof(paranoid_audit_result_t, chi2_statistic); }
int paranoid_offset_current_stage(void)   { return (int)offsetof(paranoid_audit_result_t, current_stage); }
int paranoid_offset_all_pass(void)        { return (int)offsetof(paranoid_audit_result_t, all_pass); }

const char* paranoid_version(void) {
    return "paranoid " PARANOID_VERSION_STRING " (OpenSSL WASM/WASI)";
}

/* ═══════════════════════════════════════════════════════════
   PASSWORD GENERATION — CSPRNG + rejection sampling
   ═══════════════════════════════════════════════════════════ */

int paranoid_generate(
    const char *charset,
    int charset_len,
    int length,
    char *output
) {
    if (!charset || charset_len <= 0 || charset_len > PARANOID_MAX_CHARSET_LEN)
        return -2;
    if (length <= 0 || length > PARANOID_MAX_PASSWORD_LEN)
        return -2;
    if (!output)
        return -2;

    int max_valid = (256 / charset_len) * charset_len - 1;
    int filled = 0;
    unsigned char buf[512];

    while (filled < length) {
        int need = (length - filled) * 2;
        if (need > (int)sizeof(buf)) need = (int)sizeof(buf);

        if (RAND_bytes(buf, need) != 1) {
            memset(output, 0, length + 1);
            memset(buf, 0, sizeof(buf));
            return -1;
        }

        for (int i = 0; i < need && filled < length; i++) {
            if (buf[i] <= (unsigned char)max_valid) {
                output[filled++] = charset[buf[i] % charset_len];
            }
        }
    }

    /* Scrub raw random bytes */
    memset(buf, 0, sizeof(buf));
    output[length] = '\0';
    return 0;
}

/* ═══════════════════════════════════════════════════════════
   SHA-256 via OpenSSL EVP
   ═══════════════════════════════════════════════════════════ */

int paranoid_sha256(
    const unsigned char *input,
    int input_len,
    unsigned char *output
) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    unsigned int len = 0;
    int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)
          && EVP_DigestUpdate(ctx, input, input_len)
          && EVP_DigestFinal_ex(ctx, output, &len);

    EVP_MD_CTX_free(ctx);
    return ok ? 0 : -1;
}

int paranoid_sha256_hex(const char *input, char *output_hex) {
    unsigned char hash[32];
    int rc = paranoid_sha256(
        (const unsigned char*)input,
        (int)strlen(input),
        hash
    );
    if (rc != 0) return rc;

    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        output_hex[i * 2]     = hex[hash[i] >> 4];
        output_hex[i * 2 + 1] = hex[hash[i] & 0x0f];
    }
    output_hex[64] = '\0';
    return 0;
}

/* ═══════════════════════════════════════════════════════════
   STATISTICAL TESTS
   ═══════════════════════════════════════════════════════════ */

/* Complementary error function approximation (Horner) */
static double erfc_approx(double x) {
    double ax = fabs(x);
    double t = 1.0 / (1.0 + 0.3275911 * ax);
    double poly = t * (0.254829592 + t * (-0.284496736 +
                  t * (1.421413741 + t * (-1.453152027 +
                  t * 1.061405429))));
    double r = poly * exp(-x * x);
    return x >= 0 ? r : 2.0 - r;
}

double paranoid_chi_squared(
    const char *passwords,
    int num_passwords,
    int pw_length,
    const char *charset,
    int charset_len,
    int *out_df,
    double *out_p_value
) {
    /* Count character frequencies */
    int freq[256];
    memset(freq, 0, sizeof(freq));

    int total = num_passwords * pw_length;
    for (int i = 0; i < total; i++) {
        freq[(unsigned char)passwords[i]]++;
    }

    /* Chi-squared statistic */
    double expected = (double)total / charset_len;
    double chi2 = 0.0;
    for (int i = 0; i < charset_len; i++) {
        unsigned char c = (unsigned char)charset[i];
        double diff = (double)freq[c] - expected;
        chi2 += (diff * diff) / expected;
    }

    int df = charset_len - 1;
    if (out_df) *out_df = df;

    /* Wilson-Hilferty p-value approximation */
    double z = pow(chi2 / df, 1.0 / 3.0) - (1.0 - 2.0 / (9.0 * df));
    z /= sqrt(2.0 / (9.0 * df));
    double p = 0.5 * erfc_approx(z / sqrt(2.0));

    if (out_p_value) *out_p_value = p;
    return chi2;
}

double paranoid_serial_correlation(
    const char *data,
    int total_chars
) {
    if (total_chars < 2) return 0.0;

    double mean = 0.0;
    for (int i = 0; i < total_chars; i++) {
        mean += (unsigned char)data[i];
    }
    mean /= total_chars;

    double num = 0.0, den = 0.0;
    for (int i = 0; i < total_chars - 1; i++) {
        double di = (unsigned char)data[i] - mean;
        double di1 = (unsigned char)data[i + 1] - mean;
        num += di * di1;
    }
    for (int i = 0; i < total_chars; i++) {
        double d = (unsigned char)data[i] - mean;
        den += d * d;
    }

    return den == 0.0 ? 0.0 : num / den;
}

int paranoid_count_collisions(
    const char *passwords,
    int num_passwords,
    int pw_length
) {
    /*
     * Simple O(n²) comparison — fine for batch sizes ≤ 2000.
     * We hash each password and compare hashes.
     */
    int dupes = 0;

    /* Use SHA-256 fingerprints for comparison */
    unsigned char (*hashes)[32] = malloc(num_passwords * 32);
    if (!hashes) return -1;

    for (int i = 0; i < num_passwords; i++) {
        paranoid_sha256(
            (const unsigned char*)(passwords + i * pw_length),
            pw_length,
            hashes[i]
        );
    }

    for (int i = 1; i < num_passwords; i++) {
        for (int j = 0; j < i; j++) {
            if (memcmp(hashes[i], hashes[j], 32) == 0) {
                dupes++;
                break;
            }
        }
    }

    free(hashes);
    return dupes;
}

/* ═══════════════════════════════════════════════════════════
   PATTERN DETECTION
   ═══════════════════════════════════════════════════════════ */

static int check_patterns(const char *pw, int len) {
    int issues = 0;

    /* Triple repeats */
    for (int i = 0; i < len - 2; i++) {
        if (pw[i] == pw[i+1] && pw[i+1] == pw[i+2]) issues++;
    }

    /* Sequential runs (ascending) */
    for (int i = 0; i < len - 2; i++) {
        if ((unsigned char)pw[i] + 1 == (unsigned char)pw[i+1] &&
            (unsigned char)pw[i+1] + 1 == (unsigned char)pw[i+2]) {
            issues++;
        }
    }

    /* Keyboard walk fragments */
    static const char *walks[] = {
        "qwert", "asdfg", "zxcvb", "12345",
        "qazws", "!@#$%", NULL
    };
    for (int w = 0; walks[w]; w++) {
        int wlen = (int)strlen(walks[w]);
        for (int i = 0; i <= len - wlen; i++) {
            int match = 1;
            for (int j = 0; j < wlen && match; j++) {
                /* Case-insensitive */
                char a = pw[i+j], b = walks[w][j];
                if (a >= 'A' && a <= 'Z') a += 32;
                if (a != b) match = 0;
            }
            if (match) issues++;
        }
    }

    return issues;
}

/* ═══════════════════════════════════════════════════════════
   MAIN AUDIT PIPELINE
   ═══════════════════════════════════════════════════════════ */

int paranoid_run_audit(
    const char *charset,
    int charset_len,
    int pw_length,
    int batch_size,
    paranoid_audit_result_t *result
) {
    if (!result || !charset) return -1;
    if (charset_len <= 0 || charset_len > PARANOID_MAX_CHARSET_LEN) return -2;
    if (pw_length <= 0 || pw_length > PARANOID_MAX_PASSWORD_LEN) return -2;
    if (batch_size <= 0 || batch_size > PARANOID_MAX_BATCH_SIZE) return -2;

    memset(result, 0, sizeof(*result));
    result->charset_size = charset_len;
    result->password_length = pw_length;
    result->batch_size = batch_size;

    /* ── Stage 1: Generate primary password ── */
    result->current_stage = 1;

    int rc = paranoid_generate(charset, charset_len, pw_length, result->password);
    if (rc != 0) return rc;

    paranoid_sha256_hex(result->password, result->sha256_hex);

    /* ── Stage 2: Generate batch + chi-squared ── */
    result->current_stage = 2;

    char *batch = malloc(batch_size * pw_length);
    if (!batch) return -1;

    for (int i = 0; i < batch_size; i++) {
        rc = paranoid_generate(charset, charset_len, pw_length,
                               batch + i * pw_length);
        if (rc != 0) { free(batch); return rc; }
    }

    result->chi2_statistic = paranoid_chi_squared(
        batch, batch_size, pw_length,
        charset, charset_len,
        &result->chi2_df,
        &result->chi2_p_value
    );
    result->chi2_pass = (result->chi2_p_value > 0.01) ? 1 : 0;

    /* ── Stage 3: Serial correlation ── */
    result->current_stage = 3;

    int total_chars = batch_size * pw_length;
    result->serial_correlation = paranoid_serial_correlation(batch, total_chars);
    result->serial_pass = (fabs(result->serial_correlation) < 0.05) ? 1 : 0;

    /* ── Stage 4: Collision detection ── */
    result->current_stage = 4;

    result->duplicates = paranoid_count_collisions(batch, batch_size, pw_length);
    result->collision_pass = (result->duplicates == 0) ? 1 : 0;

    free(batch);

    /* ── Stage 5: Entropy proof + Uniqueness ── */
    result->current_stage = 5;

    result->bits_per_char = log2((double)charset_len);
    result->total_entropy = pw_length * result->bits_per_char;
    result->log10_search_space = pw_length * log10((double)charset_len);

    /* Brute-force time at 1e12 hash/s */
    double log_seconds = result->log10_search_space - log10(2.0) - 12.0;
    double seconds_per_year = 365.25 * 24.0 * 3600.0;
    result->brute_force_years = pow(10.0, log_seconds - log10(seconds_per_year));

    /* NIST thresholds */
    result->nist_memorized    = (result->total_entropy >= 30.0)  ? 1 : 0;
    result->nist_high_value   = (result->total_entropy >= 80.0)  ? 1 : 0;
    result->nist_crypto_equiv = (result->total_entropy >= 128.0) ? 1 : 0;
    result->nist_post_quantum = (result->total_entropy >= 256.0) ? 1 : 0;

    /* Uniqueness (birthday paradox) — same stage as entropy */
    /* P(collision) ≈ k²/2S for k << S, in log space */
    double log_S = pw_length * log((double)charset_len);
    double log_exp = 2.0 * log((double)batch_size) - log(2.0) - log_S;
    result->collision_probability = exp(log_exp);
    if (result->collision_probability > 1.0) result->collision_probability = 1.0;

    /* k for 50% collision: k ≈ √(2S·ln2) */
    result->passwords_for_50pct = exp(0.5 * (log_S + log(2.0) + log(log(2.0))));

    /* Rejection sampling self-audit */
    result->rejection_max_valid = (256 / charset_len) * charset_len - 1;
    result->rejection_rate_pct =
        (double)(255 - result->rejection_max_valid) / 256.0 * 100.0;

    /* ── Stage 6: Pattern check ── */
    result->current_stage = 6;
    result->pattern_issues = check_patterns(result->password, pw_length);

    /* ── Stage 7: Threat assessment (display-only, set for UI) ── */
    result->current_stage = 7;

    /* ── Final ── */
    result->all_pass = result->chi2_pass
                    && result->serial_pass
                    && result->collision_pass
                    && (result->pattern_issues == 0);

    result->current_stage = 8; /* Done */
    return 0;
}
