/**
 * paranoid.h — Public API for the paranoid WASM module
 *
 * ARCHITECTURE:
 *   This header defines the COMPLETE computation surface.
 *   The browser-side JS is ONLY a display layer that:
 *     1. Provides the WASI random_get import
 *     2. Calls these exported functions
 *     3. Reads result structs from WASM linear memory
 *     4. Sets textContent on DOM elements
 *
 *   ALL cryptographic generation, statistical testing, entropy
 *   proofs, and threat assessment runs inside the WASM sandbox.
 *
 * BUILD:
 *   Compiled against jedisct1/openssl-wasm (submodule) with Zig.
 *   See Makefile for targets.
 */

#ifndef PARANOID_H
#define PARANOID_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ═══════════════════════════════════════════════════════════
   VERSION & BUILD INFO
   ═══════════════════════════════════════════════════════════ */

#define PARANOID_VERSION_MAJOR 2
#define PARANOID_VERSION_MINOR 0
#define PARANOID_VERSION_PATCH 0
#define PARANOID_VERSION_STRING "2.0.0"

/** Return version string. */
const char* paranoid_version(void);

/* ═══════════════════════════════════════════════════════════
   PASSWORD GENERATION
   
   Uses OpenSSL RAND_bytes() → WASI random_get → browser CSPRNG.
   Rejection sampling ensures uniform distribution over charset.
   Raw random bytes are scrubbed from stack after use.
   ═══════════════════════════════════════════════════════════ */

#define PARANOID_MAX_PASSWORD_LEN 256
#define PARANOID_MAX_CHARSET_LEN  128
#define PARANOID_MAX_BATCH_SIZE   2000

/**
 * Generate a single password.
 *
 * @param charset     Charset string (null-terminated)
 * @param charset_len Length of charset (redundant but defensive)
 * @param length      Desired password length (1..MAX_PASSWORD_LEN)
 * @param output      Output buffer (must be length+1 bytes)
 * @return            0 on success, -1 on CSPRNG failure, -2 on invalid args
 */
int paranoid_generate(
    const char *charset,
    int charset_len,
    int length,
    char *output
);

/* ═══════════════════════════════════════════════════════════
   BATCH GENERATION + STATISTICAL AUDIT
   
   Generates N passwords and runs the full statistical suite
   in a single call. Results are written to a struct in WASM
   memory that JS reads field-by-field.
   ═══════════════════════════════════════════════════════════ */

/** Result of running the full audit suite. */
typedef struct {
    /* Generation */
    char     password[PARANOID_MAX_PASSWORD_LEN + 1];
    char     sha256_hex[65];
    int      password_length;
    int      charset_size;

    /* Chi-squared uniformity test */
    double   chi2_statistic;
    int      chi2_df;
    double   chi2_p_value;
    int      chi2_pass;           /* 1 if p > 0.01 */

    /* Serial correlation */
    double   serial_correlation;
    int      serial_pass;         /* 1 if |r| < 0.05 */

    /* Collision check */
    int      batch_size;
    int      duplicates;
    int      collision_pass;      /* 1 if 0 duplicates */

    /* Entropy proof */
    double   bits_per_char;
    double   total_entropy;
    double   log10_search_space;
    double   brute_force_years;   /* at 1e12 hash/s */

    /* NIST compliance */
    int      nist_memorized;      /* 1 if >= 30 bits */
    int      nist_high_value;     /* 1 if >= 80 bits */
    int      nist_crypto_equiv;   /* 1 if >= 128 bits */
    int      nist_post_quantum;   /* 1 if >= 256 bits */

    /* Uniqueness (birthday paradox) */
    double   collision_probability;
    double   passwords_for_50pct;

    /* Rejection sampling audit */
    int      rejection_max_valid;
    double   rejection_rate_pct;

    /* Pattern check */
    int      pattern_issues;      /* count of detected weak patterns */

    /* Overall */
    int      all_pass;            /* 1 if every test passed */

    /* Stage tracking (JS polls this) */
    int      current_stage;       /* 0=idle, 1=gen, 2=chi2, ... 7=done */

} paranoid_audit_result_t;

/**
 * Run the complete 7-layer audit.
 *
 * This is the main entry point. It:
 *   1. Generates a password via CSPRNG + rejection sampling
 *   2. Generates a batch of passwords for statistical testing
 *   3. Runs chi-squared uniformity test
 *   4. Runs serial correlation test
 *   5. Runs collision detection
 *   6. Computes entropy proof + NIST compliance
 *   7. Computes uniqueness proof (birthday paradox)
 *   8. Checks for weak patterns
 *   9. Fills the result struct
 *
 * The `current_stage` field is updated as each stage completes,
 * allowing JS to poll and update the UI progressively.
 *
 * @param charset     Charset string
 * @param charset_len Charset length
 * @param pw_length   Desired password length
 * @param batch_size  Number of passwords for statistical tests
 * @param result      Pointer to result struct (in WASM memory)
 * @return            0 on success, negative on error
 */
int paranoid_run_audit(
    const char *charset,
    int charset_len,
    int pw_length,
    int batch_size,
    paranoid_audit_result_t *result
);

/**
 * Get a pointer to a statically-allocated result struct.
 * JS calls this once to get the address, then reads fields
 * after paranoid_run_audit() completes.
 *
 * @return Pointer to the global result struct.
 */
paranoid_audit_result_t* paranoid_get_result_ptr(void);

/**
 * Get the size of the result struct (for JS to know bounds).
 */
int paranoid_get_result_size(void);

/**
 * Runtime struct layout verification.
 * JS calls these at init to confirm its hardcoded offsets match
 * the compiler's actual struct layout. Mismatch = refuse to run.
 */
int paranoid_offset_password_length(void);
int paranoid_offset_chi2_statistic(void);
int paranoid_offset_current_stage(void);
int paranoid_offset_all_pass(void);

/* ═══════════════════════════════════════════════════════════
   HASHING
   ═══════════════════════════════════════════════════════════ */

/**
 * SHA-256 hash via OpenSSL EVP.
 *
 * @param input      Input bytes
 * @param input_len  Length of input
 * @param output     32-byte output buffer
 * @return           0 on success
 */
int paranoid_sha256(
    const unsigned char *input,
    int input_len,
    unsigned char *output
);

/**
 * SHA-256 hash, output as hex string.
 *
 * @param input      Input string (null-terminated)
 * @param output_hex 65-byte output buffer (64 hex chars + null)
 * @return           0 on success
 */
int paranoid_sha256_hex(
    const char *input,
    char *output_hex
);

/* ═══════════════════════════════════════════════════════════
   INDIVIDUAL STATISTICAL TESTS (for testing/debugging)
   ═══════════════════════════════════════════════════════════ */

/** Chi-squared test on a set of passwords. */
double paranoid_chi_squared(
    const char *passwords,  /* concatenated, each pw_length chars */
    int num_passwords,
    int pw_length,
    const char *charset,
    int charset_len,
    int *out_df,
    double *out_p_value
);

/** Serial correlation on concatenated password bytes. */
double paranoid_serial_correlation(
    const char *passwords,
    int total_chars
);

/** Count duplicate passwords in a batch. */
int paranoid_count_collisions(
    const char *passwords,  /* concatenated */
    int num_passwords,
    int pw_length
);

#ifdef __cplusplus
}
#endif

#endif /* PARANOID_H */
