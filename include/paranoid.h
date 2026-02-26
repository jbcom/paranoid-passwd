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
 *   Uses a platform abstraction layer (paranoid_platform.h) that
 *   delegates to OpenSSL (native) or WASI+compact-SHA (WASM).
 *   See src/platform_native.c and src/platform_wasm.c for backends.
 *
 * TODO: HUMAN_REVIEW - replaced OpenSSL with platform abstraction references
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

/* TODO: HUMAN_REVIEW - version bumped from 2.0.0 to 3.0.0 for
 * platform abstraction + new API additions (F1-F5). */
#define PARANOID_VERSION_MAJOR 3
#define PARANOID_VERSION_MINOR 0
#define PARANOID_VERSION_PATCH 0
#define PARANOID_VERSION_STRING "3.0.0"

/** Return version string. */
const char* paranoid_version(void);

/* ═══════════════════════════════════════════════════════════
   PASSWORD GENERATION

   Uses platform abstraction (paranoid_platform_random) which
   delegates to OpenSSL RAND_bytes (native) or WASI random_get
   (WASM) → browser CSPRNG.
   Rejection sampling ensures uniform distribution over charset.
   Raw random bytes are scrubbed from stack after use.

   TODO: HUMAN_REVIEW - replaced OpenSSL with platform abstraction
   ═══════════════════════════════════════════════════════════ */

#define PARANOID_MAX_PASSWORD_LEN 256
#define PARANOID_MAX_CHARSET_LEN  128
#define PARANOID_MAX_BATCH_SIZE   2000
#define PARANOID_MAX_MULTI_COUNT  10     /* F1: max passwords per generate_multiple call */
#define PARANOID_MAX_CONSTRAINED_ATTEMPTS 100  /* F3: max rejection sampling attempts */

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

    /* ── New v3.0 fields (F5) ── */
    /* TODO: HUMAN_REVIEW - new fields added at END of struct for
     * binary compatibility with existing code reading earlier fields. */

    /* Multi-password support */
    int      num_passwords;        /* how many passwords were generated */

    /* Compliance results (one per framework) */
    /* TODO: HUMAN_REVIEW - verify compliance thresholds against current standards */
    int      compliance_nist;      /* 1=compliant, 0=not */
    int      compliance_pci_dss;
    int      compliance_hipaa;
    int      compliance_soc2;
    int      compliance_gdpr;
    int      compliance_iso27001;

    /* Character composition of generated password */
    int      count_lowercase;
    int      count_uppercase;
    int      count_digits;
    int      count_symbols;

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
 * SHA-256 hash via platform abstraction.
 * Native: delegates to OpenSSL EVP SHA-256
 * WASM:   delegates to compact FIPS 180-4 implementation
 *
 * TODO: HUMAN_REVIEW - replaced OpenSSL with platform abstraction
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

/* ═══════════════════════════════════════════════════════════
   F1: MULTI-PASSWORD GENERATION
   ═══════════════════════════════════════════════════════════ */

/**
 * Generate multiple passwords in one call.
 *
 * TODO: HUMAN_REVIEW - new API, verify input validation
 *
 * @param charset      Charset string
 * @param charset_len  Charset length
 * @param length       Password length per password
 * @param count        Number of passwords to generate (1..PARANOID_MAX_MULTI_COUNT)
 * @param output       Output buffer (must be count * (length+1) bytes)
 * @return             0 on success, -1 on CSPRNG failure, -2 on invalid args
 */
int paranoid_generate_multiple(
    const char *charset,
    int charset_len,
    int length,
    int count,
    char *output
);

/* ═══════════════════════════════════════════════════════════
   F2: CHARSET VALIDATION
   ═══════════════════════════════════════════════════════════ */

/**
 * Validate and normalize a custom charset string.
 * Removes duplicates, validates all chars are printable ASCII (32-126).
 * Output is sorted by ASCII value, deduplicated.
 *
 * TODO: HUMAN_REVIEW - verify printable ASCII range
 *
 * @param input        Raw charset string from user (null-terminated)
 * @param output       Normalized output buffer (deduplicated, sorted)
 * @param output_size  Size of output buffer (must be >= unique chars + 1)
 * @return             Length of normalized charset, or -1 on error
 */
int paranoid_validate_charset(
    const char *input,
    char *output,
    int output_size
);

/* ═══════════════════════════════════════════════════════════
   F3: CONSTRAINED PASSWORD GENERATION
   ═══════════════════════════════════════════════════════════ */

/**
 * Minimum character-type requirements for constrained generation.
 * Set a field to 0 to impose no requirement for that type.
 */
typedef struct {
    int min_lowercase;    /* minimum [a-z] chars, 0 = no requirement */
    int min_uppercase;    /* minimum [A-Z] chars */
    int min_digits;       /* minimum [0-9] chars */
    int min_symbols;      /* minimum non-alphanumeric chars */
} paranoid_char_requirements_t;

/**
 * Generate a password meeting minimum character-type requirements.
 * Uses rejection sampling: generates via paranoid_generate(), then
 * checks requirements. Regenerates if not met (max PARANOID_MAX_CONSTRAINED_ATTEMPTS).
 *
 * TODO: HUMAN_REVIEW - verify rejection sampling preserves uniform
 * distribution over the valid subset of passwords.
 *
 * @param charset      Charset string
 * @param charset_len  Charset length
 * @param length       Password length
 * @param reqs         Character-type requirements
 * @param output       Output buffer (must be length+1 bytes)
 * @return 0 on success, -1 on CSPRNG failure, -2 on invalid args,
 *         -3 if requirements impossible, -4 if exhausted attempts
 */
int paranoid_generate_constrained(
    const char *charset,
    int charset_len,
    int length,
    const paranoid_char_requirements_t *reqs,
    char *output
);

/* ═══════════════════════════════════════════════════════════
   F4: COMPLIANCE FRAMEWORK THRESHOLDS

   TODO: HUMAN_REVIEW - verify compliance thresholds against
   current standards. Standards are updated periodically.
   ═══════════════════════════════════════════════════════════ */

/**
 * Compliance framework threshold definition.
 * Each framework specifies minimum requirements that a password
 * must meet to be considered compliant.
 */
typedef struct {
    const char *name;           /* e.g. "NIST SP 800-63B" */
    const char *description;    /* e.g. "US federal standard for digital identity" */
    int min_length;             /* minimum password length */
    double min_entropy_bits;    /* minimum entropy in bits */
    int require_mixed_case;     /* 1 if mixed case required */
    int require_digits;         /* 1 if digits required */
    int require_symbols;        /* 1 if symbols required */
} paranoid_compliance_framework_t;

/* Built-in framework definitions
 * TODO: HUMAN_REVIEW - verify compliance thresholds against current standards */
extern const paranoid_compliance_framework_t PARANOID_COMPLIANCE_NIST;
extern const paranoid_compliance_framework_t PARANOID_COMPLIANCE_PCI_DSS;
extern const paranoid_compliance_framework_t PARANOID_COMPLIANCE_HIPAA;
extern const paranoid_compliance_framework_t PARANOID_COMPLIANCE_SOC2;
extern const paranoid_compliance_framework_t PARANOID_COMPLIANCE_GDPR;
extern const paranoid_compliance_framework_t PARANOID_COMPLIANCE_ISO27001;

/**
 * Check if audit result meets a compliance framework.
 *
 * Checks password_length, total_entropy, and character composition
 * against the framework's thresholds.
 *
 * TODO: HUMAN_REVIEW - verify compliance check logic
 *
 * @param result     Audit result (must have character counts populated)
 * @param framework  Compliance framework to check against
 * @return           1 if compliant, 0 if not
 */
int paranoid_check_compliance(
    const paranoid_audit_result_t *result,
    const paranoid_compliance_framework_t *framework
);

#ifdef __cplusplus
}
#endif

#endif /* PARANOID_H */
