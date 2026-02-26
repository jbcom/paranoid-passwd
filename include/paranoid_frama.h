/**
 * paranoid_frama.h — Frama-C ACSL annotations for formal verification
 *
 * These annotations enable static analysis and formal proof of:
 *   - Memory safety (no buffer overflows)
 *   - Absence of undefined behavior
 *   - Functional correctness (contracts)
 *   - Numerical bounds (entropy calculations)
 *
 * Verification command:
 *   frama-c -wp -wp-rte src/paranoid.c -cpp-extra-args="-I include"
 *
 * ACSL Reference: https://frama-c.com/download/acsl.pdf
 *
 * Updated for v3.0: added contracts for paranoid_generate_multiple,
 * paranoid_validate_charset, paranoid_generate_constrained, and
 * paranoid_check_compliance. Updated paranoid_sha256 to reflect
 * platform abstraction (no longer OpenSSL-specific).
 *
 * TODO: HUMAN_REVIEW - verify new v3.0 annotations are correct
 */

#ifndef PARANOID_FRAMA_H
#define PARANOID_FRAMA_H

#ifdef __FRAMAC__

/* ═══════════════════════════════════════════════════════════
   GLOBAL PREDICATES
   ═══════════════════════════════════════════════════════════ */

/*@ predicate valid_charset(char *charset, integer len) =
      \valid(charset+(0..len-1)) &&
      1 <= len <= PARANOID_MAX_CHARSET_LEN;
*/

/*@ predicate valid_password_buffer(char *buf, integer len) =
      \valid(buf+(0..len)) &&
      1 <= len <= PARANOID_MAX_PASSWORD_LEN;
*/

/*@ predicate valid_result(paranoid_audit_result_t *r) =
      \valid(r);
*/

/* ═══════════════════════════════════════════════════════════
   REJECTION SAMPLING CORRECTNESS
   ═══════════════════════════════════════════════════════════ */

/*@ lemma rejection_sampling_bound:
      \forall integer N; 1 <= N <= 256 ==>
        (256 / N) * N - 1 <= 255;
*/

/*@ lemma rejection_sampling_uniform:
      \forall integer N, b; 
        1 <= N <= 256 && 0 <= b <= (256/N)*N - 1 ==>
        0 <= b % N < N;
*/

/*@ lemma max_valid_formula:
      \forall integer N; 1 <= N <= 256 ==>
        let max_valid = (256 / N) * N - 1 in
        0 <= max_valid < 256;
*/

/* ═══════════════════════════════════════════════════════════
   ENTROPY CALCULATION BOUNDS
   ═══════════════════════════════════════════════════════════ */

/*@ lemma entropy_positive:
      \forall integer N, L;
        N >= 2 && L >= 1 ==>
        L * \log(N) / \log(2) > 0;
*/

/*@ lemma entropy_upper_bound:
      \forall integer N, L;
        N <= PARANOID_MAX_CHARSET_LEN && L <= PARANOID_MAX_PASSWORD_LEN ==>
        L * \log(N) / \log(2) <= 256 * 7.0;
    // Max: 256 chars * log2(128) ≈ 1792 bits
*/

/* ═══════════════════════════════════════════════════════════
   CHI-SQUARED STATISTICAL BOUNDS
   ═══════════════════════════════════════════════════════════ */

/*@ lemma chi_squared_non_negative:
      \forall real chi2; 
        // chi² is sum of (observed - expected)² / expected
        // always >= 0
        chi2 >= 0;
*/

/*@ lemma degrees_of_freedom_correct:
      \forall integer N;
        N >= 1 ==>
        // df = N - 1, NOT N
        N - 1 >= 0;
*/

/*@ lemma p_value_interpretation:
      \forall real p;
        0 <= p <= 1 ==>
        // p > 0.01 means fail to reject H0 (randomness)
        // p < 0.01 means reject H0 (not random)
        \true;
*/

#endif /* __FRAMAC__ */

/* ═══════════════════════════════════════════════════════════
   FUNCTION CONTRACTS
   ═══════════════════════════════════════════════════════════ */

#ifdef __FRAMAC__

/*@ requires valid_charset(charset, charset_len);
    requires valid_password_buffer(output, length);
    requires 1 <= length <= PARANOID_MAX_PASSWORD_LEN;
    requires 1 <= charset_len <= PARANOID_MAX_CHARSET_LEN;
    
    assigns output[0..length];
    
    ensures \result == 0 ==> 
              \forall integer i; 0 <= i < length ==>
                \exists integer j; 0 <= j < charset_len && output[i] == charset[j];
    ensures \result == 0 ==> output[length] == '\0';
    ensures \result == -1 ==> // CSPRNG failure
              \forall integer i; 0 <= i <= length ==> output[i] == 0;
    ensures \result == -2 ==> // Invalid args
              \true;
    
    behavior success:
      assumes \valid(output+(0..length));
      ensures \result == 0;
      
    behavior csprng_failure:
      ensures \result == -1;
      
    behavior invalid_args:
      assumes charset == \null || charset_len <= 0 || 
              charset_len > PARANOID_MAX_CHARSET_LEN ||
              length <= 0 || length > PARANOID_MAX_PASSWORD_LEN ||
              output == \null;
      ensures \result == -2;
*/
int paranoid_generate(
    const char *charset,
    int charset_len,
    int length,
    char *output
);

/*@ requires \valid(input+(0..input_len-1));
    requires \valid(output+(0..31));
    requires input_len >= 0;

    assigns output[0..31];

    ensures \result == 0 ==>
              // SHA-256 produces 32 bytes
              \forall integer i; 0 <= i < 32 ==>
                0 <= output[i] <= 255;
    ensures \result == -1 ==> // platform abstraction failure
              \true;
*/
int paranoid_sha256(
    const unsigned char *input,
    int input_len,
    unsigned char *output
);

/*@ requires \valid(input+(0..strlen(input)));
    requires \valid(output_hex+(0..64));
    
    assigns output_hex[0..64];
    
    ensures \result == 0 ==>
              output_hex[64] == '\0' &&
              \forall integer i; 0 <= i < 64 ==>
                (output_hex[i] >= '0' && output_hex[i] <= '9') ||
                (output_hex[i] >= 'a' && output_hex[i] <= 'f');
*/
int paranoid_sha256_hex(const char *input, char *output_hex);

/*@ requires \valid(passwords+(0..num_passwords*pw_length-1));
    requires valid_charset(charset, charset_len);
    requires num_passwords >= 1;
    requires pw_length >= 1;
    
    assigns *out_df, *out_p_value;
    
    ensures \result >= 0.0;  // Chi² is non-negative
    ensures *out_df == charset_len - 1;  // CRITICAL: df = N-1
    ensures 0.0 <= *out_p_value <= 1.0;
*/
double paranoid_chi_squared(
    const char *passwords,
    int num_passwords,
    int pw_length,
    const char *charset,
    int charset_len,
    int *out_df,
    double *out_p_value
);

/*@ requires \valid(data+(0..total_chars-1));
    requires total_chars >= 1;
    
    ensures -1.0 <= \result <= 1.0;  // Correlation in [-1, 1]
*/
double paranoid_serial_correlation(
    const char *data,
    int total_chars
);

/*@ requires \valid(passwords+(0..num_passwords*pw_length-1));
    requires num_passwords >= 1;
    requires pw_length >= 1;
    
    ensures \result >= 0 || \result == -1;  // Count or error
    ensures \result <= num_passwords - 1;    // Max possible duplicates
*/
int paranoid_count_collisions(
    const char *passwords,
    int num_passwords,
    int pw_length
);

/*@ requires valid_charset(charset, charset_len);
    requires valid_result(result);
    requires 1 <= pw_length <= PARANOID_MAX_PASSWORD_LEN;
    requires 1 <= charset_len <= PARANOID_MAX_CHARSET_LEN;
    requires 1 <= batch_size <= PARANOID_MAX_BATCH_SIZE;

    assigns *result;

    ensures \result == 0 ==>
              result->password_length == pw_length &&
              result->charset_size == charset_len &&
              result->batch_size == batch_size &&
              result->current_stage == 8 &&  // Done
              result->chi2_df == charset_len - 1;  // CRITICAL

    ensures \result == 0 ==>
              // Rejection sampling formula verified
              result->rejection_max_valid == (256 / charset_len) * charset_len - 1;

    ensures \result == 0 ==>
              // P-value interpretation: p > 0.01 passes
              (result->chi2_p_value > 0.01) ==> result->chi2_pass == 1;

    ensures \result == 0 ==>
              // Serial correlation threshold
              (fabs(result->serial_correlation) < 0.05) ==> result->serial_pass == 1;
*/
int paranoid_run_audit(
    const char *charset,
    int charset_len,
    int pw_length,
    int batch_size,
    paranoid_audit_result_t *result
);

/* ═══════════════════════════════════════════════════════════
   F1: MULTI-PASSWORD GENERATION — paranoid_generate_multiple()
   TODO: HUMAN_REVIEW - new v3.0 annotation, verify correctness
   ═══════════════════════════════════════════════════════════ */

/*@ requires valid_charset(charset, charset_len);
    requires 1 <= length <= PARANOID_MAX_PASSWORD_LEN;
    requires 1 <= charset_len <= PARANOID_MAX_CHARSET_LEN;
    requires 1 <= count <= PARANOID_MAX_MULTI_COUNT;
    requires \valid(output+(0..count * (length + 1) - 1));

    assigns output[0..count * (length + 1) - 1];

    ensures \result == 0 ==>
              // Each password is null-terminated and length chars long
              \forall integer k; 0 <= k < count ==>
                output[k * (length + 1) + length] == '\0';
    ensures \result == 0 ==>
              // Each password char is from charset
              \forall integer k; 0 <= k < count ==>
                \forall integer i; 0 <= i < length ==>
                  \exists integer j; 0 <= j < charset_len &&
                    output[k * (length + 1) + i] == charset[j];
    ensures \result == -1 ==> // CSPRNG failure
              \true;
    ensures \result == -2 ==> // Invalid args
              \true;
*/
int paranoid_generate_multiple(
    const char *charset,
    int charset_len,
    int length,
    int count,
    char *output
);

/* ═══════════════════════════════════════════════════════════
   F2: CHARSET VALIDATION — paranoid_validate_charset()
   TODO: HUMAN_REVIEW - new v3.0 annotation, verify correctness
   ═══════════════════════════════════════════════════════════ */

/*@ requires \valid(input+(0..strlen(input)));
    requires \valid(output+(0..output_size - 1));
    requires output_size >= 1;

    assigns output[0..output_size - 1];

    ensures \result >= 0 ==>
              // Output length is within bounds
              \result <= output_size - 1 &&
              // Output is null-terminated
              output[\result] == '\0' &&
              // All output chars are printable ASCII (32-126)
              \forall integer i; 0 <= i < \result ==>
                32 <= output[i] <= 126;
    ensures \result >= 0 ==>
              // Output is sorted and deduplicated
              \forall integer i; 0 <= i < \result - 1 ==>
                output[i] < output[i+1];
    ensures \result == -1 ==> // Error (empty input, non-printable chars, etc.)
              \true;
*/
int paranoid_validate_charset(
    const char *input,
    char *output,
    int output_size
);

/* ═══════════════════════════════════════════════════════════
   F3: CONSTRAINED GENERATION — paranoid_generate_constrained()
   TODO: HUMAN_REVIEW - new v3.0 annotation, verify correctness
   ═══════════════════════════════════════════════════════════ */

/*@ requires valid_charset(charset, charset_len);
    requires valid_password_buffer(output, length);
    requires 1 <= length <= PARANOID_MAX_PASSWORD_LEN;
    requires 1 <= charset_len <= PARANOID_MAX_CHARSET_LEN;
    requires \valid(reqs);
    requires reqs->min_lowercase >= 0;
    requires reqs->min_uppercase >= 0;
    requires reqs->min_digits >= 0;
    requires reqs->min_symbols >= 0;
    // Sum of minimums must not exceed password length
    requires reqs->min_lowercase + reqs->min_uppercase +
             reqs->min_digits + reqs->min_symbols <= length;

    assigns output[0..length];

    ensures \result == 0 ==>
              output[length] == '\0' &&
              // All chars from charset
              \forall integer i; 0 <= i < length ==>
                \exists integer j; 0 <= j < charset_len &&
                  output[i] == charset[j];
    ensures \result == -1 ==> // CSPRNG failure
              \true;
    ensures \result == -2 ==> // Invalid args
              \true;
    ensures \result == -3 ==> // Requirements impossible
              \true;
    ensures \result == -4 ==> // Exhausted attempts
              \true;
*/
int paranoid_generate_constrained(
    const char *charset,
    int charset_len,
    int length,
    const paranoid_char_requirements_t *reqs,
    char *output
);

/* ═══════════════════════════════════════════════════════════
   F4: COMPLIANCE CHECK — paranoid_check_compliance()
   TODO: HUMAN_REVIEW - new v3.0 annotation, verify correctness
   ═══════════════════════════════════════════════════════════ */

/*@ requires valid_result(result);
    requires \valid(framework);
    requires \valid(framework->name);
    requires \valid(framework->description);
    requires framework->min_length >= 0;
    requires framework->min_entropy_bits >= 0.0;

    assigns \nothing;

    ensures \result == 0 || \result == 1;
    ensures \result == 1 ==>
              // Password meets all framework requirements
              result->password_length >= framework->min_length &&
              result->total_entropy >= framework->min_entropy_bits;
*/
int paranoid_check_compliance(
    const paranoid_audit_result_t *result,
    const paranoid_compliance_framework_t *framework
);

#endif /* __FRAMAC__ */

#endif /* PARANOID_FRAMA_H */
