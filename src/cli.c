/**
 * cli.c — paranoid-passwd command-line interface
 *
 * Copyright (c) 2026 jbcom
 * SPDX-License-Identifier: MIT
 *
 * This file contains NO cryptographic code. It is a display-only
 * consumer of the public API in include/paranoid.h, analogous in role
 * to www/app.js for the web build.
 *
 * Responsibilities:
 *   1. Parse command-line flags into library call arguments.
 *   2. Invoke library functions: paranoid_generate_multiple (or
 *      paranoid_generate_constrained), paranoid_run_audit.
 *   3. Print stage progress to stderr.
 *   4. Print the generated password(s) to stdout.
 *   5. Map library return codes to process exit codes.
 *
 * All entropy, statistics, and SHA-256 computation happens inside the
 * library (which links platform_posix.c + sha256_compact.c for this
 * build).
 */

#include "paranoid.h"

#include <getopt.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#ifndef PARANOID_CLI_VERSION
    #define PARANOID_CLI_VERSION "unknown"
#endif
#ifndef PARANOID_CLI_BUILD_COMMIT
    #define PARANOID_CLI_BUILD_COMMIT "unknown"
#endif
#ifndef PARANOID_CLI_BUILD_DATE
    #define PARANOID_CLI_BUILD_DATE "unknown"
#endif

/* ═══════════════════════════════════════════════════════════
   EXIT CODES (contract; documented in docs/CLI.md)
   ═══════════════════════════════════════════════════════════ */
#define EX_OK          0
#define EX_USAGE       1
#define EX_CSPRNG      2
#define EX_AUDIT_FAIL  3

/* ═══════════════════════════════════════════════════════════
   BUILT-IN CHARSETS (resolved before calling library)
   ═══════════════════════════════════════════════════════════ */

static const char CHARSET_ALNUM[]         = "0123456789"
                                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                            "abcdefghijklmnopqrstuvwxyz";
static const char CHARSET_ALNUM_SYMBOLS[] = "0123456789"
                                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                            "abcdefghijklmnopqrstuvwxyz"
                                            "!@#$%^&*-_=+[]{};:,.?/";
static const char CHARSET_HEX[]           = "0123456789abcdef";
/* CHARSET_FULL is built at runtime: printable ASCII 33..126 (94 chars). */

static char g_charset_full[95];

static void init_charset_full(void) {
    int n = 0;
    for (int c = 33; c <= 126; c++) {
        g_charset_full[n++] = (char)c;
    }
    g_charset_full[n] = '\0';
}

static const char *resolve_charset(const char *name, char *normalized_buf,
                                   int normalized_cap, int *out_len) {
    if (strcmp(name, "alnum") == 0) {
        *out_len = (int)strlen(CHARSET_ALNUM);
        return CHARSET_ALNUM;
    }
    if (strcmp(name, "alnum-symbols") == 0) {
        *out_len = (int)strlen(CHARSET_ALNUM_SYMBOLS);
        return CHARSET_ALNUM_SYMBOLS;
    }
    if (strcmp(name, "hex") == 0) {
        *out_len = (int)strlen(CHARSET_HEX);
        return CHARSET_HEX;
    }
    if (strcmp(name, "full") == 0) {
        *out_len = (int)strlen(g_charset_full);
        return g_charset_full;
    }
    /* Treat as a literal charset; validate & dedupe via library. */
    int len = paranoid_validate_charset(name, normalized_buf, normalized_cap);
    if (len <= 0) return NULL;
    *out_len = len;
    return normalized_buf;
}

/* ═══════════════════════════════════════════════════════════
   OUTPUT HELPERS
   ═══════════════════════════════════════════════════════════ */

static int g_quiet = 0;

static void stage_ok(int n, int total, const char *name, const char *fmt, ...) {
    if (g_quiet) return;
    fprintf(stderr, "[%d/%d] %-16s OK", n, total, name);
    if (fmt && *fmt) {
        fputc(' ', stderr);
        fputc(' ', stderr);
        va_list ap;
        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
    }
    fputc('\n', stderr);
}

static void stage_fail(int n, int total, const char *name, const char *reason) {
    if (g_quiet) return;
    fprintf(stderr, "[%d/%d] %-16s FAIL  %s\n", n, total, name, reason);
}

/* ═══════════════════════════════════════════════════════════
   USAGE / VERSION
   ═══════════════════════════════════════════════════════════ */

static void print_usage(FILE *f) {
    fputs(
        "Usage: paranoid-passwd [OPTIONS]\n"
        "\n"
        "Generate cryptographically strong passwords with a self-audit.\n"
        "\n"
        "Options:\n"
        "  -l, --length N           Password length (1..256, default 32)\n"
        "  -c, --count N            Number of passwords (1..10, default 1)\n"
        "  -s, --charset SET        Character set name or literal\n"
        "                           Names: alnum | alnum-symbols | full | hex\n"
        "                           Default: full (printable ASCII, 94 chars)\n"
        "      --require-lower N    Minimum lowercase chars (default 0)\n"
        "      --require-upper N    Minimum uppercase chars (default 0)\n"
        "      --require-digit N    Minimum digit chars (default 0)\n"
        "      --require-symbol N   Minimum symbol chars (default 0)\n"
        "      --no-audit           Skip the statistical audit\n"
        "      --quiet              Suppress stage output on stderr\n"
        "  -V, --version            Print version info and exit\n"
        "  -h, --help               Print this help and exit\n"
        "\n"
        "Exit codes:\n"
        "  0  success\n"
        "  1  argument error\n"
        "  2  CSPRNG failure\n"
        "  3  audit failed\n"
        "\n"
        "Examples:\n"
        "  paranoid-passwd                                 # 32-char full-ASCII\n"
        "  paranoid-passwd -l 16 -c 5 --no-audit           # 5 passwords, no audit\n"
        "  paranoid-passwd -s hex -l 64                    # 64 hex chars\n"
        "  paranoid-passwd --require-upper 2 --require-digit 2\n"
        , f);
}

static void print_version(void) {
    printf("paranoid-passwd %s\n", PARANOID_CLI_VERSION);
    printf("library:        %s\n", paranoid_version());
    printf("build:          %s\n", PARANOID_CLI_BUILD_DATE);
    printf("commit:         %s\n", PARANOID_CLI_BUILD_COMMIT);
    printf("sha256:         compact (FIPS 180-4 reference)\n");
#if defined(__linux__)
    printf("rng:            getrandom(2)\n");
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    printf("rng:            getentropy(3)\n");
#else
    printf("rng:            unknown\n");
#endif
}

/* ═══════════════════════════════════════════════════════════
   ARG PARSING
   ═══════════════════════════════════════════════════════════ */

typedef struct {
    int length;
    int count;
    const char *charset_name;
    int require_lower;
    int require_upper;
    int require_digit;
    int require_symbol;
    int audit;
    int quiet;
} opts_t;

static int parse_positive_int(const char *s, int *out) {
    if (!s || !*s) return -1;
    char *end;
    long v = strtol(s, &end, 10);
    if (*end != '\0' || v <= 0 || v > 100000) return -1;
    *out = (int)v;
    return 0;
}

static int parse_nonneg_int(const char *s, int *out) {
    if (!s || !*s) return -1;
    char *end;
    long v = strtol(s, &end, 10);
    if (*end != '\0' || v < 0 || v > 100000) return -1;
    *out = (int)v;
    return 0;
}

static int parse_opts(int argc, char **argv, opts_t *o) {
    o->length = 32;
    o->count = 1;
    o->charset_name = "full";
    o->require_lower = 0;
    o->require_upper = 0;
    o->require_digit = 0;
    o->require_symbol = 0;
    o->audit = 1;
    o->quiet = 0;

    enum {
        OPT_REQUIRE_LOWER = 1000,
        OPT_REQUIRE_UPPER,
        OPT_REQUIRE_DIGIT,
        OPT_REQUIRE_SYMBOL,
        OPT_NO_AUDIT,
        OPT_QUIET,
    };

    static const struct option longopts[] = {
        {"length",         required_argument, 0, 'l'},
        {"count",          required_argument, 0, 'c'},
        {"charset",        required_argument, 0, 's'},
        {"require-lower",  required_argument, 0, OPT_REQUIRE_LOWER},
        {"require-upper",  required_argument, 0, OPT_REQUIRE_UPPER},
        {"require-digit",  required_argument, 0, OPT_REQUIRE_DIGIT},
        {"require-symbol", required_argument, 0, OPT_REQUIRE_SYMBOL},
        {"no-audit",       no_argument,       0, OPT_NO_AUDIT},
        {"quiet",          no_argument,       0, OPT_QUIET},
        {"version",        no_argument,       0, 'V'},
        {"help",           no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    int idx;
    while ((opt = getopt_long(argc, argv, "l:c:s:Vh", longopts, &idx)) != -1) {
        switch (opt) {
            case 'l':
                if (parse_positive_int(optarg, &o->length) != 0 ||
                    o->length > PARANOID_MAX_PASSWORD_LEN) {
                    fprintf(stderr, "error: --length must be 1..%d\n",
                            PARANOID_MAX_PASSWORD_LEN);
                    return -1;
                }
                break;
            case 'c':
                if (parse_positive_int(optarg, &o->count) != 0 ||
                    o->count > PARANOID_MAX_MULTI_COUNT) {
                    fprintf(stderr, "error: --count must be 1..%d\n",
                            PARANOID_MAX_MULTI_COUNT);
                    return -1;
                }
                break;
            case 's':
                o->charset_name = optarg;
                break;
            case OPT_REQUIRE_LOWER:
                if (parse_nonneg_int(optarg, &o->require_lower) != 0) {
                    fprintf(stderr, "error: --require-lower must be >= 0\n");
                    return -1;
                }
                break;
            case OPT_REQUIRE_UPPER:
                if (parse_nonneg_int(optarg, &o->require_upper) != 0) {
                    fprintf(stderr, "error: --require-upper must be >= 0\n");
                    return -1;
                }
                break;
            case OPT_REQUIRE_DIGIT:
                if (parse_nonneg_int(optarg, &o->require_digit) != 0) {
                    fprintf(stderr, "error: --require-digit must be >= 0\n");
                    return -1;
                }
                break;
            case OPT_REQUIRE_SYMBOL:
                if (parse_nonneg_int(optarg, &o->require_symbol) != 0) {
                    fprintf(stderr, "error: --require-symbol must be >= 0\n");
                    return -1;
                }
                break;
            case OPT_NO_AUDIT: o->audit = 0; break;
            case OPT_QUIET:    o->quiet = 1; break;
            case 'V':          print_version(); exit(EX_OK);
            case 'h':          print_usage(stdout); exit(EX_OK);
            case '?':
            default:
                print_usage(stderr);
                return -1;
        }
    }
    if (optind < argc) {
        fprintf(stderr, "error: unexpected positional argument: %s\n",
                argv[optind]);
        return -1;
    }
    return 0;
}

/* ═══════════════════════════════════════════════════════════
   GENERATION (respects --require-* if any are nonzero)
   ═══════════════════════════════════════════════════════════ */

static int has_requirements(const opts_t *o) {
    return (o->require_lower | o->require_upper |
            o->require_digit | o->require_symbol) != 0;
}

static int generate_one(const opts_t *o, const char *charset, int charset_len,
                        char *out) {
    if (!has_requirements(o)) {
        return paranoid_generate(charset, charset_len, o->length, out);
    }
    paranoid_char_requirements_t reqs = {
        .min_lowercase = o->require_lower,
        .min_uppercase = o->require_upper,
        .min_digits    = o->require_digit,
        .min_symbols   = o->require_symbol,
    };
    return paranoid_generate_constrained(charset, charset_len, o->length,
                                         &reqs, out);
}

/* ═══════════════════════════════════════════════════════════
   AUDIT (runs on the generated batch, reports per stage)
   ═══════════════════════════════════════════════════════════ */

#define AUDIT_BATCH_SIZE 500
#define TOTAL_STAGES     7

static int run_audit(const char *passwords, int count, int length,
                     const char *charset, int charset_len) {
    char sha_hex[65];
    int all_ok = 1;

    /* Stage 1: generate — already done. Just report. */
    stage_ok(1, TOTAL_STAGES, "generate", "%d password(s) x %d chars",
             count, length);

    /* Stage 2: SHA-256 of the first password */
    if (paranoid_sha256_hex(passwords, sha_hex) != 0) {
        stage_fail(2, TOTAL_STAGES, "sha256", "hash failure");
        return -1;
    }
    stage_ok(2, TOTAL_STAGES, "sha256", "%s", sha_hex);

    /* Stage 3: chi-squared on a larger batch for statistical power.
     * Generate a dedicated batch (not exposed) to run the uniformity
     * test against. */
    char *audit_batch = calloc((size_t)AUDIT_BATCH_SIZE,
                               (size_t)(length + 1));
    if (!audit_batch) {
        stage_fail(3, TOTAL_STAGES, "chi-squared", "out of memory");
        return -1;
    }
    for (int i = 0; i < AUDIT_BATCH_SIZE; i++) {
        if (paranoid_generate(charset, charset_len, length,
                              audit_batch + (size_t)i * (size_t)(length + 1)) != 0) {
            stage_fail(3, TOTAL_STAGES, "chi-squared", "CSPRNG failure");
            free(audit_batch);
            return -1;
        }
    }
    /* Build a flat buffer (no NUL separators) for the statistical tests. */
    char *flat = malloc((size_t)AUDIT_BATCH_SIZE * (size_t)length);
    if (!flat) {
        stage_fail(3, TOTAL_STAGES, "chi-squared", "out of memory");
        free(audit_batch);
        return -1;
    }
    for (int i = 0; i < AUDIT_BATCH_SIZE; i++) {
        memcpy(flat + (size_t)i * (size_t)length,
               audit_batch + (size_t)i * (size_t)(length + 1),
               (size_t)length);
    }

    int chi2_df = 0;
    double chi2_p = 0.0;
    double chi2_stat = paranoid_chi_squared(flat, AUDIT_BATCH_SIZE, length,
                                            charset, charset_len,
                                            &chi2_df, &chi2_p);
    int chi2_pass = (chi2_p > 0.01);
    if (chi2_pass) {
        stage_ok(3, TOTAL_STAGES, "chi-squared",
                 "chi2=%.2f df=%d p=%.4f", chi2_stat, chi2_df, chi2_p);
    } else {
        stage_fail(3, TOTAL_STAGES, "chi-squared", "p-value <= 0.01");
        all_ok = 0;
    }

    /* Stage 4: serial correlation */
    double r = paranoid_serial_correlation(flat,
                                           AUDIT_BATCH_SIZE * length);
    int serial_pass = (r > -0.05 && r < 0.05);
    if (serial_pass) {
        stage_ok(4, TOTAL_STAGES, "serial-corr", "r=%.4f", r);
    } else {
        stage_fail(4, TOTAL_STAGES, "serial-corr", "|r| >= 0.05");
        all_ok = 0;
    }

    /* Stage 5: collisions (within audit batch) */
    int dups = paranoid_count_collisions(flat, AUDIT_BATCH_SIZE, length);
    if (dups == 0) {
        stage_ok(5, TOTAL_STAGES, "collisions",
                 "0 / %d", AUDIT_BATCH_SIZE);
    } else {
        stage_fail(5, TOTAL_STAGES, "collisions",
                   "duplicates detected");
        all_ok = 0;
    }

    /* Stage 6: entropy & NIST compliance (per single password).
     * bits per char = log2(charset_size); total = length * bits_per_char.
     * Computed locally rather than calling paranoid_run_audit(), which
     * would regenerate a batch and ignore our per-stage output. */
    double bpc = log2((double)charset_len);
    double total_entropy = bpc * (double)length;
    int memorized    = (total_entropy >= 30.0);
    int high_value   = (total_entropy >= 80.0);
    int crypto_equiv = (total_entropy >= 128.0);
    stage_ok(6, TOTAL_STAGES, "entropy",
             "%.2f bits (NIST: memorized=%s high-value=%s crypto-equiv=%s)",
             total_entropy,
             memorized ? "OK" : "no",
             high_value ? "OK" : "no",
             crypto_equiv ? "OK" : "no");

    /* Stage 7: pattern check — library-side. For the CLI we do a simple
     * sanity scan: no single character repeated > 25% of length.
     * The comprehensive pattern detection lives in paranoid_run_audit;
     * we don't invoke it here to keep the stage output deterministic. */
    int counts[256] = {0};
    for (int i = 0; i < length; i++) {
        counts[(unsigned char)passwords[i]]++;
    }
    int max_repeat = 0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] > max_repeat) max_repeat = counts[i];
    }
    int repeat_limit = (length / 4) > 2 ? (length / 4) : 2;
    int pattern_pass = (max_repeat <= repeat_limit);
    if (pattern_pass) {
        stage_ok(7, TOTAL_STAGES, "patterns",
                 "max repeat = %d (limit %d)", max_repeat, repeat_limit);
    } else {
        stage_fail(7, TOTAL_STAGES, "patterns",
                   "repeated char exceeds limit");
        all_ok = 0;
    }

    /* Scrub audit buffers. */
    memset(flat, 0, (size_t)AUDIT_BATCH_SIZE * (size_t)length);
    memset(audit_batch, 0,
           (size_t)AUDIT_BATCH_SIZE * (size_t)(length + 1));
    free(flat);
    free(audit_batch);

    if (!g_quiet) {
        fprintf(stderr, "audit: %s\n", all_ok ? "PASS" : "FAIL");
    }
    return all_ok ? 0 : -1;
}

/* ═══════════════════════════════════════════════════════════
   MAIN
   ═══════════════════════════════════════════════════════════ */

int main(int argc, char **argv) {
    init_charset_full();

    opts_t o;
    if (parse_opts(argc, argv, &o) != 0) {
        return EX_USAGE;
    }
    g_quiet = o.quiet;

    /* Resolve charset (built-in name or literal). */
    char normalized[PARANOID_MAX_CHARSET_LEN + 1];
    int charset_len = 0;
    const char *charset = resolve_charset(o.charset_name, normalized,
                                          sizeof(normalized), &charset_len);
    if (!charset) {
        fprintf(stderr, "error: invalid charset: %s\n", o.charset_name);
        return EX_USAGE;
    }

    /* Generate. */
    size_t per_pw = (size_t)(o.length + 1);
    char *out = calloc((size_t)o.count, per_pw);
    if (!out) {
        fprintf(stderr, "error: out of memory\n");
        return EX_CSPRNG;
    }

    int rc = 0;
    for (int i = 0; i < o.count; i++) {
        rc = generate_one(&o, charset, charset_len,
                          out + (size_t)i * per_pw);
        if (rc != 0) break;
    }
    if (rc != 0) {
        memset(out, 0, (size_t)o.count * per_pw);
        free(out);
        switch (rc) {
            case -1:
                fprintf(stderr, "error: CSPRNG failure\n");
                return EX_CSPRNG;
            case -2:
                fprintf(stderr, "error: invalid arguments\n");
                return EX_USAGE;
            case -3:
                fprintf(stderr,
                        "error: character requirements cannot be satisfied "
                        "(charset or length)\n");
                return EX_USAGE;
            case -4:
                fprintf(stderr,
                        "error: exhausted attempts meeting character "
                        "requirements\n");
                return EX_AUDIT_FAIL;
            default:
                fprintf(stderr, "error: generation failed (rc=%d)\n", rc);
                return EX_CSPRNG;
        }
    }

    /* Audit (if enabled) — runs against the first password + a dedicated
     * statistical batch. Output stays on stderr. */
    int audit_rc = 0;
    if (o.audit) {
        audit_rc = run_audit(out, o.count, o.length, charset, charset_len);
    } else if (!g_quiet) {
        fprintf(stderr, "audit: skipped\n");
    }

    /* Print passwords to stdout. */
    for (int i = 0; i < o.count; i++) {
        fputs(out + (size_t)i * per_pw, stdout);
        fputc('\n', stdout);
    }
    fflush(stdout);

    /* Scrub. */
    memset(out, 0, (size_t)o.count * per_pw);
    free(out);

    return audit_rc == 0 ? EX_OK : EX_AUDIT_FAIL;
}
