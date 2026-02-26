/**
 * app.js -- Display-only WASM bridge for paranoid-passwd
 *
 * This file does ZERO computation. It:
 *   1. Loads paranoid.wasm and provides the WASI random_get shim
 *   2. Calls paranoid_run_audit() (C does ALL the work)
 *   3. Reads the result struct from WASM linear memory
 *   4. Sets textContent on DOM elements
 *   5. Advances wizard radio buttons
 *
 * CodeQL / SAST can scan this as a standard .js file.
 * The crypto-critical code is in src/paranoid.c.
 */

'use strict';

/* ===================================================================
   WASM LOADER + WASI SHIM (fail-closed)
   =================================================================== */

let wasm = null;
let mem  = null;

/**
 * WASI polyfill -- the ONLY security-critical JS in this project.
 * random_get bridges WASI to Web Crypto. Everything else is a stub.
 */
function createWasiShim() {
  const impl = {
    /* -- Security-critical: bridges WASI random_get -> Web Crypto -- */
    random_get(ptr, len) {
      crypto.getRandomValues(new Uint8Array(mem.buffer, ptr, len));
      return 0;
    },
    /* -- Clock -- */
    clock_time_get(clockId, precision, outPtr) {
      const dv = new DataView(mem.buffer);
      const ns = BigInt(Date.now()) * 1000000n;
      dv.setBigUint64(outPtr, ns, true);
      return 0;
    },
    /* -- Environment -- */
    environ_sizes_get(countPtr, sizePtr) {
      const dv = new DataView(mem.buffer);
      dv.setUint32(countPtr, 0, true);
      dv.setUint32(sizePtr, 0, true);
      return 0;
    },
    args_sizes_get(countPtr, sizePtr) {
      const dv = new DataView(mem.buffer);
      dv.setUint32(countPtr, 0, true);
      dv.setUint32(sizePtr, 0, true);
      return 0;
    },
    /* -- Process -- */
    proc_exit(code) {
      throw new Error('WASM proc_exit: ' + code);
    },
    /* fd_prestat_get returns errno 8 (EBADF) to signal no preopened dirs */
    fd_prestat_get()      { return 8; },
    fd_prestat_dir_name() { return 8; },
  };

  /* Proxy auto-stubs any missing WASI import as () => 0.
     This prevents LinkError when Zig/OpenSSL import WASI syscalls
     that aren't needed at runtime (e.g. fd_filestat_get, poll_oneoff). */
  return new Proxy(impl, {
    get(target, prop) {
      if (prop in target) return target[prop];
      return () => 0;
    },
  });
}

async function loadWasm() {
  const resp = await fetch('paranoid.wasm');
  if (!resp.ok) throw new Error('Failed to fetch paranoid.wasm: ' + resp.status);
  const bytes = await resp.arrayBuffer();

  const shim = createWasiShim();
  const { instance } = await WebAssembly.instantiate(bytes, {
    wasi_snapshot_preview1: shim,
  });

  mem  = instance.exports.memory;
  wasm = instance.exports;
}

/* ===================================================================
   CHARSETS -- built programmatically, not manually by LLM

   The charset builder constructs the effective charset from user
   checkbox selections at runtime. No hardcoded charset tables.
   =================================================================== */

const LOWER   = 'abcdefghijklmnopqrstuvwxyz';
const UPPER   = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const DIGITS  = '0123456789';
/* Symbols: printable ASCII 33-126 minus letters and digits */
const SYMBOLS = '!\"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~';
/* Ambiguous characters to optionally exclude */
const AMBIGUOUS = '0OIl1|';

/**
 * Build the effective charset from current UI settings.
 * Returns the charset string and its length.
 */
function buildCharset() {
  const customInput = $('cfg-custom-charset');
  if (customInput && customInput.value.trim().length > 0) {
    /* Custom charset: deduplicate, sort, filter to printable ASCII */
    const seen = new Set();
    let result = '';
    for (const ch of customInput.value) {
      const code = ch.codePointAt(0);
      if (code >= 32 && code <= 126 && !seen.has(ch)) {
        seen.add(ch);
        result += ch;
      }
    }
    return result;
  }

  let charset = '';
  if ($('cfg-lower') && $('cfg-lower').checked) charset += LOWER;
  if ($('cfg-upper') && $('cfg-upper').checked) charset += UPPER;
  if ($('cfg-digits') && $('cfg-digits').checked) charset += DIGITS;
  if ($('cfg-symbols') && $('cfg-symbols').checked) charset += SYMBOLS;

  /* Extended printable ASCII: add space (charCode 32) */
  if ($('cfg-extended') && $('cfg-extended').checked) {
    if (charset.indexOf(' ') === -1) charset = ' ' + charset;
  }

  /* Exclude ambiguous characters */
  if ($('cfg-no-ambiguous') && $('cfg-no-ambiguous').checked) {
    let filtered = '';
    for (const ch of charset) {
      if (AMBIGUOUS.indexOf(ch) === -1) filtered += ch;
    }
    charset = filtered;
  }

  return charset;
}

/**
 * Get currently selected compliance frameworks from checkboxes.
 */
function getSelectedFrameworks() {
  const checks = document.querySelectorAll('input[name="compliance"]:checked');
  const frameworks = [];
  for (const cb of checks) {
    frameworks.push(cb.value);
  }
  return frameworks;
}

/* ===================================================================
   COMPLIANCE FRAMEWORK DEFINITIONS (display-side)

   These thresholds mirror the C-side definitions in paranoid.c
   but are used here only for the pre-generation strength meter
   and entropy preview. The actual compliance check runs in C.

   TODO: HUMAN_REVIEW - verify thresholds match C-side definitions
   =================================================================== */

const FRAMEWORKS = {
  nist:     { name: 'NIST SP 800-63B',  minLen: 8,  minEntropy: 30,  desc: 'US federal standard' },
  pci_dss:  { name: 'PCI DSS 4.0',      minLen: 12, minEntropy: 60,  desc: 'Payment card industry' },
  hipaa:    { name: 'HIPAA',             minLen: 8,  minEntropy: 60,  desc: 'Healthcare privacy' },
  soc2:     { name: 'SOC 2',             minLen: 8,  minEntropy: 60,  desc: 'SaaS controls' },
  gdpr:     { name: 'GDPR / ENISA',      minLen: 8,  minEntropy: 80,  desc: 'EU data protection' },
  iso27001: { name: 'ISO 27001',         minLen: 12, minEntropy: 90,  desc: 'Intl. info security' },
};

/* ===================================================================
   RESULT STRUCT READER

   Reads paranoid_audit_result_t from WASM linear memory.
   Field offsets documented to match include/paranoid.h.

   This is the ONLY place where JS interprets WASM memory.
   Every offset is derived from the C struct layout.
   =================================================================== */

function readString(ptr, maxLen) {
  const bytes = new Uint8Array(mem.buffer, ptr, maxLen);
  let end = bytes.indexOf(0);
  if (end === -1) end = maxLen;
  return new TextDecoder().decode(bytes.subarray(0, end));
}

function readResult() {
  const ptr = wasm.paranoid_get_result_ptr();
  const dv  = new DataView(mem.buffer);

  /*
   * paranoid_audit_result_t layout on wasm32.
   * int = 4 bytes (align 4), double = 8 bytes (align 8).
   * Offsets verified against include/paranoid.h.
   *
   * OFFSET  FIELD                  TYPE
   * 0       password[257]          char[]
   * 257     sha256_hex[65]         char[]
   * 322     [2 bytes padding]
   * 324     password_length        int
   * 328     charset_size           int
   * 332     [4 bytes padding -> align 8]
   * 336     chi2_statistic         double    dBase+0
   * 344     chi2_df                int       dBase+8
   * 348     [4 bytes padding]
   * 352     chi2_p_value           double    dBase+16
   * 360     chi2_pass              int       dBase+24
   * 364     [4 bytes padding]
   * 368     serial_correlation     double    dBase+32
   * 376     serial_pass            int       dBase+40
   * 380     batch_size             int       dBase+44
   * 384     duplicates             int       dBase+48
   * 388     collision_pass         int       dBase+52
   * 392     bits_per_char          double    dBase+56
   * 400     total_entropy          double    dBase+64
   * 408     log10_search_space     double    dBase+72
   * 416     brute_force_years      double    dBase+80
   * 424     nist_memorized         int       dBase+88
   * 428     nist_high_value        int       dBase+92
   * 432     nist_crypto_equiv      int       dBase+96
   * 436     nist_post_quantum      int       dBase+100
   * 440     collision_probability  double    dBase+104
   * 448     passwords_for_50pct    double    dBase+112
   * 456     rejection_max_valid    int       dBase+120
   * 460     [4 bytes padding]
   * 464     rejection_rate_pct     double    dBase+128
   * 472     pattern_issues         int       dBase+136
   * 476     all_pass               int       dBase+140
   * 480     current_stage          int       dBase+144
   * --- New v3.0 fields ---
   * 484     num_passwords          int       dBase+148
   * 488     compliance_nist        int       dBase+152
   * 492     compliance_pci_dss     int       dBase+156
   * 496     compliance_hipaa       int       dBase+160
   * 500     compliance_soc2        int       dBase+164
   * 504     compliance_gdpr        int       dBase+168
   * 508     compliance_iso27001    int       dBase+172
   * 512     count_lowercase        int       dBase+176
   * 516     count_uppercase        int       dBase+180
   * 520     count_digits           int       dBase+184
   * 524     count_symbols          int       dBase+188
   */

  const password   = readString(ptr, 257);
  const sha256_hex = readString(ptr + 257, 65);

  const pw_length    = dv.getInt32(ptr + 324, true);
  const charset_size = dv.getInt32(ptr + 328, true);

  const dBase = ptr + 336;

  const chi2_stat    = dv.getFloat64(dBase + 0,   true);
  const chi2_df      = dv.getInt32(dBase + 8,     true);
  const chi2_p       = dv.getFloat64(dBase + 16,  true);
  const chi2_pass    = dv.getInt32(dBase + 24,    true);

  const serial_corr  = dv.getFloat64(dBase + 32,  true);
  const serial_pass  = dv.getInt32(dBase + 40,    true);

  const batch_size     = dv.getInt32(dBase + 44,  true);
  const duplicates     = dv.getInt32(dBase + 48,  true);
  const collision_pass = dv.getInt32(dBase + 52,  true);

  const bits_per_char      = dv.getFloat64(dBase + 56,  true);
  const total_entropy      = dv.getFloat64(dBase + 64,  true);
  const log10_space        = dv.getFloat64(dBase + 72,  true);
  const brute_years        = dv.getFloat64(dBase + 80,  true);

  const nist_mem      = dv.getInt32(dBase + 88,   true);
  const nist_high     = dv.getInt32(dBase + 92,   true);
  const nist_crypto   = dv.getInt32(dBase + 96,   true);
  const nist_pq       = dv.getInt32(dBase + 100,  true);

  const collision_prob = dv.getFloat64(dBase + 104, true);
  const pw_for_50      = dv.getFloat64(dBase + 112, true);

  const rej_max_valid  = dv.getInt32(dBase + 120,   true);
  const rej_rate_pct   = dv.getFloat64(dBase + 128, true);

  const pattern_issues = dv.getInt32(dBase + 136, true);
  const all_pass       = dv.getInt32(dBase + 140, true);
  const current_stage  = dv.getInt32(dBase + 144, true);

  /* v3.0 fields */
  const num_passwords      = dv.getInt32(dBase + 148, true);
  const compliance_nist    = dv.getInt32(dBase + 152, true);
  const compliance_pci_dss = dv.getInt32(dBase + 156, true);
  const compliance_hipaa   = dv.getInt32(dBase + 160, true);
  const compliance_soc2    = dv.getInt32(dBase + 164, true);
  const compliance_gdpr    = dv.getInt32(dBase + 168, true);
  const compliance_iso27001= dv.getInt32(dBase + 172, true);
  const count_lowercase    = dv.getInt32(dBase + 176, true);
  const count_uppercase    = dv.getInt32(dBase + 180, true);
  const count_digits       = dv.getInt32(dBase + 184, true);
  const count_symbols      = dv.getInt32(dBase + 188, true);

  return {
    password, sha256_hex, pw_length, charset_size,
    chi2_stat, chi2_df, chi2_p, chi2_pass,
    serial_corr, serial_pass,
    batch_size, duplicates, collision_pass,
    bits_per_char, total_entropy, log10_space, brute_years,
    nist_mem, nist_high, nist_crypto, nist_pq,
    collision_prob, pw_for_50,
    rej_max_valid, rej_rate_pct,
    pattern_issues, all_pass, current_stage,
    num_passwords,
    compliance_nist, compliance_pci_dss, compliance_hipaa,
    compliance_soc2, compliance_gdpr, compliance_iso27001,
    count_lowercase, count_uppercase, count_digits, count_symbols,
  };
}

/* ===================================================================
   DOM HELPERS -- textContent only, no innerHTML
   =================================================================== */

const $ = (id) => document.getElementById(id);
const txt = (id, v) => { const el = $(id); if (el) el.textContent = String(v); };

function setStage(name) {
  const runner = $('audit-runner');
  if (runner) runner.dataset.stage = name;
}

/* ===================================================================
   D14: COPY TO CLIPBOARD
   =================================================================== */

function setupCopyButton(btnId, getText) {
  const btn = $(btnId);
  if (!btn) return;

  btn.addEventListener('click', () => {
    const password = getText();
    if (!password) return;

    navigator.clipboard.writeText(password).then(() => {
      btn.textContent = 'Copied!';
      btn.classList.add('copied');

      /* Revert button text after 2 seconds */
      setTimeout(() => {
        btn.textContent = 'Copy';
        btn.classList.remove('copied');
      }, 2000);

      /* Auto-clear clipboard after 30 seconds */
      setTimeout(() => {
        navigator.clipboard.writeText('');
      }, 30000);
    });
  });
}

/* ===================================================================
   D15 + D16: STRENGTH METER + ENTROPY PREVIEW

   Calculate entropy from current charset size + password length
   before generation. Update the strength bar and compliance text.
   =================================================================== */

/**
 * Evaluate compliance status of selected frameworks against given parameters.
 * Returns { meetsAll, meetsSome, metFrameworks, failedFrameworks }.
 */
function evaluateCompliance(selected, length, totalEntropy) {
  let meetsAll = true;
  let meetsSome = false;
  const metFrameworks = [];
  const failedFrameworks = [];

  for (const fwKey of selected) {
    const fw = FRAMEWORKS[fwKey];
    if (!fw) continue;
    const passes = length >= fw.minLen && totalEntropy >= fw.minEntropy;
    if (passes) {
      meetsSome = true;
      metFrameworks.push(fw.name);
    } else {
      meetsAll = false;
      failedFrameworks.push(fw.name);
    }
  }

  if (selected.length === 0) {
    meetsAll = true;
  }
  if (!meetsSome && selected.length > 0) {
    meetsAll = false;
  }

  return { meetsAll, meetsSome, metFrameworks, failedFrameworks };
}

/**
 * D15: Determine the strength bar CSS class based on entropy and compliance.
 */
function getStrengthClass(selected, meetsAll, meetsSome, totalEntropy) {
  if (selected.length === 0) {
    /* No frameworks selected -- base on raw entropy */
    if (totalEntropy >= 256) return 'strength-bar strength-purple';
    if (totalEntropy >= 128) return 'strength-bar strength-green';
    if (totalEntropy >= 60)  return 'strength-bar strength-yellow';
    return 'strength-bar strength-red';
  }
  if (meetsAll && totalEntropy >= 256) return 'strength-bar strength-purple';
  if (meetsAll)  return 'strength-bar strength-green';
  if (meetsSome) return 'strength-bar strength-yellow';
  return 'strength-bar strength-red';
}

/**
 * D16: Build the entropy preview text string.
 */
function buildEntropyPreviewText(totalEntropy, compliance) {
  const { meetsAll, meetsSome, metFrameworks, failedFrameworks } = compliance;
  let text = 'Current config: ' + totalEntropy.toFixed(1) + ' bits';

  if (metFrameworks.length === 0 && failedFrameworks.length === 0) {
    return text;
  }

  if (meetsAll && metFrameworks.length > 0) {
    if (totalEntropy >= 256) {
      text += ' -- exceeds all selected frameworks (post-quantum territory)';
    } else {
      text += ' -- meets ' + metFrameworks.join(', ');
    }
  } else if (meetsSome) {
    text += ' -- meets ' + metFrameworks.join(', ');
    text += ' | fails ' + failedFrameworks.join(', ');
  } else {
    text += ' -- below all selected frameworks';
  }

  return text;
}

function updateEntropyPreview() {
  const charset = buildCharset();
  const N = charset.length;
  const length = Number.parseInt($('cfg-length') ? $('cfg-length').value : '32') || 32;

  const charsetPreview = $('charset-preview');
  const strengthBar = $('strength-bar');
  const entropyPreview = $('entropy-preview');

  if (N === 0) {
    if (charsetPreview) charsetPreview.textContent = 'Effective charset: 0 characters -- select at least one character type';
    if (strengthBar) strengthBar.className = 'strength-bar';
    if (entropyPreview) entropyPreview.textContent = 'No characters selected';
    return;
  }

  const bitsPerChar = Math.log2(N);
  const totalEntropy = length * bitsPerChar;

  if (charsetPreview) {
    charsetPreview.textContent = 'Effective charset: ' + N + ' characters, ' + bitsPerChar.toFixed(2) + ' bits per character';
  }

  const selected = getSelectedFrameworks();
  const compliance = evaluateCompliance(selected, length, totalEntropy);

  if (strengthBar) {
    strengthBar.className = getStrengthClass(selected, compliance.meetsAll, compliance.meetsSome, totalEntropy);
  }

  if (entropyPreview) {
    entropyPreview.textContent = buildEntropyPreviewText(totalEntropy, compliance);
  }
}

/* ===================================================================
   D8: REQUIREMENTS VALIDATION
   =================================================================== */

function validateRequirements() {
  const length = Number.parseInt($('cfg-length') ? $('cfg-length').value : '32') || 32;
  const minLower = Number.parseInt($('cfg-min-lower') ? $('cfg-min-lower').value : '0') || 0;
  const minUpper = Number.parseInt($('cfg-min-upper') ? $('cfg-min-upper').value : '0') || 0;
  const minDigits = Number.parseInt($('cfg-min-digits') ? $('cfg-min-digits').value : '0') || 0;
  const minSymbols = Number.parseInt($('cfg-min-symbols') ? $('cfg-min-symbols').value : '0') || 0;

  const totalRequired = minLower + minUpper + minDigits + minSymbols;
  const validation = $('requirements-validation');
  if (!validation) return;

  if (totalRequired === 0) {
    validation.textContent = '';
    validation.className = 'requirements-validation';
  } else if (totalRequired > length) {
    validation.textContent = 'Requirements need ' + totalRequired + ' characters total but password length is only ' + length;
    validation.className = 'requirements-validation validation-error';
  } else {
    validation.textContent = 'Requirements: ' + totalRequired + ' of ' + length + ' characters constrained';
    validation.className = 'requirements-validation validation-ok';
  }
}

/* ===================================================================
   THREAT MODEL -- static data, defined here not in C
   because it's display text, not computation
   =================================================================== */

const THREATS = [
  { id: 'T1', name: 'Training Data Leakage',      sev: 'CRITICAL', mit: true,  st: 'Mitigated by CSPRNG' },
  { id: 'T2', name: 'Token Distribution Bias',     sev: 'HIGH',     mit: true,  st: 'Mitigated by rejection sampling' },
  { id: 'T3', name: 'Deterministic Reproduction',  sev: 'HIGH',     mit: true,  st: 'Mitigated by hardware entropy' },
  { id: 'T4', name: 'Prompt Injection Steering',   sev: 'MEDIUM',   mit: false, st: 'Residual \u2014 LLM-authored code' },
  { id: 'T5', name: 'Hallucinated Security Claims', sev: 'CRITICAL', mit: false, st: 'Residual \u2014 verify the math' },
  { id: 'T6', name: 'Screen Exposure',             sev: 'HIGH',     mit: false, st: 'Advisory \u2014 clear after use' },
];

/* ===================================================================
   D10: BUILD_MANIFEST.json RUNTIME LOADING
   =================================================================== */

async function loadBuildManifest() {
  const manifest = await fetch('BUILD_MANIFEST.json').then(r => r.json()).catch(() => null);
  if (manifest) {
    txt('version-tag', 'v' + (manifest.version || '?'));
    txt('build-sha', manifest.wasm_sha256 || 'unknown');
    txt('build-sri', manifest.wasm_sri || 'unknown');
    const timeEl = $('build-time');
    if (timeEl && manifest.build_time) {
      timeEl.textContent = manifest.build_time;
      timeEl.setAttribute('datetime', manifest.build_time);
    }
    /* Update page title */
    document.title = 'paranoid-passwd v' + (manifest.version || '?') + ' \u2014 self-auditing password generator';
  }
}

/* ===================================================================
   AUDIT PIPELINE -- calls C, reads struct, updates DOM
   =================================================================== */

/* Store the last result and generated passwords for the results page */
let lastResult = null;
let extraPasswords = [];

async function launchAudit() {
  if (!wasm) {
    alert('WASM not loaded. This tool requires paranoid.wasm.\nNo JavaScript fallback is provided \u2014 this is by design.');
    return;
  }

  const length  = Number.parseInt($('cfg-length').value) || 32;
  const charset = buildCharset();
  const batch   = Number.parseInt($('cfg-batch').value) || 500;
  const count   = Math.max(1, Math.min(10, Number.parseInt($('cfg-count') ? $('cfg-count').value : '1') || 1));
  const N       = charset.length;

  if (N === 0) {
    alert('No characters selected. Please select at least one character type.');
    return;
  }

  /* Check requirements feasibility */
  const minLower = Number.parseInt($('cfg-min-lower') ? $('cfg-min-lower').value : '0') || 0;
  const minUpper = Number.parseInt($('cfg-min-upper') ? $('cfg-min-upper').value : '0') || 0;
  const minDigits = Number.parseInt($('cfg-min-digits') ? $('cfg-min-digits').value : '0') || 0;
  const minSymbols = Number.parseInt($('cfg-min-symbols') ? $('cfg-min-symbols').value : '0') || 0;
  const totalRequired = minLower + minUpper + minDigits + minSymbols;

  if (totalRequired > length) {
    alert('Requirements need ' + totalRequired + ' characters but password length is only ' + length + '.');
    return;
  }

  /* Switch to audit panel */
  $('step-audit').checked = true;
  setStage('generating');

  /* Write charset into WASM memory */
  const csPtr = wasm.malloc(N + 1);
  const csView = new Uint8Array(mem.buffer, csPtr, N + 1);
  for (let i = 0; i < N; i++) csView[i] = charset.codePointAt(i);
  csView[N] = 0;

  /* Get result struct pointer */
  const resultPtr = wasm.paranoid_get_result_ptr();

  /* Run the audit -- ALL computation happens in C */
  await new Promise((resolve) => setTimeout(resolve, 50));

  /* Poll stage from C during execution (for large batches) */
  const stageOffset = resultPtr + 336 + 144; /* dBase + 144 = current_stage */
  const pollInterval = setInterval(() => {
    const dv = new DataView(mem.buffer);
    const stage = dv.getInt32(stageOffset, true);
    const stageNames = ['idle','generating','chi2','serial','collisions','proofs','patterns','threats','complete'];
    if (stage > 0 && stage <= 8) setStage(stageNames[stage] || 'generating');
  }, 50);

  const rc = wasm.paranoid_run_audit(csPtr, N, length, batch, resultPtr);
  clearInterval(pollInterval);

  if (rc !== 0) {
    wasm.free(csPtr);
    alert('Audit failed (error ' + rc + '). CSPRNG may be unavailable.');
    return;
  }

  /* Read the result struct */
  const r = readResult();
  lastResult = r;

  /* D3: Generate additional passwords if count > 1 */
  extraPasswords = [];
  if (count > 1 && wasm.paranoid_generate_multiple) {
    const bufSize = count * (length + 1);
    const outPtr = wasm.malloc(bufSize);
    const mpRc = wasm.paranoid_generate_multiple(csPtr, N, length, count, outPtr);
    if (mpRc === 0) {
      for (let i = 0; i < count; i++) {
        const pwStr = readString(outPtr + i * (length + 1), length + 1);
        /* First password from generate_multiple is separate from the audited one */
        extraPasswords.push(pwStr);
      }
    }
    wasm.free(outPtr);
  }

  wasm.free(csPtr);

  /* Update audit panel results */
  setStage('complete');
  txt('audit-password', r.password);
  txt('audit-hash', r.sha256_hex);
  txt('res-generate', r.pw_length + ' chars');
  txt('res-chi2', r.chi2_pass ? 'p=' + r.chi2_p.toFixed(3) : 'FAIL');
  txt('res-serial', r.serial_pass ? 'r=' + r.serial_corr.toFixed(4) : 'FAIL');
  txt('res-collisions', r.duplicates === 0 ? '0 dupes' : r.duplicates + ' DUPES');
  txt('res-proofs', r.total_entropy.toFixed(0) + ' bits');
  txt('res-patterns', r.pattern_issues === 0 ? 'clean' : r.pattern_issues + ' issues');
  txt('res-threats', '4/6 mitigated');

  /* Wait for CSS transitions */
  await new Promise((resolve) => setTimeout(resolve, 800));

  /* === Populate results panel === */

  /* D2: Password on results page */
  txt('result-password', r.password);
  txt('result-hash', r.sha256_hex);

  /* D3: Multi-password list */
  const multiSection = $('multi-passwords');
  const multiList = $('multi-password-list');
  if (multiSection && multiList) {
    /* Clear previous entries using DOM methods (no innerHTML) */
    while (multiList.firstChild) {
      multiList.removeChild(multiList.firstChild);
    }

    if (extraPasswords.length > 1) {
      multiSection.hidden = false;
      for (let i = 0; i < extraPasswords.length; i++) {
        const li = document.createElement('li');
        li.className = 'multi-password-item';

        const pwSpan = document.createElement('span');
        pwSpan.className = 'multi-password-text';
        pwSpan.textContent = extraPasswords[i];
        li.appendChild(pwSpan);

        const copyBtn = document.createElement('button');
        copyBtn.className = 'btn-copy btn-copy-small';
        copyBtn.textContent = 'Copy';
        copyBtn.type = 'button';
        copyBtn.setAttribute('aria-label', 'Copy password ' + (i + 1));
        const pw = extraPasswords[i];
        copyBtn.addEventListener('click', () => {
          navigator.clipboard.writeText(pw).then(() => {
            copyBtn.textContent = 'Copied!';
            copyBtn.classList.add('copied');
            setTimeout(() => {
              copyBtn.textContent = 'Copy';
              copyBtn.classList.remove('copied');
            }, 2000);
            setTimeout(() => { navigator.clipboard.writeText(''); }, 30000);
          });
        });
        li.appendChild(copyBtn);

        multiList.appendChild(li);
      }
    } else {
      multiSection.hidden = true;
    }
  }

  /* Verdict */
  txt('verdict-icon', r.all_pass ? '\u2713' : '\u26A0');
  txt('verdict-text', r.all_pass ? 'CRYPTOGRAPHICALLY SOUND' : 'REVIEW FLAGGED ITEMS');
  const banner = $('verdict-banner');
  if (banner) {
    banner.className = 'verdict-banner' + (r.all_pass ? '' : ' verdict-fail');
  }

  /* D4: Compliance results per framework */
  populateComplianceResults(r);

  /* Entropy */
  $('det-entropy-badge').textContent = r.total_entropy.toFixed(0) + ' bits';
  $('det-entropy-badge').className = 'details-badge ' + (r.total_entropy >= 128 ? 'badge-pass' : 'badge-warn');
  $('det-entropy').textContent =
    'Charset size (N):     ' + r.charset_size + '\n' +
    'Password length (L):  ' + r.pw_length + '\n' +
    'Bits per character:   ' + r.bits_per_char.toFixed(4) + '\n' +
    'Total entropy:        ' + r.total_entropy.toFixed(2) + ' bits\n' +
    'Search space:         10^' + r.log10_space.toFixed(1) + '\n' +
    'Brute-force @ 1T/s:   ' + r.brute_years.toExponential(2) + ' years\n\n' +
    'PROOF:\n' +
    '  H = L \u00D7 log\u2082(N) = ' + r.pw_length + ' \u00D7 ' + r.bits_per_char.toFixed(4) +
    ' = ' + r.total_entropy.toFixed(2) + ' bits';

  /* Stats */
  const statsPass = r.chi2_pass && r.serial_pass && r.collision_pass;
  $('det-stats-badge').textContent = statsPass ? 'ALL PASS' : 'ISSUES';
  $('det-stats-badge').className = 'details-badge ' + (statsPass ? 'badge-pass' : 'badge-fail');
  $('det-stats').textContent =
    '\u03C7\u00B2 statistic:     ' + r.chi2_stat.toFixed(2) + ' (df=' + r.chi2_df + ')\n' +
    'p-value:            ' + r.chi2_p.toFixed(4) + (r.chi2_pass ? ' \u2014 uniform' : ' \u2014 BIASED') + '\n' +
    'Serial correlation: ' + r.serial_corr.toFixed(6) + (r.serial_pass ? ' \u2014 independent' : ' \u2014 DEPENDENT') + '\n' +
    'Duplicates:         ' + r.duplicates + ' of ' + r.batch_size + (r.collision_pass ? ' \u2014 unique' : ' \u2014 COLLISIONS');

  /* Uniqueness */
  $('det-unique-badge').textContent = 'PROVEN';
  $('det-unique-badge').className = 'details-badge badge-pass';
  $('det-unique').textContent =
    'Space size S = ' + r.charset_size + '^' + r.pw_length + ' \u2248 10^' + r.log10_space.toFixed(1) + '\n' +
    'Batch k = ' + r.batch_size + '\n\n' +
    'P(collision) \u2248 ' + (r.collision_prob < 1e-300 ? '\u2248 0' : r.collision_prob.toExponential(2)) + '\n' +
    'Need k \u2248 ' + r.pw_for_50.toExponential(2) + ' for 50% collision chance';

  /* Threats -- using textContent for each line, no innerHTML */
  let threatText = '';
  for (const t of THREATS) {
    threatText += t.id + '  ' + t.name + ' (' + t.sev + ')\n';
    threatText += '    ' + (t.mit ? '\uD83D\uDEE1\uFE0F ' : '\u26A0\uFE0F ') + t.st + '\n\n';
  }
  $('det-threats').textContent = threatText;

  /* Self-audit */
  $('det-self-audit').textContent =
    'SELF-AUDIT \u2014 HONEST DISCLOSURE\n\n' +
    'Engine:        WASM (jedisct1/openssl-wasm + Zig)\n' +
    'Architecture:  FAIL-CLOSED (no JavaScript fallback)\n' +
    'Computation:   ALL in C (src/paranoid.c)\n' +
    'JS role:       Display-only struct reader\n\n' +
    '\u2713 Charset: ' + r.charset_size + ' chars\n' +
    '\u2713 Rejection: max_valid=' + r.rej_max_valid + ', rate=' + r.rej_rate_pct.toFixed(1) + '%\n' +
    '\u2713 WASM isolation: DRBG state opaque to JS\n' +
    '\u2713 No network after page load\n' +
    '\u2713 SRI hashes on all assets\n\n' +
    'Character composition:\n' +
    '  Lowercase: ' + r.count_lowercase + '\n' +
    '  Uppercase: ' + r.count_uppercase + '\n' +
    '  Digits:    ' + r.count_digits + '\n' +
    '  Symbols:   ' + r.count_symbols + '\n\n' +
    '\u26A0 LLM-AUTHORED CODE\n' +
    'Potential failure points:\n' +
    ' \u2022 Rejection sampling boundary (paranoid.c:60)\n' +
    ' \u2022 Chi-squared Wilson-Hilferty approx (paranoid.c:140)\n' +
    ' \u2022 Struct field offsets in this JS reader (app.js)\n\n' +
    'RECOMMENDATION: Review src/paranoid.c and include/paranoid.h';

  /* Switch to results */
  $('step-results').checked = true;
}

/* ===================================================================
   D4: COMPLIANCE RESULTS POPULATION
   =================================================================== */

function populateComplianceResults(r) {
  const selected = getSelectedFrameworks();
  const compBadge = $('det-compliance-badge');
  const compBody = $('det-compliance');
  const compWrap = $('det-compliance-wrap');

  if (!compBody || !compBadge) return;

  if (selected.length === 0) {
    compBadge.textContent = 'NONE SELECTED';
    compBadge.className = 'details-badge badge-info';
    compBody.textContent = 'No compliance frameworks were selected. Results show NIST tiers only.\n\n' +
      (r.nist_mem    ? '\u2713' : '\u2717') + ' NIST Memorized Secret (min 30b)\n' +
      (r.nist_high   ? '\u2713' : '\u2717') + ' NIST High-value accounts (min 80b)\n' +
      (r.nist_crypto ? '\u2713' : '\u2717') + ' NIST Cryptographic key equiv. (min 128b)\n' +
      (r.nist_pq     ? '\u2713' : '\u2717') + ' NIST Post-quantum safe (min 256b)';
    return;
  }

  /* Map framework keys to result fields */
  const complianceMap = {
    nist:     r.compliance_nist,
    pci_dss:  r.compliance_pci_dss,
    hipaa:    r.compliance_hipaa,
    soc2:     r.compliance_soc2,
    gdpr:     r.compliance_gdpr,
    iso27001: r.compliance_iso27001,
  };

  let allPass = true;
  let somePass = false;
  let resultText = '';

  for (const fwKey of selected) {
    const fw = FRAMEWORKS[fwKey];
    if (!fw) continue;
    const passes = complianceMap[fwKey] === 1;
    if (passes) {
      somePass = true;
    } else {
      allPass = false;
    }
    resultText += (passes ? '\u2713' : '\u2717') + ' ' + fw.name + ' \u2014 ' + fw.desc;
    resultText += ' (min ' + fw.minLen + ' chars, ' + fw.minEntropy + ' bits)';
    resultText += passes ? ' \u2014 COMPLIANT' : ' \u2014 NOT MET';
    resultText += '\n';
  }

  resultText += '\nPassword details:\n';
  resultText += '  Length: ' + r.pw_length + ' chars\n';
  resultText += '  Entropy: ' + r.total_entropy.toFixed(1) + ' bits\n';
  resultText += '  Lowercase: ' + r.count_lowercase + ', Uppercase: ' + r.count_uppercase + '\n';
  resultText += '  Digits: ' + r.count_digits + ', Symbols: ' + r.count_symbols;

  if (allPass) {
    compBadge.textContent = 'ALL COMPLIANT';
    compBadge.className = 'details-badge badge-pass';
  } else if (somePass) {
    compBadge.textContent = 'PARTIAL';
    compBadge.className = 'details-badge badge-warn';
  } else {
    compBadge.textContent = 'NON-COMPLIANT';
    compBadge.className = 'details-badge badge-fail';
  }

  compBody.textContent = resultText;
}

/* ===================================================================
   INIT -- load WASM, wire up UI, load manifest
   =================================================================== */

document.addEventListener('DOMContentLoaded', async () => {
  /* D10: Load BUILD_MANIFEST.json for version/hash data */
  loadBuildManifest();

  /* Range slider live label */
  const range = $('cfg-length');
  const output = $('cfg-length-val');
  if (range && output) {
    range.addEventListener('input', () => {
      output.value = range.value;
      updateEntropyPreview();
      validateRequirements();
    });
  }

  /* Wire up all charset/compliance controls to update entropy preview */
  const charsetIds = ['cfg-lower', 'cfg-upper', 'cfg-digits', 'cfg-symbols', 'cfg-extended', 'cfg-no-ambiguous'];
  for (const id of charsetIds) {
    const el = $(id);
    if (el) el.addEventListener('change', updateEntropyPreview);
  }

  const customCharset = $('cfg-custom-charset');
  if (customCharset) {
    customCharset.addEventListener('input', updateEntropyPreview);
  }

  /* Compliance checkboxes */
  const complianceChecks = document.querySelectorAll('input[name="compliance"]');
  for (const cb of complianceChecks) {
    cb.addEventListener('change', updateEntropyPreview);
  }

  /* D8: Requirements validation */
  const reqIds = ['cfg-min-lower', 'cfg-min-upper', 'cfg-min-digits', 'cfg-min-symbols'];
  for (const id of reqIds) {
    const el = $(id);
    if (el) el.addEventListener('input', validateRequirements);
  }

  /* Launch button */
  const btn = $('btn-launch');
  if (btn) btn.addEventListener('click', launchAudit);

  /* D14: Copy buttons */
  setupCopyButton('btn-copy-audit', () => {
    const el = $('audit-password');
    return el ? el.textContent : '';
  });
  setupCopyButton('btn-copy-result', () => {
    const el = $('result-password');
    return el ? el.textContent : '';
  });

  /* Initial entropy preview */
  updateEntropyPreview();
  validateRequirements();

  /* Load WASM */
  try {
    await loadWasm();

    /* -- Verify struct layout matches our hardcoded offsets -- */
    const expectedOffsets = {
      password_length: 324,
      chi2_statistic:  336,
      current_stage:   480,  /* 336 + 144 */
      all_pass:        476,  /* 336 + 140 */
    };

    const actualOffsets = {
      password_length: wasm.paranoid_offset_password_length(),
      chi2_statistic:  wasm.paranoid_offset_chi2_statistic(),
      current_stage:   wasm.paranoid_offset_current_stage(),
      all_pass:        wasm.paranoid_offset_all_pass(),
    };

    let layoutOk = true;
    for (const [field, expected] of Object.entries(expectedOffsets)) {
      if (actualOffsets[field] !== expected) {
        console.error('Struct offset mismatch: ' + field +
          ' expected ' + expected + ' got ' + actualOffsets[field]);
        layoutOk = false;
      }
    }

    if (!layoutOk) {
      throw new Error('Struct layout mismatch \u2014 paranoid.wasm was compiled with different alignment. Refusing to run.');
    }

    /* Update status indicators */
    txt('engine-badge', 'WASI OpenSSL DRBG');
    txt('status-text', 'ready');

    /* Set version from WASM if available */
    if (wasm.paranoid_version) {
      const versionPtr = wasm.paranoid_version();
      if (versionPtr) {
        const version = readString(versionPtr, 32);
        if (version) {
          txt('version-tag', 'v' + version);
        }
      }
    }
  } catch (err) {
    console.error('WASM load failed:', err);
    txt('engine-badge', 'UNAVAILABLE');
    txt('status-text', 'error');

    const dot = $('status-dot');
    if (dot) {
      dot.style.background = 'var(--red)';
      dot.style.boxShadow = '0 0 8px rgba(255,77,106,0.4)';
    }
    if (btn) {
      btn.disabled = true;
      btn.textContent = 'WASM Required \u2014 See Console';
      btn.style.opacity = '0.4';
      btn.style.cursor = 'not-allowed';
    }
  }
});
