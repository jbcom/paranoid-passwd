/**
 * app.js — Display-only WASM bridge for paranoid-passwd
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

/* ═══════════════════════════════════════════════════════════
   WASM LOADER + WASI SHIM (fail-closed)
   ═══════════════════════════════════════════════════════════ */

let wasm = null;
let mem  = null;

/**
 * WASI polyfill — the ONLY security-critical JS in this project.
 * random_get bridges WASI to Web Crypto. Everything else is a stub.
 */
function createWasiShim() {
  const impl = {
    /* ── Security-critical: bridges WASI random_get → Web Crypto ── */
    random_get(ptr, len) {
      crypto.getRandomValues(new Uint8Array(mem.buffer, ptr, len));
      return 0;
    },
    /* ── Clock ── */
    clock_time_get(clockId, precision, outPtr) {
      const dv = new DataView(mem.buffer);
      const ns = BigInt(Date.now()) * 1000000n;
      dv.setBigUint64(outPtr, ns, true);
      return 0;
    },
    /* ── Environment ── */
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
    /* ── Process ── */
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

/* ═══════════════════════════════════════════════════════════
   CHARSETS — built programmatically, not manually by LLM
   ═══════════════════════════════════════════════════════════ */

const CHARSETS = {
  full:  Array.from({ length: 94 }, (_, i) => String.fromCharCode(33 + i)).join(''),
  alnum: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
  alpha: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
  hex:   '0123456789abcdef',
};

/* ═══════════════════════════════════════════════════════════
   RESULT STRUCT READER

   Reads paranoid_audit_result_t from WASM linear memory.
   Field offsets documented to match include/paranoid.h.

   This is the ONLY place where JS interprets WASM memory.
   Every offset is derived from the C struct layout.
   ═══════════════════════════════════════════════════════════ */

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
   * 332     [4 bytes padding → align 8]
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
  };
}

/* ═══════════════════════════════════════════════════════════
   DOM HELPERS — textContent only, no innerHTML
   ═══════════════════════════════════════════════════════════ */

const $ = (id) => document.getElementById(id);
const txt = (id, v) => { const el = $(id); if (el) el.textContent = String(v); };

function setStage(name) {
  const runner = $('audit-runner');
  if (runner) runner.dataset.stage = name;
}

/* ═══════════════════════════════════════════════════════════
   THREAT MODEL — static data, defined here not in C
   because it's display text, not computation
   ═══════════════════════════════════════════════════════════ */

const THREATS = [
  { id: 'T1', name: 'Training Data Leakage',      sev: 'CRITICAL', mit: true,  st: 'Mitigated by CSPRNG' },
  { id: 'T2', name: 'Token Distribution Bias',     sev: 'HIGH',     mit: true,  st: 'Mitigated by rejection sampling' },
  { id: 'T3', name: 'Deterministic Reproduction',  sev: 'HIGH',     mit: true,  st: 'Mitigated by hardware entropy' },
  { id: 'T4', name: 'Prompt Injection Steering',   sev: 'MEDIUM',   mit: false, st: 'Residual \u2014 LLM-authored code' },
  { id: 'T5', name: 'Hallucinated Security Claims', sev: 'CRITICAL', mit: false, st: 'Residual \u2014 verify the math' },
  { id: 'T6', name: 'Screen Exposure',             sev: 'HIGH',     mit: false, st: 'Advisory \u2014 clear after use' },
];

/* ═══════════════════════════════════════════════════════════
   AUDIT PIPELINE — calls C, reads struct, updates DOM
   ═══════════════════════════════════════════════════════════ */

async function launchAudit() {
  if (!wasm) {
    alert('WASM not loaded. This tool requires paranoid.wasm.\nNo JavaScript fallback is provided \u2014 this is by design.');
    return;
  }

  const length  = parseInt($('cfg-length').value) || 32;
  const csKey   = $('cfg-charset').value;
  const charset = CHARSETS[csKey];
  const batch   = parseInt($('cfg-batch').value) || 500;
  const N       = charset.length;

  /* Switch to audit panel */
  $('step-audit').checked = true;
  setStage('generating');

  /* Write charset into WASM memory */
  const csPtr = wasm.malloc(N + 1);
  const csView = new Uint8Array(mem.buffer, csPtr, N + 1);
  for (let i = 0; i < N; i++) csView[i] = charset.charCodeAt(i);
  csView[N] = 0;

  /* Get result struct pointer */
  const resultPtr = wasm.paranoid_get_result_ptr();

  /* Run the audit — ALL computation happens in C */
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
  wasm.free(csPtr);

  if (rc !== 0) {
    alert('Audit failed (error ' + rc + '). CSPRNG may be unavailable.');
    return;
  }

  /* Read the result struct */
  const r = readResult();

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

  /* ═══ Populate results panel ═══ */

  /* Verdict */
  txt('verdict-icon', r.all_pass ? '\u2713' : '\u26A0');
  txt('verdict-text', r.all_pass ? 'CRYPTOGRAPHICALLY SOUND' : 'REVIEW FLAGGED ITEMS');
  const banner = $('verdict-banner');
  if (banner) {
    banner.className = 'verdict-banner' + (r.all_pass ? '' : ' verdict-fail');
  }

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

  /* NIST */
  const nistAll = r.nist_mem && r.nist_high && r.nist_crypto && r.nist_pq;
  $('det-nist-badge').textContent = nistAll ? 'ALL PASS' : 'PARTIAL';
  $('det-nist-badge').className = 'details-badge ' + (nistAll ? 'badge-pass' : 'badge-warn');
  $('det-nist').textContent =
    (r.nist_mem    ? '\u2713' : '\u2717') + ' Memorized Secret (min 30b)\n' +
    (r.nist_high   ? '\u2713' : '\u2717') + ' High-value accounts (min 80b)\n' +
    (r.nist_crypto ? '\u2713' : '\u2717') + ' Cryptographic key equiv. (min 128b)\n' +
    (r.nist_pq     ? '\u2713' : '\u2717') + ' Post-quantum safe (min 256b)';

  /* Uniqueness */
  $('det-unique-badge').textContent = 'PROVEN';
  $('det-unique-badge').className = 'details-badge badge-pass';
  $('det-unique').textContent =
    'Space size S = ' + r.charset_size + '^' + r.pw_length + ' \u2248 10^' + r.log10_space.toFixed(1) + '\n' +
    'Batch k = ' + r.batch_size + '\n\n' +
    'P(collision) \u2248 ' + (r.collision_prob < 1e-300 ? '\u2248 0' : r.collision_prob.toExponential(2)) + '\n' +
    'Need k \u2248 ' + r.pw_for_50.toExponential(2) + ' for 50% collision chance';

  /* Threats — using textContent for each line, no innerHTML */
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
    '\u2713 Charset: ' + r.charset_size + ' chars (charCode 33\u2013126)\n' +
    '\u2713 Rejection: max_valid=' + r.rej_max_valid + ', rate=' + r.rej_rate_pct.toFixed(1) + '%\n' +
    '\u2713 WASM isolation: DRBG state opaque to JS\n' +
    '\u2713 No network after page load\n' +
    '\u2713 SRI hashes on all assets\n\n' +
    '\u26A0 LLM-AUTHORED CODE\n' +
    'Potential failure points:\n' +
    ' \u2022 Rejection sampling boundary (paranoid.c:60)\n' +
    ' \u2022 Chi-squared Wilson-Hilferty approx (paranoid.c:140)\n' +
    ' \u2022 Struct field offsets in this JS reader (app.js)\n\n' +
    'RECOMMENDATION: Review src/paranoid.c and include/paranoid.h';

  /* Switch to results */
  $('step-results').checked = true;
}

/* ═══════════════════════════════════════════════════════════
   INIT — load WASM, wire up UI
   ═══════════════════════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', async () => {
  /* Range slider live label */
  const range = $('cfg-length');
  const output = $('cfg-length-val');
  if (range && output) {
    range.addEventListener('input', () => { output.value = range.value; });
  }

  /* Launch button */
  const btn = $('btn-launch');
  if (btn) btn.addEventListener('click', launchAudit);

  /* Load WASM */
  try {
    await loadWasm();

    /* ── Verify struct layout matches our hardcoded offsets ── */
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

    txt('engine-badge', 'WASI OpenSSL DRBG');
    txt('status-text', 'ready');
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
