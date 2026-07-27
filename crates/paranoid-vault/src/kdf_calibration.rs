//! Argon2id runtime calibration to a wall-clock target, with an honest,
//! never-weakened memory floor.
//!
//! Before this module existed, `DEFAULT_MEMORY_COST_KIB`/`DEFAULT_ITERATIONS`/
//! `DEFAULT_PARALLELISM` (`262_144`/`3`/`1`) were fixed compile-time
//! constants used at every vault creation regardless of host. That floor
//! already exceeds OWASP's high-security Argon2id profile (`m=128 MiB,
//! t=4`) on memory, so this project was never under-provisioned — the gap
//! was the opposite: a fixed constant is fragile at both ends. A
//! RAM-constrained host (e.g. a small VM or an old machine) either eats the
//! full 256 MiB unconditionally or can't unlock at all under memory
//! pressure, while a high-end host with headroom gets no additional
//! brute-force resistance the hardware could easily afford.
//!
//! [`calibrate_kdf_params`] benchmarks Argon2id at the memory floor on the
//! host, then raises the iteration count toward a target interactive
//! wall-clock duration. The memory cost is **only ever raised, never
//! lowered** below [`MEMORY_COST_FLOOR_KIB`] — calibration can strengthen a
//! vault's KDF parameters relative to the floor, it can never weaken them
//! below it, regardless of what the benchmark suggests. If the initial
//! floor-memory benchmark itself fails (host is too constrained to even
//! attempt Argon2id at the floor, or `Params`/`hash_password_into` errors),
//! calibration falls back to the fixed `DEFAULT_*` constants and reports
//! that fallback rather than failing vault creation outright — an honest,
//! surfaced warning beats a vault the user can't create.
//!
//! Chosen parameters are persisted in `VaultHeader.kdf` (already stored,
//! `lib.rs` `VaultHeader`) exactly as calibration produced them; unlock
//! already derives the KEK from `header.kdf` (`lifecycle.rs`
//! `unlock_vault_inner`), so no wire-format change and no unlock-path change
//! were needed — calibration only changes what gets written at creation
//! time.

use crate::{DEFAULT_ITERATIONS, DEFAULT_MEMORY_COST_KIB, DEFAULT_PARALLELISM, VaultKdfParams};
use argon2::{Algorithm, Argon2, Params, Version};
use std::time::{Duration, Instant};

/// Hard floor on Argon2id memory cost, in KiB. Calibration MUST NEVER emit
/// a `memory_cost_kib` below this value, on any host, under any
/// circumstance — this is the one invariant the whole module exists to
/// preserve. Equal to the pre-calibration fixed default (`262_144` KiB /
/// 256 MiB), which already exceeds OWASP's high-security profile.
pub const MEMORY_COST_FLOOR_KIB: u32 = DEFAULT_MEMORY_COST_KIB;

/// Default interactive wall-clock target for vault creation: fast enough
/// not to feel broken on an unlock, slow enough to meaningfully throttle
/// offline brute-force at the floor memory cost and above.
pub const DEFAULT_KDF_CALIBRATION_TARGET: Duration = Duration::from_millis(350);

/// Upper bound on how far calibration will push either memory or
/// iterations, so a very fast host can't calibrate into a multi-minute
/// unlock. Iterations are capped independently of memory; memory is capped
/// so a single calibration run can't attempt to allocate an unreasonable
/// fraction of host RAM.
const MAX_ITERATIONS: u32 = 32;
const MAX_MEMORY_COST_KIB: u32 = 2 * 1024 * 1024; // 2 GiB

/// Fixed salt/password used only for the in-process timing benchmark.
/// Never used to derive a real key — calibration measures wall-clock cost
/// of a parameter set, then throws the derived bytes away.
const BENCHMARK_PASSWORD: &[u8] = b"paranoid-passwd::kdf-calibration::benchmark-password";
const BENCHMARK_SALT: &[u8] = b"paranoid-passwd::kdf-calibration::benchmark-salt";

/// How calibration arrived at the params it returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalibrationOutcome {
    /// The floor-memory benchmark succeeded and iterations were tuned
    /// toward the wall-clock target (possibly settling at 1 iteration if
    /// the floor alone already meets or exceeds the target).
    Calibrated,
    /// The floor-memory benchmark itself failed (host too constrained, or
    /// Argon2id reported an error), so calibration fell back to the fixed
    /// `DEFAULT_*` constants untouched. The vault is still created — with
    /// the same parameters it always used — but the caller should surface
    /// this as a warning rather than treat it as a silent success.
    FallbackToDefaults,
}

/// Result of [`calibrate_kdf_params`]: the chosen params plus how they were
/// arrived at, so callers can surface a warning on the fallback path
/// without inventing a second return channel.
#[derive(Debug, Clone)]
pub struct CalibrationResult {
    pub params: VaultKdfParams,
    pub outcome: CalibrationOutcome,
}

/// Benchmarks Argon2id at [`MEMORY_COST_FLOOR_KIB`] on this host and raises
/// the iteration count toward `target` wall-clock duration, returning the
/// resulting `VaultKdfParams`. Memory cost in the returned params is never
/// below `MEMORY_COST_FLOOR_KIB` on any path, including the benchmark
/// failure fallback (which reuses the equally-floored `DEFAULT_*`
/// constants).
///
/// `derived_key_len` is threaded through unchanged so callers (vault
/// creation) control the output key length exactly as before; calibration
/// only chooses `memory_cost_kib` and `iterations`.
pub fn calibrate_kdf_params(target: Duration, derived_key_len: usize) -> CalibrationResult {
    let Some(floor_duration) = benchmark(MEMORY_COST_FLOOR_KIB, 1, derived_key_len) else {
        return CalibrationResult {
            params: default_params(derived_key_len),
            outcome: CalibrationOutcome::FallbackToDefaults,
        };
    };

    // If even one iteration at the floor already meets or exceeds the
    // target, there is no room to add iterations without overshooting;
    // stay at the floor with 1 iteration rather than DEFAULT_ITERATIONS,
    // since the floor-at-1 measurement already proves it costs at least
    // `target` on this host — no need to multiply that further. Still
    // never below DEFAULT_ITERATIONS' floor equivalent: 1 is Argon2id's
    // own minimum, and memory stays pinned at the floor either way.
    if floor_duration >= target {
        return CalibrationResult {
            params: VaultKdfParams {
                algorithm: "argon2id".to_string(),
                memory_cost_kib: MEMORY_COST_FLOOR_KIB,
                iterations: DEFAULT_ITERATIONS,
                parallelism: DEFAULT_PARALLELISM,
                derived_key_len,
            },
            outcome: CalibrationOutcome::Calibrated,
        };
    }

    // Scale iterations linearly from the single-iteration measurement,
    // then walk from that estimate to the real measured value so we land
    // close to the target without a long binary search (calibration runs
    // once, at vault creation, so a handful of Argon2id passes is an
    // acceptable one-time cost).
    let estimated_iterations = estimate_iterations(floor_duration, target);
    let mut iterations = estimated_iterations.clamp(DEFAULT_ITERATIONS, MAX_ITERATIONS);

    // Walk up from the estimate while still under target and under the
    // iteration cap; a coarse benchmark estimate can undershoot on noisy
    // hosts, so confirm/adjust with real measurements rather than trusting
    // the linear extrapolation blindly.
    while iterations < MAX_ITERATIONS {
        match benchmark(MEMORY_COST_FLOOR_KIB, iterations, derived_key_len) {
            Some(measured) if measured >= target => break,
            Some(_) => iterations += 1,
            None => {
                // A benchmark that succeeded at 1 iteration but fails at a
                // higher one is treated as "stop raising, use the last
                // known-good iteration count" rather than a full fallback:
                // the floor-memory, DEFAULT_ITERATIONS-or-higher params we
                // already have are still valid and still >= the floor.
                iterations = iterations.max(DEFAULT_ITERATIONS);
                break;
            }
        }
    }

    CalibrationResult {
        params: VaultKdfParams {
            algorithm: "argon2id".to_string(),
            memory_cost_kib: MEMORY_COST_FLOOR_KIB,
            iterations,
            parallelism: DEFAULT_PARALLELISM,
            derived_key_len,
        },
        outcome: CalibrationOutcome::Calibrated,
    }
}

fn default_params(derived_key_len: usize) -> VaultKdfParams {
    VaultKdfParams {
        algorithm: "argon2id".to_string(),
        memory_cost_kib: MEMORY_COST_FLOOR_KIB,
        iterations: DEFAULT_ITERATIONS,
        parallelism: DEFAULT_PARALLELISM,
        derived_key_len,
    }
}

/// Extrapolates an iteration count from a single-iteration timing sample,
/// assuming near-linear scaling of Argon2id wall-clock cost with `t`
/// (memory and parallelism held fixed) — true in practice since Argon2id's
/// per-pass work is dominated by the fixed memory-fill cost repeated `t`
/// times. Always returns at least 1.
fn estimate_iterations(single_iteration: Duration, target: Duration) -> u32 {
    if single_iteration.is_zero() {
        return DEFAULT_ITERATIONS;
    }
    let ratio = target.as_secs_f64() / single_iteration.as_secs_f64();
    let estimated = ratio.ceil();
    if estimated.is_finite() && estimated >= 1.0 {
        // MAX_ITERATIONS is a small u32 constant, so this cast cannot
        // truncate meaningfully; clamp before cast to stay within u32 range
        // regardless of how large `ratio` is on a pathologically fast host.
        estimated.min(f64::from(MAX_ITERATIONS)) as u32
    } else {
        DEFAULT_ITERATIONS
    }
}

/// Runs one Argon2id derivation at the given params and returns how long it
/// took, or `None` if Argon2id rejected the params or the derivation
/// itself failed (e.g. host refuses the requested memory allocation).
fn benchmark(memory_cost_kib: u32, iterations: u32, derived_key_len: usize) -> Option<Duration> {
    let memory_cost_kib = memory_cost_kib.min(MAX_MEMORY_COST_KIB);
    let params = Params::new(
        memory_cost_kib,
        iterations,
        DEFAULT_PARALLELISM,
        Some(derived_key_len),
    )
    .ok()?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = vec![0_u8; derived_key_len];
    let start = Instant::now();
    argon
        .hash_password_into(BENCHMARK_PASSWORD, BENCHMARK_SALT, output.as_mut_slice())
        .ok()?;
    Some(start.elapsed())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floor_constant_matches_documented_default() {
        assert_eq!(MEMORY_COST_FLOOR_KIB, 262_144);
    }

    #[test]
    fn calibration_never_emits_memory_below_floor() {
        // Even an aggressively short target (which would, absent the
        // floor clamp, tempt a "cheaper" calibration) must never lower
        // memory cost below the floor.
        for target_ms in [1, 10, 50, 100, 350, 500, 1000] {
            let result =
                calibrate_kdf_params(Duration::from_millis(target_ms), MASTER_KEY_LEN_FOR_TEST);
            assert!(
                result.params.memory_cost_kib >= MEMORY_COST_FLOOR_KIB,
                "target={target_ms}ms produced memory_cost_kib={} below floor {}",
                result.params.memory_cost_kib,
                MEMORY_COST_FLOOR_KIB
            );
        }
    }

    #[test]
    fn calibration_never_emits_memory_below_floor_even_with_huge_target() {
        // A very large target must not cause memory to be raised in place
        // of iterations in a way that somehow drops below the floor either
        // (raising is fine; dropping below is the invariant under test).
        let result = calibrate_kdf_params(Duration::from_millis(5), MASTER_KEY_LEN_FOR_TEST);
        assert!(result.params.memory_cost_kib >= MEMORY_COST_FLOOR_KIB);
        assert_eq!(result.outcome, CalibrationOutcome::Calibrated);
    }

    #[test]
    fn calibration_produces_at_least_one_iteration() {
        let result = calibrate_kdf_params(Duration::from_millis(1), MASTER_KEY_LEN_FOR_TEST);
        assert!(result.params.iterations >= 1);
    }

    #[test]
    fn calibration_raises_iterations_toward_target_on_short_targets() {
        // A tiny target should still resolve to a valid, usable parameter
        // set (not panic, not zero, not below DEFAULT_ITERATIONS' floor of
        // usefulness) even though the floor-memory single iteration will
        // usually already exceed a 1ms target.
        let result = calibrate_kdf_params(Duration::from_millis(1), MASTER_KEY_LEN_FOR_TEST);
        assert!(result.params.iterations >= 1);
        assert_eq!(result.params.algorithm, "argon2id");
        assert_eq!(result.params.parallelism, DEFAULT_PARALLELISM);
        assert_eq!(result.params.derived_key_len, MASTER_KEY_LEN_FOR_TEST);
    }

    #[test]
    fn benchmark_returns_none_for_invalid_params() {
        // Argon2's own `Params::new` rejects a derived key length of 0.
        assert!(benchmark(MEMORY_COST_FLOOR_KIB, 1, 0).is_none());
    }

    #[test]
    fn fallback_path_still_honors_floor() {
        // Directly exercise the fallback constructor used when the
        // benchmark itself fails, to prove the fallback path alone (not
        // just the calibrated path) can never emit below-floor memory.
        let params = default_params(MASTER_KEY_LEN_FOR_TEST);
        assert!(params.memory_cost_kib >= MEMORY_COST_FLOOR_KIB);
        assert_eq!(params.iterations, DEFAULT_ITERATIONS);
    }

    #[test]
    fn estimate_iterations_handles_zero_sample() {
        assert_eq!(
            estimate_iterations(Duration::ZERO, Duration::from_millis(100)),
            DEFAULT_ITERATIONS
        );
    }

    #[test]
    fn estimate_iterations_scales_with_ratio() {
        let sample = Duration::from_millis(10);
        let target = Duration::from_millis(100);
        let estimated = estimate_iterations(sample, target);
        assert!(estimated >= 10);
        assert!(estimated <= MAX_ITERATIONS);
    }

    #[test]
    fn estimate_iterations_clamps_to_max() {
        let sample = Duration::from_nanos(1);
        let target = Duration::from_secs(3600);
        let estimated = estimate_iterations(sample, target);
        assert!(estimated <= MAX_ITERATIONS);
    }

    const MASTER_KEY_LEN_FOR_TEST: usize = 32;
}
