//! Timing side-channel — empirical verification of constant-time
//! `find_target_match` discipline.
//!
//! Threat model.  An attacker invokes the detector with
//! attacker-controlled inputs and measures response time.  In a
//! variable-time implementation, matching the FIRST target in the
//! curated list is faster than matching the LAST (the early-break
//! short-circuit halves the work for early matches).  Over many
//! samples this leak is exploitable: the attacker can fingerprint
//! curated-list membership without ever seeing the verdict.
//!
//! Mitigation (Move 4 of state-level red-team plan).
//! `find_target_match` now walks the entire curated target list
//! every call.  Equality via `ct_u32_slice_eq` accumulates the
//! comparison bit without early-breaking on first inequality.
//! Per-target work is independent of input.
//!
//! This test runs `detect` many times against inputs that match a
//! curated target at spread-out positions in the list — first,
//! middle, last — and asserts the coefficient-of-variation
//! (stddev / mean) across those positions is below threshold. All
//! of them return `TargetMatch`, so they take the same downstream
//! path; their only difference is where in the list the match sits,
//! which is exactly the leak the threat model describes. Each
//! target's per-iteration work is a fixed pair of constant-time
//! slice comparisons against a skeleton and a lowercase form
//! precomputed once at list load, so list position cannot change
//! the time. Comparing a matched input against an unmatched one
//! would instead compare two different detector paths — a match
//! returns at the first rung, a non-match runs the whole ladder —
//! a difference the verdict already reveals and not a list-position
//! leak.

use std::time::Instant;

use unicode_rust::security::identity::homoglyph_confusable as h;

const ITERATIONS_PER_INPUT: u32 = if cfg!(debug_assertions) {
    1_000
} else {
    50_000
};
const WARMUP_ROUNDS: u32 = if cfg!(debug_assertions) { 100 } else { 1000 };
const VARIANCE_THRESHOLD: f64 = 0.20; // 20% — generous for noisy benchmarks

fn time_ns_per_call(input: &[u32]) -> f64 {
    let start = Instant::now();
    let mut iterations_run = 0;
    while iterations_run < ITERATIONS_PER_INPUT {
        let v = h::detect(input);
        // Defeat dead-code elimination by reading the verdict.
        std::hint::black_box(&v);
        iterations_run += 1;
    }
    let elapsed_ns = start.elapsed().as_nanos() as f64;
    elapsed_ns / (ITERATIONS_PER_INPUT as f64)
}

#[test]
fn timing_constant_across_match_positions() {
    // Six curated targets that are all six codepoints long, matched
    // at spread-out positions in the curated list, each with exactly
    // one Cyrillic look-alike substituted so its letter skeleton
    // equals the target and `TargetMatch` fires. Equal length and
    // one substitution each hold the input-dependent work — the
    // skeleton descent and restriction-level scan, both linear in
    // input length — constant across the six, so the only thing that
    // varies is where in the list the match sits. A variable-time
    // walk that short-circuits on the matching index would make the
    // early positions faster than the late ones; the constant-time
    // discipline (walk the whole list every call, fixed work per
    // target against a precomputed skeleton and lowercase form) makes
    // them equal. Different-length inputs would instead measure the
    // per-codepoint skeleton cost, which is legitimate and not a
    // list-position leak.

    let solana = [0x73, 0x043E, 0x6C, 0x61, 0x6E, 0x61]; // position 9
    let lodash = [0x6C, 0x043E, 0x64, 0x61, 0x73, 0x68]; // position 15
    let pandas = [0x70, 0x0430, 0x6E, 0x64, 0x61, 0x73]; // position 27
    let google = [0x67, 0x043E, 0x6F, 0x67, 0x6C, 0x65]; // position 45
    let paypal = [0x70, 0x0430, 0x79, 0x70, 0x61, 0x6C]; // position 55
    let tiktok = [0x74, 0x69, 0x6B, 0x74, 0x043E, 0x6B]; // position 64

    let inputs: [&[u32]; 6] = [&solana, &lodash, &pandas, &google, &paypal, &tiktok];

    // Warm up to stabilize cache, branch predictor, and the lazily
    // built curated-target table.
    let mut warmup_rounds_run = 0;
    while warmup_rounds_run < WARMUP_ROUNDS {
        for input in inputs {
            std::hint::black_box(h::detect(input));
        }
        warmup_rounds_run += 1;
    }

    let times: Vec<f64> = inputs.iter().map(|input| time_ns_per_call(input)).collect();

    let mean = times.iter().sum::<f64>() / (times.len() as f64);
    let variance =
        times.iter().map(|t| (t - mean).powi(2)).sum::<f64>() / (times.len() as f64);
    let stddev = variance.sqrt();
    let cv = stddev / mean;

    for (input, t) in inputs.iter().zip(times.iter()) {
        eprintln!("  {:>2} cps -> {:.0} ns/call", input.len(), t);
    }
    eprintln!(
        "  mean = {:.0} ns | stddev = {:.0} ns | CoV = {:.3}",
        mean, stddev, cv,
    );

    // Constant-time claim: timing variance across list positions is
    // below VARIANCE_THRESHOLD. The pre-mitigation early-break impl
    // had CoV ≈ 0.5 between the first and last target; walking the
    // whole list holds it under 0.20.
    assert!(
        cv < VARIANCE_THRESHOLD,
        "Timing CoV {:.3} exceeds threshold {:.2} — find_target_match leaks curated-list position",
        cv, VARIANCE_THRESHOLD,
    );
}
