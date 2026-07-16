//! Full-suite policy-scan latency.
//!
//! Times `scan_default` (every detector family, `Mode::Enforce`) across
//! representative gateway messages and two large sizes. Clean input is the
//! worst case — nothing short-circuits, so every family runs to completion —
//! and the 4k/1k ratio empirically checks the linear-time shape the Lean
//! proofs guarantee. Deterministic inputs only (no randomness).

use std::time::Instant;
use unicode_rust::security::policy::{scan_default, Profile};

fn time_ns_per_call(input: &[u32], iterations: u32) -> f64 {
    let start = Instant::now();
    let mut ran = 0u32;
    while ran < iterations {
        std::hint::black_box(scan_default(
            Profile::ChatMessage,
            std::hint::black_box(input),
        ));
        ran += 1;
    }
    start.elapsed().as_nanos() as f64 / iterations as f64
}

fn build(pattern: &[u32], len: usize) -> Vec<u32> {
    let mut v = Vec::with_capacity(len);
    while v.len() < len {
        v.push(pattern[v.len() % pattern.len()]);
    }
    v
}

#[test]
fn full_suite_scan_latency() {
    let chat_ascii: Vec<u32> = "hey, meeting at 3pm in room 204 - bring the report"
        .chars()
        .map(|c| c as u32)
        .collect();
    let username: Vec<u32> = "alice_smith_2024".chars().map(|c| c as u32).collect();
    // Latin/Cyrillic homoglyph mix (a, e swapped for Cyrillic look-alikes).
    let homoglyph: Vec<u32> = vec![0x61, 0x0430, 0x62, 0x0435, 0x63, 0x6F, 0x6D];
    // Mixed latin + combining marks for the linearity probe.
    let pattern = [0x61u32, 0x0301, 0x62, 0x20, 0x4E, 0x65];
    let big_1k = build(&pattern, 1024);
    let big_4k = build(&pattern, 4096);

    // Warmup also triggers every OnceLock table init.
    for _ in 0..500 {
        std::hint::black_box(scan_default(Profile::ChatMessage, &chat_ascii));
        std::hint::black_box(scan_default(Profile::ChatMessage, &big_1k));
    }

    let t_chat = time_ns_per_call(&chat_ascii, 2000);
    let t_user = time_ns_per_call(&username, 2000);
    let t_homo = time_ns_per_call(&homoglyph, 2000);
    let t_1k = time_ns_per_call(&big_1k, 200);
    let t_4k = time_ns_per_call(&big_4k, 200);

    println!("full-suite scan_default(ChatMessage, Enforce) latency:");
    println!(
        "  chat_ascii ({:>4} cp) = {:>10.0} ns  ({:.1} ns/cp)",
        chat_ascii.len(),
        t_chat,
        t_chat / chat_ascii.len() as f64
    );
    println!("  username   ({:>4} cp) = {:>10.0} ns", username.len(), t_user);
    println!("  homoglyph  ({:>4} cp) = {:>10.0} ns", homoglyph.len(), t_homo);
    println!(
        "  big_1k     (1024 cp) = {:>10.0} ns  ({:.1} ns/cp)",
        t_1k,
        t_1k / 1024.0
    );
    println!(
        "  big_4k     (4096 cp) = {:>10.0} ns  ({:.1} ns/cp)",
        t_4k,
        t_4k / 4096.0
    );
    println!(
        "  4k/1k ratio          = {:.2}   (~4.0 => linear)",
        t_4k / t_1k
    );
    println!(
        "  throughput/core      ~ {:.2} M codepoints/s",
        1.0e9 / (t_1k / 1024.0) / 1.0e6
    );

    assert!(t_chat > 0.0 && t_4k > t_1k);
}
