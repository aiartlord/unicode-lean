//! Stream-Safe-Text-Format-violation detection (F2) — inputs whose consecutive
//! non-starter run exceeds the UAX #15 §13 `streamSafeLimit` of 30. Such an
//! input (the canonical "Zalgo" shape, a single base codepoint followed by a
//! long combining-mark run) forces unbounded combining-mark buffers in
//! receiver-side streaming normalization (`toNFC` / `toNFD` / `toNFKC` /
//! `toNFKD`) and is a known DoS vector.
//!
//! Direct port of `Unicode/Security/Form/StreamSafeViolation.lean`. UAX #15 §13
//! defines Stream-Safe Text Format as the remediation: insert U+034F COMBINING
//! GRAPHEME JOINER (a starter) after every 30 consecutive non-starters, which
//! bounds the normalization buffer. `StreamSafeViolation` is the security
//! verdict over the same property — distinct from `RendererDivergence`'s
//! `combiningStackOverflow` (the cosmetic 4-mark threshold), this is the
//! spec-mandated DoS-prevention bound.
//!
//! A codepoint is a non-starter iff its Canonical_Combining_Class is non-zero
//! (UAX #15 D49). This module reads CCC from the port's own bundled UCD table
//! via `ucd::ccc`, never a host normalizer.
//!
//! Sub-threat: `streamSafeOverrun (basePos, runLen)` — the first non-starter
//! run whose length exceeds `streamSafeLimit`. `basePos` is the index of that
//! run's first non-starter codepoint.

use crate::security::identity::ucd;

// ─────────────────────────────────────────────────────────────────────
// §1 Run inventory
// ─────────────────────────────────────────────────────────────────────

/// UAX #15 §13 Stream-Safe limit: the maximum number of consecutive
/// non-starters permitted before a COMBINING GRAPHEME JOINER must be inserted.
pub const STREAM_SAFE_LIMIT: usize = 30;

/// True iff `cp` is a non-starter — a codepoint with non-zero
/// Canonical_Combining_Class (UAX #15 D49). Starters have CCC = 0.
fn is_non_starter(cp: u32) -> bool {
    ucd::ccc(cp) != 0
}

/// Inventory of `(start_index, length)` for every maximal non-starter run in
/// `input`. Mirrors `collectRunsGo`: a run opens on the first non-starter, its
/// start index is fixed to that codepoint's absolute index, and it closes
/// (emitting its `(start, length)` pair) on the next starter or at end of input.
fn non_starter_runs(input: &[u32]) -> Vec<(usize, usize)> {
    let mut runs: Vec<(usize, usize)> = Vec::new();
    let mut cur_start: Option<usize> = None;
    let mut cur_len: usize = 0;
    for (i, &cp) in input.iter().enumerate() {
        if is_non_starter(cp) {
            if cur_start.is_none() {
                cur_start = Some(i);
            }
            cur_len += 1;
        } else {
            if let Some(s) = cur_start {
                runs.push((s, cur_len));
            }
            cur_start = None;
            cur_len = 0;
        }
    }
    if let Some(s) = cur_start {
        runs.push((s, cur_len));
    }
    runs
}

/// First non-starter run whose length exceeds `STREAM_SAFE_LIMIT`, as
/// `(start_index, length)`.
fn first_overrun(input: &[u32]) -> Option<(usize, usize)> {
    non_starter_runs(input)
        .into_iter()
        .find(|&(_start, len)| len > STREAM_SAFE_LIMIT)
}

/// Longest non-starter run length in `input`.
fn max_run_len(input: &[u32]) -> usize {
    non_starter_runs(input)
        .into_iter()
        .fold(0, |acc, (_start, len)| if len > acc { len } else { acc })
}

/// Number of distinct non-starter runs that exceed `STREAM_SAFE_LIMIT`.
fn overrun_count(input: &[u32]) -> usize {
    non_starter_runs(input).into_iter().fold(
        0,
        |acc, (_start, len)| {
            if len > STREAM_SAFE_LIMIT {
                acc + 1
            } else {
                acc
            }
        },
    )
}

/// Total non-starter codepoints in `input` (sum of all run lengths).
fn total_non_starters(input: &[u32]) -> usize {
    non_starter_runs(input)
        .into_iter()
        .fold(0, |acc, (_start, len)| acc + len)
}

// ─────────────────────────────────────────────────────────────────────
// §2 Types
// ─────────────────────────────────────────────────────────────────────

/// Sub-threats this detector can fire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubThreat {
    /// The first non-starter run whose length exceeds `STREAM_SAFE_LIMIT`.
    /// `base_pos` is the index of the run's first non-starter codepoint;
    /// `run_len` is the run's length.
    StreamSafeOverrun {
        /// Index of the run's first non-starter codepoint.
        base_pos: usize,
        /// Length of the overrunning non-starter run.
        run_len: usize,
    },
}

impl SubThreat {
    /// Human-facing classification tag for this sub-threat.
    pub fn tag(&self) -> &'static str {
        match self {
            SubThreat::StreamSafeOverrun {
                base_pos: _,
                run_len: _,
            } => "StreamSafeOverrun",
        }
    }
}

/// Top-level F2 classification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Classification {
    /// No non-starter run exceeds the Stream-Safe limit.
    Clear,
    /// A hazard was found: the sub-threat, its implicated positions, and any
    /// decoded bytes (always empty for this detector — the field mirrors the
    /// spec's `Classification.hazard` shape).
    Hazard {
        /// The sub-threat that fired.
        sub: SubThreat,
        /// The codepoint positions the sub-threat implicates.
        positions: Vec<usize>,
        /// Decoded byte context (unused by this detector; always empty).
        decoded: Vec<u8>,
    },
}

impl Classification {
    /// True iff the input is clear.
    pub fn is_clear(&self) -> bool {
        match self {
            Classification::Clear => true,
            Classification::Hazard {
                sub: _,
                positions: _,
                decoded: _,
            } => false,
        }
    }

    /// Human-facing tag for a hazard, or `None` when clear.
    pub fn tag(&self) -> Option<&'static str> {
        match self {
            Classification::Clear => None,
            Classification::Hazard {
                sub,
                positions: _,
                decoded: _,
            } => Some(sub.tag()),
        }
    }

    /// Implicated positions (empty when clear).
    pub fn positions(&self) -> &[usize] {
        match self {
            Classification::Clear => &[],
            Classification::Hazard {
                sub: _,
                positions,
                decoded: _,
            } => positions,
        }
    }
}

/// F2 verdict — the structured output of `detect`. The run-inventory summaries
/// (`max_run_len`, `overrun_count`, `total_non_starters`) are exposed so
/// downstream callers can size the buffer pressure a streaming normalizer would
/// see.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    /// The scanned input codepoints.
    pub input: Vec<u32>,
    /// The classification verdict.
    pub classify: Classification,
    /// Longest non-starter run length in `input`.
    pub max_run_len: usize,
    /// Number of distinct non-starter runs exceeding the Stream-Safe limit.
    pub overrun_count: usize,
    /// Total non-starter codepoints in `input`.
    pub total_non_starters: usize,
}

// ─────────────────────────────────────────────────────────────────────
// §3 Top-level detection
// ─────────────────────────────────────────────────────────────────────

/// The F2 detection function. Fires `StreamSafeOverrun` on the first
/// non-starter run whose length exceeds `STREAM_SAFE_LIMIT`.
pub fn detect(input: &[u32]) -> Verdict {
    let classification = match first_overrun(input) {
        Some((base_pos, run_len)) => Classification::Hazard {
            sub: SubThreat::StreamSafeOverrun { base_pos, run_len },
            positions: vec![base_pos],
            decoded: Vec::new(),
        },
        None => Classification::Clear,
    };
    Verdict {
        input: input.to_vec(),
        classify: classification,
        max_run_len: max_run_len(input),
        overrun_count: overrun_count(input),
        total_non_starters: total_non_starters(input),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ground truth: the `detect_*` theorems in
    // `Unicode/Security/Form/StreamSafeViolation.lean`. Each Lean detect vector
    // maps to one `#[test]` below. This detector is context-free — every vector
    // is expressible in the shared detector fixture
    // (`fixtures/security/detectors/stream_safe_violation.json`).
    //
    // U+0301 COMBINING ACUTE ACCENT has CCC = 230 (a non-starter); the ASCII
    // letters in these vectors have CCC = 0 (starters).

    const ACUTE: u32 = 0x0301;

    /// Build "a" followed by `n` combining acute accents.
    fn a_plus_marks(n: usize) -> Vec<u32> {
        let mut v = vec![0x61u32];
        v.extend(std::iter::repeat_n(ACUTE, n));
        v
    }

    // `detect_empty_clear`: empty input is clear.
    #[test]
    fn detect_empty_clear() {
        let v = detect(&[]);
        assert!(v.classify.is_clear());
        assert_eq!(v.classify.tag(), None);
        assert_eq!(v.max_run_len, 0);
        assert_eq!(v.overrun_count, 0);
        assert_eq!(v.total_non_starters, 0);
    }

    // `detect_ascii_clear`: the pure-ASCII "Hello" input is clear.
    #[test]
    fn detect_ascii_clear() {
        let v = detect(&[0x48, 0x65, 0x6C, 0x6C, 0x6F]);
        assert!(v.classify.is_clear());
        assert_eq!(v.max_run_len, 0);
        assert_eq!(v.total_non_starters, 0);
    }

    // `detect_one_combine_clear`: a starter plus a single combining mark
    // ("a" + U+0301) is clear.
    #[test]
    fn detect_one_combine_clear() {
        let v = detect(&[0x61, ACUTE]);
        assert!(v.classify.is_clear());
        assert_eq!(v.max_run_len, 1);
        assert_eq!(v.overrun_count, 0);
        assert_eq!(v.total_non_starters, 1);
    }

    // `detect_thirty_marks_clear`: exactly 30 combining marks after a starter
    // is the boundary case — stays clear under strict `>`.
    #[test]
    fn detect_thirty_marks_clear() {
        let v = detect(&a_plus_marks(30));
        assert!(v.classify.is_clear());
        assert_eq!(v.classify.tag(), None);
        assert_eq!(v.max_run_len, 30);
        assert_eq!(v.overrun_count, 0);
        assert_eq!(v.total_non_starters, 30);
    }

    // `detect_thirtyone_marks_hazard`: 31 combining marks after a starter fires
    // `StreamSafeOverrun` with `firstOverrun = some (1, 31)` and positions `[1]`.
    #[test]
    fn detect_thirtyone_marks_hazard() {
        let v = detect(&a_plus_marks(31));
        assert!(!v.classify.is_clear());
        assert_eq!(v.classify.tag(), Some("StreamSafeOverrun"));
        assert_eq!(v.classify.positions(), &[1]);
        assert_eq!(
            v.classify,
            Classification::Hazard {
                sub: SubThreat::StreamSafeOverrun {
                    base_pos: 1,
                    run_len: 31,
                },
                positions: vec![1],
                decoded: Vec::new(),
            }
        );
        assert_eq!(v.max_run_len, 31);
        assert_eq!(v.overrun_count, 1);
        assert_eq!(v.total_non_starters, 31);
    }

    // ── Run-inventory structure checks (follow directly from the spec's
    //    `collectRunsGo` / `nonStarterRuns` definitions) ──────────────────────

    // A non-starter run that opens at index 0 (no leading starter) records its
    // start as 0. Firing at the 31st mark of a bare 31-mark run.
    #[test]
    fn bare_mark_run_starts_at_zero() {
        let input: Vec<u32> = std::iter::repeat_n(ACUTE, 31).collect();
        let v = detect(&input);
        assert_eq!(v.classify.tag(), Some("StreamSafeOverrun"));
        assert_eq!(v.classify.positions(), &[0]);
        assert_eq!(v.max_run_len, 31);
        assert_eq!(v.total_non_starters, 31);
    }

    // Two separate runs, each under the limit, stay clear but are both counted
    // in the totals. "a" + 30 marks + "b" + 30 marks.
    #[test]
    fn two_short_runs_clear_totals_summed() {
        let mut input = a_plus_marks(30);
        input.push(0x62);
        input.extend(std::iter::repeat_n(ACUTE, 30));
        let v = detect(&input);
        assert!(v.classify.is_clear());
        assert_eq!(v.max_run_len, 30);
        assert_eq!(v.overrun_count, 0);
        assert_eq!(v.total_non_starters, 60);
    }

    // The first overrun wins: a short run before a long run does not shadow it,
    // and the reported base_pos is the long run's start. "a" + 5 marks + "b" +
    // 31 marks — the run starting at index 7 fires.
    #[test]
    fn first_overrun_reports_long_run_start() {
        let mut input = a_plus_marks(5);
        input.push(0x62);
        input.extend(std::iter::repeat_n(ACUTE, 31));
        let v = detect(&input);
        assert_eq!(v.classify.tag(), Some("StreamSafeOverrun"));
        assert_eq!(v.classify.positions(), &[7]);
        assert_eq!(v.max_run_len, 31);
        assert_eq!(v.overrun_count, 1);
        assert_eq!(v.total_non_starters, 36);
    }
}
