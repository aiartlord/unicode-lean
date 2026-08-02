//! ai-watermark-detectability — character-level detector for inputs carrying
//! codepoint patterns consistent with a known AI watermark scheme. Answers the
//! question: does this input contain markers attributable to a watermarking
//! protocol?
//!
//! Direct port of `Unicode/Security/Crypto/AiWatermarkDetectability.lean`.
//!
//! Threat model — provenance-attribution attacker. An input either (a) carries
//! an AI provider's watermark codepoints (a legitimate provenance marker) or
//! (b) carries injected markers that impersonate a provider's scheme to
//! discredit the content as AI-generated. Character-level detection alone
//! cannot distinguish (a) from (b); the detector reports the matched scheme and
//! leaves provider-specific authentication to downstream code.
//!
//! Probe inventory (priority order, first match wins):
//!
//!   1. `adversarial`              — NNBSP count >= 3 at arithmetic-progression positions.
//!   2. `gpt5ZwspModulo`           — ZWSP count >= 3 at arithmetic-progression positions.
//!   3. `unknown`                  — invisible markers from >= 2 distinct categories.
//!   4. `nnbspBoundary`            — single-category NNBSP.
//!   5. `variationSelectorCarrier` — VS NOT adjacent to an emoji codepoint.
//!   6. `zwjNonEmoji`              — ZWJ NOT adjacent to an emoji codepoint.
//!   7. `smartQuoteAlternation`    — paired curly quotes, no ASCII straight quotes.
//!   8. `emDashPattern`            — em-dashes, no ASCII hyphen-minus.
//!   9. `statisticalTokenChoice`   — input contains an AI-favored lexical pattern.
//!  10. `defaultIgnorableCarrier`  — single-category residual Default_Ignorable.
//!
//! The Emoji property table is bundled in the port's own `data/emoji-data.txt`
//! (UTS #51 17.0, byte-identical to the UCD source the Lean spec cites); the
//! adjacency probe parses the `Emoji` rows from it, never a host emoji library.

use std::sync::OnceLock;

use crate::security::identity::ucd;

// ─────────────────────────────────────────────────────────────────────
// §1 Types
// ─────────────────────────────────────────────────────────────────────

/// The conceptual watermark cue class a sub-threat probes for, drawn from the
/// fixed vocabulary in `Unicode.Generated.WatermarkSchemes.CueClass`. Ported
/// here because the port exposes no generated watermark-schemes module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CueClass {
    /// A codepoint-frequency bias toward a pinned "green list" of tokens.
    GreenListBias,
    /// A fixed-period or carrier-byte channel surfacing a pseudorandom function.
    PseudorandomSeq,
    /// A stylistic-distribution drift away from natural human writing.
    SemanticDrift,
}

/// Sub-threats this detector can fire. Each variant has a corresponding probe
/// in `detect`; the argument carries the position payload the conformance
/// harness's attribution column reads back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubThreat {
    /// Single-category NNBSP (U+202F) markers; `marker_count` is how many.
    NnbspBoundary {
        /// Count of NNBSP markers.
        marker_count: usize,
    },
    /// Variation selector(s) not adjacent to an emoji; `marker_count` is how many.
    VariationSelectorCarrier {
        /// Count of non-emoji-adjacent variation selectors.
        marker_count: usize,
    },
    /// ZWJ(s) not adjacent to an emoji; `marker_count` is how many.
    ZwjNonEmoji {
        /// Count of non-emoji-adjacent ZWJs.
        marker_count: usize,
    },
    /// Residual Default_Ignorable markers; `marker_count` is how many.
    DefaultIgnorableCarrier {
        /// Count of residual default-ignorable markers.
        marker_count: usize,
    },
    /// ZWSP (U+200B) markers at arithmetic-progression positions; `first_pos`
    /// is the first ZWSP position.
    Gpt5ZwspModulo {
        /// First ZWSP position.
        first_pos: usize,
    },
    /// Em-dash (U+2014) stylistic signature; `first_pos` is the first em-dash.
    EmDashPattern {
        /// First em-dash position.
        first_pos: usize,
    },
    /// Paired curly-quote stylistic signature; `first_pos` is the first quote.
    SmartQuoteAlternation {
        /// First curly-quote position.
        first_pos: usize,
    },
    /// AI-favored lexical pattern hit; `first_pos` is the match start.
    StatisticalTokenChoice {
        /// Start position of the matched vocabulary word.
        first_pos: usize,
    },
    /// Over-regular marker placement impersonating a scheme; `impersonated_scheme`
    /// names the surfaced scheme, `first_pos` the first marker position.
    Adversarial {
        /// The scheme the over-regular placement impersonates.
        impersonated_scheme: String,
        /// First marker position.
        first_pos: usize,
    },
    /// Multi-category invisible-marker mixing; `anomaly_marker` is the total
    /// invisible-marker count (attribution to a single scheme fails).
    Unknown {
        /// Total invisible-marker count across all categories.
        anomaly_marker: usize,
    },
}

impl SubThreat {
    /// Human-facing classification tag for this sub-threat.
    pub fn tag(&self) -> &'static str {
        match self {
            SubThreat::NnbspBoundary { marker_count: _ } => "NnbspBoundary",
            SubThreat::VariationSelectorCarrier { marker_count: _ } => "VariationSelectorCarrier",
            SubThreat::ZwjNonEmoji { marker_count: _ } => "ZwjNonEmoji",
            SubThreat::DefaultIgnorableCarrier { marker_count: _ } => "DefaultIgnorableCarrier",
            SubThreat::Gpt5ZwspModulo { first_pos: _ } => "Gpt5ZwspModulo",
            SubThreat::EmDashPattern { first_pos: _ } => "EmDashPattern",
            SubThreat::SmartQuoteAlternation { first_pos: _ } => "SmartQuoteAlternation",
            SubThreat::StatisticalTokenChoice { first_pos: _ } => "StatisticalTokenChoice",
            SubThreat::Adversarial {
                impersonated_scheme: _,
                first_pos: _,
            } => "Adversarial",
            SubThreat::Unknown { anomaly_marker: _ } => "Unknown",
        }
    }

    /// Map this sub-threat to the conceptual watermark cue class it probes for.
    /// Marker-encoded sub-threats route to `PseudorandomSeq`; vocabulary-bias
    /// to `GreenListBias`; stylistic-distribution to `SemanticDrift`; `Unknown`
    /// (multi-category mixing) implicates no single scheme.
    pub fn cue_class(&self) -> Option<CueClass> {
        match self {
            SubThreat::NnbspBoundary { marker_count: _ }
            | SubThreat::VariationSelectorCarrier { marker_count: _ }
            | SubThreat::ZwjNonEmoji { marker_count: _ }
            | SubThreat::DefaultIgnorableCarrier { marker_count: _ } => Some(CueClass::PseudorandomSeq),
            SubThreat::Gpt5ZwspModulo { first_pos: _ } => Some(CueClass::PseudorandomSeq),
            SubThreat::EmDashPattern { first_pos: _ } => Some(CueClass::SemanticDrift),
            SubThreat::SmartQuoteAlternation { first_pos: _ } => Some(CueClass::SemanticDrift),
            SubThreat::StatisticalTokenChoice { first_pos: _ } => Some(CueClass::GreenListBias),
            SubThreat::Adversarial {
                impersonated_scheme: _,
                first_pos: _,
            } => Some(CueClass::PseudorandomSeq),
            SubThreat::Unknown { anomaly_marker: _ } => None,
        }
    }
}

/// Top-level AiWatermarkDetectability classification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Classification {
    /// No watermark marker detected (semantically `noWatermark`).
    Clear,
    /// A hazard: the fired sub-threat plus the implicated marker positions.
    Hazard {
        /// The sub-threat that fired.
        sub: SubThreat,
        /// The codepoint positions the sub-threat implicates.
        positions: Vec<usize>,
    },
}

impl Classification {
    /// True iff no watermark marker was detected.
    pub fn is_clear(&self) -> bool {
        match self {
            Classification::Clear => true,
            Classification::Hazard { sub: _, positions: _ } => false,
        }
    }

    /// Human-facing tag for a hazard, or `None` when clear.
    pub fn tag(&self) -> Option<&'static str> {
        match self {
            Classification::Clear => None,
            Classification::Hazard { sub, positions: _ } => Some(sub.tag()),
        }
    }

    /// Implicated positions ( empty when clear ).
    pub fn positions(&self) -> &[usize] {
        match self {
            Classification::Clear => &[],
            Classification::Hazard { sub: _, positions } => positions,
        }
    }
}

/// AiWatermarkDetectability verdict — the structured output of `detect`.
/// `marker_count` is the count of codepoints matching the fired scheme's probe
/// (0 when clear).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    /// The scanned input codepoints.
    pub input: Vec<u32>,
    /// The classification verdict.
    pub classify: Classification,
    /// Count of codepoints matching the fired scheme (0 when clear).
    pub marker_count: usize,
}

/// Optional context for the modulo-probe tolerances. Each field controls how
/// strictly the corresponding probe checks its arithmetic-progression
/// condition; the defaults of `0` require exact equality of consecutive gaps.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Context {
    /// ZWSP-modulo tolerance. `0` requires the ZWSP-position arithmetic
    /// progression to be exact. `k > 0` accepts position gaps within +/- k of
    /// the first gap, catching modulo schedules with light jitter.
    pub zwsp_modulo_tolerance: usize,
    /// NNBSP-arithmetic tolerance (the `adversarial` probe). Same semantic as
    /// `zwsp_modulo_tolerance` but for the NNBSP positions.
    pub adversarial_tolerance: usize,
}

// ─────────────────────────────────────────────────────────────────────
// §2 Emoji property table (bundled data/emoji-data.txt, Emoji rows)
// ─────────────────────────────────────────────────────────────────────

const EMOJI_DATA_RAW: &str = include_str!("../../../data/emoji-data.txt");

/// Parse the `Emoji` (`Emoji=Yes`) closed intervals from emoji-data.txt. Each
/// non-comment row is `<range> ; <property> # <comment>`; we keep only rows
/// whose property is exactly `Emoji`.
fn parse_emoji_ranges() -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    for raw_line in EMOJI_DATA_RAW.lines() {
        let body = match raw_line.find('#') {
            Some(idx) => &raw_line[..idx],
            None => raw_line,
        };
        let stripped = body.trim();
        if stripped.is_empty() {
            continue;
        }
        let mut fields = stripped.split(';');
        let (Some(range_field), Some(prop_field)) = (fields.next(), fields.next()) else {
            continue;
        };
        if prop_field.trim() != "Emoji" {
            continue;
        }
        let range = range_field.trim();
        let (lo, hi) = match range.split_once("..") {
            Some((a, b)) => {
                let (Some(a), Some(b)) =
                    (u32::from_str_radix(a.trim(), 16).ok(), u32::from_str_radix(b.trim(), 16).ok())
                else {
                    continue;
                };
                (a, b)
            }
            None => match u32::from_str_radix(range, 16) {
                Ok(single) => (single, single),
                Err(_parse_error) => continue,
            },
        };
        out.push((lo, hi));
    }
    out
}

fn emoji_ranges() -> &'static Vec<(u32, u32)> {
    static T: OnceLock<Vec<(u32, u32)>> = OnceLock::new();
    T.get_or_init(parse_emoji_ranges)
}

/// True iff `cp` has the `Emoji = Yes` property per emoji-data.txt.
fn is_emoji(cp: u32) -> bool {
    emoji_ranges().iter().any(|&(lo, hi)| lo <= cp && cp <= hi)
}

// ─────────────────────────────────────────────────────────────────────
// §3 Codepoint probes
// ─────────────────────────────────────────────────────────────────────

/// True iff `cp` is U+202F NARROW NO-BREAK SPACE.
fn is_nnbsp(cp: u32) -> bool {
    cp == 0x202F
}

/// True iff `cp` is U+200D ZERO WIDTH JOINER.
fn is_zwj(cp: u32) -> bool {
    cp == 0x200D
}

/// True iff `cp` is a Variation Selector — the basic block U+FE00..U+FE0F
/// (VS1..VS16) or the Plane-14 IVS block U+E0100..U+E01EF (VS17..VS256).
fn is_variation_selector(cp: u32) -> bool {
    (0xFE00..=0xFE0F).contains(&cp) || (0xE0100..=0xE01EF).contains(&cp)
}

/// True iff `cp` is Default_Ignorable_Code_Point per DerivedCoreProperties.txt.
/// Reuses the port's own UCD table, never a host normalizer.
fn is_default_ignorable(cp: u32) -> bool {
    ucd::is_default_ignorable(cp)
}

/// True iff `cp` is U+200B ZERO WIDTH SPACE.
fn is_zwsp(cp: u32) -> bool {
    cp == 0x200B
}

/// True iff `cp` is U+2014 EM DASH.
fn is_em_dash(cp: u32) -> bool {
    cp == 0x2014
}

/// True iff `cp` is U+002D HYPHEN-MINUS (ASCII).
fn is_hyphen_minus(cp: u32) -> bool {
    cp == 0x002D
}

/// True iff `cp` is one of the four "curly" quotation marks: U+2018 / U+2019
/// (single open/close) and U+201C / U+201D (double open/close).
fn is_curly_quote(cp: u32) -> bool {
    cp == 0x2018 || cp == 0x2019 || cp == 0x201C || cp == 0x201D
}

/// True iff `cp` is an ASCII straight quote — U+0022 (double) or U+0027
/// (single / apostrophe).
fn is_straight_quote(cp: u32) -> bool {
    cp == 0x0022 || cp == 0x0027
}

/// True iff `input[i]` is adjacent (immediate predecessor OR immediate
/// successor) to an emoji codepoint. Two-sided check, single pass. Used by the
/// VS and ZWJ probes to exclude legitimate emoji-context occurrences.
fn is_adjacent_to_emoji(input: &[u32], i: usize) -> bool {
    let prev_is_emoji = match i {
        0 => false,
        _nonzero => match input.get(i - 1) {
            Some(&cp) => is_emoji(cp),
            None => false,
        },
    };
    let next_is_emoji = match input.get(i + 1) {
        Some(&cp) => is_emoji(cp),
        None => false,
    };
    prev_is_emoji || next_is_emoji
}

/// All positions in `input` matching predicate `p`.
fn all_positions(p: impl Fn(u32) -> bool, input: &[u32]) -> Vec<usize> {
    input
        .iter()
        .enumerate()
        .filter_map(|(idx, &cp)| if p(cp) { Some(idx) } else { None })
        .collect()
}

/// True iff `positions` forms an arithmetic progression with all consecutive
/// gaps within `tolerance` of the first gap. Empty + singleton lists are
/// vacuously arithmetic. `positions` is assumed ascending (produced by
/// `all_positions`), so gaps are non-negative.
fn positions_are_arithmetic_within(positions: &[usize], tolerance: usize) -> bool {
    if positions.len() < 2 {
        return true;
    }
    let first_gap = positions[1] - positions[0];
    (0..positions.len() - 1).all(|i| {
        let gap = positions[i + 1] - positions[i];
        gap <= first_gap + tolerance && first_gap <= gap + tolerance
    })
}

/// First start-position at which `pattern` appears as a contiguous sub-slice of
/// `input`, or `None` if absent.
fn contains_sublist(pattern: &[u32], input: &[u32]) -> Option<usize> {
    if pattern.is_empty() || pattern.len() > input.len() {
        return None;
    }
    let max_start = input.len() - pattern.len();
    (0..=max_start).find(|&start| input[start..start + pattern.len()] == *pattern)
}

/// The "AI-favored" lexical-pattern catalog (each word as its codepoint
/// sequence), transcribed verbatim from the pinned `aiFavoredVocabulary`
/// literal in the Lean spec (parsed from `Ucd/Security/AiFavoredVocabulary.txt`
/// and drift-gated there against a fresh parse).
fn ai_favored_vocabulary() -> &'static [&'static [u32]] {
    &[
        &[100, 101, 108, 118, 101],
        &[100, 101, 108, 118, 105, 110, 103],
        &[116, 97, 112, 101, 115, 116, 114, 121],
        &[105, 110, 116, 114, 105, 99, 97, 116, 101],
        &[110, 117, 97, 110, 99, 101, 100],
        &[109, 111, 114, 101, 111, 118, 101, 114],
        &[102, 117, 114, 116, 104, 101, 114, 109, 111, 114, 101],
        &[114, 101, 97, 108, 109],
        &[101, 108, 117, 99, 105, 100, 97, 116, 101],
        &[115, 104, 111, 119, 99, 97, 115, 105, 110, 103],
        &[117, 110, 100, 101, 114, 115, 99, 111, 114, 101, 115],
        &[117, 110, 100, 101, 114, 115, 99, 111, 114, 101, 100],
        &[112, 105, 118, 111, 116, 97, 108],
        &[98, 111, 108, 115, 116, 101, 114],
        &[109, 117, 108, 116, 105, 102, 97, 99, 101, 116, 101, 100],
        &[116, 101, 115, 116, 97, 109, 101, 110, 116],
        &[102, 111, 115, 116, 101, 114],
        &[104, 111, 108, 105, 115, 116, 105, 99],
        &[112, 97, 114, 97, 100, 105, 103, 109],
        &[116, 114, 97, 110, 115, 102, 111, 114, 109, 97, 116, 105, 118, 101],
        &[115, 112, 101, 97, 114, 104, 101, 97, 100],
        &[109, 101, 116, 105, 99, 117, 108, 111, 117, 115],
        &[109, 101, 116, 105, 99, 117, 108, 111, 117, 115, 108, 121],
        &[101, 109, 112, 111, 119, 101, 114],
        &[101, 109, 112, 111, 119, 101, 114, 105, 110, 103],
        &[112, 114, 111, 102, 111, 117, 110, 100],
        &[112, 114, 111, 102, 111, 117, 110, 100, 108, 121],
        &[99, 111, 109, 112, 101, 108, 108, 105, 110, 103],
        &[99, 111, 109, 112, 114, 101, 104, 101, 110, 115, 105, 118, 101],
        &[99, 114, 117, 99, 105, 97, 108],
        &[100, 97, 117, 110, 116, 105, 110, 103],
        &[114, 111, 98, 117, 115, 116],
        &[115, 116, 114, 101, 97, 109, 108, 105, 110, 101],
        &[101, 110, 114, 105, 99, 104],
        &[101, 120, 101, 109, 112, 108, 105, 102, 121],
        &[99, 97, 112, 116, 105, 118, 97, 116, 105, 110, 103],
        &[100, 105, 115, 99, 101, 114, 110, 105, 110, 103],
        &[109, 101, 115, 109, 101, 114, 105, 122, 101],
        &[105, 110, 116, 114, 105, 99, 97, 116, 101, 108, 121],
        &[105, 109, 98, 117, 101],
        &[
            112, 108, 97, 121, 115, 32, 97, 32, 99, 114, 117, 99, 105, 97, 108, 32, 114, 111, 108,
            101,
        ],
        &[
            112, 108, 97, 121, 115, 32, 97, 32, 112, 105, 118, 111, 116, 97, 108, 32, 114, 111,
            108, 101,
        ],
        &[
            105, 116, 32, 105, 115, 32, 105, 109, 112, 111, 114, 116, 97, 110, 116, 32, 116, 111,
            32, 110, 111, 116, 101,
        ],
        &[
            105, 116, 32, 105, 115, 32, 119, 111, 114, 116, 104, 32, 110, 111, 116, 105, 110, 103,
        ],
        &[105, 110, 32, 99, 111, 110, 99, 108, 117, 115, 105, 111, 110],
        &[105, 110, 32, 101, 115, 115, 101, 110, 99, 101],
        &[100, 101, 108, 118, 101, 32, 105, 110, 116, 111],
        &[100, 101, 108, 118, 105, 110, 103, 32, 105, 110, 116, 111],
        &[116, 97, 112, 101, 115, 116, 114, 121, 32, 111, 102],
        &[114, 101, 97, 108, 109, 32, 111, 102],
    ]
}

// ─────────────────────────────────────────────────────────────────────
// §4 Top-level detection
// ─────────────────────────────────────────────────────────────────────

/// The detection function. Runs every probe in the fixed priority order
/// (most-specific first); the first hit wins. See the module header for the
/// probe inventory and the ordering rationale.
pub fn detect_with_context(ctx: &Context, input: &[u32]) -> Verdict {
    let nnbsp_positions = all_positions(is_nnbsp, input);
    let nnbsp_count = nnbsp_positions.len();

    // Probe 1: adversarial — NNBSP too-regular.
    let adversarial_fires = nnbsp_count >= 3
        && positions_are_arithmetic_within(&nnbsp_positions, ctx.adversarial_tolerance);

    // Probe 2: gpt5ZwspModulo — ZWSP arithmetic progression.
    let zwsp_positions = all_positions(is_zwsp, input);
    let zwsp_count = zwsp_positions.len();
    let zwsp_modulo_fires = zwsp_count >= 3
        && positions_are_arithmetic_within(&zwsp_positions, ctx.zwsp_modulo_tolerance);

    let vs_all_pos = all_positions(is_variation_selector, input);
    let vs_non_emoji_pos: Vec<usize> = vs_all_pos
        .into_iter()
        .filter(|&i| !is_adjacent_to_emoji(input, i))
        .collect();
    let vs_non_emoji_count = vs_non_emoji_pos.len();

    let zwj_all_pos = all_positions(is_zwj, input);
    let zwj_non_emoji_pos: Vec<usize> = zwj_all_pos
        .into_iter()
        .filter(|&i| !is_adjacent_to_emoji(input, i))
        .collect();
    let zwj_non_emoji_count = zwj_non_emoji_pos.len();

    // Probe 7: smartQuoteAlternation — curly quotes only.
    let curly_positions = all_positions(is_curly_quote, input);
    let curly_count = curly_positions.len();
    let has_straight_quote = input.iter().any(|&cp| is_straight_quote(cp));
    let smart_quote_fires = curly_count >= 2 && !has_straight_quote;

    // Probe 8: emDashPattern — em-dashes without hyphen-minus.
    let em_dash_positions = all_positions(is_em_dash, input);
    let em_dash_count = em_dash_positions.len();
    let has_hyphen_minus = input.iter().any(|&cp| is_hyphen_minus(cp));
    let em_dash_fires = em_dash_count >= 2 && !has_hyphen_minus;

    // Probe 9: statisticalTokenChoice — scan the pinned vocabulary. Each word is
    // compared as a contiguous sub-slice of the input.
    let vocab_hit = ai_favored_vocabulary()
        .iter()
        .find_map(|pattern| contains_sublist(pattern, input));

    // Residual default-ignorables (excluding VS and ZWJ, handled above).
    let is_residual_di =
        |cp: u32| is_default_ignorable(cp) && !is_variation_selector(cp) && !is_zwj(cp);
    let di_positions = all_positions(is_residual_di, input);
    let di_count = di_positions.len();

    // Probe 3: unknown — invisible markers from >= 2 distinct categories.
    let category_count = usize::from(nnbsp_count > 0)
        + usize::from(vs_non_emoji_count > 0)
        + usize::from(zwj_non_emoji_count > 0)
        + usize::from(di_count > 0);
    let unknown_fires = category_count >= 2;
    let total_invisible_count = nnbsp_count + vs_non_emoji_count + zwj_non_emoji_count + di_count;

    let (classification, fired_count): (Classification, usize) = if adversarial_fires {
        let first_pos = nnbsp_positions.first().copied().unwrap_or(0);
        (
            Classification::Hazard {
                sub: SubThreat::Adversarial {
                    impersonated_scheme: "nnbspBoundary".to_string(),
                    first_pos,
                },
                positions: nnbsp_positions,
            },
            nnbsp_count,
        )
    } else if zwsp_modulo_fires {
        let first_pos = zwsp_positions.first().copied().unwrap_or(0);
        (
            Classification::Hazard {
                sub: SubThreat::Gpt5ZwspModulo { first_pos },
                positions: zwsp_positions,
            },
            zwsp_count,
        )
    } else if unknown_fires {
        let all_invisible_pos: Vec<usize> = input
            .iter()
            .enumerate()
            .filter_map(|(idx, &cp)| {
                if is_nnbsp(cp)
                    || is_variation_selector(cp)
                    || is_zwj(cp)
                    || is_default_ignorable(cp)
                {
                    Some(idx)
                } else {
                    None
                }
            })
            .collect();
        (
            Classification::Hazard {
                sub: SubThreat::Unknown {
                    anomaly_marker: total_invisible_count,
                },
                positions: all_invisible_pos,
            },
            total_invisible_count,
        )
    } else if nnbsp_count > 0 {
        (
            Classification::Hazard {
                sub: SubThreat::NnbspBoundary {
                    marker_count: nnbsp_count,
                },
                positions: nnbsp_positions,
            },
            nnbsp_count,
        )
    } else if vs_non_emoji_count > 0 {
        (
            Classification::Hazard {
                sub: SubThreat::VariationSelectorCarrier {
                    marker_count: vs_non_emoji_count,
                },
                positions: vs_non_emoji_pos,
            },
            vs_non_emoji_count,
        )
    } else if zwj_non_emoji_count > 0 {
        (
            Classification::Hazard {
                sub: SubThreat::ZwjNonEmoji {
                    marker_count: zwj_non_emoji_count,
                },
                positions: zwj_non_emoji_pos,
            },
            zwj_non_emoji_count,
        )
    } else if smart_quote_fires {
        let first_pos = curly_positions.first().copied().unwrap_or(0);
        (
            Classification::Hazard {
                sub: SubThreat::SmartQuoteAlternation { first_pos },
                positions: curly_positions,
            },
            curly_count,
        )
    } else if em_dash_fires {
        let first_pos = em_dash_positions.first().copied().unwrap_or(0);
        (
            Classification::Hazard {
                sub: SubThreat::EmDashPattern { first_pos },
                positions: em_dash_positions,
            },
            em_dash_count,
        )
    } else if let Some(pos) = vocab_hit {
        (
            Classification::Hazard {
                sub: SubThreat::StatisticalTokenChoice { first_pos: pos },
                positions: vec![pos],
            },
            1,
        )
    } else if di_count > 0 {
        (
            Classification::Hazard {
                sub: SubThreat::DefaultIgnorableCarrier {
                    marker_count: di_count,
                },
                positions: di_positions,
            },
            di_count,
        )
    } else {
        (Classification::Clear, 0)
    };

    Verdict {
        input: input.to_vec(),
        classify: classification,
        marker_count: fired_count,
    }
}

/// Convenience wrapper over `detect_with_context` with the empty context —
/// exact-arithmetic settings (`zwsp_modulo_tolerance = 0`,
/// `adversarial_tolerance = 0`).
pub fn detect(input: &[u32]) -> Verdict {
    detect_with_context(&Context::default(), input)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ground truth: every probe spot-check, `detect_*`, priority, tolerance, and
    // cue-class theorem in `Unicode/Security/Crypto/AiWatermarkDetectability.lean`.
    // Each Lean theorem maps to one `#[test]` below; a theorem asserting multiple
    // conjuncts maps to one assertion per conjunct.

    fn tag(input: &[u32]) -> Option<&'static str> {
        detect(input).classify.tag()
    }

    // ── §4 probe spot checks ────────────────────────────────────────────

    #[test]
    fn is_nnbsp_checks() {
        assert!(is_nnbsp(0x202F));
        assert!(!is_nnbsp(0x20));
        assert!(!is_nnbsp(0x3000));
    }

    #[test]
    fn is_zwj_checks() {
        assert!(is_zwj(0x200D));
        assert!(!is_zwj(0x200B));
        assert!(!is_zwj(0x200C));
    }

    #[test]
    fn is_vs_checks() {
        assert!(is_variation_selector(0xFE00));
        assert!(is_variation_selector(0xFE0F));
        assert!(is_variation_selector(0xE0100));
        assert!(!is_variation_selector(0x61));
        assert!(!is_variation_selector(0x200D));
    }

    #[test]
    fn is_default_ignorable_checks() {
        assert!(is_default_ignorable(0x200B));
        assert!(is_default_ignorable(0x200D));
        assert!(is_default_ignorable(0x00AD));
        assert!(!is_default_ignorable(0x202F));
        assert!(!is_default_ignorable(0x61));
    }

    #[test]
    fn is_emoji_checks() {
        assert!(is_emoji(0x1F600));
        assert!(!is_emoji(0x200D));
        assert!(!is_emoji(0x61));
    }

    #[test]
    fn is_adjacent_to_emoji_negative() {
        assert!(!is_adjacent_to_emoji(&[0x61, 0xFE0F, 0x62], 1));
    }

    #[test]
    fn is_adjacent_to_emoji_after_smiley() {
        assert!(is_adjacent_to_emoji(&[0x1F600, 0xFE0F], 1));
    }

    #[test]
    fn is_adjacent_to_emoji_before_smiley() {
        assert!(is_adjacent_to_emoji(&[0xFE0F, 0x1F600], 0));
    }

    // ── §6 detect spot checks ───────────────────────────────────────────

    #[test]
    fn detect_empty_clear() {
        assert_eq!(detect(&[]).classify, Classification::Clear);
    }

    #[test]
    fn detect_ascii_clear() {
        assert_eq!(detect(&[0x61, 0x62, 0x63]).classify, Classification::Clear);
    }

    #[test]
    fn detect_han_clear() {
        assert_eq!(detect(&[0x4E2D, 0x6587]).classify, Classification::Clear);
    }

    #[test]
    fn detect_nnbsp_fires() {
        let v = detect(&[0x61, 0x202F, 0x62]);
        assert_eq!(v.classify.tag(), Some("NnbspBoundary"));
        assert_eq!(v.classify.positions(), &[1]);
        assert_eq!(v.marker_count, 1);
    }

    #[test]
    fn detect_vs_in_plain_text_fires() {
        let v = detect(&[0x61, 0xFE0F, 0x62]);
        assert_eq!(v.classify.tag(), Some("VariationSelectorCarrier"));
        assert_eq!(v.marker_count, 1);
    }

    #[test]
    fn detect_vs_after_emoji_clear() {
        assert_eq!(detect(&[0x1F600, 0xFE0F]).classify, Classification::Clear);
    }

    #[test]
    fn detect_zwj_in_plain_text_fires() {
        let v = detect(&[0x61, 0x200D, 0x62]);
        assert_eq!(v.classify.tag(), Some("ZwjNonEmoji"));
        assert_eq!(v.marker_count, 1);
    }

    #[test]
    fn detect_zwj_emoji_sequence_clear() {
        assert_eq!(
            detect(&[0x1F469, 0x200D, 0x1F52C]).classify,
            Classification::Clear
        );
    }

    #[test]
    fn detect_soft_hyphen_fires() {
        let v = detect(&[0x61, 0x00AD, 0x62]);
        assert_eq!(v.classify.tag(), Some("DefaultIgnorableCarrier"));
        assert_eq!(v.marker_count, 1);
    }

    #[test]
    fn detect_zwsp_fires() {
        let v = detect(&[0x61, 0x200B, 0x62]);
        assert_eq!(v.classify.tag(), Some("DefaultIgnorableCarrier"));
        assert_eq!(v.marker_count, 1);
    }

    #[test]
    fn detect_priority_unknown_over_nnbsp_with_di() {
        assert_eq!(tag(&[0x61, 0x202F, 0x00AD, 0x62]), Some("Unknown"));
    }

    #[test]
    fn detect_priority_unknown_over_vs_with_zwj() {
        assert_eq!(tag(&[0x61, 0xFE0F, 0x200D, 0x62]), Some("Unknown"));
    }

    #[test]
    fn detect_multiple_nnbsp_aggregates() {
        let v = detect(&[0x61, 0x202F, 0x62, 0x202F, 0x63]);
        assert_eq!(v.classify.tag(), Some("NnbspBoundary"));
        assert_eq!(v.marker_count, 2);
        assert_eq!(v.classify.positions(), &[1, 3]);
    }

    // ── §7 refinement-probe spot checks ─────────────────────────────────

    #[test]
    fn detect_adversarial_arithmetic_nnbsp() {
        let v = detect(&[0x61, 0x202F, 0x62, 0x202F, 0x63, 0x202F, 0x64]);
        assert_eq!(v.classify.tag(), Some("Adversarial"));
        assert_eq!(v.marker_count, 3);
    }

    #[test]
    fn detect_nnbsp_two_below_adversarial_threshold() {
        assert_eq!(
            tag(&[0x61, 0x202F, 0x62, 0x202F, 0x63]),
            Some("NnbspBoundary")
        );
    }

    #[test]
    fn detect_gpt5_zwsp_modulo() {
        let v = detect(&[0x61, 0x200B, 0x62, 0x200B, 0x63, 0x200B, 0x64]);
        assert_eq!(v.classify.tag(), Some("Gpt5ZwspModulo"));
        assert_eq!(v.marker_count, 3);
    }

    #[test]
    fn detect_zwsp_two_below_modulo_threshold() {
        assert_eq!(
            tag(&[0x61, 0x200B, 0x62, 0x200B, 0x63]),
            Some("DefaultIgnorableCarrier")
        );
    }

    #[test]
    fn detect_smart_quote_alternation() {
        let v = detect(&[0x201C, 0x61, 0x62, 0x63, 0x201D]);
        assert_eq!(v.classify.tag(), Some("SmartQuoteAlternation"));
        assert_eq!(v.marker_count, 2);
    }

    #[test]
    fn detect_smart_quote_with_straight_clear() {
        assert_eq!(
            detect(&[0x201C, 0x61, 0x22, 0x201D]).classify,
            Classification::Clear
        );
    }

    #[test]
    fn detect_em_dash_pattern() {
        let v = detect(&[
            0x61, 0x62, 0x20, 0x2014, 0x20, 0x63, 0x64, 0x20, 0x2014, 0x20, 0x65, 0x66,
        ]);
        assert_eq!(v.classify.tag(), Some("EmDashPattern"));
        assert_eq!(v.marker_count, 2);
    }

    #[test]
    fn detect_em_dash_with_hyphen_clear() {
        assert_eq!(
            detect(&[0x61, 0x62, 0x2D, 0x63, 0x64, 0x20, 0x2014, 0x20, 0x65, 0x66]).classify,
            Classification::Clear
        );
    }

    #[test]
    fn detect_statistical_token_delve() {
        let v = detect(&[0x64, 0x65, 0x6C, 0x76, 0x65]);
        assert_eq!(v.classify.tag(), Some("StatisticalTokenChoice"));
        assert_eq!(v.marker_count, 1);
    }

    #[test]
    fn detect_statistical_token_moreover_embedded() {
        let v = detect(&[
            0x3B, 0x20, 0x6D, 0x6F, 0x72, 0x65, 0x6F, 0x76, 0x65, 0x72, 0x2C, 0x20,
        ]);
        assert_eq!(v.classify.tag(), Some("StatisticalTokenChoice"));
        assert_eq!(v.classify.positions(), &[2]);
    }

    #[test]
    fn detect_unknown_nnbsp_plus_di() {
        let v = detect(&[0x61, 0x202F, 0x00AD, 0x62]);
        assert_eq!(v.classify.tag(), Some("Unknown"));
        assert_eq!(v.marker_count, 2);
    }

    #[test]
    fn detect_unknown_vs_plus_zwj() {
        let v = detect(&[0x61, 0xFE0F, 0x200D, 0x62]);
        assert_eq!(v.classify.tag(), Some("Unknown"));
        assert_eq!(v.marker_count, 2);
    }

    #[test]
    fn detect_unknown_nnbsp_plus_zwj() {
        let v = detect(&[0x61, 0x202F, 0x200D, 0x62]);
        assert_eq!(v.classify.tag(), Some("Unknown"));
        assert_eq!(v.marker_count, 2);
    }

    #[test]
    fn detect_single_category_skips_unknown() {
        assert_eq!(tag(&[0x61, 0x202F, 0x62]), Some("NnbspBoundary"));
    }

    #[test]
    fn detect_priority_adversarial_over_nnbsp() {
        assert_eq!(
            tag(&[0x61, 0x202F, 0x62, 0x202F, 0x63, 0x202F, 0x64]),
            Some("Adversarial")
        );
    }

    #[test]
    fn detect_priority_zwsp_modulo_over_di() {
        assert_eq!(
            tag(&[0x61, 0x200B, 0x62, 0x200B, 0x63, 0x200B, 0x64]),
            Some("Gpt5ZwspModulo")
        );
    }

    // ── §8 tolerance-parameterised probes ───────────────────────────────

    #[test]
    fn detect_zwsp_jittered_strict_clear() {
        // ZWSPs at 1, 3, 6 (gaps 2, 3). Bare detect (tolerance 0) does not fire
        // gpt5ZwspModulo; falls through to defaultIgnorableCarrier.
        let input = [0x61, 0x200B, 0x62, 0x200B, 0x63, 0x64, 0x200B, 0x65];
        assert_eq!(tag(&input), Some("DefaultIgnorableCarrier"));
    }

    #[test]
    fn detect_zwsp_jittered_tolerant_fires() {
        let input = [0x61, 0x200B, 0x62, 0x200B, 0x63, 0x64, 0x200B, 0x65];
        let ctx = Context {
            zwsp_modulo_tolerance: 1,
            ..Context::default()
        };
        let v = detect_with_context(&ctx, &input);
        assert_eq!(v.classify.tag(), Some("Gpt5ZwspModulo"));
    }

    #[test]
    fn detect_with_context_default_matches_detect() {
        let d = detect(&[0x61, 0x202F, 0x62]);
        let c = detect_with_context(&Context::default(), &[0x61, 0x202F, 0x62]);
        assert_eq!(c.classify, d.classify);
    }

    // ── §7 cue-class coverage ───────────────────────────────────────────

    #[test]
    fn every_cue_class_is_probed() {
        let classes = [
            CueClass::GreenListBias,
            CueClass::PseudorandomSeq,
            CueClass::SemanticDrift,
        ];
        let sub_threats = [
            SubThreat::NnbspBoundary { marker_count: 0 },
            SubThreat::VariationSelectorCarrier { marker_count: 0 },
            SubThreat::ZwjNonEmoji { marker_count: 0 },
            SubThreat::DefaultIgnorableCarrier { marker_count: 0 },
            SubThreat::Gpt5ZwspModulo { first_pos: 0 },
            SubThreat::EmDashPattern { first_pos: 0 },
            SubThreat::SmartQuoteAlternation { first_pos: 0 },
            SubThreat::StatisticalTokenChoice { first_pos: 0 },
            SubThreat::Adversarial {
                impersonated_scheme: String::new(),
                first_pos: 0,
            },
        ];
        for cls in classes {
            assert!(
                sub_threats.iter().any(|st| st.cue_class() == Some(cls)),
                "cue class {cls:?} is not probed by any sub-threat"
            );
        }
    }

    // The `Unknown` sub-threat maps to no single cue class.
    #[test]
    fn unknown_has_no_cue_class() {
        assert_eq!(SubThreat::Unknown { anomaly_marker: 0 }.cue_class(), None);
    }
}
