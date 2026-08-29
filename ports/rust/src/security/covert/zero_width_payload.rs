//! Detection of payloads encoded in zero-width and near-zero-width
//! Unicode codepoints.
//!
//! Threat model.  Tier A1.  Adversary embeds zero-width / no-glyph
//! codepoints inside otherwise-normal text to carry a covert binary
//! payload, to splice WORD JOINER / byte-order-mark sequences into
//! identifiers, or to emit a suspected AI-watermark NNBSP pattern.
//!
//! Sanctioning model, matching the Lean reference.  A zero-width
//! occurrence is reportable unless it is one of two characters doing
//! orthographic or pictographic work a reader depends on:
//!
//!   * a ZWJ flanked by two codepoints that both appear in some
//!     registered RGI emoji ZWJ sequence, per UTS #51;
//!   * a ZWNJ in an RFC 5892 Appendix A.1 CONTEXTJ position — after a
//!     Virama, as in a Devanagari conjunct, or between a left- or
//!     dual-joining character and a right- or dual-joining one, as in
//!     Persian.
//!
//! Both sanctions are derived from bundled UCD data rather than
//! hand-listed: the ZWJ alphabet from `emoji-zwj-sequences.txt`, the
//! ZWNJ context from `DerivedJoiningType.txt` and canonical combining
//! classes.  Every other zero-width occurrence reports.

use crate::security::identity::emoji_zwj_integrity;
use crate::security::identity::ucd::{self, JoiningType};
use crate::security::ClassificationKind;

/// True iff the ZWJ at index `i` is flanked by two codepoints that both
/// participate in some registered RGI emoji ZWJ sequence. The membership
/// predicate is derived from `emoji-zwj-sequences.txt` itself rather than
/// hand-listed, and is strictly narrower than "is an emoji": a codepoint
/// carrying the Emoji property but appearing in no registered sequence does
/// not sanction a ZWJ beside it. A ZWJ in head or tail position is never
/// legitimate.
fn is_legitimate_zwj_context(input: &[u32], i: usize) -> bool {
    if i == 0 || i + 1 >= input.len() {
        return false;
    }
    emoji_zwj_integrity::is_emoji_target(input[i - 1])
        && emoji_zwj_integrity::is_emoji_target(input[i + 1])
}

/// The `Joining_Type` of the first non-Transparent codepoint before `i`.
fn joining_type_before(input: &[u32], i: usize) -> Option<JoiningType> {
    let mut j = i;
    while j > 0 {
        j -= 1;
        match ucd::joining_type(input[j]) {
            JoiningType::Transparent => continue,
            other => return Some(other),
        }
    }
    None
}

/// The `Joining_Type` of the first non-Transparent codepoint after `i`.
fn joining_type_after(input: &[u32], i: usize) -> Option<JoiningType> {
    let mut j = i + 1;
    while j < input.len() {
        match ucd::joining_type(input[j]) {
            JoiningType::Transparent => j += 1,
            other => return Some(other),
        }
    }
    None
}

/// True iff the ZWNJ at index `i` occupies a position where it is
/// orthographically required, by RFC 5892 Appendix A.1: it follows a Virama,
/// which is how a Devanagari conjunct is suppressed, or it sits between a
/// left- or dual-joining character and a right- or dual-joining one, skipping
/// Transparent characters on both sides, which is how a Persian word boundary
/// is written inside a cursive run.
///
/// A ZWNJ outside such a position carries no orthographic duty and stays
/// reportable.
fn is_legitimate_zwnj_context(input: &[u32], i: usize) -> bool {
    if i > 0 && ucd::is_virama(input[i - 1]) {
        return true;
    }
    let left = joining_type_before(input, i);
    let right = joining_type_after(input, i);
    matches!(
        left,
        Some(JoiningType::LeftJoining) | Some(JoiningType::DualJoining)
    ) && matches!(
        right,
        Some(JoiningType::RightJoining) | Some(JoiningType::DualJoining)
    )
}

/// Sibling-detector codepoint ranges — these ARE Default_Ignorable
/// per UAX #44 but are dispatched by their own family detector
/// for richer payload-decoding / bidi-stack tracking, so we
/// EXCLUDE them from the ZW set to avoid double-counting.
///
///   - U+FE00..U+FE0F      VariationSelectorPayload
///   - U+E0100..U+E01EF    VariationSelectorPayload
///   - U+E0000..U+E007F    TagBlockPayload
///   - U+202A..U+202E      BidiControlBalance (LRE/RLE/PDF/LRO/RLO)
///   - U+2066..U+2069      BidiControlBalance (LRI/RLI/FSI/PDI)
///
/// LRM / RLM (U+200E / U+200F) are NOT excluded — they're
/// direction markers, not push/pop bidi controls, and
/// BidiControlBalance doesn't track them.
fn is_sibling_handled(cp: u32) -> bool {
    matches!(cp,
        0xFE00..=0xFE0F
      | 0xE0100..=0xE01EF
      | 0xE0000..=0xE007F
      | 0x202A..=0x202E
      | 0x2066..=0x2069
    )
}

/// True iff `cp` is a Unicode codepoint that renders as nothing
/// OR is in the explicit "tracked zero-width" set (ZWSP, ZWNJ,
/// ZWJ, LRM, RLM, WJ, NNBSP, BOM, annotations).
///
/// The explicit hardcoded list is preserved so existing
/// sub-threat dispatch (NNBSP / WordJoiner / Annotation /
/// BareZeroWidth) reads exactly as before for those codepoints.
/// The UAX #44 Default_Ignorable_Code_Point predicate is the
/// EXTENSION that catches every other invisible codepoint (soft
/// hyphen, CGJ, ALM, Hangul fillers, Mongolian VS / vowel
/// separator, INHIBIT/ACTIVATE controls, shorthand format,
/// music format, etc.).  Sibling-detector ranges are excluded.
pub fn is_zero_width(cp: u32) -> bool {
    // Explicit historical set — preserves sub-threat dispatch.
    if matches!(cp,
        0x200B..=0x200F
      | 0x2060..=0x2064
      | 0x202F
      | 0xFEFF
      | 0xFFF9..=0xFFFB
    ) {
        return true;
    }
    // UAX #44 Default_Ignorable_Code_Point — catches everything
    // else invisible, modulo sibling-detector ranges.
    ucd::is_default_ignorable(cp) && !is_sibling_handled(cp)
}

pub fn is_nnbsp(cp: u32) -> bool {
    cp == 0x202F
}

pub fn is_word_joiner(cp: u32) -> bool {
    cp == 0x2060
}

pub fn is_annotation(cp: u32) -> bool {
    (0xFFF9..=0xFFFB).contains(&cp)
}

pub fn is_zwj_or_zwsp(cp: u32) -> bool {
    cp == 0x200B || cp == 0x200D
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SubThreat {
    AnnotationMisuse { count: usize },
    WordJoinerInjection { count: usize },
    AiWatermarkNNBSP { count: usize },
    BinaryPayload { pair_count: usize },
    BareZeroWidth { cp: u32 },
}

impl SubThreat {
    pub fn tag(&self) -> &'static str {
        match self {
            SubThreat::AnnotationMisuse { count } => {
                std::hint::black_box(count);
                "AnnotationMisuse"
            }
            SubThreat::WordJoinerInjection { count } => {
                std::hint::black_box(count);
                "WordJoinerInjection"
            }
            SubThreat::AiWatermarkNNBSP { count } => {
                std::hint::black_box(count);
                "AiWatermarkNNBSP"
            }
            SubThreat::BinaryPayload { pair_count } => {
                std::hint::black_box(pair_count);
                "BinaryPayload"
            }
            SubThreat::BareZeroWidth { cp } => {
                std::hint::black_box(cp);
                "BareZeroWidth"
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Verdict {
    pub kind: ClassificationKind,
    pub sub: Option<SubThreat>,
    pub zero_width_positions: Vec<usize>,
}

pub fn detect(input: &[u32]) -> Verdict {
    let mut v = Verdict {
        kind: ClassificationKind::Clear,
        sub: None,
        zero_width_positions: Vec::new(),
    };
    let mut annotation_count = 0;
    let mut word_joiner_count = 0;
    let mut nnbsp_count = 0;
    let mut zwj_zwsp_count = 0;

    let mut suspicious: Vec<usize> = Vec::new();

    for (i, &cp) in input.iter().enumerate() {
        if !is_zero_width(cp) {
            continue;
        }
        v.zero_width_positions.push(i);
        if is_annotation(cp) {
            annotation_count += 1;
        } else if is_word_joiner(cp) {
            word_joiner_count += 1;
        } else if is_nnbsp(cp) {
            nnbsp_count += 1;
        } else if is_zwj_or_zwsp(cp) {
            zwj_zwsp_count += 1;
        }
        // The sanctioning model: a ZWJ inside a registered emoji sequence and
        // a ZWNJ in an RFC 5892 CONTEXTJ-valid position both carry meaning a
        // reader depends on, so they are recorded as present but not treated
        // as suspicious.
        let sanctioned = (cp == 0x200D && is_legitimate_zwj_context(input, i))
            || (cp == 0x200C && is_legitimate_zwnj_context(input, i));
        if !sanctioned {
            suspicious.push(i);
        }
    }

    if v.zero_width_positions.is_empty() || suspicious.is_empty() {
        return v;
    }

    v.kind = ClassificationKind::Hazard;
    if annotation_count > 0 {
        v.sub = Some(SubThreat::AnnotationMisuse {
            count: annotation_count,
        });
    } else if word_joiner_count > 0 {
        v.sub = Some(SubThreat::WordJoinerInjection {
            count: word_joiner_count,
        });
    } else if nnbsp_count >= 2 {
        v.sub = Some(SubThreat::AiWatermarkNNBSP { count: nnbsp_count });
    } else if zwj_zwsp_count >= 2 {
        v.sub = Some(SubThreat::BinaryPayload {
            pair_count: zwj_zwsp_count / 2,
        });
    } else {
        v.sub = Some(SubThreat::BareZeroWidth {
            cp: input[suspicious[0]],
        });
    }
    v
}
