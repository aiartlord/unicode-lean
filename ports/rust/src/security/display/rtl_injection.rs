//! Right-to-left injection detection for left-to-right-declared fields.
//!
//! Threat model.  Tier A1.  An adversary places strong-RTL codepoints
//! (Hebrew, Arabic, …) or bidi format-controls (RLO, LRO, PDF, the
//! isolates) into a field the surrounding UI declares left-to-right —
//! a username box, a filename, a source-code token.  A bidi-aware
//! renderer reorders the visible glyphs, so what the reviewer reads
//! differs from the logical byte order the machine acts on.
//!
//! This is a direct port of `Unicode/Security/Display/RtlInjection.lean`.
//! The four sub-threats, their priority, and the reported positions
//! match that module's `detect` exactly; the strong-RTL / strong-LTR
//! predicates read `Bidi_Class` from the bundled `UnicodeData.txt`
//! (see [`ucd::is_strong_rtl`]), mirroring the spec's `lookupBidiClass`.

use crate::security::covert::bidi_control_balance::is_bidi_format_control;
use crate::security::identity::ucd;

/// The classification of one RTL-injection scan.  `sub` is `None` for a
/// clear input; otherwise it carries the fixture-row tag of the single
/// highest-priority sub-threat that fired, with the offending positions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Detection {
    pub sub: Option<&'static str>,
    pub positions: Vec<usize>,
}

impl Detection {
    fn clear() -> Self {
        Detection {
            sub: None,
            positions: Vec::new(),
        }
    }

    fn hazard(tag: &'static str, positions: Vec<usize>) -> Self {
        Detection {
            sub: Some(tag),
            positions,
        }
    }
}

/// Count of strong-RTL codepoints in `input`.
fn count_strong_rtl(input: &[u32]) -> usize {
    input.iter().filter(|&&cp| ucd::is_strong_rtl(cp)).count()
}

/// Position of the first bidi format-control in `input`.
fn first_bidi_control_pos(input: &[u32]) -> Option<usize> {
    input.iter().position(|&cp| is_bidi_format_control(cp))
}

/// Position, codepoint, and RTL-ness of the first strong (L, R, or AL)
/// codepoint in `input`.
fn first_strong_char(input: &[u32]) -> Option<(usize, bool)> {
    input.iter().enumerate().find_map(|(idx, &cp)| {
        if ucd::is_strong_rtl(cp) {
            Some((idx, true))
        } else if ucd::is_strong_ltr(cp) {
            Some((idx, false))
        } else {
            None
        }
    })
}

/// Position of the first strong-RTL codepoint in `input`.
fn first_strong_rtl_pos(input: &[u32]) -> Option<usize> {
    input.iter().position(|&cp| ucd::is_strong_rtl(cp))
}

/// Length of the longest consecutive run of strong-RTL codepoints in
/// `input`, together with that run's starting position; `(0, 0)` when
/// there are no strong-RTL codepoints.
fn longest_rtl_run(input: &[u32]) -> (usize, usize) {
    let mut longest = 0;
    let mut longest_start = 0;
    let mut current = 0;
    let mut current_start = 0;
    for (idx, &cp) in input.iter().enumerate() {
        if ucd::is_strong_rtl(cp) {
            let new_start = if current == 0 { idx } else { current_start };
            current += 1;
            current_start = new_start;
            if current > longest {
                longest = current;
                longest_start = new_start;
            }
        } else {
            current = 0;
        }
    }
    (longest, longest_start)
}

/// Phase 3 of the spec: a mid-stream strong-RTL codepoint in a field
/// that did not lead with one.  A run of four or more is a mixed-overflow
/// takeover; a shorter run is a single mid-stream strong-RTL hazard.
fn phase3(input: &[u32], strong_rtl: usize, run_len: usize, run_start: usize) -> Detection {
    if strong_rtl == 0 {
        return Detection::clear();
    }
    if run_len >= 4 {
        return Detection::hazard("MixedOverflow", vec![run_start]);
    }
    match first_strong_rtl_pos(input) {
        Some(pos) => Detection::hazard("StrongRTLInLTR", vec![pos]),
        // Unreachable when strong_rtl > 0.
        None => Detection::clear(),
    }
}

/// The declared display direction of the field holding an input.
///
/// A caller handling Hebrew, Arabic or Persian UI text declares its field
/// right-to-left. Every other reading treats the input as a declared-LTR
/// string, under which right-to-left content is itself the hazard.
///
/// Mirrors `FieldDirection` in `Unicode/Security/Display/RtlInjection.lean`,
/// which is that spec's alias for the UAX #9 paragraph-direction vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FieldDirection {
    #[default]
    Ltr,
    Rtl,
}

/// Detect right-to-left injection in a field whose declared display direction
/// is `direction`.
///
/// A bidi format control reorders what a reviewer sees whichever way the field
/// runs, so Phase 1 holds unconditionally and trumps all.
///
/// Phases 2 and 3 ask whether right-to-left text has taken over or been spliced
/// into a left-to-right field. That question has no premise in a right-to-left
/// field, where right-to-left text is the content. The mirror-image hazard,
/// strong-LTR injection into a right-to-left field, belongs to the separate
/// detector the scope note assigns it to.
///
/// Within a left-to-right field: (1) any bidi format-control anywhere fires
/// `BidiControlInLTRField`; otherwise (2) a leading strong-RTL codepoint fires
/// `FieldTakeover`; otherwise (3) mid-stream strong-RTL is classified by run
/// length.
pub fn detect_with_context(direction: FieldDirection, input: &[u32]) -> Detection {
    let strong_rtl = count_strong_rtl(input);
    let (run_len, run_start) = longest_rtl_run(input);

    // Phase 1: bidi format-control trumps all, in either direction.
    if let Some(pos) = first_bidi_control_pos(input) {
        return Detection::hazard("BidiControlInLTRField", vec![pos]);
    }

    // A right-to-left field carrying right-to-left text carries its content.
    if direction == FieldDirection::Rtl {
        return Detection::clear();
    }

    // Phase 2: leading-RTL field-direction takeover.
    match first_strong_char(input) {
        Some((pos, true)) => Detection::hazard("FieldTakeover", vec![pos]),
        // Leading strong-LTR, or no strong char at all: fall to phase 3.
        Some((_, false)) | None => phase3(input, strong_rtl, run_len, run_start),
    }
}

/// Detect right-to-left injection in a field declared left-to-right, the
/// reading the module scope note fixes for an undeclared field.
pub fn detect(input: &[u32]) -> Detection {
    detect_with_context(FieldDirection::Ltr, input)
}

#[cfg(test)]
mod rtl_field_tests {
    use super::{detect, detect_with_context, FieldDirection};

    // Ground truth: the `detectWithContext_rtl_*` theorems in
    // `Unicode/Security/Display/RtlInjection.lean`, each proven by `decide`.

    #[test]
    fn rtl_field_hebrew_clear() {
        let v = detect_with_context(FieldDirection::Rtl, &[0x05D0, 0x42, 0x43]);
        assert_eq!(v.sub, None);
    }

    #[test]
    fn rtl_field_persian_clear() {
        let v = detect_with_context(FieldDirection::Rtl, &[0x06CC, 0x200C, 0x0647]);
        assert_eq!(v.sub, None);
    }

    /// Declaring a field right-to-left admits its own script without admitting
    /// a Trojan Source payload.
    #[test]
    fn rtl_field_bidi_control_still_fires() {
        let v = detect_with_context(FieldDirection::Rtl, &[0x41, 0x202E, 0x42]);
        assert_eq!(v.sub, Some("BidiControlInLTRField"));
    }

    #[test]
    fn detect_is_ltr_reading() {
        let input = [0x05D0, 0x42, 0x43];
        assert_eq!(
            detect(&input).sub,
            detect_with_context(FieldDirection::Ltr, &input).sub
        );
        assert_eq!(detect(&input).sub, Some("FieldTakeover"));
    }
}

#[cfg(test)]
mod tests {
    use super::detect;

    // Ground truth: the `detect_*` spot-check theorems in
    // `Unicode/Security/Display/RtlInjection.lean`, each proven by `decide`.

    #[test]
    fn clear_digits() {
        assert_eq!(detect(&[0x30, 0x31, 0x32, 0x33]).sub, None);
    }

    #[test]
    fn clear_cyrillic() {
        assert_eq!(detect(&[0x043F]).sub, None);
    }

    #[test]
    fn rlo_in_ltr_field() {
        assert_eq!(detect(&[0x41, 0x202E, 0x42]).sub, Some("BidiControlInLTRField"));
    }

    #[test]
    fn field_takeover_hebrew() {
        assert_eq!(detect(&[0x05D0, 0x42, 0x43]).sub, Some("FieldTakeover"));
    }

    #[test]
    fn field_takeover_arabic() {
        assert_eq!(detect(&[0x0627, 0x42, 0x43]).sub, Some("FieldTakeover"));
    }

    #[test]
    fn mid_stream_hebrew() {
        assert_eq!(detect(&[0x41, 0x42, 0x05D0, 0x44]).sub, Some("StrongRTLInLTR"));
    }

    #[test]
    fn overflow_hebrew() {
        assert_eq!(
            detect(&[0x41, 0x42, 0x05D0, 0x05D1, 0x05D2, 0x05D3, 0x44]).sub,
            Some("MixedOverflow")
        );
    }
}
