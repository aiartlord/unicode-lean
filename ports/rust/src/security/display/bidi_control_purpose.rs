//! Which bidi format controls in an input serve a purpose, and which do not.
//!
//! Direct port of `Unicode/Security/Display/BidiControlPurpose.lean`. The nine
//! UAX #9 format controls exist to manage right-to-left text: a span is doing
//! that job when the text it encloses is right-to-left, or when it forces
//! left-to-right text inside a right-to-left context. A span enclosing no
//! strong right-to-left character in a left-to-right context manages nothing
//! (`LRI user PDI` around Latin text, `LRO return PDF` around a keyword), and
//! an unbalanced control never manages anything. Every Trojan Source payload is
//! a control of that kind; a balanced embedding around an Arabic string literal
//! is the opposite case and renders the literal as written.
//!
//! This is not source-region filtering: the question is asked of every control
//! wherever it sits, and it is decided from the codepoints the span encloses,
//! never from where a tokenizer would place it.
//!
//! Rule, as the Lean `walk` states it:
//!
//! - An opener pushes a span: its position, whether it is an isolate (closed
//!   by PDI) or an embedding/override (closed by PDF), and whether it is
//!   right-to-left in effect (RLE, RLO, RLI, FSI) or left-to-right (LRE, LRO,
//!   LRI).
//! - A strong right-to-left codepoint (Bidi_Class R or AL) marks every open
//!   span as having seen right-to-left text.
//! - PDF closes the top span when it is an embedding; against an isolate on
//!   top, or an empty stack, it is an orphan. PDI closes down to the innermost
//!   isolate, implicitly terminating the embeddings above it, which are thereby
//!   unbalanced; with no isolate open it is an orphan.
//! - A closed right-to-left span is purposeful iff it saw right-to-left text; a
//!   closed left-to-right span is purposeful iff it sits in right-to-left
//!   context (an open right-to-left span encloses it, or the paragraph's first
//!   strong character is right-to-left).
//! - Reported: every orphan, every opener still open at the end, every
//!   embedding a PDI terminated implicitly, and both ends of every closed span
//!   that was not purposeful.

use crate::security::covert::bidi_control_balance::{is_pdf, is_pdi};
use crate::security::identity::ucd;

/// True iff `cp` opens a span that is right-to-left in effect: RLE, RLO, RLI,
/// or FSI (whose direction resolves from its content). Mirrors `opensRtlKind`.
pub fn opens_rtl_kind(cp: u32) -> bool {
    cp == 0x202B || cp == 0x202E || cp == 0x2067 || cp == 0x2068
}

/// True iff `cp` opens a span that is left-to-right in effect: LRE, LRO, LRI.
/// Mirrors `opensLtrKind`.
pub fn opens_ltr_kind(cp: u32) -> bool {
    cp == 0x202A || cp == 0x202D || cp == 0x2066
}

/// True iff `cp` opens an isolate (closed by PDI rather than PDF). Mirrors
/// `opensIsolateKind`.
pub fn opens_isolate_kind(cp: u32) -> bool {
    cp == 0x2066 || cp == 0x2067 || cp == 0x2068
}

/// ASCII code syntax: the codepoints a Trojan Source payload moves — quotes,
/// brackets, comment markers, statement separators, operators. Prose
/// punctuation, space and digits are not in the set. Mirrors `isCodeSyntax`.
pub fn is_code_syntax(cp: u32) -> bool {
    matches!(
        cp,
        0x22 | 0x27
            | 0x60
            | 0x28
            | 0x29
            | 0x5B
            | 0x5D
            | 0x7B
            | 0x7D
            | 0x2F
            | 0x5C
            | 0x2A
            | 0x23
            | 0x3B
            | 0x3C
            | 0x3E
            | 0x3D
            | 0x2B
            | 0x7C
            | 0x26
            | 0x25
            | 0x24
            | 0x40
            | 0x5E
            | 0x7E
    )
}

/// One open span: where it opened, how it closes, its direction in effect, and
/// what has appeared directly inside it — strong right-to-left text, strong
/// left-to-right text, ASCII code syntax. Mirrors `OpenSpan`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct OpenSpan {
    pos: usize,
    isolate: bool,
    rtl_kind: bool,
    saw_rtl: bool,
    saw_ltr: bool,
    saw_syntax: bool,
}

/// True iff a span closing here sits in right-to-left context. Mirrors
/// `inRtlContext`.
fn in_rtl_context(enclosing: &[OpenSpan], paragraph_rtl: bool) -> bool {
    paragraph_rtl || enclosing.iter().any(|s| s.rtl_kind)
}

/// A closed span is purposeful iff its direct content is exactly its own
/// direction and carries no code syntax. Mirrors `spanPurposeful`.
fn span_purposeful(s: OpenSpan, enclosing: &[OpenSpan], paragraph_rtl: bool) -> bool {
    if s.rtl_kind {
        s.saw_rtl && !s.saw_ltr && !s.saw_syntax
    } else {
        in_rtl_context(enclosing, paragraph_rtl) && s.saw_ltr && !s.saw_rtl && !s.saw_syntax
    }
}

/// UAX #9 P2/P3: the paragraph runs right-to-left iff its first strong
/// character is right-to-left. Mirrors `paragraphIsRtl`.
pub fn paragraph_is_rtl(input: &[u32]) -> bool {
    input
        .iter()
        .find(|&&cp| ucd::is_strong_rtl(cp) || ucd::is_strong_ltr(cp))
        .map(|&cp| ucd::is_strong_rtl(cp))
        .unwrap_or(false)
}

/// Positions of the purposeless bidi format controls in `input`, in input
/// order. Empty iff every control is balanced and manages right-to-left text.
/// Mirrors `purposelessControlPositions`.
pub fn purposeless_control_positions(input: &[u32]) -> Vec<usize> {
    let paragraph_rtl = paragraph_is_rtl(input);
    // The stack's top is the vector's last element; the Lean list's head.
    let mut stack: Vec<OpenSpan> = Vec::new();
    let mut acc: Vec<usize> = Vec::new();
    for (idx, &cp) in input.iter().enumerate() {
        if opens_rtl_kind(cp) || opens_ltr_kind(cp) {
            stack.push(OpenSpan {
                pos: idx,
                isolate: opens_isolate_kind(cp),
                rtl_kind: opens_rtl_kind(cp),
                saw_rtl: false,
                saw_ltr: false,
                saw_syntax: false,
            });
        } else if is_pdf(cp) {
            match stack.last().copied() {
                Some(top) if top.isolate => {
                    // PDF against an open isolate closes nothing (UAX #9 X7).
                    acc.push(idx);
                }
                Some(top) => {
                    stack.pop();
                    if !span_purposeful(top, &stack, paragraph_rtl) {
                        acc.push(top.pos);
                        acc.push(idx);
                    }
                }
                None => acc.push(idx),
            }
        } else if is_pdi(cp) {
            match stack.iter().rposition(|s| s.isolate) {
                None => acc.push(idx),
                Some(iso_index) => {
                    // Embeddings above the isolate are terminated implicitly.
                    let dropped: Vec<usize> =
                        stack[iso_index + 1..].iter().map(|s| s.pos).collect();
                    let iso = stack[iso_index];
                    stack.truncate(iso_index);
                    acc.extend(dropped);
                    if !span_purposeful(iso, &stack, paragraph_rtl) {
                        acc.push(iso.pos);
                        acc.push(idx);
                    }
                }
            }
        } else if let Some(top) = stack.last_mut() {
            // Content is recorded against the innermost open span only: a
            // nested span manages its own content (Lean `markContent`).
            top.saw_rtl |= ucd::is_strong_rtl(cp);
            top.saw_ltr |= ucd::is_strong_ltr(cp);
            top.saw_syntax |= is_code_syntax(cp);
        }
    }
    acc.extend(stack.iter().map(|s| s.pos));
    acc.sort_unstable();
    acc.dedup();
    acc
}

/// True iff `input` carries at least one purposeless bidi format control.
/// Mirrors `hasPurposelessControl`.
pub fn has_purposeless_control(input: &[u32]) -> bool {
    !purposeless_control_positions(input).is_empty()
}

/// Position and codepoint of the first purposeless control, if any. Mirrors
/// `firstPurposelessControl`.
pub fn first_purposeless_control(input: &[u32]) -> Option<(usize, u32)> {
    purposeless_control_positions(input)
        .first()
        .and_then(|&pos| input.get(pos).map(|&cp| (pos, cp)))
}

#[cfg(test)]
mod tests {
    use super::{first_purposeless_control, has_purposeless_control, purposeless_control_positions};

    // Ground truth: the spot-check theorems in
    // `Unicode/Security/Display/BidiControlPurpose.lean`, each proven by `decide`.

    #[test]
    fn empty_and_plain_text() {
        assert_eq!(purposeless_control_positions(&[]), Vec::<usize>::new());
        assert_eq!(purposeless_control_positions(&[0x41, 0x05D0]), Vec::<usize>::new());
    }

    #[test]
    fn balanced_empty_isolate_is_purposeless() {
        assert_eq!(purposeless_control_positions(&[0x2066, 0x2069]), vec![0, 1]);
    }

    #[test]
    fn lone_rlo_is_unbalanced() {
        assert_eq!(purposeless_control_positions(&[0x202E, 0x41]), vec![0]);
    }

    #[test]
    fn rle_around_latin_is_purposeless() {
        assert_eq!(
            purposeless_control_positions(&[0x41, 0x202B, 0x42, 0x202C]),
            vec![1, 3]
        );
    }

    #[test]
    fn rle_around_arabic_is_purposeful() {
        assert_eq!(
            purposeless_control_positions(&[0x41, 0x202B, 0x0645, 0x202C, 0x42]),
            Vec::<usize>::new()
        );
    }

    #[test]
    fn lre_in_rtl_paragraph_is_purposeful() {
        assert_eq!(
            purposeless_control_positions(&[0x05D0, 0x202A, 0x41, 0x202C]),
            Vec::<usize>::new()
        );
    }

    #[test]
    fn lro_around_latin_is_purposeless() {
        assert_eq!(purposeless_control_positions(&[0x202D, 0x72, 0x202C]), vec![0, 2]);
    }

    #[test]
    fn lri_around_latin_is_purposeless() {
        assert_eq!(
            purposeless_control_positions(&[0x22, 0x2066, 0x20, 0x75, 0x2069, 0x22]),
            vec![1, 4]
        );
    }

    #[test]
    fn orphan_pdf() {
        assert_eq!(purposeless_control_positions(&[0x41, 0x202C]), vec![1]);
    }

    #[test]
    fn pdi_terminates_embedding_implicitly() {
        // The Hebrew letter is the embedding's content, not the isolate's, so
        // the isolate encloses nothing of its own and is purposeless too.
        assert_eq!(
            purposeless_control_positions(&[0x2067, 0x202B, 0x05D0, 0x2069]),
            vec![0, 1, 3]
        );
    }

    #[test]
    fn planted_letter_does_not_legitimise_a_mixed_span() {
        assert_eq!(
            purposeless_control_positions(&[0x202B, 0x61, 0x62, 0x0645, 0x202C]),
            vec![0, 4]
        );
    }

    #[test]
    fn code_syntax_inside_an_rtl_span_is_reported() {
        assert_eq!(
            purposeless_control_positions(&[0x202B, 0x0645, 0x22, 0x29, 0x202C]),
            vec![0, 4]
        );
    }

    #[test]
    fn nested_acronym_is_purposeful() {
        assert_eq!(
            purposeless_control_positions(&[
                0x202B, 0x0645, 0x202A, 0x47, 0x50, 0x55, 0x202C, 0x0631, 0x202C
            ]),
            Vec::<usize>::new()
        );
    }

    #[test]
    fn first_and_has() {
        assert_eq!(first_purposeless_control(&[0x41, 0x202E, 0x42]), Some((1, 0x202E)));
        assert!(!has_purposeless_control(&[0x22, 0x202B, 0x0645, 0x0631, 0x202C, 0x22]));
    }
}
