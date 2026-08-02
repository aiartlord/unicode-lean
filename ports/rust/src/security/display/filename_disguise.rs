//! FilenameDisguise — detection of filename/extension disguise attacks where the
//! visible extension differs from the byte extension (display-layer detector).
//!
//! Byte-faithful transliteration of
//! `Unicode/Security/Display/FilenameDisguise.lean`.
//!
//! Threat model. An adversary delivers a file whose rendered name looks like a
//! benign type (`document.txt`) but whose actual byte extension is executable —
//! the canonical attack inserts `U+202E` RIGHT-TO-LEFT OVERRIDE so
//! `document<RLO>txt.exe` renders as `document exe.txt`.
//!
//! Detection is presentation- and language-agnostic: it surfaces every codepoint
//! that could cause display-vs-byte divergence in the filename — any bidi
//! format-control anywhere, and any fullwidth/halfwidth or combining (grapheme
//! Extend) codepoint in the extension region (after the last `.`). Native-RTL
//! names with no bidi controls clear. It reuses the port's own predicates (the
//! bidi-format-control set, the grapheme Extend class, the fullwidth range),
//! never a host filesystem or rendering library.
//!
//! Sub-threats (priority order):
//!   1. `RloFlip`            any bidi format-control in the input.
//!   2. `WidthClassExt`      a fullwidth/halfwidth codepoint in the extension.
//!   3. `CombiningInExt`     a combining (Extend) codepoint in the extension.
//!   4. `MultipleExtensions` >= 3 dots (advisory; e.g. legitimate `.tar.gz.sig`).

use crate::security::covert::bidi_control_balance;
use crate::segmentation::grapheme;

// ─────────────────────────────────────────────────────────────────────
// §1 Types
// ─────────────────────────────────────────────────────────────────────

/// Sub-threat enumeration for FilenameDisguise, in priority order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubThreat {
    /// A bidi format-control at `position` (codepoint `control_cp`).
    RloFlip {
        /// Position of the first bidi format-control.
        position: usize,
        /// The bidi format-control codepoint.
        control_cp: u32,
    },
    /// A fullwidth/halfwidth codepoint in the extension, at `position`.
    WidthClassExt {
        /// Position of the fullwidth/halfwidth codepoint.
        position: usize,
        /// The fullwidth/halfwidth codepoint.
        cp: u32,
    },
    /// A combining (grapheme Extend) codepoint in the extension, at `position`.
    CombiningInExt {
        /// Position of the combining codepoint.
        position: usize,
        /// The combining codepoint.
        cp: u32,
    },
    /// Three or more `.` separators (advisory).
    MultipleExtensions {
        /// The number of `.` separators.
        dot_count: usize,
    },
}

impl SubThreat {
    /// Fixture-row tag string for this sub-threat (matches `SubThreat.tag`).
    pub fn tag(&self) -> &'static str {
        match self {
            SubThreat::RloFlip {
                position: _,
                control_cp: _,
            } => "RloFlip",
            SubThreat::WidthClassExt { position: _, cp: _ } => "WidthClassExt",
            SubThreat::CombiningInExt { position: _, cp: _ } => "CombiningInExt",
            SubThreat::MultipleExtensions { dot_count: _ } => "MultipleExtensions",
        }
    }
}

/// Top-level classification for FilenameDisguise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Classification {
    /// No disguise trigger present.
    Clear,
    /// A disguise trigger fired.
    Hazard {
        /// The sub-threat that fired.
        sub: SubThreat,
        /// The implicated positions.
        positions: Vec<usize>,
        /// The decoded-byte projection (always empty here; shape parity with Lean).
        decoded: Vec<u8>,
    },
}

impl Classification {
    /// True iff the classification is `Clear`.
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

/// The structured output of `detect` (mirrors the Lean `Verdict`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    /// The scanned input codepoints.
    pub input: Vec<u32>,
    /// The classification verdict.
    pub classify: Classification,
    /// Positions of every `.` separator.
    pub dot_positions: Vec<usize>,
    /// Position of the last `.` (the extension separator), if any.
    pub last_dot_pos: Option<usize>,
    /// Count of bidi format-controls anywhere in the input.
    pub bidi_control_count: usize,
    /// Count of fullwidth/halfwidth codepoints in the extension region.
    pub fullwidth_in_ext: usize,
    /// Count of combining (Extend) codepoints in the extension region.
    pub combining_in_ext: usize,
}

// ─────────────────────────────────────────────────────────────────────
// §2 Core predicates
// ─────────────────────────────────────────────────────────────────────

/// True iff `cp` is `U+002E FULL STOP` (the extension separator).
pub fn is_ascii_dot(cp: u32) -> bool {
    cp == 0x002E
}

/// True iff `cp` is in the Halfwidth and Fullwidth Forms block.
pub fn is_fullwidth_halfwidth(cp: u32) -> bool {
    (0xFF01..=0xFFEF).contains(&cp)
}

/// True iff `cp` is a bidi format-control (reuses the port's own predicate).
pub fn is_bidi_format_control(cp: u32) -> bool {
    bidi_control_balance::is_bidi_format_control(cp)
}

/// True iff `cp` has `Grapheme_Cluster_Break = Extend` (reuses the port's table).
pub fn is_grapheme_extend(cp: u32) -> bool {
    grapheme::is_grapheme_extend(cp)
}

// ─────────────────────────────────────────────────────────────────────
// §3 Sub-detectors
// ─────────────────────────────────────────────────────────────────────

/// Positions of every `.` in `input`.
fn dot_positions(input: &[u32]) -> Vec<usize> {
    input
        .iter()
        .enumerate()
        .filter_map(|(idx, &cp)| if is_ascii_dot(cp) { Some(idx) } else { None })
        .collect()
}

/// Position and codepoint of the first bidi format-control.
fn first_bidi_control(input: &[u32]) -> Option<(usize, u32)> {
    input
        .iter()
        .enumerate()
        .find_map(|(idx, &cp)| if is_bidi_format_control(cp) { Some((idx, cp)) } else { None })
}

/// Position and codepoint of the first fullwidth/halfwidth codepoint at or after `start`.
fn first_fullwidth_from(input: &[u32], start: usize) -> Option<(usize, u32)> {
    input
        .iter()
        .enumerate()
        .find_map(|(idx, &cp)| {
            if idx >= start && is_fullwidth_halfwidth(cp) { Some((idx, cp)) } else { None }
        })
}

/// Position and codepoint of the first Extend codepoint at or after `start`.
fn first_extend_from(input: &[u32], start: usize) -> Option<(usize, u32)> {
    input
        .iter()
        .enumerate()
        .find_map(|(idx, &cp)| {
            if idx >= start && is_grapheme_extend(cp) { Some((idx, cp)) } else { None }
        })
}

/// Count of fullwidth/halfwidth codepoints at or after `start`.
fn count_fullwidth_from(input: &[u32], start: usize) -> usize {
    input
        .iter()
        .enumerate()
        .filter(|(idx, &cp)| *idx >= start && is_fullwidth_halfwidth(cp))
        .count()
}

/// Count of Extend codepoints at or after `start`.
fn count_extend_from(input: &[u32], start: usize) -> usize {
    input
        .iter()
        .enumerate()
        .filter(|(idx, &cp)| *idx >= start && is_grapheme_extend(cp))
        .count()
}

// ─────────────────────────────────────────────────────────────────────
// §4 Top-level detection
// ─────────────────────────────────────────────────────────────────────

/// The FilenameDisguise detection function.
pub fn detect(input: &[u32]) -> Verdict {
    let dots = dot_positions(input);
    let last_dot = dots.last().copied();
    let ext_start = match last_dot {
        Some(p) => p + 1,
        None => input.len(),
    };
    let bidi_count = input.iter().filter(|&&cp| is_bidi_format_control(cp)).count();
    let fw_in_ext = count_fullwidth_from(input, ext_start);
    let ext_in_ext = count_extend_from(input, ext_start);

    let classification = match first_bidi_control(input) {
        // Priority 1: any bidi format-control.
        Some((pos, ctl_cp)) => Classification::Hazard {
            sub: SubThreat::RloFlip {
                position: pos,
                control_cp: ctl_cp,
            },
            positions: vec![pos],
            decoded: Vec::new(),
        },
        None => match first_fullwidth_from(input, ext_start) {
            // Priority 2: fullwidth/halfwidth in the extension.
            Some((pos, cp)) => Classification::Hazard {
                sub: SubThreat::WidthClassExt { position: pos, cp },
                positions: vec![pos],
                decoded: Vec::new(),
            },
            None => match first_extend_from(input, ext_start) {
                // Priority 3: combining mark in the extension.
                Some((pos, cp)) => Classification::Hazard {
                    sub: SubThreat::CombiningInExt { position: pos, cp },
                    positions: vec![pos],
                    decoded: Vec::new(),
                },
                None => {
                    // Priority 4: three or more extensions (advisory).
                    if dots.len() >= 3 {
                        Classification::Hazard {
                            sub: SubThreat::MultipleExtensions {
                                dot_count: dots.len(),
                            },
                            positions: dots.clone(),
                            decoded: Vec::new(),
                        }
                    } else {
                        Classification::Clear
                    }
                }
            },
        },
    };

    Verdict {
        input: input.to_vec(),
        classify: classification,
        dot_positions: dots,
        last_dot_pos: last_dot,
        bidi_control_count: bidi_count,
        fullwidth_in_ext: fw_in_ext,
        combining_in_ext: ext_in_ext,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ground truth: every `detect_*` theorem in
    // `Unicode/Security/Display/FilenameDisguise.lean`. Each maps to one `#[test]`;
    // the shared context-free fixture
    // (`fixtures/security/detectors/filename_disguise.json`) carries the same vectors.

    fn tag(input: &[u32]) -> Option<&'static str> {
        detect(input).classify.tag()
    }

    // `detect_empty_clear`
    #[test]
    fn detect_empty_clear() {
        assert!(detect(&[]).classify.is_clear());
    }

    // `detect_plain_txt_clear` — "document.txt"
    #[test]
    fn detect_plain_txt_clear() {
        let v = detect(&[
            0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74, 0x2E, 0x74, 0x78, 0x74,
        ]);
        assert!(v.classify.is_clear());
        assert_eq!(v.last_dot_pos, Some(8));
    }

    // `detect_no_extension_clear` — "foo"
    #[test]
    fn detect_no_extension_clear() {
        let v = detect(&[0x66, 0x6F, 0x6F]);
        assert!(v.classify.is_clear());
        assert_eq!(v.last_dot_pos, None);
    }

    // `detect_tar_gz_clear` — "archive.tar.gz" (2 dots, below the multi-ext bound)
    #[test]
    fn detect_tar_gz_clear() {
        assert!(detect(&[
            0x61, 0x72, 0x63, 0x68, 0x69, 0x76, 0x65, 0x2E, 0x74, 0x61, 0x72, 0x2E, 0x67, 0x7A,
        ])
        .classify
        .is_clear());
    }

    // `detect_rlo_flip` — "document<RLO>txt.exe"
    #[test]
    fn detect_rlo_flip() {
        let v = detect(&[
            0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74, 0x202E, 0x74, 0x78, 0x74, 0x2E, 0x65,
            0x78, 0x65,
        ]);
        assert_eq!(v.classify.tag(), Some("RloFlip"));
        assert_eq!(v.classify.positions(), &[8]);
    }

    // `detect_fullwidth_exe` — "file.ＥＸＥ"
    #[test]
    fn detect_fullwidth_exe() {
        assert_eq!(
            tag(&[0x66, 0x69, 0x6C, 0x65, 0x2E, 0xFF25, 0xFF38, 0xFF25]),
            Some("WidthClassExt")
        );
    }

    // `detect_combining_in_ext` — "file.é xe" (combining acute in the extension)
    #[test]
    fn detect_combining_in_ext() {
        assert_eq!(
            tag(&[0x66, 0x69, 0x6C, 0x65, 0x2E, 0x65, 0x0301, 0x78, 0x65]),
            Some("CombiningInExt")
        );
    }

    // `detect_triple_extension` — "setup.tar.gz.sig"
    #[test]
    fn detect_triple_extension() {
        let v = detect(&[
            0x73, 0x65, 0x74, 0x75, 0x70, 0x2E, 0x74, 0x61, 0x72, 0x2E, 0x67, 0x7A, 0x2E, 0x73,
            0x69, 0x67,
        ]);
        assert_eq!(v.classify.tag(), Some("MultipleExtensions"));
    }

    // `detect_hebrew_clear` — native Hebrew name, no bidi controls.
    #[test]
    fn detect_hebrew_clear() {
        assert!(detect(&[0x05D0, 0x05D1, 0x05D2, 0x2E, 0x74, 0x78, 0x74])
            .classify
            .is_clear());
    }

    // `detect_isolate_flip` — RLI/PDI isolate variant, also RloFlip.
    #[test]
    fn detect_isolate_flip() {
        assert_eq!(
            tag(&[
                0x64, 0x6F, 0x63, 0x2067, 0x74, 0x78, 0x74, 0x2E, 0x65, 0x78, 0x65, 0x2069,
            ]),
            Some("RloFlip")
        );
    }

    // Priority: bidi control outranks a fullwidth extension.
    #[test]
    fn bidi_beats_fullwidth() {
        assert_eq!(tag(&[0x202E, 0x66, 0x2E, 0xFF25]), Some("RloFlip"));
    }
}
