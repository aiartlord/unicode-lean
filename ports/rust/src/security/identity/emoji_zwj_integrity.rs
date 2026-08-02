//! EmojiZwjIntegrity — detection of malformed / unsanctioned emoji ZWJ-sequence
//! shapes per UTS #51 (the identity-layer detector I3).
//!
//! Byte-faithful transliteration of
//! `Unicode/Security/Identity/EmojiZwjIntegrity.lean`.
//!
//! Threat model. An adversary crafts an emoji-shaped codepoint sequence
//! containing one or more `U+200D` ZERO WIDTH JOINERs but violating the
//! sanctioned RGI ZWJ-sequence shape — by exceeding the RGI length cap, by
//! joining a non-emoji codepoint, by emitting adjacent ZWJ pairs, or by
//! overflowing the skin-tone count. Any non-RGI ZWJ-containing sequence is
//! renderer-dependent, and that renderer divergence is the attack surface.
//!
//! Sanctioning data. UTS #51 defines the RGI ZWJ sequences in
//! `emoji-zwj-sequences.txt`, bundled in the port's own
//! `data/emoji-zwj-sequences.txt` (never a host emoji library). The registered
//! set gives both the exact-match membership test (`is_registered_zwj_sequence`)
//! and the ZWJ *alphabet* — every distinct codepoint occurring at any position
//! of any registered sequence, excluding the joiner — which is the canonical
//! "what may flank a ZWJ?" predicate.
//!
//! Algorithm (one pass over `input`).
//!   Phase 1 — collect ZWJ positions and the skin-tone count.
//!   Phase 2 — short-circuit `Clear` if there are no ZWJs and the skin-tone
//!             count is at most 1.
//!   Phase 3 — a registered RGI sequence is always `Clear`.
//!   Phase 4 — check sub-threats by priority:
//!               1. `DoubleZWJ`            ZWJ-ZWJ adjacency
//!               2. `NonEmojiInjection`    ZWJ adjacent to a non-emoji codepoint
//!               3. `OverLength`           sequence longer than the RGI cap
//!               4. `SkinToneOverflow`     skin-tone count >= 5
//!               5. `UnregisteredSequence` catch-all when ZWJs are present but
//!                                         the sequence is not registered.

use std::collections::HashSet;
use std::sync::OnceLock;

// ─────────────────────────────────────────────────────────────────────
// §1 Constants
// ─────────────────────────────────────────────────────────────────────

/// Conservative cap on the length of a sanctioned RGI ZWJ sequence
/// (`maxRgiLength` in the Lean spec). The longest current entry (a four-person
/// family with skin tones) reaches ~13-14 codepoints; 16 is a safe upper bound.
pub const MAX_RGI_LENGTH: usize = 16;

/// The ZERO WIDTH JOINER codepoint.
pub const ZWJ: u32 = 0x200D;

// ─────────────────────────────────────────────────────────────────────
// §2 Types
// ─────────────────────────────────────────────────────────────────────

/// Sub-threat enumeration for EmojiZwjIntegrity, in priority order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubThreat {
    /// ZWJ-ZWJ adjacency; `positions` are the first ZWJ of each adjacent pair.
    DoubleZwj {
        /// Positions of the first ZWJ in each ZWJ-ZWJ pair.
        positions: Vec<usize>,
    },
    /// A ZWJ flanked by a non-emoji codepoint (or sitting at an input edge).
    NonEmojiInjection {
        /// Position of the offending ZWJ.
        zwj_pos: usize,
        /// The non-emoji codepoint that flanks it (0 for an edge ZWJ).
        non_emoji_cp: u32,
    },
    /// The sequence is longer than `MAX_RGI_LENGTH`.
    OverLength {
        /// The observed sequence length.
        length: usize,
        /// The RGI length cap that was exceeded.
        max_length: usize,
    },
    /// Five or more skin-tone modifiers (the family-emoji maximum is four).
    SkinToneOverflow {
        /// The observed skin-tone modifier count.
        count: usize,
    },
    /// ZWJs are present and no other sub-threat matched, but the sequence is
    /// not a registered RGI ZWJ sequence.
    UnregisteredSequence {
        /// The length of the unregistered ZWJ chain.
        chain_len: usize,
    },
}

impl SubThreat {
    /// Fixture-row tag string for this sub-threat (matches `SubThreat.tag`).
    pub fn tag(&self) -> &'static str {
        match self {
            SubThreat::DoubleZwj { positions: _ } => "DoubleZWJ",
            SubThreat::NonEmojiInjection {
                zwj_pos: _,
                non_emoji_cp: _,
            } => "NonEmojiInjection",
            SubThreat::OverLength {
                length: _,
                max_length: _,
            } => "OverLength",
            SubThreat::SkinToneOverflow { count: _ } => "SkinToneOverflow",
            SubThreat::UnregisteredSequence { chain_len: _ } => "UnregisteredSequence",
        }
    }
}

/// Top-level classification for EmojiZwjIntegrity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Classification {
    /// A well-formed or non-ZWJ input.
    Clear,
    /// A hazard: the fired sub-threat, the implicated positions, and the
    /// (always-empty for this detector) decoded-byte projection.
    Hazard {
        /// The sub-threat that fired.
        sub: SubThreat,
        /// The codepoint positions the sub-threat implicates.
        positions: Vec<usize>,
        /// The decoded-byte projection (always empty here; kept for shape parity
        /// with the Lean `Classification.hazard`).
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
    /// Positions of every ZWJ in the input.
    pub zwj_positions: Vec<usize>,
    /// The chain length (0 when there are no ZWJs, else the input length).
    pub chain_length: usize,
    /// True iff the input is exactly a registered RGI ZWJ sequence.
    pub is_registered_rgi: bool,
    /// Count of skin-tone modifier codepoints (U+1F3FB..U+1F3FF).
    pub skin_tone_count: usize,
}

// ─────────────────────────────────────────────────────────────────────
// §3 RGI ZWJ-sequence data (bundled data/emoji-zwj-sequences.txt)
// ─────────────────────────────────────────────────────────────────────

const EMOJI_ZWJ_RAW: &str = include_str!("../../../data/emoji-zwj-sequences.txt");

/// Parse the registered RGI ZWJ sequences from `emoji-zwj-sequences.txt`. Each
/// non-comment row is `<cp> <cp> ... ; RGI_Emoji_ZWJ_Sequence ; <desc> # <cmt>`;
/// the codepoint list is the field before the first `;`.
fn parse_zwj_sequences() -> Vec<Vec<u32>> {
    let mut out = Vec::new();
    for raw_line in EMOJI_ZWJ_RAW.lines() {
        let body = match raw_line.find('#') {
            Some(idx) => &raw_line[..idx],
            None => raw_line,
        };
        let stripped = body.trim();
        if stripped.is_empty() {
            continue;
        }
        let seq_field = match stripped.split(';').next() {
            Some(field) => field,
            None => continue,
        };
        let mut seq = Vec::new();
        let mut parsed_ok = true;
        for token in seq_field.split_whitespace() {
            match u32::from_str_radix(token, 16) {
                Ok(cp) => seq.push(cp),
                Err(_parse_error) => {
                    parsed_ok = false;
                    break;
                }
            }
        }
        if parsed_ok && !seq.is_empty() {
            out.push(seq);
        }
    }
    out
}

fn zwj_sequences() -> &'static Vec<Vec<u32>> {
    static T: OnceLock<Vec<Vec<u32>>> = OnceLock::new();
    T.get_or_init(parse_zwj_sequences)
}

/// The ZWJ alphabet: every distinct codepoint occurring at any position of any
/// registered RGI ZWJ sequence, excluding the joiner U+200D itself.
fn build_zwj_alphabet() -> HashSet<u32> {
    let mut set = HashSet::new();
    for seq in zwj_sequences() {
        for &cp in seq {
            if cp != ZWJ {
                set.insert(cp);
            }
        }
    }
    set
}

fn zwj_alphabet() -> &'static HashSet<u32> {
    static T: OnceLock<HashSet<u32>> = OnceLock::new();
    T.get_or_init(build_zwj_alphabet)
}

/// True iff `cps` is exactly a registered RGI ZWJ sequence.
pub fn is_registered_zwj_sequence(cps: &[u32]) -> bool {
    zwj_sequences().iter().any(|seq| seq.as_slice() == cps)
}

/// True iff `cp` appears at some position of a registered RGI ZWJ sequence
/// (the canonical "what may flank a ZWJ?" predicate).
pub fn is_emoji_target(cp: u32) -> bool {
    zwj_alphabet().contains(&cp)
}

// ─────────────────────────────────────────────────────────────────────
// §4 Core predicates
// ─────────────────────────────────────────────────────────────────────

/// True iff `cp` is the ZWJ codepoint.
pub fn is_zwj(cp: u32) -> bool {
    cp == ZWJ
}

/// True iff `cp` is an emoji skin-tone modifier (U+1F3FB..U+1F3FF).
pub fn is_emoji_modifier(cp: u32) -> bool {
    (0x1F3FB..=0x1F3FF).contains(&cp)
}

/// Positions of every ZWJ in `input`.
fn zwj_positions(input: &[u32]) -> Vec<usize> {
    input
        .iter()
        .enumerate()
        .filter_map(|(idx, &cp)| if is_zwj(cp) { Some(idx) } else { None })
        .collect()
}

/// Count of skin-tone modifier codepoints.
fn skin_tone_count(input: &[u32]) -> usize {
    input.iter().filter(|&&cp| is_emoji_modifier(cp)).count()
}

/// Positions of the first ZWJ in each ZWJ-ZWJ adjacent pair.
fn double_zwj_positions(input: &[u32]) -> Vec<usize> {
    let mut out = Vec::new();
    for idx in 0..input.len() {
        let cp = input[idx];
        match input.get(idx + 1) {
            Some(&next_cp) => {
                if is_zwj(cp) && is_zwj(next_cp) {
                    out.push(idx);
                }
            }
            None => {}
        }
    }
    out
}

/// The first ZWJ position where either neighbour is a non-emoji codepoint, as
/// `(zwj_pos, offending_cp)`. A ZWJ at an input edge (no preceding or no
/// following codepoint) is itself an injection-class hazard, reported with
/// offending codepoint 0.
fn first_non_emoji_injection(input: &[u32]) -> Option<(usize, u32)> {
    for idx in 0..input.len() {
        if !is_zwj(input[idx]) {
            continue;
        }
        let prev = if idx == 0 { None } else { Some(input[idx - 1]) };
        let next = input.get(idx + 1).copied();
        match (prev, next) {
            (Some(prev_cp), Some(next_cp)) => {
                if !is_emoji_target(prev_cp) {
                    return Some((idx, prev_cp));
                } else if !is_emoji_target(next_cp) {
                    return Some((idx, next_cp));
                }
            }
            (None, _) => return Some((idx, 0)),
            (Some(_prev_cp), None) => return Some((idx, 0)),
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────
// §5 Top-level detection
// ─────────────────────────────────────────────────────────────────────

/// The EmojiZwjIntegrity detection function.
pub fn detect(input: &[u32]) -> Verdict {
    let zwjs = zwj_positions(input);
    let st_count = skin_tone_count(input);
    let is_rgi = is_registered_zwj_sequence(input);
    let chain_len = if zwjs.is_empty() { 0 } else { input.len() };

    if zwjs.is_empty() && st_count <= 1 {
        return Verdict {
            input: input.to_vec(),
            classify: Classification::Clear,
            zwj_positions: Vec::new(),
            chain_length: 0,
            is_registered_rgi: is_rgi,
            skin_tone_count: st_count,
        };
    }

    let classification = if is_rgi {
        // Phase 3: a registered RGI sequence is always clear.
        Classification::Clear
    } else {
        // Phase 4.1: ZWJ-ZWJ adjacency.
        let dzwj = double_zwj_positions(input);
        if !dzwj.is_empty() {
            Classification::Hazard {
                sub: SubThreat::DoubleZwj {
                    positions: dzwj.clone(),
                },
                positions: dzwj,
                decoded: Vec::new(),
            }
        } else {
            // Phase 4.2: ZWJ adjacent to a non-emoji codepoint.
            match first_non_emoji_injection(input) {
                Some((zwj_pos, offend_cp)) => Classification::Hazard {
                    sub: SubThreat::NonEmojiInjection {
                        zwj_pos,
                        non_emoji_cp: offend_cp,
                    },
                    positions: vec![zwj_pos],
                    decoded: Vec::new(),
                },
                None => {
                    // Phase 4.3: length cap.
                    if input.len() > MAX_RGI_LENGTH {
                        Classification::Hazard {
                            sub: SubThreat::OverLength {
                                length: input.len(),
                                max_length: MAX_RGI_LENGTH,
                            },
                            positions: Vec::new(),
                            decoded: Vec::new(),
                        }
                    } else if st_count >= 5 {
                        // Phase 4.4: skin-tone overflow.
                        Classification::Hazard {
                            sub: SubThreat::SkinToneOverflow { count: st_count },
                            positions: Vec::new(),
                            decoded: Vec::new(),
                        }
                    } else if !zwjs.is_empty() {
                        // Phase 4.5: catch-all for unregistered ZWJ sequences.
                        Classification::Hazard {
                            sub: SubThreat::UnregisteredSequence {
                                chain_len: input.len(),
                            },
                            positions: zwjs.clone(),
                            decoded: Vec::new(),
                        }
                    } else {
                        Classification::Clear
                    }
                }
            }
        }
    };

    Verdict {
        input: input.to_vec(),
        classify: classification,
        zwj_positions: zwjs,
        chain_length: chain_len,
        is_registered_rgi: is_rgi,
        skin_tone_count: st_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ground truth: every `detect_*` theorem in
    // `Unicode/Security/Identity/EmojiZwjIntegrity.lean`. Each Lean theorem maps
    // to one `#[test]` below. This detector is context-free — every vector is
    // expressible in the shared detector fixture
    // (`fixtures/security/detectors/emoji_zwj_integrity.json`).

    fn tag(input: &[u32]) -> Option<&'static str> {
        detect(input).classify.tag()
    }

    // ── data-layer sanity ───────────────────────────────────────────────

    #[test]
    fn is_emoji_modifier_checks() {
        assert!(is_emoji_modifier(0x1F3FB));
        assert!(is_emoji_modifier(0x1F3FF));
        assert!(!is_emoji_modifier(0x1F3FA));
        assert!(!is_emoji_modifier(0x1F600));
    }

    #[test]
    fn zwj_alphabet_admits_heart_rejects_grinning() {
        // U+2764 HEAVY BLACK HEART appears in couple-with-heart RGI sequences.
        assert!(is_emoji_target(0x2764));
        // U+1F468 MAN appears in family/couple RGI sequences.
        assert!(is_emoji_target(0x1F468));
        // U+1F600 GRINNING FACE appears in no registered RGI ZWJ sequence.
        assert!(!is_emoji_target(0x1F600));
        // The joiner itself is excluded from the alphabet.
        assert!(!is_emoji_target(ZWJ));
    }

    #[test]
    fn registered_membership_is_exact() {
        // MAN + ZWJ + LAPTOP (man technologist) is a registered RGI sequence.
        assert!(is_registered_zwj_sequence(&[0x1F468, 0x200D, 0x1F4BB]));
        // MAN + ZWJ + WOMAN is not a registered RGI sequence.
        assert!(!is_registered_zwj_sequence(&[0x1F468, 0x200D, 0x1F469]));
    }

    // ── §5 detect spot checks (one per Lean theorem) ─────────────────────

    // `detect_empty_clear`
    #[test]
    fn detect_empty_clear() {
        let v = detect(&[]);
        assert!(v.classify.is_clear());
        assert_eq!(v.classify.tag(), None);
        assert_eq!(v.zwj_positions, Vec::<usize>::new());
        assert_eq!(v.chain_length, 0);
        assert_eq!(v.skin_tone_count, 0);
    }

    // `detect_ascii_clear`
    #[test]
    fn detect_ascii_clear() {
        assert!(detect(&[0x48, 0x65, 0x6C, 0x6C, 0x6F]).classify.is_clear());
    }

    // `detect_plain_emoji_clear`
    #[test]
    fn detect_plain_emoji_clear() {
        assert!(detect(&[0x1F600]).classify.is_clear());
    }

    // `detect_one_skintone_clear` — a base plus a single skin-tone (count = 1).
    #[test]
    fn detect_one_skintone_clear() {
        let v = detect(&[0x1F44B, 0x1F3FB]);
        assert!(v.classify.is_clear());
        assert_eq!(v.skin_tone_count, 1);
    }

    // `detect_family_rgi_clear` — man + woman + girl + boy via ZWJs (registered).
    #[test]
    fn detect_family_rgi_clear() {
        let v = detect(&[0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467, 0x200D, 0x1F466]);
        assert!(v.classify.is_clear());
        assert!(v.is_registered_rgi);
    }

    // `detect_double_zwj` — ZWJ + ZWJ adjacency.
    #[test]
    fn detect_double_zwj() {
        let v = detect(&[0x1F600, 0x200D, 0x200D, 0x1F600]);
        assert_eq!(v.classify.tag(), Some("DoubleZWJ"));
        assert_eq!(v.classify.positions(), &[1]);
    }

    // `detect_non_emoji_injection` — ZWJ joining ASCII 'a'.
    #[test]
    fn detect_non_emoji_injection() {
        let v = detect(&[0x1F600, 0x200D, 0x0061]);
        assert_eq!(v.classify.tag(), Some("NonEmojiInjection"));
    }

    // `detect_skin_tone_overflow` — five skin-tone modifiers.
    #[test]
    fn detect_skin_tone_overflow() {
        let v = detect(&[0x1F44B, 0x1F3FB, 0x1F3FC, 0x1F3FD, 0x1F3FE, 0x1F3FF]);
        assert_eq!(v.classify.tag(), Some("SkinToneOverflow"));
        assert_eq!(v.skin_tone_count, 5);
    }

    // `detect_man_laptop_registered_clear` — man technologist (registered).
    #[test]
    fn detect_man_laptop_registered_clear() {
        assert!(detect(&[0x1F468, 0x200D, 0x1F4BB]).classify.is_clear());
    }

    // `detect_unregistered` — man + ZWJ + woman: both flanks are in the RGI
    // alphabet but the joined sequence is not registered.
    #[test]
    fn detect_unregistered() {
        let v = detect(&[0x1F468, 0x200D, 0x1F469]);
        assert_eq!(v.classify.tag(), Some("UnregisteredSequence"));
    }

    // `detect_grinning_laptop_non_emoji_injection` — grinning face is not a
    // valid ZWJ-join target, so this surfaces as NonEmojiInjection.
    #[test]
    fn detect_grinning_laptop_non_emoji_injection() {
        assert_eq!(
            tag(&[0x1F600, 0x200D, 0x1F4BB]),
            Some("NonEmojiInjection")
        );
    }

    // ── structural checks (follow from the priority ladder) ──────────────

    // A long chain of valid ZWJ-joined targets that is not registered and hits
    // no earlier sub-threat surfaces as OverLength once it exceeds the cap.
    #[test]
    fn over_length_fires_past_cap() {
        // 9 men joined by 8 ZWJs = 17 codepoints (> MAX_RGI_LENGTH).
        let mut input = Vec::new();
        for i in 0..9 {
            if i > 0 {
                input.push(0x200D);
            }
            input.push(0x1F468);
        }
        assert_eq!(input.len(), 17);
        let v = detect(&input);
        assert_eq!(v.classify.tag(), Some("OverLength"));
        assert_eq!(
            v.classify,
            Classification::Hazard {
                sub: SubThreat::OverLength {
                    length: 17,
                    max_length: MAX_RGI_LENGTH,
                },
                positions: Vec::new(),
                decoded: Vec::new(),
            }
        );
    }

    // A ZWJ at the trailing edge of input is an injection-class hazard.
    #[test]
    fn trailing_zwj_is_injection() {
        let v = detect(&[0x1F468, 0x200D]);
        assert_eq!(v.classify.tag(), Some("NonEmojiInjection"));
        assert_eq!(v.classify.positions(), &[1]);
    }

    // Double-ZWJ wins over the unregistered catch-all (priority order).
    #[test]
    fn double_zwj_beats_unregistered() {
        // man ZWJ ZWJ boy — adjacent ZWJs present.
        let v = detect(&[0x1F468, 0x200D, 0x200D, 0x1F466]);
        assert_eq!(v.classify.tag(), Some("DoubleZWJ"));
    }
}
