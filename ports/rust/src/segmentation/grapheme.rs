//! UAX #29 default extended grapheme cluster segmentation.
//!
//! A transcription of the Lean algorithm
//! `Unicode.Segmentation.GraphemeBreak.graphemeBreaks`. The active Lean tree
//! proves `graphemeBreaks_eq_spec`, relating that algorithm to the declarative
//! UAX #29 GB1-GB999 specification. The state fields, rule order, and
//! transition below mirror that reference.

use crate::segmentation::grapheme_tables::{Gcb, Incb, EXTPICT_RANGES, GCB_RANGES, INCB_RANGES};

// The property tables are grouped by property value (as in the UCD source),
// not globally sorted by code point, so lookups scan linearly for the covering
// range — mirroring the verified Lean `find?`. Each class is a partition, so at
// most one range covers a code point and the first match is the only match.

/// Grapheme_Cluster_Break class of `cp`, `Gcb::Other` when uncovered.
pub fn lookup_gcb(cp: u32) -> Gcb {
    GCB_RANGES
        .iter()
        .find(|r| r.0 <= cp && cp <= r.1)
        .map(|r| r.2)
        .unwrap_or(Gcb::Other)
}

/// True iff `cp` has `Grapheme_Cluster_Break = Extend` — a combining mark that
/// stacks onto the preceding base. The RendererDivergence detector uses this to
/// measure Zalgo-style combining-mark stacks.
pub fn is_grapheme_extend(cp: u32) -> bool {
    lookup_gcb(cp) == Gcb::Extend
}

/// Indic_Conjunct_Break class of `cp`, `Incb::None` when uncovered.
pub fn lookup_incb(cp: u32) -> Incb {
    INCB_RANGES
        .iter()
        .find(|r| r.0 <= cp && cp <= r.1)
        .map(|r| r.2)
        .unwrap_or(Incb::None)
}

/// Whether `cp` has the Extended_Pictographic property.
pub fn is_ext_pict(cp: u32) -> bool {
    EXTPICT_RANGES.iter().any(|r| r.0 <= cp && cp <= r.1)
}

/// GB11 left-context state: mirrors the Lean `EPicState`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum EpicState {
    None,
    AfterEp,
    AfterEpZwj,
}

/// GB9c left-context state: mirrors the Lean `InCBState`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum IncbState {
    None,
    Consonant,
    Linker,
}

/// Running scan state, mirroring the Lean `State`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct State {
    prev_class: Option<Gcb>,
    epic_state: EpicState,
    incb_state: IncbState,
    ri_run: u32,
}

impl State {
    fn initial() -> Self {
        State {
            prev_class: None,
            epic_state: EpicState::None,
            incb_state: IncbState::None,
            ri_run: 0,
        }
    }
}

/// Whether a grapheme cluster break occurs immediately before `cp` given the
/// running state. Implements UAX #29 GB1–GB999 in canonical order; first match
/// wins, the trailing GB999 breaks every otherwise-unmatched pair.
fn should_break_before(cp: u32, s: &State) -> bool {
    let bc = lookup_gcb(cp);
    let incb = lookup_incb(cp);
    let is_ep = is_ext_pict(cp);
    match s.prev_class {
        None => true, // GB1: sot ÷
        Some(pc) => {
            if pc == Gcb::Cr && bc == Gcb::Lf {
                false // GB3: CR × LF
            } else if pc == Gcb::Control || pc == Gcb::Cr || pc == Gcb::Lf {
                true // GB4: (Control | CR | LF) ÷
            } else if bc == Gcb::Control || bc == Gcb::Cr || bc == Gcb::Lf {
                true // GB5: ÷ (Control | CR | LF)
            } else if pc == Gcb::L
                && (bc == Gcb::L || bc == Gcb::V || bc == Gcb::Lv || bc == Gcb::Lvt)
            {
                false // GB6: L × (L | V | LV | LVT)
            } else if (pc == Gcb::Lv || pc == Gcb::V) && (bc == Gcb::V || bc == Gcb::T) {
                false // GB7: (LV | V) × (V | T)
            } else if (pc == Gcb::Lvt || pc == Gcb::T) && bc == Gcb::T {
                false // GB8: (LVT | T) × T
            } else if bc == Gcb::Extend || bc == Gcb::Zwj {
                false // GB9: × (Extend | ZWJ)
            } else if bc == Gcb::SpacingMark {
                false // GB9a: × SpacingMark
            } else if pc == Gcb::Prepend {
                false // GB9b: Prepend ×
            } else if s.incb_state == IncbState::Linker && incb == Incb::Consonant {
                false // GB9c: Consonant (Extend|Linker)* Linker (Extend|Linker)* × Consonant
            } else if s.epic_state == EpicState::AfterEpZwj && is_ep {
                false // GB11: ExtPict Extend* ZWJ × ExtPict
            } else if bc == Gcb::RegionalIndicator && s.ri_run % 2 == 1 {
                false // GB12/GB13: odd-parity RI run extends
            } else {
                true // GB999: Any ÷ Any
            }
        }
    }
}

/// Update the running state after consuming `cp`. Mirrors the Lean `advance`.
fn advance(cp: u32, s: &State) -> State {
    let bc = lookup_gcb(cp);
    let incb = lookup_incb(cp);
    let is_ep = is_ext_pict(cp);
    let epic_state = if is_ep {
        EpicState::AfterEp
    } else if s.epic_state == EpicState::AfterEp && bc == Gcb::Extend {
        EpicState::AfterEp
    } else if s.epic_state == EpicState::AfterEp && bc == Gcb::Zwj {
        EpicState::AfterEpZwj
    } else {
        EpicState::None
    };
    let incb_state = if incb == Incb::Consonant {
        IncbState::Consonant
    } else if s.incb_state == IncbState::Consonant && incb == Incb::Linker {
        IncbState::Linker
    } else if s.incb_state == IncbState::Consonant && incb == Incb::Extend {
        IncbState::Consonant
    } else if s.incb_state == IncbState::Linker && incb == Incb::Linker {
        IncbState::Linker
    } else if s.incb_state == IncbState::Linker && incb == Incb::Extend {
        IncbState::Linker
    } else {
        IncbState::None
    };
    let ri_run = if bc == Gcb::RegionalIndicator {
        s.ri_run + 1
    } else {
        0
    };
    State {
        prev_class: Some(bc),
        epic_state,
        incb_state,
        ri_run,
    }
}

/// Boundary mask of length `cps.len() + 1`. Entry `i` is `true` when a grapheme
/// cluster break occurs immediately before position `i` — entry `0` is the GB1
/// start-of-text break, entry `cps.len()` the GB2 end-of-text break, both always
/// `true`. Mirrors the Lean `graphemeBreaks`.
pub fn grapheme_breaks(cps: &[u32]) -> Vec<bool> {
    let mut bs = Vec::with_capacity(cps.len() + 1);
    let mut s = State::initial();
    for &cp in cps {
        bs.push(should_break_before(cp, &s));
        s = advance(cp, &s);
    }
    bs.push(true); // GB2: eot ÷
    bs
}

/// Split `cps` into grapheme clusters (the code points between consecutive
/// boundaries).
pub fn grapheme_clusters(cps: &[u32]) -> Vec<Vec<u32>> {
    let breaks = grapheme_breaks(cps);
    let mut out: Vec<Vec<u32>> = Vec::new();
    let mut cur: Vec<u32> = Vec::new();
    for (i, &cp) in cps.iter().enumerate() {
        if breaks[i] && !cur.is_empty() {
            out.push(core::mem::take(&mut cur));
        }
        cur.push(cp);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_each_its_own_cluster() {
        // "abc" -> break before each + eot: 4 breaks, 3 clusters.
        assert_eq!(
            grapheme_breaks(&[0x61, 0x62, 0x63]),
            vec![true, true, true, true]
        );
        assert_eq!(grapheme_clusters(&[0x61, 0x62, 0x63]).len(), 3);
    }

    #[test]
    fn combining_mark_joins() {
        // e + COMBINING ACUTE (U+0301) is one cluster (GB9).
        assert_eq!(grapheme_breaks(&[0x65, 0x0301]), vec![true, false, true]);
        assert_eq!(grapheme_clusters(&[0x65, 0x0301]).len(), 1);
    }

    #[test]
    fn crlf_is_one_cluster() {
        // CR LF is a single cluster (GB3).
        assert_eq!(grapheme_breaks(&[0x0D, 0x0A]), vec![true, false, true]);
    }

    #[test]
    fn flag_pair_is_one_cluster() {
        // Regional indicators 🇯🇵 (U+1F1EF U+1F1F5) form one cluster (GB12).
        assert_eq!(
            grapheme_breaks(&[0x1F1EF, 0x1F1F5]),
            vec![true, false, true]
        );
        assert_eq!(grapheme_clusters(&[0x1F1EF, 0x1F1F5]).len(), 1);
    }

    #[test]
    fn four_flags_are_two_clusters() {
        // Four regional indicators = two flags = two clusters (GB12/13 parity).
        let cps = [0x1F1EF, 0x1F1F5, 0x1F1FA, 0x1F1F8];
        assert_eq!(grapheme_clusters(&cps).len(), 2);
    }

    #[test]
    fn emoji_zwj_sequence_is_one_cluster() {
        // 👨‍👩‍👧 : man ZWJ woman ZWJ girl is one cluster (GB11).
        let cps = [0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467];
        assert_eq!(grapheme_clusters(&cps).len(), 1);
    }
}
