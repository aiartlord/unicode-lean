//! UAX #14 default line breaking.
//!
//! A transcription of the Lean algorithm
//! `Unicode.Segmentation.LineBreak.lineBreaks`, whose `lineBreaks_length`
//! theorem fixes the output shape: one break-opportunity flag per boundary
//! position. The rule order, rule bodies, and snapshot fields below mirror that
//! reference — LB2 through LB31 in UAX #14 R7's canonical order, first match
//! winning, the trailing LB31 breaking every otherwise-unmatched pair.
//!
//! Where a line may break is a property of a sequence rather than of a code
//! point, so the entry point returns a flag per boundary instead of a predicate
//! over code points.
//!
//! Three mechanisms carry the context the rules read:
//!
//! * LB1 is applied at lookup time by [`resolved_class`], which folds the
//!   tailorable `AI`, `CJ`, `SA`, `SG` and `XX` into the algorithm's working
//!   alphabet. `SA` needs General_Category to choose between `CM` and `AL`.
//! * LB9 — treat `X CM*` / `X ZWJ*` as `X` — is realised through [`Snapshot`],
//!   whose fields hold the most recent class that was not `CM` or `ZWJ`. LB10,
//!   treating a leftover `CM` or `ZWJ` as `AL`, is the fallback taken when no
//!   such class exists.
//! * The rules naming a third character — LB15b, LB15c, the LB25 bracket and
//!   the fourth LB28a sub-rule — read the suffix beginning at the position
//!   being decided, so a lookahead needs no index arithmetic.
//!
//! Two departures from the Lean. Its positional reads are `lits[i]!` and
//! `cps[i]!`; here every read comes from a slice the caller already holds, so
//! no access can leave the sequence. And its `spSinceNoSp` snapshot field is
//! written by its fold and read by no rule, so this transcription omits it.

use crate::east_asian_width::{east_asian_width, EastAsianWidthClass};
use crate::general_category::{general_category, Gc};
use crate::segmentation::grapheme::is_ext_pict;
use crate::segmentation::line_break_tables::{Lb, DEFAULT_LB, LB_RANGES};

/// Raw `Line_Break` class of `cp`, before LB1, [`DEFAULT_LB`] when no range
/// covers it.
///
/// The ranges partition the code space and are sorted by lower bound, so the
/// covering range is unique and a binary search finds it.
pub fn raw_class(cp: u32) -> Lb {
    let mut lo = 0usize;
    let mut hi = LB_RANGES.len();
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let (range_lo, range_hi, class) = LB_RANGES[mid];
        if cp < range_lo {
            hi = mid;
        } else if cp > range_hi {
            lo = mid + 1;
        } else {
            return class;
        }
    }
    DEFAULT_LB
}

/// The `Line_Break` class `cp` carries once LB1 has tailored it.
///
/// `AI`, `SG` and `XX` resolve to `AL`; `CJ` to `NS`; `SA` to `CM` when the
/// code point is a non-spacing or spacing combining mark and to `AL` otherwise.
/// Every other class is already in the working alphabet.
pub fn resolved_class(cp: u32) -> Lb {
    match raw_class(cp) {
        Lb::Ai => Lb::Al,
        Lb::Cj => Lb::Ns,
        Lb::Sg => Lb::Al,
        Lb::Xx => Lb::Al,
        Lb::Sa => {
            // LB1 reads only the two combining-mark categories here; an
            // enclosing mark is not among them.
            match general_category(cp) {
                Gc::Mn | Gc::Mc => Lb::Cm,
                _ => Lb::Al,
            }
        }
        resolved => resolved,
    }
}

/// True iff LB9 absorbs this class into the character before it.
fn is_cm_zwj(class: Lb) -> bool {
    class == Lb::Cm || class == Lb::Zwj
}

/// True iff a preceding class blocks LB9's absorption, so a following `CM` or
/// `ZWJ` stands on its own and LB10 reads it as `AL`.
fn blocks_absorb(class: Lb) -> bool {
    matches!(
        class,
        Lb::Bk | Lb::Cr | Lb::Lf | Lb::Nl | Lb::Sp | Lb::Zw
    )
}

/// True iff the class is `QU` and the code point is initial punctuation, the
/// refinement LB15a reads.
fn is_pi_quote(cp: u32, class: Lb) -> bool {
    class == Lb::Qu && general_category(cp) == Gc::Pi
}

/// True iff the class is `QU` and the code point is final punctuation, the
/// refinement LB15b reads.
fn is_pf_quote(cp: u32, class: Lb) -> bool {
    class == Lb::Qu && general_category(cp) == Gc::Pf
}

/// True iff the code point is U+2010 HYPHEN, which LB20a and LB21a name
/// explicitly because UCD 17.0 moved it from class `HY` to class `HH`.
fn is_hyphen_u2010(cp: u32) -> bool {
    cp == 0x2010
}

/// True iff `cp` is East_Asian_Width `F`, `W` or `H`, the set LB25 and LB30
/// read.
fn is_east_asian_full_wide(cp: u32) -> bool {
    matches!(
        east_asian_width(cp),
        EastAsianWidthClass::F | EastAsianWidthClass::W | EastAsianWidthClass::H
    )
}

/// True iff `cp` counts as East Asian for LB19a's tailoring, which treats
/// `Ambiguous` as East Asian alongside `Fullwidth`, `Wide` and `Halfwidth`.
/// Wider than [`is_east_asian_full_wide`].
fn is_east_asian_or_ambiguous(cp: u32) -> bool {
    matches!(
        east_asian_width(cp),
        EastAsianWidthClass::F
            | EastAsianWidthClass::W
            | EastAsianWidthClass::H
            | EastAsianWidthClass::A
    )
}

/// True iff the effective class is present and among `classes`.
fn eff_in(effective: Option<Lb>, classes: &[Lb]) -> bool {
    match effective {
        Some(class) => classes.contains(&class),
        None => false,
    }
}

/// The left-hand context a boundary decision reads: the classes and code points
/// of the most recent characters LB9 did not absorb, plus the running counters
/// the rules keep. Mirrors the Lean `EffSnapshot`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Snapshot {
    /// Class of the most recent character that was not `CM` or `ZWJ`.
    eff_prev: Option<Lb>,
    /// Its code point — LB20a, LB21a and LB28a name U+2010 and U+25CC.
    eff_prev_cp: Option<u32>,
    /// Class of the most recent character that was not `CM`, `ZWJ` or `SP`.
    eff_prev_no_sp: Option<Lb>,
    /// Class of the second most recent such character.
    eff_prev_prev: Option<Lb>,
    /// Its code point.
    eff_prev_prev_cp: Option<u32>,
    /// Whether an LB15a initial-punctuation quote window is open.
    in_pi_quote_window: bool,
    /// Length of the current regional-indicator run, for LB30a.
    ri_run: u32,
    /// Whether an LB25 numeric chain is open.
    in_nu_chain: bool,
}

impl Snapshot {
    /// The context before any character has been read.
    fn initial() -> Self {
        Snapshot {
            eff_prev: None,
            eff_prev_cp: None,
            eff_prev_no_sp: None,
            eff_prev_prev: None,
            eff_prev_prev_cp: None,
            in_pi_quote_window: false,
            ri_run: 0,
            in_nu_chain: false,
        }
    }
}

/// The class a `CM` or `ZWJ` takes from what it attaches to under LB9, or `AL`
/// under LB10 when nothing absorbs it.
fn effective_class(class: Lb, eff_prev: Option<Lb>) -> Lb {
    if !is_cm_zwj(class) {
        return class;
    }
    match eff_prev {
        None => Lb::Al,
        Some(prev) => {
            if blocks_absorb(prev) {
                Lb::Al
            } else {
                class
            }
        }
    }
}

/// Fold one character into the context. A character LB9 absorbs leaves the
/// context untouched, which is what makes the neighbours it records effective
/// rather than literal. Mirrors the Lean `buildSnapshots` step.
fn advance(snapshot: &Snapshot, cp: u32, class: Lb) -> Snapshot {
    let effective = effective_class(class, snapshot.eff_prev);
    if is_cm_zwj(effective) {
        return *snapshot;
    }

    // LB15a opens its window only where an initial-punctuation quote stands
    // outside a word; a space carries an open window forward.
    let left_context_opens = match snapshot.eff_prev {
        None => true,
        Some(prev) => matches!(
            prev,
            Lb::Bk | Lb::Cr | Lb::Lf | Lb::Nl | Lb::Op | Lb::Qu | Lb::Gl | Lb::Sp | Lb::Zw
        ),
    };
    let in_pi_quote_window = if is_pi_quote(cp, effective) && left_context_opens {
        true
    } else if effective == Lb::Sp {
        snapshot.in_pi_quote_window
    } else {
        false
    };

    let in_nu_chain = if effective == Lb::Nu {
        true
    } else {
        snapshot.in_nu_chain
            && matches!(effective, Lb::Sy | Lb::Is | Lb::Cl | Lb::Cp | Lb::Pr)
    };

    Snapshot {
        eff_prev: Some(effective),
        eff_prev_cp: Some(cp),
        eff_prev_no_sp: if effective == Lb::Sp {
            snapshot.eff_prev_no_sp
        } else {
            Some(effective)
        },
        eff_prev_prev: snapshot.eff_prev,
        eff_prev_prev_cp: snapshot.eff_prev_cp,
        in_pi_quote_window,
        ri_run: if effective == Lb::Ri {
            snapshot.ri_run + 1
        } else {
            0
        },
        in_nu_chain,
    }
}

/// LB15b holds when the final quote is last, or when what follows it cannot
/// itself open a line.
fn final_quote_closes(ahead: &[(u32, Lb)]) -> bool {
    match ahead.first() {
        None => true,
        Some(&(_cp, next)) => matches!(
            next,
            Lb::Sp
                | Lb::Gl
                | Lb::Wj
                | Lb::Cl
                | Lb::Qu
                | Lb::Cp
                | Lb::Ex
                | Lb::Is
                | Lb::Sy
                | Lb::Bk
                | Lb::Cr
                | Lb::Lf
                | Lb::Nl
                | Lb::Zw
        ),
    }
}

/// The fourth LB28a sub-rule looks past any `CM` or `ZWJ` the cluster absorbs,
/// so the character it tests is the first significant one ahead.
fn next_significant_is_vf(ahead: &[(u32, Lb)]) -> bool {
    match ahead.iter().find(|&&(_cp, class)| !is_cm_zwj(class)) {
        Some(&(_cp, class)) => class == Lb::Vf,
        None => false,
    }
}

/// Whether a line break opportunity falls immediately before the head of
/// `suffix`, given the character before it and the context accumulated from
/// everything earlier.
///
/// `suffix` begins at the position being decided, so its head is the current
/// character and its tail supplies every lookahead the rules take.
fn breaks_before(prev: (u32, Lb), suffix: &[(u32, Lb)], s: &Snapshot) -> bool {
    let (prev_cp, prev_class) = prev;
    let (current_cp, current_class) = match suffix.first() {
        None => return true, // LB3
        Some(&head) => head,
    };
    let ahead = &suffix[1..];

    let eff = effective_class(current_class, s.eff_prev);
    let left = if is_cm_zwj(prev_class) {
        s.eff_prev
    } else {
        Some(prev_class)
    };

    // LB4
    if prev_class == Lb::Bk {
        return true;
    }
    // LB5
    if prev_class == Lb::Cr && current_class == Lb::Lf {
        return false;
    }
    if matches!(prev_class, Lb::Cr | Lb::Lf | Lb::Nl) {
        return true;
    }
    // LB6
    if matches!(current_class, Lb::Bk | Lb::Cr | Lb::Lf | Lb::Nl) {
        return false;
    }
    // LB7
    if current_class == Lb::Sp || current_class == Lb::Zw {
        return false;
    }
    // LB8
    if s.eff_prev_no_sp == Some(Lb::Zw) {
        return true;
    }
    // LB8a
    if prev_class == Lb::Zwj {
        return false;
    }
    // LB9
    if is_cm_zwj(current_class) {
        if let Some(prev_eff) = s.eff_prev {
            if !blocks_absorb(prev_eff) {
                return false;
            }
        }
    }
    // LB11
    if eff == Lb::Wj || eff_in(left, &[Lb::Wj]) {
        return false;
    }
    // LB12
    if eff_in(left, &[Lb::Gl]) {
        return false;
    }
    // LB12a
    if eff == Lb::Gl {
        let glue_keeps_left = match left {
            Some(class) => !matches!(class, Lb::Sp | Lb::Ba | Lb::Hy | Lb::Hh),
            None => true,
        };
        if glue_keeps_left {
            return false;
        }
    }
    // LB15c, which UCD 17.0 orders above LB13 and LB15d: break before an `IS`
    // that opens a number and follows a space, as in "equals .35".
    if prev_class == Lb::Sp
        && eff == Lb::Is
        && ahead.first().map(|&(_cp, class)| class) == Some(Lb::Nu)
    {
        return true;
    }
    // LB13
    if matches!(eff, Lb::Cl | Lb::Cp | Lb::Ex | Lb::Is | Lb::Sy) {
        return false;
    }
    // LB14
    if s.eff_prev_no_sp == Some(Lb::Op) {
        return false;
    }
    // LB15a
    if s.in_pi_quote_window {
        return false;
    }
    // LB15b
    if is_pf_quote(current_cp, eff) && final_quote_closes(ahead) {
        return false;
    }
    // LB15d
    if eff == Lb::Is {
        return false;
    }
    // LB16
    if eff == Lb::Ns
        && (s.eff_prev_no_sp == Some(Lb::Cl) || s.eff_prev_no_sp == Some(Lb::Cp))
    {
        return false;
    }
    // LB17
    if eff == Lb::B2 && s.eff_prev_no_sp == Some(Lb::B2) {
        return false;
    }
    // LB18
    if prev_class == Lb::Sp {
        return true;
    }
    // LB19 and LB19a. A quote neither breaks before nor after, except on the
    // OUTER side of an initial or final punctuation quote standing in
    // contiguous East Asian content — there the default break applies, so a
    // line may break at the quote boundary. The inner side stays unbroken,
    // being the boundary inside the quote's own scope.
    if eff == Lb::Qu {
        let open_quote_in_east_asian = is_pi_quote(current_cp, eff)
            && is_east_asian_or_ambiguous(prev_cp)
            && is_east_asian_or_ambiguous(current_cp)
            && ahead
                .first()
                .map(|&(cp, _class)| is_east_asian_or_ambiguous(cp))
                .unwrap_or(false);
        if !open_quote_in_east_asian {
            return false;
        }
    }
    if eff_in(left, &[Lb::Qu]) {
        let close_quote_in_east_asian = match s.eff_prev_cp {
            None => false,
            Some(quote_cp) => {
                is_pf_quote(quote_cp, Lb::Qu)
                    && s.eff_prev_prev_cp
                        .map(is_east_asian_or_ambiguous)
                        .unwrap_or(false)
                    && is_east_asian_or_ambiguous(quote_cp)
                    && is_east_asian_or_ambiguous(current_cp)
            }
        };
        if !close_quote_in_east_asian {
            return false;
        }
    }
    // LB20
    if eff == Lb::Cb || eff_in(left, &[Lb::Cb]) {
        return true;
    }

    // LB20.1 and LB20a both require the hyphen's own left context to be
    // outside a word, the same start-of-segment set.
    let hyphen_left_context_opens = match s.eff_prev_prev {
        None => true,
        Some(class) => matches!(
            class,
            Lb::Bk | Lb::Cr | Lb::Lf | Lb::Nl | Lb::Sp | Lb::Zw | Lb::Cb | Lb::Gl
        ),
    };
    // LB20.1, UCD 17.0: an explicit hyphen joins a following letter only where
    // its own left context is outside a word. A mid-word `HH` falls through to
    // LB31.
    if eff_in(left, &[Lb::Hh])
        && (eff == Lb::Al || eff == Lb::Hl)
        && hyphen_left_context_opens
    {
        return false;
    }
    // LB20a, with UCD 17.0's right side broadened to `HL` beside `AL`.
    if eff == Lb::Al || eff == Lb::Hl {
        let hyphen_carries_left = match s.eff_prev {
            None => false,
            Some(class) => {
                class == Lb::Hy
                    || class == Lb::Hh
                    || s.eff_prev_cp.map(is_hyphen_u2010).unwrap_or(false)
            }
        };
        if hyphen_carries_left && hyphen_left_context_opens {
            return false;
        }
    }
    // LB21
    if matches!(eff, Lb::Ba | Lb::Hy | Lb::Hh | Lb::Ns) {
        return false;
    }
    if eff_in(left, &[Lb::Bb]) {
        return false;
    }
    // LB21a: an `HL` letter followed by an `HY` hyphen or U+2010 glues to what
    // comes next unless that is itself `HL`. A `BA` does not glue here.
    if s.eff_prev_prev == Some(Lb::Hl) && eff != Lb::Hl {
        let hyphen_is_hy_or_2010 = match s.eff_prev {
            None => false,
            Some(class) => {
                class == Lb::Hy || s.eff_prev_cp.map(is_hyphen_u2010).unwrap_or(false)
            }
        };
        if hyphen_is_hy_or_2010 {
            return false;
        }
    }
    // LB21b
    if eff == Lb::Hl && eff_in(left, &[Lb::Sy]) {
        return false;
    }
    // LB22
    if eff == Lb::In {
        return false;
    }
    // LB23
    if eff == Lb::Nu && eff_in(left, &[Lb::Al, Lb::Hl]) {
        return false;
    }
    if (eff == Lb::Al || eff == Lb::Hl) && eff_in(left, &[Lb::Nu]) {
        return false;
    }
    // LB23a
    if matches!(eff, Lb::Id | Lb::Eb | Lb::Em) && eff_in(left, &[Lb::Pr]) {
        return false;
    }
    if eff == Lb::Po && eff_in(left, &[Lb::Id, Lb::Eb, Lb::Em]) {
        return false;
    }
    // LB24
    if (eff == Lb::Al || eff == Lb::Hl) && eff_in(left, &[Lb::Pr, Lb::Po]) {
        return false;
    }
    if (eff == Lb::Pr || eff == Lb::Po) && eff_in(left, &[Lb::Al, Lb::Hl]) {
        return false;
    }
    // LB25, closing an open numeric chain with a `CL` or `CP` suffix and a
    // following `PO` or `PR`.
    if s.in_nu_chain && matches!(eff, Lb::Cl | Lb::Cp | Lb::Po | Lb::Pr) {
        return false;
    }
    // LB25, opening a chain
    if eff == Lb::Nu && eff_in(left, &[Lb::Pr, Lb::Po, Lb::Hy, Lb::Op, Lb::Is]) {
        return false;
    }
    // LB25, chain body
    if eff == Lb::Nu && eff_in(left, &[Lb::Nu]) {
        return false;
    }
    // LB25, extending an open chain across a `SY`
    if eff == Lb::Nu && eff_in(left, &[Lb::Sy]) && s.in_nu_chain {
        return false;
    }
    // LB25, bracketed prefix: a `PR` joins an `OP` only when the `OP` itself
    // opens a number, and neither is East Asian Fullwidth, Wide or Halfwidth.
    if eff == Lb::Op
        && eff_in(left, &[Lb::Pr])
        && !is_east_asian_full_wide(current_cp)
        && s.eff_prev_cp
            .map(|cp| !is_east_asian_full_wide(cp))
            .unwrap_or(false)
        && ahead.first().map(|&(_cp, class)| class) == Some(Lb::Nu)
    {
        return false;
    }
    // LB26
    if eff_in(left, &[Lb::Jl]) && matches!(eff, Lb::Jl | Lb::Jv | Lb::H2 | Lb::H3) {
        return false;
    }
    if eff_in(left, &[Lb::Jv, Lb::H2]) && (eff == Lb::Jv || eff == Lb::Jt) {
        return false;
    }
    if eff_in(left, &[Lb::Jt, Lb::H3]) && eff == Lb::Jt {
        return false;
    }
    // LB27
    if eff_in(left, &[Lb::Jl, Lb::Jv, Lb::Jt, Lb::H2, Lb::H3])
        && (eff == Lb::In || eff == Lb::Po)
    {
        return false;
    }
    if eff_in(left, &[Lb::Pr]) && matches!(eff, Lb::Jl | Lb::Jv | Lb::Jt | Lb::H2 | Lb::H3)
    {
        return false;
    }
    // LB28
    if (eff == Lb::Al || eff == Lb::Hl) && eff_in(left, &[Lb::Al, Lb::Hl]) {
        return false;
    }

    // LB28a, the aksara cluster rules. U+25CC DOTTED CIRCLE carries class `AL`
    // and stands in for a cluster base throughout.
    let left_is_aksara_base = eff_in(left, &[Lb::Ak, Lb::As])
        || (s.eff_prev_cp == Some(0x25CC) && s.eff_prev == Some(Lb::Al));
    if eff_in(left, &[Lb::Ap]) && (eff == Lb::Ak || eff == Lb::As || current_cp == 0x25CC)
    {
        return false;
    }
    if left_is_aksara_base && (eff == Lb::Vf || eff == Lb::Vi) {
        return false;
    }
    if s.eff_prev == Some(Lb::Vi)
        && (s.eff_prev_prev == Some(Lb::Ak)
            || s.eff_prev_prev == Some(Lb::As)
            || s.eff_prev_prev_cp == Some(0x25CC))
        && (eff == Lb::Ak || current_cp == 0x25CC)
    {
        return false;
    }
    if left_is_aksara_base
        && (eff == Lb::Ak || eff == Lb::As || current_cp == 0x25CC)
        && next_significant_is_vf(ahead)
    {
        return false;
    }
    // LB29
    if (eff == Lb::Al || eff == Lb::Hl) && eff_in(left, &[Lb::Is]) {
        return false;
    }
    // LB30, where the bracket must not be East Asian Fullwidth, Wide or
    // Halfwidth.
    if eff == Lb::Op
        && eff_in(left, &[Lb::Al, Lb::Hl, Lb::Nu])
        && !is_east_asian_full_wide(current_cp)
    {
        return false;
    }
    if matches!(eff, Lb::Al | Lb::Hl | Lb::Nu)
        && eff_in(left, &[Lb::Cp])
        && !is_east_asian_full_wide(prev_cp)
    {
        return false;
    }
    // LB30a
    if eff == Lb::Ri && s.ri_run % 2 == 1 {
        return false;
    }
    // LB30b
    if eff == Lb::Em && eff_in(left, &[Lb::Eb]) {
        return false;
    }
    if eff == Lb::Em {
        let previous_is_unassigned_pictograph = match s.eff_prev_cp {
            None => false,
            Some(cp) => is_ext_pict(cp) && general_category(cp) == Gc::Cn,
        };
        if previous_is_unassigned_pictograph {
            return false;
        }
    }
    // LB31
    true
}

/// One break-opportunity flag per boundary of the code point sequence, so a
/// sequence of `n` code points yields `n + 1` flags — the shape the Lean
/// `lineBreaks_length` theorem fixes.
///
/// Entry `0` is `false` — LB2 forbids a break at the start of text — and entry
/// `n` is `true` per LB3, which requires one at the end.
pub fn line_breaks(cps: &[u32]) -> Vec<bool> {
    let pairs: Vec<(u32, Lb)> = cps.iter().map(|&cp| (cp, resolved_class(cp))).collect();
    let mut out = Vec::with_capacity(pairs.len() + 1);
    let mut snapshot = Snapshot::initial();
    for (index, &(cp, class)) in pairs.iter().enumerate() {
        match index.checked_sub(1) {
            None => out.push(false), // LB2
            Some(before) => {
                out.push(breaks_before(pairs[before], &pairs[index..], &snapshot));
            }
        }
        snapshot = advance(&snapshot, cp, class);
    }
    out.push(true); // LB3
    out
}

/// The code point sequence split at every break opportunity — the runs a
/// renderer may place on separate lines.
pub fn line_runs(cps: &[u32]) -> Vec<Vec<u32>> {
    let breaks = line_breaks(cps);
    let mut out: Vec<Vec<u32>> = Vec::new();
    let mut current: Vec<u32> = Vec::new();
    for (index, &cp) in cps.iter().enumerate() {
        current.push(cp);
        if breaks.get(index + 1) == Some(&true) && !current.is_empty() {
            out.push(core::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_carries_one_flag_per_boundary() {
        // The Lean `lineBreaks_length` theorem: `cps.length + 1` flags.
        for length in 0..8usize {
            let cps: Vec<u32> = (0..length).map(|i| 0x61 + i as u32).collect();
            assert_eq!(line_breaks(&cps).len(), length + 1);
        }
    }

    #[test]
    fn start_of_text_never_breaks_and_end_always_does() {
        let breaks = line_breaks(&[0x61, 0x62]);
        assert_eq!(breaks.first(), Some(&false)); // LB2
        assert_eq!(breaks.last(), Some(&true)); // LB3
    }

    #[test]
    fn a_word_is_one_run_and_a_space_opens_the_next() {
        // LB28 keeps letters together; LB18 breaks after a space.
        assert_eq!(line_breaks(&[0x61, 0x62]), vec![false, false, true]);
        let runs = line_runs(&[0x61, 0x20, 0x62]);
        assert_eq!(runs, vec![vec![0x61, 0x20], vec![0x62]]);
    }

    #[test]
    fn a_mandatory_break_character_breaks_after_itself() {
        // LB4: BK ÷. U+000C FORM FEED is class BK.
        assert_eq!(line_breaks(&[0x61, 0x000C, 0x62]), vec![false, false, true, true]);
    }

    #[test]
    fn carriage_return_line_feed_is_not_split() {
        // LB5: CR × LF, then a mandatory break after the pair.
        assert_eq!(line_breaks(&[0x0D, 0x0A, 0x61]), vec![false, false, true, true]);
    }

    #[test]
    fn a_combining_mark_takes_the_class_of_its_base() {
        // LB9: `X CM` behaves as `X`, so no break falls inside the pair.
        assert_eq!(line_breaks(&[0x61, 0x0301]), vec![false, false, true]);
    }

    #[test]
    fn a_word_joiner_glues_both_sides() {
        // LB11: × WJ and WJ ×.
        assert_eq!(
            line_breaks(&[0x61, 0x2060, 0x62]),
            vec![false, false, false, true]
        );
    }

    #[test]
    fn a_space_before_a_number_opening_period_breaks() {
        // LB15c: SP ÷ IS NU — "a .35" breaks before the period.
        let breaks = line_breaks(&[0x61, 0x20, 0x2E, 0x33, 0x35]);
        assert_eq!(breaks, vec![false, false, true, false, false, true]);
    }

    #[test]
    fn a_numeric_chain_holds_together() {
        // LB25: "1,000" is one run across the SY separator.
        assert_eq!(line_runs(&[0x31, 0x2C, 0x30, 0x30, 0x30]).len(), 1);
    }

    #[test]
    fn regional_indicators_pair_off() {
        // LB30a: an even-length RI run takes no break inside a pair, and a
        // second pair may start a new line.
        let breaks = line_breaks(&[0x1F1EF, 0x1F1F5, 0x1F1FA, 0x1F1F8]);
        assert_eq!(breaks, vec![false, false, true, false, true]);
    }

    #[test]
    fn an_emoji_modifier_stays_on_its_base() {
        // LB30b: EB × EM.
        assert_eq!(line_breaks(&[0x1F466, 0x1F3FB]), vec![false, false, true]);
    }

    #[test]
    fn lb1_resolves_the_tailorable_classes() {
        // AI, SG and XX resolve to AL; CJ to NS. U+3041 HIRAGANA LETTER SMALL A
        // is CJ, so it resolves to NS.
        assert_eq!(raw_class(0x3041), Lb::Cj);
        assert_eq!(resolved_class(0x3041), Lb::Ns);
        // U+00A7 SECTION SIGN is AI, resolving to AL.
        assert_eq!(raw_class(0x00A7), Lb::Ai);
        assert_eq!(resolved_class(0x00A7), Lb::Al);
        // A surrogate code point is SG, resolving to AL.
        assert_eq!(raw_class(0xD800), Lb::Sg);
        assert_eq!(resolved_class(0xD800), Lb::Al);
        // U+05EB lies in the Hebrew block's unassigned gap, which no
        // `LineBreak.txt` range covers, so it takes the `@missing` XX default
        // and LB1 resolves it to AL.
        assert_eq!(raw_class(0x05EB), Lb::Xx);
        assert_eq!(resolved_class(0x05EB), Lb::Al);
    }

    #[test]
    fn lb1_resolves_sa_by_general_category() {
        // U+0E31 THAI CHARACTER MAI HAN-AKAT is SA with General_Category Mn,
        // so LB1 reads it as CM; U+0E01 THAI CHARACTER KO KAI is SA with
        // category Lo, so LB1 reads it as AL.
        assert_eq!(raw_class(0x0E31), Lb::Sa);
        assert_eq!(resolved_class(0x0E31), Lb::Cm);
        assert_eq!(raw_class(0x0E01), Lb::Sa);
        assert_eq!(resolved_class(0x0E01), Lb::Al);
    }
}
