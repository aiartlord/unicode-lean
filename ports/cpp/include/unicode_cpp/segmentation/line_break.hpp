// UAX #14 default line breaking.
//
// A port of the Lean algorithm Unicode.Segmentation.LineBreak.lineBreaks,
// whose lineBreaks_length theorem fixes the output shape: one
// break-opportunity flag per boundary position. The rule order, rule bodies,
// and snapshot fields below mirror that reference -- LB2 through LB31 in
// UAX #14 R7's canonical order, first match winning, the trailing LB31
// breaking every otherwise-unmatched pair.
//
// Where a line may break is a property of a sequence rather than of a code
// point, so the entry point returns a flag per boundary instead of a predicate
// over code points.
//
// Three mechanisms carry the context the rules read:
//
//   * LB1 is applied at lookup time by resolved_class, which folds the
//     tailorable AI, CJ, SA, SG and XX into the algorithm's working alphabet.
//     SA needs General_Category to choose between CM and AL.
//   * LB9 -- treat X CM* / X ZWJ* as X -- is realised through Snapshot, whose
//     fields hold the most recent class that was not CM or ZWJ. LB10, treating
//     a leftover CM or ZWJ as AL, is the fallback taken when no such class
//     exists.
//   * The rules naming a third character -- LB15b, LB15c, the LB25 bracket and
//     the fourth LB28a sub-rule -- read the suffix beginning at the position
//     being decided, so a lookahead needs no index arithmetic.
//
// Two departures from the Lean. Its positional reads are lits[i]! and cps[i]!;
// here every read comes from a span the caller already holds, so no access can
// leave the sequence. And its spSinceNoSp snapshot field is written by its fold
// and read by no rule, so this port omits it.
//
// The two properties UAX #14 needs beyond the Line_Break class --
// General_Category for LB1's SA resolution, the Pi/Pf quote refinement and
// LB30b, and East_Asian_Width for LB19a, LB25 and LB30 -- come from the
// generated headers above this layer, so this header takes code points and
// needs no data directory, as segmentation/grapheme.hpp does.

#ifndef UNICODE_CPP_SEGMENTATION_LINE_BREAK_HPP
#define UNICODE_CPP_SEGMENTATION_LINE_BREAK_HPP

#include <cstdint>
#include <initializer_list>
#include <optional>
#include <span>
#include <utility>
#include <vector>

#include "unicode_cpp/east_asian_width_tables.hpp"
#include "unicode_cpp/general_category_tables.hpp"
#include "unicode_cpp/segmentation/grapheme.hpp"
#include "unicode_cpp/segmentation/line_break_tables.hpp"

namespace unicode_cpp::segmentation {

// One character as the algorithm reads it: its code point and its LB1-resolved
// class.
using Classified = std::pair<std::uint32_t, Lb>;

// The Line_Break class cp carries once LB1 has tailored it.
//
// AI, SG and XX resolve to AL; CJ to NS; SA to CM when the code point is a
// non-spacing or spacing combining mark and to AL otherwise. Every other class
// is already in the working alphabet.
inline Lb resolved_class(std::uint32_t cp) {
  switch (raw_class(cp)) {
    case Lb::Ai:
    case Lb::Sg:
    case Lb::Xx:
      return Lb::Al;
    case Lb::Cj:
      return Lb::Ns;
    case Lb::Sa: {
      // LB1 reads only the two combining-mark categories here; an enclosing
      // mark is not among them.
      const GeneralCategory gc = general_category(cp);
      return (gc == GeneralCategory::Mn || gc == GeneralCategory::Mc) ? Lb::Cm
                                                                     : Lb::Al;
    }
    default:
      return raw_class(cp);
  }
}

// Whether LB9 absorbs this class into the character before it.
inline bool is_cm_zwj(Lb cls) { return cls == Lb::Cm || cls == Lb::Zwj; }

// Whether a preceding class blocks LB9's absorption, so a following CM or ZWJ
// stands on its own and LB10 reads it as AL.
inline bool blocks_absorb(Lb cls) {
  return cls == Lb::Bk || cls == Lb::Cr || cls == Lb::Lf || cls == Lb::Nl ||
         cls == Lb::Sp || cls == Lb::Zw;
}

// Whether the class is QU and the code point is initial punctuation, the
// refinement LB15a reads.
inline bool is_pi_quote(std::uint32_t cp, Lb cls) {
  return cls == Lb::Qu && general_category(cp) == GeneralCategory::Pi;
}

// Whether the class is QU and the code point is final punctuation, the
// refinement LB15b reads.
inline bool is_pf_quote(std::uint32_t cp, Lb cls) {
  return cls == Lb::Qu && general_category(cp) == GeneralCategory::Pf;
}

// Whether the code point is U+2010 HYPHEN, which LB20a and LB21a name
// explicitly because UCD 17.0 moved it from class HY to class HH.
inline bool is_hyphen_u2010(std::uint32_t cp) { return cp == 0x2010; }

// Whether cp is East_Asian_Width F, W or H, the set LB25 and LB30 read.
inline bool is_east_asian_full_wide(std::uint32_t cp) {
  const EastAsianWidthClass w = east_asian_width_class(cp);
  return w == EastAsianWidthClass::F || w == EastAsianWidthClass::W ||
         w == EastAsianWidthClass::H;
}

// Whether cp counts as East Asian for LB19a's tailoring, which treats
// Ambiguous as East Asian alongside Fullwidth, Wide and Halfwidth. Wider than
// is_east_asian_full_wide.
inline bool is_east_asian_or_ambiguous(std::uint32_t cp) {
  const EastAsianWidthClass w = east_asian_width_class(cp);
  return w == EastAsianWidthClass::F || w == EastAsianWidthClass::W ||
         w == EastAsianWidthClass::H || w == EastAsianWidthClass::A;
}

// Whether the effective class is present and among classes.
inline bool eff_in(const std::optional<Lb> &effective,
                   std::initializer_list<Lb> classes) {
  if (!effective.has_value()) {
    return false;
  }
  for (const Lb cls : classes) {
    if (*effective == cls) {
      return true;
    }
  }
  return false;
}

// The left-hand context a boundary decision reads: the classes and code points
// of the most recent characters LB9 did not absorb, plus the running counters
// the rules keep. Mirrors the Lean EffSnapshot.
struct Snapshot {
  // Class of the most recent character that was not CM or ZWJ.
  std::optional<Lb> eff_prev;
  // Its code point -- LB20a, LB21a and LB28a name U+2010 and U+25CC.
  std::optional<std::uint32_t> eff_prev_cp;
  // Class of the most recent character that was not CM, ZWJ or SP.
  std::optional<Lb> eff_prev_no_sp;
  // Class of the second most recent such character.
  std::optional<Lb> eff_prev_prev;
  // Its code point.
  std::optional<std::uint32_t> eff_prev_prev_cp;
  // Whether an LB15a initial-punctuation quote window is open.
  bool in_pi_quote_window;
  // Length of the current regional-indicator run, for LB30a.
  std::uint32_t ri_run;
  // Whether an LB25 numeric chain is open.
  bool in_nu_chain;
};

// The context before any character has been read.
inline Snapshot initial_snapshot() {
  return Snapshot{std::nullopt, std::nullopt, std::nullopt, std::nullopt,
                  std::nullopt, false,        0,            false};
}

// The class a CM or ZWJ takes from what it attaches to under LB9, or AL under
// LB10 when nothing absorbs it.
inline Lb effective_class(Lb cls, const std::optional<Lb> &eff_prev) {
  if (!is_cm_zwj(cls)) {
    return cls;
  }
  if (!eff_prev.has_value()) {
    return Lb::Al;
  }
  return blocks_absorb(*eff_prev) ? Lb::Al : cls;
}

// Fold one character into the context. A character LB9 absorbs leaves the
// context untouched, which is what makes the neighbours it records effective
// rather than literal. Mirrors the Lean buildSnapshots step.
inline Snapshot advance_line_break(const Snapshot &s, std::uint32_t cp,
                                   Lb cls) {
  const Lb effective = effective_class(cls, s.eff_prev);
  if (is_cm_zwj(effective)) {
    return s;
  }

  // LB15a opens its window only where an initial-punctuation quote stands
  // outside a word; a space carries an open window forward.
  const bool left_context_opens =
      !s.eff_prev.has_value() ||
      eff_in(s.eff_prev, {Lb::Bk, Lb::Cr, Lb::Lf, Lb::Nl, Lb::Op, Lb::Qu,
                          Lb::Gl, Lb::Sp, Lb::Zw});
  bool in_pi_quote_window = false;
  if (is_pi_quote(cp, effective) && left_context_opens) {
    in_pi_quote_window = true;
  } else if (effective == Lb::Sp) {
    in_pi_quote_window = s.in_pi_quote_window;
  }

  bool in_nu_chain = false;
  if (effective == Lb::Nu) {
    in_nu_chain = true;
  } else if (s.in_nu_chain) {
    in_nu_chain = effective == Lb::Sy || effective == Lb::Is ||
                  effective == Lb::Cl || effective == Lb::Cp ||
                  effective == Lb::Pr;
  }

  Snapshot out;
  out.eff_prev = effective;
  out.eff_prev_cp = cp;
  out.eff_prev_no_sp = (effective == Lb::Sp) ? s.eff_prev_no_sp
                                             : std::make_optional(effective);
  out.eff_prev_prev = s.eff_prev;
  out.eff_prev_prev_cp = s.eff_prev_cp;
  out.in_pi_quote_window = in_pi_quote_window;
  out.ri_run = (effective == Lb::Ri) ? s.ri_run + 1 : 0;
  out.in_nu_chain = in_nu_chain;
  return out;
}

// LB15b holds when the final quote is last, or when what follows it cannot
// itself open a line.
inline bool final_quote_closes(std::span<const Classified> ahead) {
  if (ahead.empty()) {
    return true;
  }
  const Lb next = ahead.front().second;
  return next == Lb::Sp || next == Lb::Gl || next == Lb::Wj ||
         next == Lb::Cl || next == Lb::Qu || next == Lb::Cp ||
         next == Lb::Ex || next == Lb::Is || next == Lb::Sy ||
         next == Lb::Bk || next == Lb::Cr || next == Lb::Lf ||
         next == Lb::Nl || next == Lb::Zw;
}

// The fourth LB28a sub-rule looks past any CM or ZWJ the cluster absorbs, so
// the character it tests is the first significant one ahead.
inline bool next_significant_is_vf(std::span<const Classified> ahead) {
  for (const Classified &entry : ahead) {
    if (!is_cm_zwj(entry.second)) {
      return entry.second == Lb::Vf;
    }
  }
  return false;
}

// The class at the head of a suffix, or nothing past its end.
inline std::optional<Lb> head_class(std::span<const Classified> ahead) {
  if (ahead.empty()) {
    return std::nullopt;
  }
  return ahead.front().second;
}

// Whether a line break opportunity falls immediately before the head of
// suffix, given the character before it and the context accumulated from
// everything earlier.
//
// suffix begins at the position being decided, so its head is the current
// character and its tail supplies every lookahead the rules take.
inline bool breaks_before(const Classified &prev,
                          std::span<const Classified> suffix,
                          const Snapshot &s) {
  if (suffix.empty()) {
    return true;  // LB3
  }
  const std::uint32_t prev_cp = prev.first;
  const Lb prev_class = prev.second;
  const std::uint32_t current_cp = suffix.front().first;
  const Lb current_class = suffix.front().second;
  const std::span<const Classified> ahead = suffix.subspan(1);

  const Lb eff = effective_class(current_class, s.eff_prev);
  const std::optional<Lb> left =
      is_cm_zwj(prev_class) ? s.eff_prev : std::make_optional(prev_class);

  // LB4
  if (prev_class == Lb::Bk) {
    return true;
  }
  // LB5
  if (prev_class == Lb::Cr && current_class == Lb::Lf) {
    return false;
  }
  if (prev_class == Lb::Cr || prev_class == Lb::Lf || prev_class == Lb::Nl) {
    return true;
  }
  // LB6
  if (current_class == Lb::Bk || current_class == Lb::Cr ||
      current_class == Lb::Lf || current_class == Lb::Nl) {
    return false;
  }
  // LB7
  if (current_class == Lb::Sp || current_class == Lb::Zw) {
    return false;
  }
  // LB8
  if (s.eff_prev_no_sp == std::make_optional(Lb::Zw)) {
    return true;
  }
  // LB8a
  if (prev_class == Lb::Zwj) {
    return false;
  }
  // LB9
  if (is_cm_zwj(current_class) && s.eff_prev.has_value() &&
      !blocks_absorb(*s.eff_prev)) {
    return false;
  }
  // LB11
  if (eff == Lb::Wj || eff_in(left, {Lb::Wj})) {
    return false;
  }
  // LB12
  if (eff_in(left, {Lb::Gl})) {
    return false;
  }
  // LB12a
  if (eff == Lb::Gl &&
      !eff_in(left, {Lb::Sp, Lb::Ba, Lb::Hy, Lb::Hh})) {
    return false;
  }
  // LB15c, which UCD 17.0 orders above LB13 and LB15d: break before an IS that
  // opens a number and follows a space, as in "equals .35".
  if (prev_class == Lb::Sp && eff == Lb::Is &&
      head_class(ahead) == std::make_optional(Lb::Nu)) {
    return true;
  }
  // LB13
  if (eff == Lb::Cl || eff == Lb::Cp || eff == Lb::Ex || eff == Lb::Is ||
      eff == Lb::Sy) {
    return false;
  }
  // LB14
  if (s.eff_prev_no_sp == std::make_optional(Lb::Op)) {
    return false;
  }
  // LB15a
  if (s.in_pi_quote_window) {
    return false;
  }
  // LB15b
  if (is_pf_quote(current_cp, eff) && final_quote_closes(ahead)) {
    return false;
  }
  // LB15d
  if (eff == Lb::Is) {
    return false;
  }
  // LB16
  if (eff == Lb::Ns && (s.eff_prev_no_sp == std::make_optional(Lb::Cl) ||
                        s.eff_prev_no_sp == std::make_optional(Lb::Cp))) {
    return false;
  }
  // LB17
  if (eff == Lb::B2 && s.eff_prev_no_sp == std::make_optional(Lb::B2)) {
    return false;
  }
  // LB18
  if (prev_class == Lb::Sp) {
    return true;
  }
  // LB19 and LB19a. A quote neither breaks before nor after, except on the
  // OUTER side of an initial or final punctuation quote standing in contiguous
  // East Asian content -- there the default break applies, so a line may break
  // at the quote boundary. The inner side stays unbroken, being the boundary
  // inside the quote's own scope.
  if (eff == Lb::Qu) {
    const bool next_east_asian =
        !ahead.empty() && is_east_asian_or_ambiguous(ahead.front().first);
    const bool open_quote_in_east_asian =
        is_pi_quote(current_cp, eff) && is_east_asian_or_ambiguous(prev_cp) &&
        is_east_asian_or_ambiguous(current_cp) && next_east_asian;
    if (!open_quote_in_east_asian) {
      return false;
    }
  }
  if (eff_in(left, {Lb::Qu})) {
    bool close_quote_in_east_asian = false;
    if (s.eff_prev_cp.has_value()) {
      const std::uint32_t quote_cp = *s.eff_prev_cp;
      close_quote_in_east_asian =
          is_pf_quote(quote_cp, Lb::Qu) && s.eff_prev_prev_cp.has_value() &&
          is_east_asian_or_ambiguous(*s.eff_prev_prev_cp) &&
          is_east_asian_or_ambiguous(quote_cp) &&
          is_east_asian_or_ambiguous(current_cp);
    }
    if (!close_quote_in_east_asian) {
      return false;
    }
  }
  // LB20
  if (eff == Lb::Cb || eff_in(left, {Lb::Cb})) {
    return true;
  }

  // LB20.1 and LB20a both require the hyphen's own left context to be outside
  // a word, the same start-of-segment set.
  const bool hyphen_left_context_opens =
      !s.eff_prev_prev.has_value() ||
      eff_in(s.eff_prev_prev, {Lb::Bk, Lb::Cr, Lb::Lf, Lb::Nl, Lb::Sp, Lb::Zw,
                               Lb::Cb, Lb::Gl});
  // LB20.1, UCD 17.0: an explicit hyphen joins a following letter only where
  // its own left context is outside a word. A mid-word HH falls through to
  // LB31.
  if (eff_in(left, {Lb::Hh}) && (eff == Lb::Al || eff == Lb::Hl) &&
      hyphen_left_context_opens) {
    return false;
  }
  // LB20a, with UCD 17.0's right side broadened to HL beside AL.
  if (eff == Lb::Al || eff == Lb::Hl) {
    const bool hyphen_carries_left =
        s.eff_prev.has_value() &&
        (*s.eff_prev == Lb::Hy || *s.eff_prev == Lb::Hh ||
         (s.eff_prev_cp.has_value() && is_hyphen_u2010(*s.eff_prev_cp)));
    if (hyphen_carries_left && hyphen_left_context_opens) {
      return false;
    }
  }
  // LB21
  if (eff == Lb::Ba || eff == Lb::Hy || eff == Lb::Hh || eff == Lb::Ns) {
    return false;
  }
  if (eff_in(left, {Lb::Bb})) {
    return false;
  }
  // LB21a: an HL letter followed by an HY hyphen or U+2010 glues to what comes
  // next unless that is itself HL. A BA does not glue here.
  if (s.eff_prev_prev == std::make_optional(Lb::Hl) && eff != Lb::Hl) {
    const bool hyphen_is_hy_or_2010 =
        s.eff_prev.has_value() &&
        (*s.eff_prev == Lb::Hy ||
         (s.eff_prev_cp.has_value() && is_hyphen_u2010(*s.eff_prev_cp)));
    if (hyphen_is_hy_or_2010) {
      return false;
    }
  }
  // LB21b
  if (eff == Lb::Hl && eff_in(left, {Lb::Sy})) {
    return false;
  }
  // LB22
  if (eff == Lb::In) {
    return false;
  }
  // LB23
  if (eff == Lb::Nu && eff_in(left, {Lb::Al, Lb::Hl})) {
    return false;
  }
  if ((eff == Lb::Al || eff == Lb::Hl) && eff_in(left, {Lb::Nu})) {
    return false;
  }
  // LB23a
  if ((eff == Lb::Id || eff == Lb::Eb || eff == Lb::Em) &&
      eff_in(left, {Lb::Pr})) {
    return false;
  }
  if (eff == Lb::Po && eff_in(left, {Lb::Id, Lb::Eb, Lb::Em})) {
    return false;
  }
  // LB24
  if ((eff == Lb::Al || eff == Lb::Hl) && eff_in(left, {Lb::Pr, Lb::Po})) {
    return false;
  }
  if ((eff == Lb::Pr || eff == Lb::Po) && eff_in(left, {Lb::Al, Lb::Hl})) {
    return false;
  }
  // LB25, closing an open numeric chain with a CL or CP suffix and a following
  // PO or PR.
  if (s.in_nu_chain && (eff == Lb::Cl || eff == Lb::Cp || eff == Lb::Po ||
                        eff == Lb::Pr)) {
    return false;
  }
  // LB25, opening a chain
  if (eff == Lb::Nu &&
      eff_in(left, {Lb::Pr, Lb::Po, Lb::Hy, Lb::Op, Lb::Is})) {
    return false;
  }
  // LB25, chain body
  if (eff == Lb::Nu && eff_in(left, {Lb::Nu})) {
    return false;
  }
  // LB25, extending an open chain across a SY
  if (eff == Lb::Nu && eff_in(left, {Lb::Sy}) && s.in_nu_chain) {
    return false;
  }
  // LB25, bracketed prefix: a PR joins an OP only when the OP itself opens a
  // number, and neither is East Asian Fullwidth, Wide or Halfwidth.
  if (eff == Lb::Op && eff_in(left, {Lb::Pr}) &&
      !is_east_asian_full_wide(current_cp) && s.eff_prev_cp.has_value() &&
      !is_east_asian_full_wide(*s.eff_prev_cp) &&
      head_class(ahead) == std::make_optional(Lb::Nu)) {
    return false;
  }
  // LB26
  if (eff_in(left, {Lb::Jl}) &&
      (eff == Lb::Jl || eff == Lb::Jv || eff == Lb::H2 || eff == Lb::H3)) {
    return false;
  }
  if (eff_in(left, {Lb::Jv, Lb::H2}) && (eff == Lb::Jv || eff == Lb::Jt)) {
    return false;
  }
  if (eff_in(left, {Lb::Jt, Lb::H3}) && eff == Lb::Jt) {
    return false;
  }
  // LB27
  if (eff_in(left, {Lb::Jl, Lb::Jv, Lb::Jt, Lb::H2, Lb::H3}) &&
      (eff == Lb::In || eff == Lb::Po)) {
    return false;
  }
  if (eff_in(left, {Lb::Pr}) &&
      (eff == Lb::Jl || eff == Lb::Jv || eff == Lb::Jt || eff == Lb::H2 ||
       eff == Lb::H3)) {
    return false;
  }
  // LB28
  if ((eff == Lb::Al || eff == Lb::Hl) && eff_in(left, {Lb::Al, Lb::Hl})) {
    return false;
  }

  // LB28a, the aksara cluster rules. U+25CC DOTTED CIRCLE carries class AL and
  // stands in for a cluster base throughout.
  const bool left_is_aksara_base =
      eff_in(left, {Lb::Ak, Lb::As}) ||
      (s.eff_prev_cp == std::make_optional<std::uint32_t>(0x25CC) &&
       s.eff_prev == std::make_optional(Lb::Al));
  if (eff_in(left, {Lb::Ap}) &&
      (eff == Lb::Ak || eff == Lb::As || current_cp == 0x25CC)) {
    return false;
  }
  if (left_is_aksara_base && (eff == Lb::Vf || eff == Lb::Vi)) {
    return false;
  }
  if (s.eff_prev == std::make_optional(Lb::Vi) &&
      (s.eff_prev_prev == std::make_optional(Lb::Ak) ||
       s.eff_prev_prev == std::make_optional(Lb::As) ||
       s.eff_prev_prev_cp == std::make_optional<std::uint32_t>(0x25CC)) &&
      (eff == Lb::Ak || current_cp == 0x25CC)) {
    return false;
  }
  if (left_is_aksara_base &&
      (eff == Lb::Ak || eff == Lb::As || current_cp == 0x25CC) &&
      next_significant_is_vf(ahead)) {
    return false;
  }
  // LB29
  if ((eff == Lb::Al || eff == Lb::Hl) && eff_in(left, {Lb::Is})) {
    return false;
  }
  // LB30, where the bracket must not be East Asian Fullwidth, Wide or
  // Halfwidth.
  if (eff == Lb::Op && eff_in(left, {Lb::Al, Lb::Hl, Lb::Nu}) &&
      !is_east_asian_full_wide(current_cp)) {
    return false;
  }
  if ((eff == Lb::Al || eff == Lb::Hl || eff == Lb::Nu) &&
      eff_in(left, {Lb::Cp}) && !is_east_asian_full_wide(prev_cp)) {
    return false;
  }
  // LB30a
  if (eff == Lb::Ri && s.ri_run % 2 == 1) {
    return false;
  }
  // LB30b
  if (eff == Lb::Em && eff_in(left, {Lb::Eb})) {
    return false;
  }
  if (eff == Lb::Em && s.eff_prev_cp.has_value()) {
    const std::uint32_t previous = *s.eff_prev_cp;
    if (is_ext_pict(previous) &&
        general_category(previous) == GeneralCategory::Cn) {
      return false;
    }
  }
  // LB31
  return true;
}

// One break-opportunity flag per boundary of the code point sequence, so a
// sequence of n code points yields n + 1 flags -- the shape the Lean
// lineBreaks_length theorem fixes.
//
// Entry 0 is false -- LB2 forbids a break at the start of text -- and entry n
// is true per LB3, which requires one at the end.
inline std::vector<bool> line_breaks(std::span<const std::uint32_t> cps) {
  std::vector<Classified> pairs;
  pairs.reserve(cps.size());
  for (const std::uint32_t cp : cps) {
    pairs.emplace_back(cp, resolved_class(cp));
  }
  std::vector<bool> out;
  out.reserve(pairs.size() + 1);
  Snapshot s = initial_snapshot();
  const std::span<const Classified> all{pairs};
  for (std::size_t i = 0; i < pairs.size(); ++i) {
    if (i == 0) {
      out.push_back(false);  // LB2
    } else {
      out.push_back(breaks_before(pairs[i - 1], all.subspan(i), s));
    }
    s = advance_line_break(s, pairs[i].first, pairs[i].second);
  }
  out.push_back(true);  // LB3
  return out;
}

// The code point sequence split at every break opportunity -- the runs a
// renderer may place on separate lines.
inline std::vector<std::vector<std::uint32_t>> line_runs(
    std::span<const std::uint32_t> cps) {
  const std::vector<bool> breaks = line_breaks(cps);
  std::vector<std::vector<std::uint32_t>> out;
  std::vector<std::uint32_t> current;
  for (std::size_t i = 0; i < cps.size(); ++i) {
    current.push_back(cps[i]);
    if (breaks[i + 1]) {
      out.push_back(current);
      current.clear();
    }
  }
  if (!current.empty()) {
    out.push_back(current);
  }
  return out;
}

}  // namespace unicode_cpp::segmentation

#endif  // UNICODE_CPP_SEGMENTATION_LINE_BREAK_HPP
