// UAX #29 default extended grapheme cluster segmentation.
//
// A port of the Lean algorithm
// Unicode.Segmentation.GraphemeBreak.graphemeBreaks. The active Lean tree
// proves graphemeBreaks_eq_spec, relating that algorithm to the declarative
// UAX #29 GB1-GB999 specification. The State fields, rule order, and transition
// below mirror that reference.
//
// The property tables are grouped by property value (as in the UCD source),
// not globally sorted by code point, so the lookups scan linearly for the
// covering range, mirroring the verified Lean find?. Each class is a partition,
// so the first covering range is the only one.

#ifndef UNICODE_CPP_SEGMENTATION_GRAPHEME_HPP
#define UNICODE_CPP_SEGMENTATION_GRAPHEME_HPP

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "unicode_cpp/segmentation/grapheme_tables.hpp"

namespace unicode_cpp::segmentation {

// Grapheme_Cluster_Break class of cp, Gcb::Other when uncovered.
inline Gcb lookup_gcb(std::uint32_t cp) {
  for (const auto &r : kGcbRanges) {
    if (r.lo <= cp && cp <= r.hi) {
      return r.cls;
    }
  }
  return Gcb::Other;
}

// Indic_Conjunct_Break class of cp, Incb::None when uncovered.
inline Incb lookup_incb(std::uint32_t cp) {
  for (const auto &r : kIncbRanges) {
    if (r.lo <= cp && cp <= r.hi) {
      return r.cls;
    }
  }
  return Incb::None;
}

// Whether cp has the Extended_Pictographic property.
inline bool is_ext_pict(std::uint32_t cp) {
  for (const auto &r : kExtPictRanges) {
    if (r.lo <= cp && cp <= r.hi) {
      return true;
    }
  }
  return false;
}

// GB11 left-context state, mirroring the Lean EPicState.
enum class EpicState : std::uint8_t { None, AfterEp, AfterEpZwj };

// GB9c left-context state, mirroring the Lean InCBState.
enum class IncbState : std::uint8_t { None, Consonant, Linker };

// Running scan state, mirroring the Lean State.
struct State {
  std::optional<Gcb> prev_class;
  EpicState epic_state;
  IncbState incb_state;
  std::uint32_t ri_run;
};

inline State initial_state() {
  return State{std::nullopt, EpicState::None, IncbState::None, 0};
}

// Whether a grapheme cluster break occurs immediately before cp given the
// running state. Implements UAX #29 GB1-GB999 in canonical order; first match
// wins, the trailing GB999 breaks every otherwise-unmatched pair.
inline bool should_break_before(std::uint32_t cp, const State &s) {
  const Gcb bc = lookup_gcb(cp);
  const Incb incb = lookup_incb(cp);
  const bool is_ep = is_ext_pict(cp);
  if (!s.prev_class.has_value()) {
    return true; // GB1: sot break
  }
  const Gcb pc = *s.prev_class;
  if (pc == Gcb::Cr && bc == Gcb::Lf) {
    return false; // GB3
  }
  if (pc == Gcb::Control || pc == Gcb::Cr || pc == Gcb::Lf) {
    return true; // GB4
  }
  if (bc == Gcb::Control || bc == Gcb::Cr || bc == Gcb::Lf) {
    return true; // GB5
  }
  if (pc == Gcb::L &&
      (bc == Gcb::L || bc == Gcb::V || bc == Gcb::Lv || bc == Gcb::Lvt)) {
    return false; // GB6
  }
  if ((pc == Gcb::Lv || pc == Gcb::V) && (bc == Gcb::V || bc == Gcb::T)) {
    return false; // GB7
  }
  if ((pc == Gcb::Lvt || pc == Gcb::T) && bc == Gcb::T) {
    return false; // GB8
  }
  if (bc == Gcb::Extend || bc == Gcb::Zwj) {
    return false; // GB9
  }
  if (bc == Gcb::SpacingMark) {
    return false; // GB9a
  }
  if (pc == Gcb::Prepend) {
    return false; // GB9b
  }
  if (s.incb_state == IncbState::Linker && incb == Incb::Consonant) {
    return false; // GB9c
  }
  if (s.epic_state == EpicState::AfterEpZwj && is_ep) {
    return false; // GB11
  }
  if (bc == Gcb::RegionalIndicator && s.ri_run % 2 == 1) {
    return false; // GB12/GB13
  }
  return true; // GB999
}

// Update the running state after consuming cp. Mirrors the Lean advance.
inline State advance(std::uint32_t cp, const State &s) {
  const Gcb bc = lookup_gcb(cp);
  const Incb incb = lookup_incb(cp);
  const bool is_ep = is_ext_pict(cp);
  EpicState epic = EpicState::None;
  if (is_ep) {
    epic = EpicState::AfterEp;
  } else if (s.epic_state == EpicState::AfterEp && bc == Gcb::Extend) {
    epic = EpicState::AfterEp;
  } else if (s.epic_state == EpicState::AfterEp && bc == Gcb::Zwj) {
    epic = EpicState::AfterEpZwj;
  }
  IncbState incb_s = IncbState::None;
  if (incb == Incb::Consonant) {
    incb_s = IncbState::Consonant;
  } else if (s.incb_state == IncbState::Consonant && incb == Incb::Linker) {
    incb_s = IncbState::Linker;
  } else if (s.incb_state == IncbState::Consonant && incb == Incb::Extend) {
    incb_s = IncbState::Consonant;
  } else if (s.incb_state == IncbState::Linker && incb == Incb::Linker) {
    incb_s = IncbState::Linker;
  } else if (s.incb_state == IncbState::Linker && incb == Incb::Extend) {
    incb_s = IncbState::Linker;
  }
  const std::uint32_t ri = (bc == Gcb::RegionalIndicator) ? s.ri_run + 1 : 0;
  return State{std::make_optional(bc), epic, incb_s, ri};
}

// Boundary mask of length cps.size() + 1. Entry i is true when a grapheme
// cluster break occurs immediately before position i -- entry 0 is the GB1
// start-of-text break, entry cps.size() the GB2 end-of-text break, both always
// true. Mirrors the Lean graphemeBreaks.
inline std::vector<bool> grapheme_breaks(std::span<const std::uint32_t> cps) {
  std::vector<bool> breaks;
  breaks.reserve(cps.size() + 1);
  State s = initial_state();
  for (const std::uint32_t cp : cps) {
    breaks.push_back(should_break_before(cp, s));
    s = advance(cp, s);
  }
  breaks.push_back(true); // GB2: eot break
  return breaks;
}

// Split cps into grapheme clusters (the code points between consecutive
// boundaries).
inline std::vector<std::vector<std::uint32_t>>
grapheme_clusters(std::span<const std::uint32_t> cps) {
  const std::vector<bool> breaks = grapheme_breaks(cps);
  std::vector<std::vector<std::uint32_t>> out;
  std::vector<std::uint32_t> cur;
  for (std::size_t i = 0; i < cps.size(); ++i) {
    if (breaks[i] && !cur.empty()) {
      out.push_back(cur);
      cur.clear();
    }
    cur.push_back(cps[i]);
  }
  if (!cur.empty()) {
    out.push_back(cur);
  }
  return out;
}

} // namespace unicode_cpp::segmentation

#endif // UNICODE_CPP_SEGMENTATION_GRAPHEME_HPP
