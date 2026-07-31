// Confusable-in-bidi-context compound detector (CVE-2021-42574 class).
//
// Threat model.  Tier compound.  A confusable (homoglyph) codepoint
// co-located with a bidi format-control is materially more dangerous than
// either alone: the homoglyph disguises an identifier while the bidi control
// reorders how a reviewer reads it.  This detector fires only when both are
// present.  Distinct from HomoglyphConfusable alone (catches the confusable
// but misses the visual reorder) and RtlInjection alone (catches the bidi but
// misses the script confusion); ConfusableBidiCompound reports the
// simultaneous occurrence.
//
// Direct port of Unicode/Security/Boundary/ConfusableBidiCompound.lean, and a
// mirror of ports/rust/src/security/boundary/confusable_bidi_compound.rs.  The
// confusable-source predicate reuses the parsed confusables map that the
// homoglyph detector consumes (homoglyph_confusable::is_confusable_source); the
// bidi predicates split the format-controls into the override class
// (LRE/RLE/LRO/RLO/PDF, U+202A..U+202E) and the isolate class
// (LRI/RLI/FSI/PDI, U+2066..U+2069), matching Unicode.TrojanSource.

#ifndef UNICODE_CPP_SECURITY_BOUNDARY_CONFUSABLE_BIDI_COMPOUND_HPP
#define UNICODE_CPP_SECURITY_BOUNDARY_CONFUSABLE_BIDI_COMPOUND_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "unicode_cpp/security/identity/homoglyph_confusable.hpp"

namespace unicode_cpp::security::boundary::confusable_bidi_compound {

// True iff cp is an override-class bidi control (LRE, RLE, LRO, RLO, PDF —
// the contiguous block U+202A..U+202E).
constexpr bool is_override(std::uint32_t cp) {
  return cp >= 0x202Au && cp <= 0x202Eu;
}

// True iff cp is an isolate-class bidi control (LRI, RLI, FSI, PDI — the
// contiguous block U+2066..U+2069).
constexpr bool is_isolate(std::uint32_t cp) {
  return cp >= 0x2066u && cp <= 0x2069u;
}

// One confusable-bidi-compound scan result.  sub is nullopt for a clear
// input; otherwise it is the sub-threat tag with the offending positions
// {confusable_pos, bidi_pos}.
struct Detection {
  std::optional<std::string> sub;
  std::vector<std::size_t> positions;
};

namespace detail {

template <typename Predicate>
inline std::optional<std::size_t> first_pos(std::span<const std::uint32_t> input,
                                            Predicate pred) {
  for (std::size_t i = 0; i < input.size(); ++i) {
    if (pred(input[i])) {
      return i;
    }
  }
  return std::nullopt;
}

} // namespace detail

// Detect a confusable codepoint sharing the input with a bidi control.
// Priority mirrors the spec: with a confusable present, an override-class
// control fires ConfusableInOverride; otherwise an isolate-class control
// fires ConfusableInIsolate; otherwise clear.  The confusable-source table is
// read from the caller-owned database (reused, not reparsed).
inline Detection detect(std::span<const std::uint32_t> input,
                        const homoglyph_confusable::Database &db) {
  const auto confusable_pos = detail::first_pos(
      input, [&db](std::uint32_t cp) {
        return homoglyph_confusable::is_confusable_source(db, cp);
      });
  if (!confusable_pos) {
    return Detection{std::nullopt, {}};
  }
  if (const auto override_pos = detail::first_pos(input, is_override)) {
    return Detection{std::optional<std::string>{"ConfusableInOverride"},
                     {*confusable_pos, *override_pos}};
  }
  if (const auto isolate_pos = detail::first_pos(input, is_isolate)) {
    return Detection{std::optional<std::string>{"ConfusableInIsolate"},
                     {*confusable_pos, *isolate_pos}};
  }
  return Detection{std::nullopt, {}};
}

} // namespace unicode_cpp::security::boundary::confusable_bidi_compound

#endif // UNICODE_CPP_SECURITY_BOUNDARY_CONFUSABLE_BIDI_COMPOUND_HPP
