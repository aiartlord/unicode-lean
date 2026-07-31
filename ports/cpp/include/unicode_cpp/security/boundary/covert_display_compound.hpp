// Covert-display compound detector (bidi control co-located with a hidden
// covert channel).
//
// Threat model.  Tier compound.  A bidi format-control that reorders the
// visible glyphs is materially more dangerous when the same input also
// carries a covert channel — an unregistered variation selector or a
// tag-block character — because the reorder hides where the covert payload
// sits.  This detector fires only when a bidi control coincides with one of
// those covert classes.
//
// Direct port of Unicode/Security/Boundary/CovertDisplayCompound.lean, and a
// mirror of ports/rust/src/security/boundary/covert_display_compound.rs.  The
// bidi predicate reuses bidi_control_balance::is_bidi_format_control; the
// suspicious-VS predicate reuses variation_selector_payload's
// is_variation_selector plus the registered-(base, VS)-pair check.  A
// "suspicious VS" is a variation selector that does not form a registered
// (base, VS) pair (StandardizedVariants / emoji-variation-sequences), the
// .suspicious case of the variation-selector classifier.  The registered-pair
// table is the static generated table already bundled with the port, so this
// detector needs no identity Database threaded through it.

#ifndef UNICODE_CPP_SECURITY_BOUNDARY_COVERT_DISPLAY_COMPOUND_HPP
#define UNICODE_CPP_SECURITY_BOUNDARY_COVERT_DISPLAY_COMPOUND_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "unicode_cpp/security/covert/bidi_control_balance.hpp"
#include "unicode_cpp/security/covert/variation_selector_payload.hpp"

namespace unicode_cpp::security::boundary::covert_display_compound {

// True iff cp is a UAX #9 bidi format control (LRE/RLE/LRO/RLO/PDF, the
// isolate class LRI/RLI/FSI/PDI, and PDI).  Reuses the covert layer's balance
// predicate so the two detectors agree on the control set.
constexpr bool is_bidi_format_control(std::uint32_t cp) {
  return bidi_control_balance::is_bidi_format_control(cp);
}

// True iff cp is in the tag-block range U+E0000..U+E007F.
constexpr bool is_tag_block_char(std::uint32_t cp) {
  return cp >= 0xE0000u && cp <= 0xE007Fu;
}

// One covert-display-compound scan result.  sub is nullopt for a clear input;
// otherwise it is the sub-threat tag with the offending positions
// {bidi_pos, covert_pos}.
struct Detection {
  std::optional<std::string> sub;
  std::vector<std::size_t> positions;
};

namespace detail {

inline std::optional<std::size_t>
first_bidi_pos(std::span<const std::uint32_t> input) {
  for (std::size_t i = 0; i < input.size(); ++i) {
    if (is_bidi_format_control(input[i])) {
      return i;
    }
  }
  return std::nullopt;
}

// First position holding a suspicious variation selector — a VS that does not
// form a registered (base, VS) pair with its predecessor.  Mirrors the
// .suspicious case of the Lean classifyPositions.
inline std::optional<std::size_t>
first_suspicious_vs_pos(std::span<const std::uint32_t> input) {
  for (std::size_t i = 0; i < input.size(); ++i) {
    const std::uint32_t cp = input[i];
    if (variation_selector_payload::is_variation_selector(cp) &&
        !(i > 0 && variation_selector_payload::detail::is_registered_variation_pair(
                       input[i - 1], cp))) {
      return i;
    }
  }
  return std::nullopt;
}

inline std::optional<std::size_t>
first_tag_block_pos(std::span<const std::uint32_t> input) {
  for (std::size_t i = 0; i < input.size(); ++i) {
    if (is_tag_block_char(input[i])) {
      return i;
    }
  }
  return std::nullopt;
}

} // namespace detail

// Detect a bidi control co-located with a covert channel.  Priority mirrors
// the spec: a bidi control must be present; then a suspicious VS fires
// BidiPlusUnregisteredVs; otherwise a tag-block character fires
// BidiPlusTagBlock; otherwise clear.
inline Detection detect(std::span<const std::uint32_t> input) {
  const auto bidi_pos = detail::first_bidi_pos(input);
  if (!bidi_pos) {
    return Detection{std::nullopt, {}};
  }
  if (const auto vs_pos = detail::first_suspicious_vs_pos(input)) {
    return Detection{std::optional<std::string>{"BidiPlusUnregisteredVs"},
                     {*bidi_pos, *vs_pos}};
  }
  if (const auto tag_pos = detail::first_tag_block_pos(input)) {
    return Detection{std::optional<std::string>{"BidiPlusTagBlock"},
                     {*bidi_pos, *tag_pos}};
  }
  return Detection{std::nullopt, {}};
}

} // namespace unicode_cpp::security::boundary::covert_display_compound

#endif // UNICODE_CPP_SECURITY_BOUNDARY_COVERT_DISPLAY_COMPOUND_HPP
