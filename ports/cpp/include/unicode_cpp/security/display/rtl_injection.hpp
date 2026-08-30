// Right-to-left injection detection for left-to-right-declared fields.
//
// Threat model.  Tier A1.  An adversary places strong-RTL codepoints
// (Hebrew, Arabic, ...) or bidi format-controls (RLO, LRO, PDF, the
// isolates) into a field the surrounding UI declares left-to-right — a
// username box, a filename, a source-code token.  A bidi-aware renderer
// reorders the visible glyphs, so what the reviewer reads differs from
// the logical byte order the machine acts on.
//
// Direct port of Unicode/Security/Display/RtlInjection.lean.  The four
// sub-threats, their priority, and the reported positions match that
// module's detect exactly; the strong-RTL / strong-LTR predicates read
// Bidi_Class from the bundled UnicodeData.txt (ucd::is_strong_rtl),
// mirroring the spec's lookupBidiClass.  Because the strong-RTL phases
// need the UCD table, detection takes an explicit ucd::Tables, matching
// how the identity-family detectors are provisioned in this port.

#ifndef UNICODE_CPP_SECURITY_DISPLAY_RTL_INJECTION_HPP
#define UNICODE_CPP_SECURITY_DISPLAY_RTL_INJECTION_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "unicode_cpp/security/covert/bidi_control_balance.hpp"
#include "unicode_cpp/security/identity/ucd.hpp"

namespace unicode_cpp::security::display::rtl_injection {

// One RTL-injection scan result.  sub is nullopt for a clear input;
// otherwise it carries the fixture-row tag of the single highest-priority
// sub-threat that fired, with the offending positions.
struct Detection {
  std::optional<std::string> sub;
  std::vector<std::size_t> positions;
};

namespace detail {

inline std::size_t count_strong_rtl(const ucd::Tables &t,
                                    std::span<const std::uint32_t> input) {
  std::size_t n = 0;
  for (std::uint32_t cp : input) {
    if (ucd::is_strong_rtl(t, cp)) {
      ++n;
    }
  }
  return n;
}

inline std::optional<std::size_t>
first_bidi_control_pos(std::span<const std::uint32_t> input) {
  for (std::size_t i = 0; i < input.size(); ++i) {
    if (bidi_control_balance::is_bidi_format_control(input[i])) {
      return i;
    }
  }
  return std::nullopt;
}

// (position, is_rtl) of the first strong (L, R, or AL) codepoint.
inline std::optional<std::pair<std::size_t, bool>>
first_strong_char(const ucd::Tables &t, std::span<const std::uint32_t> input) {
  for (std::size_t i = 0; i < input.size(); ++i) {
    if (ucd::is_strong_rtl(t, input[i])) {
      return std::pair<std::size_t, bool>{i, true};
    }
    if (ucd::is_strong_ltr(t, input[i])) {
      return std::pair<std::size_t, bool>{i, false};
    }
  }
  return std::nullopt;
}

inline std::optional<std::size_t>
first_strong_rtl_pos(const ucd::Tables &t,
                     std::span<const std::uint32_t> input) {
  for (std::size_t i = 0; i < input.size(); ++i) {
    if (ucd::is_strong_rtl(t, input[i])) {
      return i;
    }
  }
  return std::nullopt;
}

// (longest run length, run start) of consecutive strong-RTL codepoints;
// (0, 0) when there are none.
inline std::pair<std::size_t, std::size_t>
longest_rtl_run(const ucd::Tables &t, std::span<const std::uint32_t> input) {
  std::size_t longest = 0;
  std::size_t longest_start = 0;
  std::size_t current = 0;
  std::size_t current_start = 0;
  for (std::size_t i = 0; i < input.size(); ++i) {
    if (ucd::is_strong_rtl(t, input[i])) {
      std::size_t new_start = (current == 0) ? i : current_start;
      ++current;
      current_start = new_start;
      if (current > longest) {
        longest = current;
        longest_start = new_start;
      }
    } else {
      current = 0;
    }
  }
  return {longest, longest_start};
}

inline Detection phase3(const ucd::Tables &t,
                        std::span<const std::uint32_t> input,
                        std::size_t strong_rtl, std::size_t run_len,
                        std::size_t run_start) {
  if (strong_rtl == 0) {
    return Detection{std::nullopt, {}};
  }
  if (run_len >= 4) {
    return Detection{std::optional<std::string>{"MixedOverflow"}, {run_start}};
  }
  if (auto pos = first_strong_rtl_pos(t, input)) {
    return Detection{std::optional<std::string>{"StrongRTLInLTR"}, {*pos}};
  }
  // Unreachable when strong_rtl > 0.
  return Detection{std::nullopt, {}};
}

} // namespace detail

// Detect right-to-left injection in an LTR-declared field.  Priority
// mirrors the spec exactly: (1) any bidi format-control anywhere fires
// BidiControlInLTRField; otherwise (2) a leading strong-RTL codepoint fires
// FieldTakeover; otherwise (3) mid-stream strong-RTL is classified by
// run length.
inline Detection detect(const ucd::Tables &t,
                        std::span<const std::uint32_t> input) {
  const std::size_t strong_rtl = detail::count_strong_rtl(t, input);
  const auto [run_len, run_start] = detail::longest_rtl_run(t, input);

  if (auto pos = detail::first_bidi_control_pos(input)) {
    return Detection{std::optional<std::string>{"BidiControlInLTRField"}, {*pos}};
  }

  if (auto strong = detail::first_strong_char(t, input)) {
    if (strong->second) {
      return Detection{std::optional<std::string>{"FieldTakeover"},
                       {strong->first}};
    }
  }
  return detail::phase3(t, input, strong_rtl, run_len, run_start);
}

} // namespace unicode_cpp::security::display::rtl_injection

#endif // UNICODE_CPP_SECURITY_DISPLAY_RTL_INJECTION_HPP
