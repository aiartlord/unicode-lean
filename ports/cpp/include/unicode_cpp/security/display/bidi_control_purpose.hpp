// Which bidi format controls serve a purpose, and which do not.
//
// Direct port of Unicode/Security/Display/BidiControlPurpose.lean. The nine
// UAX #9 format controls exist to manage right-to-left text: a span is doing
// that job when the text it encloses is right-to-left, or when it forces
// left-to-right text inside a right-to-left context. A span enclosing no strong
// right-to-left character in a left-to-right context manages nothing (LRI user
// PDI around Latin text, LRO return PDF around a keyword), and an unbalanced
// control never manages anything. Every Trojan Source payload is a control of
// that kind; a balanced embedding around an Arabic string literal is the
// opposite case and renders the literal as written.
//
// This is not source-region filtering: the question is asked of every control
// wherever it sits, and it is decided from the codepoints the span encloses,
// never from where a tokenizer would place it.
//
// Rule, as the Lean walk states it:
//
//   - An opener pushes a span: its position, whether it is an isolate (closed
//     by PDI) or an embedding/override (closed by PDF), and whether it is
//     right-to-left in effect (RLE, RLO, RLI, FSI) or left-to-right (LRE, LRO,
//     LRI).
//   - Every other codepoint is recorded against the innermost open span only:
//     strong right-to-left (R or AL), strong left-to-right (L), or ASCII code
//     syntax. A nested span manages its own content.
//   - PDF closes the top span when it is an embedding; against an isolate on
//     top, or an empty stack, it is an orphan. PDI closes down to the innermost
//     isolate, implicitly terminating the embeddings above it, which are thereby
//     unbalanced; with no isolate open it is an orphan.
//   - A closed span is purposeful iff its direct content is exactly its own
//     direction and carries no code syntax; a left-to-right span additionally
//     needs right-to-left context (an enclosing right-to-left span, or a
//     paragraph whose first strong character is right-to-left).
//   - Reported: every orphan, every opener still open at the end, every
//     embedding a PDI terminated implicitly, and both ends of every closed span
//     that was not purposeful.
//
// The strong-direction predicates read Bidi_Class from the bundled
// UnicodeData.txt (ucd::is_strong_rtl / ucd::is_strong_ltr), so detection takes
// an explicit ucd::Tables, matching rtl_injection.

#ifndef UNICODE_CPP_SECURITY_DISPLAY_BIDI_CONTROL_PURPOSE_HPP
#define UNICODE_CPP_SECURITY_DISPLAY_BIDI_CONTROL_PURPOSE_HPP

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <vector>

#include "unicode_cpp/security/identity/ucd.hpp"

namespace unicode_cpp::security::display::bidi_control_purpose {

// RLE, RLO, RLI, or FSI (whose direction resolves from its content).
constexpr bool opens_rtl_kind(std::uint32_t cp) {
  return cp == 0x202Bu || cp == 0x202Eu || cp == 0x2067u || cp == 0x2068u;
}

// LRE, LRO, LRI.
constexpr bool opens_ltr_kind(std::uint32_t cp) {
  return cp == 0x202Au || cp == 0x202Du || cp == 0x2066u;
}

// LRI, RLI, FSI.
constexpr bool opens_isolate_kind(std::uint32_t cp) {
  return cp == 0x2066u || cp == 0x2067u || cp == 0x2068u;
}

// The ASCII codepoints a Trojan Source payload moves: quotes, brackets, comment
// markers, statement separators, operators. Prose punctuation, space and digits
// are not in the set.
constexpr bool is_code_syntax(std::uint32_t cp) {
  switch (cp) {
  case 0x22u:
  case 0x27u:
  case 0x60u:
  case 0x28u:
  case 0x29u:
  case 0x5Bu:
  case 0x5Du:
  case 0x7Bu:
  case 0x7Du:
  case 0x2Fu:
  case 0x5Cu:
  case 0x2Au:
  case 0x23u:
  case 0x3Bu:
  case 0x3Cu:
  case 0x3Eu:
  case 0x3Du:
  case 0x2Bu:
  case 0x7Cu:
  case 0x26u:
  case 0x25u:
  case 0x24u:
  case 0x40u:
  case 0x5Eu:
  case 0x7Eu:
    return true;
  default:
    return false;
  }
}

// UAX #9 P2/P3: the paragraph runs right-to-left iff its first strong
// character is right-to-left.
inline bool paragraph_is_rtl(const ucd::Tables &t,
                             std::span<const std::uint32_t> input) {
  for (std::uint32_t cp : input) {
    if (ucd::is_strong_rtl(t, cp)) {
      return true;
    }
    if (ucd::is_strong_ltr(t, cp)) {
      return false;
    }
  }
  return false;
}

namespace detail {

// One open span: where it opened, how it closes, its direction in effect, and
// what has appeared directly inside it.
struct OpenSpan {
  std::size_t pos;
  bool isolate;
  bool rtl_kind;
  bool saw_rtl;
  bool saw_ltr;
  bool saw_syntax;
};

// A closed span is purposeful iff its direct content is exactly its own
// direction and carries no code syntax; a left-to-right span additionally needs
// right-to-left context.
inline bool span_purposeful(const OpenSpan &s,
                            const std::vector<OpenSpan> &enclosing,
                            bool paragraph_rtl) {
  if (s.rtl_kind) {
    return s.saw_rtl && !s.saw_ltr && !s.saw_syntax;
  }
  const bool in_rtl_context =
      paragraph_rtl ||
      std::any_of(enclosing.begin(), enclosing.end(),
                  [](const OpenSpan &e) { return e.rtl_kind; });
  return in_rtl_context && s.saw_ltr && !s.saw_rtl && !s.saw_syntax;
}

} // namespace detail

// Positions of the purposeless bidi format controls in the input, in input
// order. Empty iff every control is balanced and manages right-to-left text.
inline std::vector<std::size_t>
purposeless_control_positions(const ucd::Tables &t,
                              std::span<const std::uint32_t> input) {
  const bool paragraph_rtl = paragraph_is_rtl(t, input);
  // The stack's back is the innermost open span.
  std::vector<detail::OpenSpan> stack;
  std::vector<std::size_t> reported;

  for (std::size_t idx = 0; idx < input.size(); ++idx) {
    const std::uint32_t cp = input[idx];
    if (opens_rtl_kind(cp) || opens_ltr_kind(cp)) {
      stack.push_back(detail::OpenSpan{idx, opens_isolate_kind(cp),
                                       opens_rtl_kind(cp), false, false,
                                       false});
    } else if (cp == 0x202Cu) {
      // PDF closes the top embedding; an isolate on top or an empty stack
      // makes it an orphan.
      if (stack.empty() || stack.back().isolate) {
        reported.push_back(idx);
      } else {
        const detail::OpenSpan top = stack.back();
        stack.pop_back();
        if (!detail::span_purposeful(top, stack, paragraph_rtl)) {
          reported.push_back(top.pos);
          reported.push_back(idx);
        }
      }
    } else if (cp == 0x2069u) {
      // PDI closes down to the innermost isolate; the embeddings above it are
      // terminated implicitly and so unbalanced. No isolate open: orphan.
      const auto iso = std::find_if(
          stack.rbegin(), stack.rend(),
          [](const detail::OpenSpan &s) { return s.isolate; });
      if (iso == stack.rend()) {
        reported.push_back(idx);
      } else {
        const std::size_t iso_index =
            static_cast<std::size_t>(std::distance(iso, stack.rend())) - 1;
        for (std::size_t k = iso_index + 1; k < stack.size(); ++k) {
          reported.push_back(stack[k].pos);
        }
        const detail::OpenSpan closed = stack[iso_index];
        stack.resize(iso_index);
        if (!detail::span_purposeful(closed, stack, paragraph_rtl)) {
          reported.push_back(closed.pos);
          reported.push_back(idx);
        }
      }
    } else if (!stack.empty()) {
      detail::OpenSpan &top = stack.back();
      top.saw_rtl = top.saw_rtl || ucd::is_strong_rtl(t, cp);
      top.saw_ltr = top.saw_ltr || ucd::is_strong_ltr(t, cp);
      top.saw_syntax = top.saw_syntax || is_code_syntax(cp);
    }
  }

  // Every opener still open at the end is unbalanced.
  for (const detail::OpenSpan &open : stack) {
    reported.push_back(open.pos);
  }

  std::sort(reported.begin(), reported.end());
  reported.erase(std::unique(reported.begin(), reported.end()),
                 reported.end());
  return reported;
}

// True iff the input carries at least one purposeless bidi format control.
inline bool has_purposeless_control(const ucd::Tables &t,
                                    std::span<const std::uint32_t> input) {
  return !purposeless_control_positions(t, input).empty();
}

// Position and codepoint of the first purposeless control, if any.
inline std::optional<std::pair<std::size_t, std::uint32_t>>
first_purposeless_control(const ucd::Tables &t,
                          std::span<const std::uint32_t> input) {
  const auto positions = purposeless_control_positions(t, input);
  if (positions.empty()) {
    return std::nullopt;
  }
  return std::pair<std::size_t, std::uint32_t>{positions.front(),
                                                input[positions.front()]};
}

} // namespace unicode_cpp::security::display::bidi_control_purpose

#endif // UNICODE_CPP_SECURITY_DISPLAY_BIDI_CONTROL_PURPOSE_HPP
