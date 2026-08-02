// CaseExpansionMismatch (form / F-layer) — codepoints whose UAX #21 default-locale
// case mapping changes the codepoint count. Byte-faithful port of
// Unicode/Security/Form/CaseExpansionMismatch.lean.
//
// Threat model (Tier A1..A2). An attacker submits text whose case-mapped form has
// a different codepoint count than the input. A receiver that fixes a 16-byte
// username column and stores toUpper(username) overflows when the user picks
// "ßßßßßßßß" (8 in → 16 stored); a receiver that checks len(stored) == len(input)
// rejects valid case-insensitive logins whose names expand under folding.
// Examples: U+00DF ß → "SS", U+FB01 ﬁ → "FI", U+0130 İ → toLower "i̇" (i + U+0307).
//
// Distinct from LocaleCaseInversion (case mapping that changes ACROSS locales):
// this fires on shapes whose mapping is locale-stable but length-changing under
// the default locale itself. It reuses the port's own UAX #21 case mapping
// (upper_codepoint / lower_codepoint, which evaluate the SpecialCasing context
// predicates), never a host casing library.
//
// Sub-threats (priority order):
//   1. UpperExpansion — first position whose default upper_codepoint yields > 1 cp.
//   2. LowerExpansion — first position whose default lower_codepoint yields > 1 cp
//      (reached only when no upper expansion fires first).
#ifndef UNICODE_CPP_SECURITY_FORM_CASE_EXPANSION_MISMATCH_HPP
#define UNICODE_CPP_SECURITY_FORM_CASE_EXPANSION_MISMATCH_HPP

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "unicode_cpp/security/identity/casing.hpp"
#include "unicode_cpp/security/identity/ucd.hpp"

namespace unicode_cpp::security::form::case_expansion_mismatch {

namespace casing = unicode_cpp::security::casing;
namespace ucd = unicode_cpp::security::ucd;

// ── §1 Types ─────────────────────────────────────────────────────────────

// Sub-threat enumeration, in priority order.
enum class SubThreatKind { UpperExpansion, LowerExpansion };

// One fired sub-threat: the kind, the expanding position, the expanding
// codepoint and the length of its (> 1) case-mapped expansion.
struct SubThreat {
    SubThreatKind kind;
    std::size_t base_pos;
    std::uint32_t cp;
    std::size_t expansion_len;

    // Fixture-row tag string for this sub-threat (matches SubThreat.tag).
    std::string_view tag() const {
        switch (kind) {
        case SubThreatKind::UpperExpansion:
            return "UpperExpansion";
        case SubThreatKind::LowerExpansion:
            return "LowerExpansion";
        }
        throw std::logic_error("case-expansion-mismatch: unreachable SubThreatKind");
    }
};

// Top-level classification: no expansion, or a fired sub-threat with its
// implicated positions.
struct Classification {
    std::optional<SubThreat> sub;
    std::vector<std::size_t> positions;

    static Classification clear() { return Classification{std::nullopt, {}}; }
    static Classification hazard(SubThreat s, std::vector<std::size_t> pos) {
        return Classification{std::move(s), std::move(pos)};
    }

    bool is_clear() const { return !sub.has_value(); }

    // Human-facing tag for a hazard, or nullopt when clear.
    std::optional<std::string_view> tag() const {
        if (!sub.has_value()) return std::nullopt;
        return sub->tag();
    }
};

// The structured output of detect (mirrors the Lean Verdict).
struct Verdict {
    std::vector<std::uint32_t> input;
    Classification classify;
    std::size_t upper_expansion_count;
    std::size_t lower_expansion_count;
    std::size_t max_expansion_len;
};

namespace detail {

// Uppercase a single codepoint in its full input context: the SpecialCasing row
// whose conditions hold (its uppercase column), else the simple uppercase
// mapping. rev_prefix is the preceding codepoints nearest-first; suffix the
// strictly-following ones.
inline std::vector<std::uint32_t> upper_codepoint(
    const casing::CasingData& c, const ucd::Tables& t, casing::Locale locale,
    const std::vector<std::uint32_t>& rev_prefix,
    const std::vector<std::uint32_t>& suffix, std::uint32_t cp) {
    const casing::CasingRow* row =
        casing::detail::find_special_row(c, t, locale, rev_prefix, suffix, cp);
    if (row != nullptr) return row->upper;
    return {casing::detail::simple_uppercase(c, cp)};
}

// Lowercase a single codepoint in its full input context (its lowercase column),
// else the simple lowercase mapping.
inline std::vector<std::uint32_t> lower_codepoint(
    const casing::CasingData& c, const ucd::Tables& t, casing::Locale locale,
    const std::vector<std::uint32_t>& rev_prefix,
    const std::vector<std::uint32_t>& suffix, std::uint32_t cp) {
    const casing::CasingRow* row =
        casing::detail::find_special_row(c, t, locale, rev_prefix, suffix, cp);
    if (row != nullptr) return row->lower;
    return {casing::detail::simple_lowercase(c, cp)};
}

// ── §2 Per-position expansion scan ───────────────────────────────────────

inline std::vector<std::uint32_t> rev_prefix_at(
    const std::vector<std::uint32_t>& input, std::size_t i) {
    std::vector<std::uint32_t> rev;
    rev.reserve(i);
    for (std::size_t k = i; k-- > 0;) {
        rev.push_back(input[k]);
    }
    return rev;
}

inline std::vector<std::uint32_t> suffix_at(
    const std::vector<std::uint32_t>& input, std::size_t i) {
    return std::vector<std::uint32_t>(
        input.begin() + static_cast<std::ptrdiff_t>(i) + 1, input.end());
}

// The default-locale uppercase expansion length at position i.
inline std::size_t upper_len_at(
    const casing::CasingData& c, const ucd::Tables& t,
    const std::vector<std::uint32_t>& input, std::size_t i) {
    return upper_codepoint(c, t, casing::Locale::Default, rev_prefix_at(input, i),
                           suffix_at(input, i), input[i])
        .size();
}

// The default-locale lowercase expansion length at position i.
inline std::size_t lower_len_at(
    const casing::CasingData& c, const ucd::Tables& t,
    const std::vector<std::uint32_t>& input, std::size_t i) {
    return lower_codepoint(c, t, casing::Locale::Default, rev_prefix_at(input, i),
                           suffix_at(input, i), input[i])
        .size();
}

// First position whose default uppercase mapping expands to > 1 codepoint.
inline std::optional<SubThreat> first_upper_expansion(
    const casing::CasingData& c, const ucd::Tables& t,
    const std::vector<std::uint32_t>& input) {
    for (std::size_t i = 0; i < input.size(); ++i) {
        std::size_t len = upper_len_at(c, t, input, i);
        if (len > 1) {
            return SubThreat{SubThreatKind::UpperExpansion, i, input[i], len};
        }
    }
    return std::nullopt;
}

// First position whose default lowercase mapping expands to > 1 codepoint.
inline std::optional<SubThreat> first_lower_expansion(
    const casing::CasingData& c, const ucd::Tables& t,
    const std::vector<std::uint32_t>& input) {
    for (std::size_t i = 0; i < input.size(); ++i) {
        std::size_t len = lower_len_at(c, t, input, i);
        if (len > 1) {
            return SubThreat{SubThreatKind::LowerExpansion, i, input[i], len};
        }
    }
    return std::nullopt;
}

inline std::size_t upper_expansion_count(
    const casing::CasingData& c, const ucd::Tables& t,
    const std::vector<std::uint32_t>& input) {
    std::size_t n = 0;
    for (std::size_t i = 0; i < input.size(); ++i) {
        if (upper_len_at(c, t, input, i) > 1) ++n;
    }
    return n;
}

inline std::size_t lower_expansion_count(
    const casing::CasingData& c, const ucd::Tables& t,
    const std::vector<std::uint32_t>& input) {
    std::size_t n = 0;
    for (std::size_t i = 0; i < input.size(); ++i) {
        if (lower_len_at(c, t, input, i) > 1) ++n;
    }
    return n;
}

inline std::size_t max_expansion_len(
    const casing::CasingData& c, const ucd::Tables& t,
    const std::vector<std::uint32_t>& input) {
    std::size_t best = 0;
    for (std::size_t i = 0; i < input.size(); ++i) {
        best = std::max(best,
                        std::max(upper_len_at(c, t, input, i),
                                 lower_len_at(c, t, input, i)));
    }
    return best;
}

}  // namespace detail

// ── §3 Top-level detection ───────────────────────────────────────────────

// The CaseExpansionMismatch detection function. Priority: an uppercase
// expansion, else a lowercase expansion, else Clear.
inline Verdict detect(const casing::CasingData& c, const ucd::Tables& t,
                      const std::vector<std::uint32_t>& input) {
    Classification classification = Classification::clear();
    if (auto upper = detail::first_upper_expansion(c, t, input)) {
        std::size_t pos = upper->base_pos;
        classification = Classification::hazard(*upper, {pos});
    } else if (auto lower = detail::first_lower_expansion(c, t, input)) {
        std::size_t pos = lower->base_pos;
        classification = Classification::hazard(*lower, {pos});
    }

    return Verdict{
        input,
        std::move(classification),
        detail::upper_expansion_count(c, t, input),
        detail::lower_expansion_count(c, t, input),
        detail::max_expansion_len(c, t, input),
    };
}

}  // namespace unicode_cpp::security::form::case_expansion_mismatch

#endif  // UNICODE_CPP_SECURITY_FORM_CASE_EXPANSION_MISMATCH_HPP
