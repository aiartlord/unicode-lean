// Normalization-bomb detection (F1) — inputs whose NFD or NFKD expansion
// exceeds documented bounds, the classic normalization-expansion DoS. A small
// input that expands to a very large normalized form exhausts memory/CPU at the
// receiving layer (Arabic ligature U+FDFA -> 18 codepoints under NFKD, etc.).
// Direct port of Unicode/Security/Form/NormalizationBomb.lean.
//
// Pure functional: compute NFD and NFKD lengths, then three priority-ordered
// checks — a per-codepoint blow-up scan, an overall NFKD ratio, an overall NFD
// ratio. Ratios are expressed in hundredths to avoid floats.
#ifndef UNICODE_CPP_SECURITY_FORM_NORMALIZATION_BOMB_HPP
#define UNICODE_CPP_SECURITY_FORM_NORMALIZATION_BOMB_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "unicode_cpp/security/identity/ucd.hpp"

namespace unicode_cpp::security::form::normalization_bomb {

namespace ucd = unicode_cpp::security::ucd;

// Maximum allowed NFKD expansion per single codepoint. Hangul <= 3, Greek
// extended forms 4, the largest non-FDFA Arabic ligature (FDFB) 8; anything
// greater than 8 is flagged.
inline constexpr std::size_t MAX_NFKD_PER_CP = 8;

// Overall-sequence NFD expansion ratio threshold, in hundredths (300 = 3x).
// Pure Hangul sits at exactly 300 and stays clear under strict `>`.
inline constexpr std::size_t NFD_RATIO_PCT = 300;

// Overall-sequence NFKD expansion ratio threshold, in hundredths (400 = 4x).
inline constexpr std::size_t NFKD_RATIO_PCT = 400;

// One normalization-bomb scan result. `sub` is empty for a clear input; a
// per-codepoint blow-up carries the offending position, the ratio hazards
// carry no position.
struct Detection {
    std::optional<std::string> sub;
    std::vector<std::size_t> positions;
};

namespace detail {

// First position whose single-codepoint NFKD expansion exceeds
// MAX_NFKD_PER_CP.
inline std::optional<std::size_t> first_blowup_cp(
    const ucd::Tables& t, const std::vector<std::uint32_t>& input) {
    for (std::size_t index = 0; index < input.size(); ++index) {
        std::vector<std::uint32_t> one{input[index]};
        if (ucd::to_nfkd(t, one).size() > MAX_NFKD_PER_CP) {
            return index;
        }
    }
    return std::nullopt;
}

// NFD ratio percentage (100 * nfdLen / inputLen); 0 on empty input.
inline std::size_t nfd_ratio_pct(const ucd::Tables& t,
                                 const std::vector<std::uint32_t>& input) {
    if (input.empty()) return 0;
    return ucd::to_nfd(t, input).size() * 100 / input.size();
}

// NFKD ratio percentage (100 * nfkdLen / inputLen); 0 on empty input.
inline std::size_t nfkd_ratio_pct(const ucd::Tables& t,
                                  const std::vector<std::uint32_t>& input) {
    if (input.empty()) return 0;
    return ucd::to_nfkd(t, input).size() * 100 / input.size();
}

}  // namespace detail

// Detect a normalization-expansion bomb. Priority: per-codepoint blow-up, then
// overall NFKD ratio, then overall NFD ratio.
inline Detection detect(const ucd::Tables& t,
                        const std::vector<std::uint32_t>& input) {
    if (auto pos = detail::first_blowup_cp(t, input)) {
        return Detection{std::string("SingleCpBlowup"), {*pos}};
    }
    if (detail::nfkd_ratio_pct(t, input) > NFKD_RATIO_PCT) {
        return Detection{std::string("NfkdHighExpansion"), {}};
    }
    if (detail::nfd_ratio_pct(t, input) > NFD_RATIO_PCT) {
        return Detection{std::string("NfdHighExpansion"), {}};
    }
    return Detection{std::nullopt, {}};
}

}  // namespace unicode_cpp::security::form::normalization_bomb

#endif  // UNICODE_CPP_SECURITY_FORM_NORMALIZATION_BOMB_HPP
