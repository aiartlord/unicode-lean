// Width-class-confusion detection — UAX #11 East Asian Width class confusion.
// A Fullwidth (EAW = F) or Halfwidth (EAW = H) codepoint whose NFKD form
// carries a different EAW class is a compatibility-fold homograph:
//
//   U+FF21 'Ａ' (F)  ->  U+0041 'A' (Na)
//   U+FF11 '１' (F)  ->  U+0031 '1' (Na)
//   U+FF71 'ｱ' (H)  ->  U+30A2 'ア' (W)
//
// Threat model.  Tier A2.  Two-system bypass: a validator that whitelists
// ASCII rejects `Ａ`, while a downstream NFKC step at storage or comparison
// time folds it to plain `A`.  The attacker claims the username ADMIN with
// ＡＤＭＩＮ against a system that did not normalise before whitelisting.
//
// Distinct from RendererDivergence's FullwidthVariance, which fires on F-class
// codepoints for renderer-cohort reasons; this is the NFKC-fold verdict, and
// the two can fire on one input independently.
//
// Detection is per input position and uses NFKD, because every compatibility
// decomposition path goes through it: the EAW class of the input codepoint is
// compared against that of the first NFKD output codepoint.  Hangul syllables
// decompose to jamos that are still W class, so pure Hangul stays clear.
//
// Direct port of Unicode/Security/Form/WidthClassConfusion.lean.
#ifndef UNICODE_CPP_SECURITY_FORM_WIDTH_CLASS_CONFUSION_HPP
#define UNICODE_CPP_SECURITY_FORM_WIDTH_CLASS_CONFUSION_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "unicode_cpp/security/identity/ucd.hpp"

namespace unicode_cpp::security::form::width_class_confusion {

namespace ucd = unicode_cpp::security::ucd;

// One width-class-confusion scan result.  `sub` is empty for a clear input,
// else the fold tag with the single position it was found at.
struct Detection {
    std::optional<std::string> sub;
    std::vector<std::size_t> positions;
};

namespace detail {

// True iff the NFKD head of `cp` carries a different EAW class.
inline bool has_width_fold(const ucd::Tables& t, std::uint32_t cp) {
    const std::uint32_t one[1] = {cp};
    const std::vector<std::uint32_t> folded = ucd::to_nfkd(t, one);
    if (folded.empty()) {
        return false;
    }
    return ucd::east_asian_width(t, folded.front())
        != ucd::east_asian_width(t, cp);
}

// First position whose codepoint has class `want` and folds away from it.
inline std::optional<std::size_t> first_fold(
    const ucd::Tables& t, const std::vector<std::uint32_t>& input,
    ucd::EastAsianWidth want) {
    for (std::size_t i = 0; i < input.size(); ++i) {
        if (ucd::east_asian_width(t, input[i]) == want
            && has_width_fold(t, input[i])) {
            return i;
        }
    }
    return std::nullopt;
}

}  // namespace detail

// Classify a codepoint sequence.  A Fullwidth fold takes priority over a
// Halfwidth one, matching the reference's sub-threat order.
inline Detection detect(
    const ucd::Tables& t, const std::vector<std::uint32_t>& input) {
    if (auto pos = detail::first_fold(t, input, ucd::EastAsianWidth::F)) {
        return Detection{std::string("FullwidthFold"), {*pos}};
    }
    if (auto pos = detail::first_fold(t, input, ucd::EastAsianWidth::H)) {
        return Detection{std::string("HalfwidthFold"), {*pos}};
    }
    return Detection{std::nullopt, {}};
}

}  // namespace unicode_cpp::security::form::width_class_confusion

#endif  // UNICODE_CPP_SECURITY_FORM_WIDTH_CLASS_CONFUSION_HPP
