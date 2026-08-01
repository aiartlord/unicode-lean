// Locale-case-inversion detection (UAX #21 / Tier A2) — inputs whose lowercase
// fold inverts across locales, the homograph-via-locale attack (CVE-2007-6692,
// CVE-2021-30245, the Spotify "İSTANBUL" / "iSTANBUL" incident class). Direct
// port of Unicode/Security/Form/LocaleCaseInversion.lean.
//
// Detection compares per-position lower_codepoint under each locale against the
// default, rather than diffing whole-string to_lower, because lower_codepoint
// evaluates the SpecialCasing context predicates with full surrounding context.
// Turkish divergence takes priority over Lithuanian (SpecialCasing has no
// az-only codepoint, so Turkish covers Azeri).
#ifndef UNICODE_CPP_SECURITY_FORM_LOCALE_CASE_INVERSION_HPP
#define UNICODE_CPP_SECURITY_FORM_LOCALE_CASE_INVERSION_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "unicode_cpp/security/identity/casing.hpp"
#include "unicode_cpp/security/identity/ucd.hpp"

namespace unicode_cpp::security::form::locale_case_inversion {

namespace casing = unicode_cpp::security::casing;
namespace ucd = unicode_cpp::security::ucd;

// One locale-case-inversion scan result: the divergent-locale sub-threat tag
// (empty when clear) and the first divergent input position.
struct Detection {
    std::optional<std::string> sub;
    std::vector<std::size_t> positions;
};

namespace detail {

// Lowercase a single codepoint in its full input context: the SpecialCasing row
// whose conditions hold, else the simple lowercase mapping.
inline std::vector<std::uint32_t> lower_codepoint(
    const casing::CasingData& c, const ucd::Tables& t, casing::Locale locale,
    const std::vector<std::uint32_t>& rev_prefix,
    const std::vector<std::uint32_t>& suffix, std::uint32_t cp) {
    const casing::CasingRow* row =
        casing::detail::find_special_row(c, t, locale, rev_prefix, suffix, cp);
    if (row != nullptr) return row->lower;
    return {casing::detail::simple_lowercase(c, cp)};
}

// First input position whose lower_codepoint under locale differs from the
// default-locale result.
inline std::optional<std::size_t> first_locale_divergence(
    const casing::CasingData& c, const ucd::Tables& t, casing::Locale locale,
    const std::vector<std::uint32_t>& input) {
    std::vector<std::uint32_t> rev_prefix;
    for (std::size_t index = 0; index < input.size(); ++index) {
        std::vector<std::uint32_t> suffix(input.begin() + static_cast<std::ptrdiff_t>(index) + 1,
                                          input.end());
        auto default_lower =
            lower_codepoint(c, t, casing::Locale::Default, rev_prefix, suffix, input[index]);
        auto locale_lower = lower_codepoint(c, t, locale, rev_prefix, suffix, input[index]);
        if (default_lower != locale_lower) return index;
        rev_prefix.insert(rev_prefix.begin(), input[index]);
    }
    return std::nullopt;
}

}  // namespace detail

// Detect an input whose lowercase fold inverts across locales. Turkish
// divergence takes priority; Lithuanian is reached only when no Turkish
// divergence is found.
inline Detection detect(const casing::CasingData& c, const ucd::Tables& t,
                        const std::vector<std::uint32_t>& input) {
    if (auto pos = detail::first_locale_divergence(c, t, casing::Locale::Turkish, input)) {
        return Detection{std::string("TurkishCaseDivergence"), {*pos}};
    }
    if (auto pos = detail::first_locale_divergence(c, t, casing::Locale::Lithuanian, input)) {
        return Detection{std::string("LithuanianCaseDivergence"), {*pos}};
    }
    return Detection{std::nullopt, {}};
}

}  // namespace unicode_cpp::security::form::locale_case_inversion

#endif  // UNICODE_CPP_SECURITY_FORM_LOCALE_CASE_INVERSION_HPP
