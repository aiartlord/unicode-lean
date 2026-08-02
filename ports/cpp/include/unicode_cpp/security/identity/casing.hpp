#pragma once

// UAX #21 case mapping (to_lower) from the pinned UCD tables, mirroring
// Unicode.Casing. Full case mappings from SpecialCasing.txt over the simple
// lowercase in UnicodeData.txt field 13, with the context predicates
// (Final_Sigma, After_Soft_Dotted, More_Above, Not_Before_Dot, After_I) driven
// by CCC and the Cased / Soft_Dotted properties from DerivedCoreProperties.txt.
// Keystone for bip39-canonical's default-locale canonicalisation; computed from
// the pinned tables, not the runtime.

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "unicode_cpp/security/identity/ucd.hpp"

namespace unicode_cpp::security::casing {

namespace ucd = unicode_cpp::security::ucd;

// SpecialCasing locales; Default covers everything not tagged Turkish / Azeri /
// Lithuanian.
enum class Locale { Default, Turkish, Azeri, Lithuanian };

struct CasingRow {
    std::vector<std::uint32_t> lower;
    std::vector<std::uint32_t> upper;
    std::vector<std::string> conditions;
};

// Casing tables loaded from SpecialCasing.txt (lower = field 1, upper = field 3)
// + UnicodeData.txt (simple lowercase = field 13, simple uppercase = field 12) +
// DerivedCoreProperties.txt (Cased / Soft_Dotted). CCC comes from a separately
// loaded ucd::Tables.
struct CasingData {
    std::unordered_map<std::uint32_t, std::vector<CasingRow>> special_casing;
    std::unordered_map<std::uint32_t, std::uint32_t> simple_lowercase;
    std::unordered_map<std::uint32_t, std::uint32_t> simple_uppercase;
    std::vector<std::pair<std::uint32_t, std::uint32_t>> cased_ranges;
    std::vector<std::pair<std::uint32_t, std::uint32_t>> soft_dotted_ranges;

    static CasingData parse(std::string_view special_casing_text,
                            std::string_view unicode_data_text,
                            std::string_view derived_core_properties_text);

    static CasingData load_from_dir(const std::filesystem::path& dir) {
        return parse(
            ucd::detail::read_file(dir / "SpecialCasing.txt"),
            ucd::detail::read_file(dir / "UnicodeData.txt"),
            ucd::detail::read_file(dir / "DerivedCoreProperties.txt"));
    }
};

namespace detail {

inline std::vector<std::uint32_t> parse_codepoint_list(std::string_view field) {
    std::vector<std::uint32_t> out;
    std::size_t i = 0;
    while (i < field.size()) {
        while (i < field.size()
               && std::isspace(static_cast<unsigned char>(field[i]))) {
            ++i;
        }
        std::size_t start = i;
        while (i < field.size()
               && !std::isspace(static_cast<unsigned char>(field[i]))) {
            ++i;
        }
        if (i > start) {
            if (auto cp = ucd::detail::parse_hex_u32(field.substr(start, i - start))) {
                out.push_back(*cp);
            }
        }
    }
    return out;
}

inline std::vector<std::string_view> split_semicolons(std::string_view line) {
    std::vector<std::string_view> fields;
    std::size_t start = 0;
    while (true) {
        std::size_t pos = line.find(';', start);
        if (pos == std::string_view::npos) {
            fields.push_back(line.substr(start));
            break;
        }
        fields.push_back(line.substr(start, pos - start));
        start = pos + 1;
    }
    return fields;
}

}  // namespace detail

inline CasingData CasingData::parse(
    std::string_view special_casing_text,
    std::string_view unicode_data_text,
    std::string_view derived_core_properties_text) {
    CasingData c;

    // SpecialCasing rows: code; lower; title; upper; conditions? .
    ucd::detail::for_each_line(special_casing_text, [&](std::string_view line) {
        auto stripped = ucd::detail::strip_comment_and_trim(line);
        if (stripped.empty()) return;
        auto fields = detail::split_semicolons(stripped);
        if (fields.size() < 4) return;
        auto code = ucd::detail::parse_hex_u32(ucd::detail::trim(fields[0]));
        if (!code) return;
        CasingRow row;
        row.lower = detail::parse_codepoint_list(fields[1]);
        row.upper = detail::parse_codepoint_list(fields[3]);
        if (fields.size() > 4) {
            std::string_view cond = ucd::detail::trim(fields[4]);
            std::size_t i = 0;
            while (i < cond.size()) {
                while (i < cond.size()
                       && std::isspace(static_cast<unsigned char>(cond[i]))) {
                    ++i;
                }
                std::size_t start = i;
                while (i < cond.size()
                       && !std::isspace(static_cast<unsigned char>(cond[i]))) {
                    ++i;
                }
                if (i > start) {
                    row.conditions.emplace_back(cond.substr(start, i - start));
                }
            }
        }
        c.special_casing[*code].push_back(std::move(row));
    });

    // Simple lowercase from UnicodeData.txt field 13; simple uppercase from
    // field 12.
    ucd::detail::for_each_line(unicode_data_text, [&](std::string_view line) {
        if (line.empty()) return;
        auto fields = detail::split_semicolons(line);
        if (fields.size() < 15) return;
        auto cp = ucd::detail::parse_hex_u32(fields[0]);
        if (!cp) return;
        if (!fields[13].empty()) {
            if (auto low = ucd::detail::parse_hex_u32(fields[13])) {
                c.simple_lowercase[*cp] = *low;
            }
        }
        if (!fields[12].empty()) {
            if (auto up = ucd::detail::parse_hex_u32(fields[12])) {
                c.simple_uppercase[*cp] = *up;
            }
        }
    });

    // Cased / Soft_Dotted ranges from DerivedCoreProperties.txt.
    ucd::detail::for_each_line(
        derived_core_properties_text, [&](std::string_view line) {
            auto stripped = ucd::detail::strip_comment_and_trim(line);
            if (stripped.empty()) return;
            std::size_t semi = stripped.find(';');
            if (semi == std::string_view::npos) return;
            std::string_view name = ucd::detail::trim(stripped.substr(semi + 1));
            if (name != "Cased" && name != "Soft_Dotted") return;
            auto range = ucd::detail::parse_range_field(stripped.substr(0, semi));
            if (name == "Cased") {
                c.cased_ranges.push_back(range);
            } else {
                c.soft_dotted_ranges.push_back(range);
            }
        });

    return c;
}

namespace detail {

inline bool in_ranges(
    const std::vector<std::pair<std::uint32_t, std::uint32_t>>& ranges,
    std::uint32_t cp) {
    for (const auto& r : ranges) {
        if (r.first <= cp && cp <= r.second) return true;
    }
    return false;
}

inline std::uint32_t simple_lowercase(const CasingData& c, std::uint32_t cp) {
    auto it = c.simple_lowercase.find(cp);
    return it == c.simple_lowercase.end() ? cp : it->second;
}

inline std::uint32_t simple_uppercase(const CasingData& c, std::uint32_t cp) {
    auto it = c.simple_uppercase.find(cp);
    return it == c.simple_uppercase.end() ? cp : it->second;
}

// Context predicates (UAX #21). rev_prefix is the preceding codepoints
// nearest-first; suffix the strictly-following ones. CCC comes from t.
inline bool more_above_after(
    const ucd::Tables& t, const std::vector<std::uint32_t>& suffix) {
    for (auto cp : suffix) {
        auto ccc = ucd::ccc(t, cp);
        if (ccc == 230) return true;
        if (ccc == 0) return false;
    }
    return false;
}

inline bool after_soft_dotted(
    const CasingData& c, const ucd::Tables& t,
    const std::vector<std::uint32_t>& rev_prefix) {
    for (auto cp : rev_prefix) {
        if (in_ranges(c.soft_dotted_ranges, cp)) return true;
        auto ccc = ucd::ccc(t, cp);
        if (ccc == 0 || ccc == 230) return false;
    }
    return false;
}

inline bool after_i(
    const ucd::Tables& t, const std::vector<std::uint32_t>& rev_prefix) {
    for (auto cp : rev_prefix) {
        if (cp == 0x0049) return true;
        auto ccc = ucd::ccc(t, cp);
        if (ccc == 0 || ccc == 230) return false;
    }
    return false;
}

inline bool before_dot(
    const ucd::Tables& t, const std::vector<std::uint32_t>& suffix) {
    for (auto cp : suffix) {
        if (cp == 0x0307) return true;
        if (ucd::ccc(t, cp) == 0) return false;
    }
    return false;
}

inline bool has_cased_before(
    const CasingData& c, const ucd::Tables& t,
    const std::vector<std::uint32_t>& rev_prefix) {
    for (auto cp : rev_prefix) {
        if (in_ranges(c.cased_ranges, cp)) return true;
        if (ucd::ccc(t, cp) == 0) return false;
    }
    return false;
}

inline bool has_cased_after(
    const CasingData& c, const ucd::Tables& t,
    const std::vector<std::uint32_t>& suffix) {
    for (auto cp : suffix) {
        if (in_ranges(c.cased_ranges, cp)) return true;
        if (ucd::ccc(t, cp) == 0) return false;
    }
    return false;
}

inline bool final_sigma(
    const CasingData& c, const ucd::Tables& t,
    const std::vector<std::uint32_t>& rev_prefix,
    const std::vector<std::uint32_t>& suffix) {
    return has_cased_before(c, t, rev_prefix) && !has_cased_after(c, t, suffix);
}

inline bool is_locale_condition(std::string_view condition) {
    return condition == "tr" || condition == "az" || condition == "lt";
}

inline bool locale_matches(Locale locale, const std::vector<std::string>& conditions) {
    bool has_locale = false;
    for (const auto& cond : conditions) {
        if (is_locale_condition(cond)) {
            has_locale = true;
            break;
        }
    }
    if (!has_locale) return true;
    for (const auto& cond : conditions) {
        if ((cond == "tr" && locale == Locale::Turkish)
            || (cond == "az" && locale == Locale::Azeri)
            || (cond == "lt" && locale == Locale::Lithuanian)) {
            return true;
        }
    }
    return false;
}

inline bool conditions_hold(
    const CasingData& c, const ucd::Tables& t, Locale locale,
    const std::vector<std::uint32_t>& rev_prefix,
    const std::vector<std::uint32_t>& suffix,
    const std::vector<std::string>& conditions) {
    if (!locale_matches(locale, conditions)) return false;
    for (const auto& cond : conditions) {
        if (is_locale_condition(cond)) continue;
        bool ok;
        if (cond == "Final_Sigma") {
            ok = final_sigma(c, t, rev_prefix, suffix);
        } else if (cond == "Not_Final_Sigma") {
            ok = !final_sigma(c, t, rev_prefix, suffix);
        } else if (cond == "After_Soft_Dotted") {
            ok = after_soft_dotted(c, t, rev_prefix);
        } else if (cond == "More_Above") {
            ok = more_above_after(t, suffix);
        } else if (cond == "Not_Before_Dot") {
            ok = !before_dot(t, suffix);
        } else if (cond == "After_I") {
            ok = after_i(t, rev_prefix);
        } else {
            ok = false;
        }
        if (!ok) return false;
    }
    return true;
}

inline const CasingRow* find_special_row(
    const CasingData& c, const ucd::Tables& t, Locale locale,
    const std::vector<std::uint32_t>& rev_prefix,
    const std::vector<std::uint32_t>& suffix, std::uint32_t cp) {
    auto it = c.special_casing.find(cp);
    if (it == c.special_casing.end()) return nullptr;
    for (const auto& row : it->second) {
        if (!row.conditions.empty()
            && conditions_hold(c, t, locale, rev_prefix, suffix, row.conditions)) {
            return &row;
        }
    }
    for (const auto& row : it->second) {
        if (row.conditions.empty()) return &row;
    }
    return nullptr;
}

}  // namespace detail

// Lowercase a codepoint sequence under locale (UAX #21 full mapping): a
// SpecialCasing row where its conditions hold, else the simple lowercase.
inline std::vector<std::uint32_t> to_lower(
    const CasingData& c, const ucd::Tables& t, Locale locale,
    const std::vector<std::uint32_t>& cps) {
    std::vector<std::uint32_t> out;
    std::vector<std::uint32_t> rev_prefix;
    for (std::size_t index = 0; index < cps.size(); ++index) {
        std::vector<std::uint32_t> suffix(cps.begin() + index + 1, cps.end());
        const CasingRow* row =
            detail::find_special_row(c, t, locale, rev_prefix, suffix, cps[index]);
        if (row != nullptr) {
            out.insert(out.end(), row->lower.begin(), row->lower.end());
        } else {
            out.push_back(detail::simple_lowercase(c, cps[index]));
        }
        rev_prefix.insert(rev_prefix.begin(), cps[index]);
    }
    return out;
}

}  // namespace unicode_cpp::security::casing
