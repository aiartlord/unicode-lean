// UCD-table-backed support module for the identity-spoofing
// detector family — NFC normalization, script lookup, UTS #39
// identifier-status / restriction-level classification.
//
// All data is loaded once from the bundled UCD files under the
// caller-provided data directory via Tables::load_from_dir.  No
// catchall fallback: parser failures throw rather than silently
// falling through, and the spec's @missing defaults (e.g. CCC = 0
// for unlisted codepoints, UAX #44 § 5.7.4) are written as explicit
// branch returns rather than ``.value_or(default)`` lookups.

#ifndef UNICODE_CPP_SECURITY_IDENTITY_UCD_HPP
#define UNICODE_CPP_SECURITY_IDENTITY_UCD_HPP

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace unicode_cpp::security::ucd {

// ─────────────────────────────────────────────────────────────────────
// Pair-hash for unordered_map<pair<u32,u32>, u32>
// ─────────────────────────────────────────────────────────────────────

struct PairHash {
    std::size_t operator()(
        const std::pair<std::uint32_t, std::uint32_t>& p) const noexcept {
        const std::size_t a = std::hash<std::uint32_t>{}(p.first);
        const std::size_t b = std::hash<std::uint32_t>{}(p.second);
        return a ^ (b + 0x9E3779B97F4A7C15ULL + (a << 6) + (a >> 2));
    }
};

// ─────────────────────────────────────────────────────────────────────
// UcdEntry — one row of UnicodeData.txt
// ─────────────────────────────────────────────────────────────────────

// The subset of Bidi_Class values the security layer distinguishes:
// the two strong-RTL classes (R, AL), strong-LTR (L), and everything
// else collapsed to Other.  Mirrors the strong distinction retained by
// Unicode.Generated.DerivedBidiClass.lookup as consumed by
// Unicode/Security/Display/RtlInjection.lean.
enum class BidiStrong : std::uint8_t { R, Al, L, Other };

// UAX #11 East_Asian_Width class.
enum class EastAsianWidth : std::uint8_t { A, F, H, N, Na, W };

struct UcdEntry {
    std::uint8_t ccc;
    std::vector<std::uint32_t> canonical_decomp;  // empty if none
    // Compatibility decomposition (field 5 with a `<tag>` prefix), tag
    // stripped.  Used by NFKD/NFKC only; empty when the row has a
    // canonical decomposition or none at all.
    std::vector<std::uint32_t> compat_decomp;  // empty if none
};

// One range row parsed from DerivedBidiClass.txt: [lo, hi] carries the
// strong Bidi_Class distinction.  Explicit rows come from DATA lines and
// are sorted by lo for binary search; default rows come from `@missing`
// comment lines and are kept in file order (last match wins).
struct BidiRange {
    std::uint32_t lo;
    std::uint32_t hi;
    BidiStrong cls;
};

struct EawRange {
    std::uint32_t lo;
    std::uint32_t hi;
    EastAsianWidth cls;
};

// Joining_Type, the cursive-joining behaviour a character has in scripts like
// Arabic. RFC 5892 Appendix A.1 uses it to decide whether a ZERO WIDTH
// NON-JOINER sits in a position its script actually requires.
enum class JoiningType { JoinCausing, DualJoining, LeftJoining, RightJoining,
                         Transparent, NonJoining };

struct JoiningTypeRange {
    std::uint32_t lo;
    std::uint32_t hi;
    JoiningType cls;
};

// ─────────────────────────────────────────────────────────────────────
// RangeEntry — one row from Scripts.txt / ScriptExtensions.txt /
// IdentifierStatus.txt
// ─────────────────────────────────────────────────────────────────────

template <typename T>
struct RangeEntry {
    std::uint32_t start;
    std::uint32_t end;
    T value;
};

// ─────────────────────────────────────────────────────────────────────
// RestrictionLevel — UTS #39 § 5.1
// ─────────────────────────────────────────────────────────────────────

enum class RestrictionLevel {
    AsciiOnly,
    SingleScript,
    HighlyRestrictive,
    ModeratelyRestrictive,
    MinimallyRestrictive,
    Unrestricted,
};

inline std::string restriction_level_tag(RestrictionLevel l) {
    switch (l) {
        case RestrictionLevel::AsciiOnly:             return "ASCIIOnly";
        case RestrictionLevel::SingleScript:          return "SingleScript";
        case RestrictionLevel::HighlyRestrictive:     return "HighlyRestrictive";
        case RestrictionLevel::ModeratelyRestrictive: return "ModeratelyRestrictive";
        case RestrictionLevel::MinimallyRestrictive:  return "MinimallyRestrictive";
        case RestrictionLevel::Unrestricted:          return "Unrestricted";
    }
    throw std::logic_error(
        "restriction_level_tag: unhandled RestrictionLevel");
}

// ─────────────────────────────────────────────────────────────────────
// Tables — parsed UCD data
// ─────────────────────────────────────────────────────────────────────

struct Tables {
    std::unordered_map<std::uint32_t, UcdEntry> ucd;
    std::unordered_set<std::uint32_t> composition_exclusions;
    std::unordered_map<
        std::pair<std::uint32_t, std::uint32_t>, std::uint32_t, PairHash>
            composition_table;
    std::vector<RangeEntry<std::string>> scripts;
    std::vector<RangeEntry<std::vector<std::string>>> script_extensions;
    // Every abbreviation occurring in `script_extensions`, which is the set the
    // resolver can name. `Unicode/ResolvedScripts.lean` models the same set as
    // its `ScriptAbbrev` enum, so a primary script outside it resolves to no
    // abbreviation on both sides. Derived once at load: the fallback path runs
    // per codepoint, so a scan of the range table there would be hot.
    std::unordered_set<std::string> script_extension_abbrevs;
    std::vector<std::pair<std::uint32_t, std::uint32_t>> id_allowed_ranges;
    // UAX #31 XID_Start / XID_Continue ranges from DerivedCoreProperties.txt,
    // in file order (membership is a linear range scan, mirroring the Cased /
    // Soft_Dotted parse in casing.hpp). Backing for the whole-string UAX #31
    // default-identifier predicate used by the AdmissibilityFormDrift detector.
    std::vector<std::pair<std::uint32_t, std::uint32_t>> xid_start_ranges;
    std::vector<std::pair<std::uint32_t, std::uint32_t>> xid_continue_ranges;
    std::unordered_map<std::string, std::string> script_long_to_short;
    std::unordered_map<std::uint32_t, std::vector<std::uint32_t>>
        case_folding;
    std::vector<std::pair<std::uint32_t, std::uint32_t>>
        default_ignorable_ranges;
    // DerivedBidiClass.txt strong-class ranges.  Explicit rows sorted by
    // lo; default (`@missing`) rows in file order.
    std::vector<BidiRange> bidi_explicit;
    std::vector<BidiRange> bidi_default;
    // EastAsianWidth.txt ranges, sorted by lo.  There is no default vector:
    // the file's `@missing` line declares N over the whole codepoint space, so
    // a lookup miss is Neutral by declaration rather than by fallback.
    std::vector<EawRange> east_asian_width;
    // DerivedJoiningType.txt ranges, sorted by lo. The file's `@missing` line
    // declares Non_Joining over the whole codepoint space, so a lookup miss is
    // Non_Joining by declaration rather than by fallback.
    std::vector<JoiningTypeRange> joining_type;

    static Tables load_from_dir(const std::filesystem::path& dir);
    static Tables parse(
        std::string_view unicode_data_text,
        std::string_view composition_exclusions_text,
        std::string_view scripts_text,
        std::string_view script_extensions_text,
        std::string_view identifier_status_text,
        std::string_view property_value_aliases_text,
        std::string_view case_folding_text,
        std::string_view derived_core_properties_text,
        std::string_view derived_bidi_class_text,
        std::string_view east_asian_width_text,
        std::string_view derived_joining_type_text);
};

// ─────────────────────────────────────────────────────────────────────
// Parsing helpers
// ─────────────────────────────────────────────────────────────────────

namespace detail {

inline std::string_view trim(std::string_view s) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) {
        s.remove_prefix(1);
    }
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) {
        s.remove_suffix(1);
    }
    return s;
}

inline std::string_view strip_comment_and_trim(std::string_view line) {
    const std::size_t hash = line.find('#');
    std::string_view body =
        hash == std::string_view::npos ? line : line.substr(0, hash);
    return trim(body);
}

inline std::optional<std::uint32_t> parse_hex_u32(std::string_view s) {
    s = trim(s);
    if (s.empty()) return std::nullopt;
    std::uint32_t out = 0;
    auto* first = s.data();
    auto* last = s.data() + s.size();
    auto [ptr, ec] = std::from_chars(first, last, out, 16);
    if (ec != std::errc() || ptr != last) return std::nullopt;
    return out;
}

inline std::pair<std::uint32_t, std::uint32_t> parse_range_field(
    std::string_view s) {
    s = trim(s);
    std::size_t dots = s.find("..");
    if (dots == std::string_view::npos) {
        auto cp = parse_hex_u32(s);
        if (!cp) {
            throw std::runtime_error(
                std::string("parse_range_field: not a hex codepoint: ")
                + std::string(s));
        }
        return {*cp, *cp};
    }
    auto a = parse_hex_u32(s.substr(0, dots));
    auto b = parse_hex_u32(s.substr(dots + 2));
    if (!a || !b) {
        throw std::runtime_error(
            std::string("parse_range_field: malformed range: ")
            + std::string(s));
    }
    return {*a, *b};
}

inline std::string read_file(const std::filesystem::path& path) {
    std::ifstream f(path);
    if (!f) {
        throw std::runtime_error(
            "ucd::read_file: cannot open " + path.string());
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

template <typename F>
inline void for_each_line(std::string_view text, F&& fn) {
    std::size_t pos = 0;
    while (pos <= text.size()) {
        std::size_t nl = text.find('\n', pos);
        std::string_view line =
            text.substr(
                pos, nl == std::string_view::npos
                         ? std::string_view::npos
                         : nl - pos);
        fn(line);
        if (nl == std::string_view::npos) break;
        pos = nl + 1;
    }
}

inline std::uint8_t ccc_lookup(
    const std::unordered_map<std::uint32_t, UcdEntry>& ucd,
    std::uint32_t cp) {
    auto it = ucd.find(cp);
    if (it == ucd.end()) {
        // UAX #44 § 5.7.4: CCC = 0 by default for unlisted codepoints.
        return 0;
    }
    return it->second.ccc;
}

}  // namespace detail

// ─────────────────────────────────────────────────────────────────────
// Tables construction
// ─────────────────────────────────────────────────────────────────────

namespace detail {

inline void parse_unicode_data(
    std::string_view text,
    std::unordered_map<std::uint32_t, UcdEntry>& out) {
    for_each_line(text, [&](std::string_view line) {
        if (line.empty() || line.front() == '#') return;
        // Split on ';'.
        std::array<std::string_view, 15> fields{};
        std::size_t field_count = 0;
        std::size_t start = 0;
        for (std::size_t i = 0; i <= line.size(); ++i) {
            if (i == line.size() || line[i] == ';') {
                if (field_count < fields.size()) {
                    fields[field_count++] = line.substr(start, i - start);
                }
                start = i + 1;
            }
        }
        if (field_count < 6) return;
        auto cp_opt = parse_hex_u32(fields[0]);
        if (!cp_opt) return;
        std::uint32_t cp = *cp_opt;

        // CCC field.
        std::string ccc_str(trim(fields[3]));
        std::uint16_t ccc_val = 0;
        auto [ptr, ec] = std::from_chars(
            ccc_str.data(), ccc_str.data() + ccc_str.size(), ccc_val);
        if (ec != std::errc()
            || ptr != ccc_str.data() + ccc_str.size()
            || ccc_val > 255) {
            std::ostringstream msg;
            msg << "UnicodeData.txt: CCC field '" << ccc_str
                << "' for U+" << std::hex << cp
                << " is not a 0-255 integer";
            throw std::runtime_error(msg.str());
        }

        // Decomposition field.  A leading `<tag>` marks a compatibility
        // decomposition (kept for NFKD/NFKC only, tag stripped); anything
        // else is a canonical decomposition (kept for NFD/NFC/NFKD/NFKC).
        std::string_view decomp_field = trim(fields[5]);
        std::vector<std::uint32_t> canonical_decomp;
        std::vector<std::uint32_t> compat_decomp;
        if (!decomp_field.empty()) {
            const bool is_compat = decomp_field.front() == '<';
            std::string_view codepoints_field = decomp_field;
            if (is_compat) {
                // Strip the leading `<tag>` prefix, keep the codepoints.
                std::size_t close = decomp_field.find('>');
                if (close != std::string_view::npos) {
                    codepoints_field = decomp_field.substr(close + 1);
                }
            }
            std::vector<std::uint32_t> parts;
            std::size_t tok_start = 0;
            for (std::size_t i = 0; i <= codepoints_field.size(); ++i) {
                if (i == codepoints_field.size()
                    || std::isspace(
                        static_cast<unsigned char>(codepoints_field[i]))) {
                    if (i > tok_start) {
                        auto tok =
                            codepoints_field.substr(tok_start, i - tok_start);
                        if (auto val = parse_hex_u32(tok)) {
                            parts.push_back(*val);
                        }
                    }
                    tok_start = i + 1;
                }
            }
            if (!parts.empty()) {
                if (is_compat) {
                    compat_decomp = std::move(parts);
                } else {
                    canonical_decomp = std::move(parts);
                }
            }
        }
        out.emplace(
            cp,
            UcdEntry{
                static_cast<std::uint8_t>(ccc_val),
                std::move(canonical_decomp),
                std::move(compat_decomp),
            });
    });
}

inline void parse_composition_exclusions(
    std::string_view text, std::unordered_set<std::uint32_t>& out) {
    for_each_line(text, [&](std::string_view line) {
        auto stripped = strip_comment_and_trim(line);
        if (stripped.empty()) return;
        if (auto cp = parse_hex_u32(stripped)) {
            out.insert(*cp);
        }
    });
}

inline void build_composition_table(
    const std::unordered_map<std::uint32_t, UcdEntry>& ucd,
    const std::unordered_set<std::uint32_t>& exclusions,
    std::unordered_map<
        std::pair<std::uint32_t, std::uint32_t>, std::uint32_t,
        PairHash>& out) {
    for (const auto& kv : ucd) {
        const std::uint32_t cp = kv.first;
        const auto& entry = kv.second;
        if (entry.canonical_decomp.size() != 2) continue;
        if (exclusions.contains(cp)) continue;
        const std::uint32_t a = entry.canonical_decomp[0];
        const std::uint32_t b = entry.canonical_decomp[1];
        if (ccc_lookup(ucd, a) != 0) continue;
        out.emplace(std::make_pair(a, b), cp);
    }
}

inline void parse_scripts(
    std::string_view text,
    std::vector<RangeEntry<std::string>>& out) {
    for_each_line(text, [&](std::string_view line) {
        auto stripped = strip_comment_and_trim(line);
        if (stripped.empty()) return;
        std::size_t semi = stripped.find(';');
        if (semi == std::string_view::npos) return;
        auto rng = parse_range_field(stripped.substr(0, semi));
        auto value = std::string(trim(stripped.substr(semi + 1)));
        out.push_back(RangeEntry<std::string>{rng.first, rng.second, value});
    });
    std::sort(out.begin(), out.end(),
        [](const auto& a, const auto& b) { return a.start < b.start; });
}

inline void parse_script_extensions(
    std::string_view text,
    std::vector<RangeEntry<std::vector<std::string>>>& out) {
    for_each_line(text, [&](std::string_view line) {
        auto stripped = strip_comment_and_trim(line);
        if (stripped.empty()) return;
        std::size_t semi = stripped.find(';');
        if (semi == std::string_view::npos) return;
        auto rng = parse_range_field(stripped.substr(0, semi));
        std::string_view list_field = trim(stripped.substr(semi + 1));
        std::vector<std::string> scripts;
        std::size_t tok_start = 0;
        for (std::size_t i = 0; i <= list_field.size(); ++i) {
            if (i == list_field.size()
                || std::isspace(
                    static_cast<unsigned char>(list_field[i]))) {
                if (i > tok_start) {
                    scripts.emplace_back(
                        list_field.substr(tok_start, i - tok_start));
                }
                tok_start = i + 1;
            }
        }
        if (!scripts.empty()) {
            out.push_back(RangeEntry<std::vector<std::string>>{
                rng.first, rng.second, std::move(scripts)});
        }
    });
    std::sort(out.begin(), out.end(),
        [](const auto& a, const auto& b) { return a.start < b.start; });
}

inline void parse_identifier_status(
    std::string_view text,
    std::vector<std::pair<std::uint32_t, std::uint32_t>>& out) {
    for_each_line(text, [&](std::string_view line) {
        auto stripped = strip_comment_and_trim(line);
        if (stripped.empty()) return;
        std::size_t semi = stripped.find(';');
        if (semi == std::string_view::npos) return;
        auto status = trim(stripped.substr(semi + 1));
        if (status != "Allowed") return;
        auto rng = parse_range_field(stripped.substr(0, semi));
        out.push_back({rng.first, rng.second});
    });
    std::sort(out.begin(), out.end(),
        [](const auto& a, const auto& b) { return a.first < b.first; });
}

inline void parse_property_value_aliases(
    std::string_view text,
    std::unordered_map<std::string, std::string>& out) {
    for_each_line(text, [&](std::string_view line) {
        auto stripped = strip_comment_and_trim(line);
        if (stripped.empty()) return;
        std::array<std::string_view, 4> fields{};
        std::size_t field_count = 0;
        std::size_t start = 0;
        for (std::size_t i = 0; i <= stripped.size(); ++i) {
            if (i == stripped.size() || stripped[i] == ';') {
                if (field_count < fields.size()) {
                    fields[field_count++] =
                        stripped.substr(start, i - start);
                }
                start = i + 1;
            }
        }
        if (field_count < 3) return;
        if (trim(fields[0]) != "sc") return;
        std::string short_name(trim(fields[1]));
        std::string long_name(trim(fields[2]));
        out.emplace(std::move(long_name), std::move(short_name));
    });
}

inline void parse_default_ignorable(
    std::string_view text,
    std::vector<std::pair<std::uint32_t, std::uint32_t>>& out) {
    for_each_line(text, [&](std::string_view line) {
        auto stripped = strip_comment_and_trim(line);
        if (stripped.empty()) return;
        std::size_t semi = stripped.find(';');
        if (semi == std::string_view::npos) return;
        auto prop = trim(stripped.substr(semi + 1));
        if (prop != "Default_Ignorable_Code_Point") return;
        auto rng = parse_range_field(stripped.substr(0, semi));
        out.push_back({rng.first, rng.second});
    });
    std::sort(out.begin(), out.end(),
        [](const auto& a, const auto& b) { return a.first < b.first; });
}

// Parse the UAX #31 XID_Start and XID_Continue derived properties from
// DerivedCoreProperties.txt in a single pass, mirroring the Cased /
// Soft_Dotted parse in casing.hpp: each `LO..HI ; XID_Start` (or
// `CP ; XID_Continue`) DATA line contributes one [lo, hi] range to the
// matching bucket, kept in file order.
inline void parse_xid_ranges(
    std::string_view text,
    std::vector<std::pair<std::uint32_t, std::uint32_t>>& xid_start,
    std::vector<std::pair<std::uint32_t, std::uint32_t>>& xid_continue) {
    for_each_line(text, [&](std::string_view line) {
        auto stripped = strip_comment_and_trim(line);
        if (stripped.empty()) return;
        std::size_t semi = stripped.find(';');
        if (semi == std::string_view::npos) return;
        auto name = trim(stripped.substr(semi + 1));
        if (name != "XID_Start" && name != "XID_Continue") return;
        auto rng = parse_range_field(stripped.substr(0, semi));
        if (name == "XID_Start") {
            xid_start.push_back(rng);
        } else {
            xid_continue.push_back(rng);
        }
    });
}

inline void parse_case_folding(
    std::string_view text,
    std::unordered_map<std::uint32_t, std::vector<std::uint32_t>>& out) {
    for_each_line(text, [&](std::string_view line) {
        auto stripped = strip_comment_and_trim(line);
        if (stripped.empty()) return;
        // Up to 4 fields: codepoint ; status ; mapping ; name
        std::array<std::string_view, 4> fields{};
        std::size_t field_count = 0;
        std::size_t start = 0;
        for (std::size_t i = 0; i <= stripped.size(); ++i) {
            if (i == stripped.size() || stripped[i] == ';') {
                if (field_count < fields.size()) {
                    fields[field_count++] =
                        stripped.substr(start, i - start);
                }
                start = i + 1;
            }
        }
        if (field_count < 3) return;
        auto status = trim(fields[1]);
        // UCD CaseFolding.txt — keep only status C (Common) and F
        // (Full) entries.  S is redundant with C/F; T is Turkic-
        // locale-specific.  Together C ∪ F is RFC 8265 § 5.2.4
        // "default full case folding".
        if (status != "C" && status != "F") return;
        auto src = parse_hex_u32(trim(fields[0]));
        if (!src) return;
        std::vector<std::uint32_t> tgt;
        std::string_view mapping = trim(fields[2]);
        std::size_t tok_start = 0;
        for (std::size_t i = 0; i <= mapping.size(); ++i) {
            if (i == mapping.size()
                || std::isspace(
                    static_cast<unsigned char>(mapping[i]))) {
                if (i > tok_start) {
                    auto tok = mapping.substr(tok_start, i - tok_start);
                    if (auto v = parse_hex_u32(tok)) tgt.push_back(*v);
                }
                tok_start = i + 1;
            }
        }
        if (!tgt.empty()) {
            out.emplace(*src, std::move(tgt));
        }
    });
}

// Map a DerivedBidiClass.txt short class token to the strong subset.
inline BidiStrong strong_of_short(std::string_view token) {
    if (token == "R") return BidiStrong::R;
    if (token == "AL") return BidiStrong::Al;
    if (token == "L") return BidiStrong::L;
    return BidiStrong::Other;
}

// Map an `@missing` long class name to the strong subset.
inline BidiStrong strong_of_long(std::string_view name) {
    if (name == "Right_To_Left") return BidiStrong::R;
    if (name == "Arabic_Letter") return BidiStrong::Al;
    if (name == "Left_To_Right") return BidiStrong::L;
    return BidiStrong::Other;
}

// Parse DerivedBidiClass.txt into explicit + default (`@missing`) ranges.
// Mirrors Unicode.Generated.DerivedBidiClass explicitRanges/defaultRanges:
// DATA lines `LO..HI ; SHORT` (or `CP ; SHORT`) yield explicit rows,
// sorted by lo; `# @missing: LO..HI; Long_Name` comment lines yield
// default rows, kept in file order.
// EastAsianWidth.txt rows into ranges sorted by lo.  Unlike
// parse_derived_bidi there is no default vector to fill: the file's
// `# @missing: 0000..10FFFF; N` line covers the whole codepoint space, so an
// absent codepoint is N by declaration.
inline void parse_east_asian_width(
    std::string_view text, std::vector<EawRange>& rows) {
    for_each_line(text, [&](std::string_view line) {
        std::size_t hash = line.find('#');
        std::string_view body =
            hash == std::string_view::npos ? line : line.substr(0, hash);
        body = trim(body);
        if (body.empty()) return;
        std::size_t semi = body.find(';');
        if (semi == std::string_view::npos) return;
        // parse_range_field throws on a malformed range rather than
        // returning an optional, matching every other parser here.
        auto rng = parse_range_field(body.substr(0, semi));
        std::string_view token = trim(body.substr(semi + 1));
        EastAsianWidth cls = EastAsianWidth::N;
        if (token == "A") cls = EastAsianWidth::A;
        else if (token == "F") cls = EastAsianWidth::F;
        else if (token == "H") cls = EastAsianWidth::H;
        else if (token == "Na") cls = EastAsianWidth::Na;
        else if (token == "W") cls = EastAsianWidth::W;
        rows.push_back(EawRange{rng.first, rng.second, cls});
    });
    std::sort(rows.begin(), rows.end(),
              [](const EawRange& a, const EawRange& b) { return a.lo < b.lo; });
}

inline void parse_joining_type(
    std::string_view text, std::vector<JoiningTypeRange>& rows) {
    for_each_line(text, [&](std::string_view line) {
        std::size_t hash = line.find('#');
        std::string_view body =
            hash == std::string_view::npos ? line : line.substr(0, hash);
        body = trim(body);
        if (body.empty()) return;
        std::size_t semi = body.find(';');
        if (semi == std::string_view::npos) return;
        auto rng = parse_range_field(body.substr(0, semi));
        std::string_view token = trim(body.substr(semi + 1));
        JoiningType cls = JoiningType::NonJoining;
        if (token == "C") cls = JoiningType::JoinCausing;
        else if (token == "D") cls = JoiningType::DualJoining;
        else if (token == "L") cls = JoiningType::LeftJoining;
        else if (token == "R") cls = JoiningType::RightJoining;
        else if (token == "T") cls = JoiningType::Transparent;
        rows.push_back(JoiningTypeRange{rng.first, rng.second, cls});
    });
    std::sort(rows.begin(), rows.end(),
              [](const JoiningTypeRange& a, const JoiningTypeRange& b) {
                  return a.lo < b.lo;
              });
}

inline void parse_derived_bidi(
    std::string_view text,
    std::vector<BidiRange>& explicit_ranges,
    std::vector<BidiRange>& default_ranges) {
    constexpr std::string_view kMissing = "# @missing:";
    for_each_line(text, [&](std::string_view line) {
        if (line.substr(0, kMissing.size()) == kMissing) {
            // `# @missing: LO..HI; Long_Class_Name`
            std::string_view rest = line.substr(kMissing.size());
            std::size_t semi = rest.find(';');
            if (semi == std::string_view::npos) return;
            auto rng = parse_range_field(rest.substr(0, semi));
            default_ranges.push_back(BidiRange{
                rng.first, rng.second,
                strong_of_long(trim(rest.substr(semi + 1)))});
            return;
        }
        std::size_t hash = line.find('#');
        std::string_view body =
            hash == std::string_view::npos ? line : line.substr(0, hash);
        body = trim(body);
        if (body.empty()) return;
        std::size_t semi = body.find(';');
        if (semi == std::string_view::npos) return;
        auto rng = parse_range_field(body.substr(0, semi));
        explicit_ranges.push_back(BidiRange{
            rng.first, rng.second,
            strong_of_short(trim(body.substr(semi + 1)))});
    });
    std::sort(explicit_ranges.begin(), explicit_ranges.end(),
        [](const BidiRange& a, const BidiRange& b) { return a.lo < b.lo; });
}

}  // namespace detail

inline Tables Tables::parse(
    std::string_view unicode_data_text,
    std::string_view composition_exclusions_text,
    std::string_view scripts_text,
    std::string_view script_extensions_text,
    std::string_view identifier_status_text,
    std::string_view property_value_aliases_text,
    std::string_view case_folding_text,
    std::string_view derived_core_properties_text,
    std::string_view derived_bidi_class_text,
    std::string_view east_asian_width_text,
    std::string_view derived_joining_type_text) {
    Tables t;
    detail::parse_unicode_data(unicode_data_text, t.ucd);
    detail::parse_composition_exclusions(
        composition_exclusions_text, t.composition_exclusions);
    detail::build_composition_table(
        t.ucd, t.composition_exclusions, t.composition_table);
    detail::parse_scripts(scripts_text, t.scripts);
    detail::parse_script_extensions(
        script_extensions_text, t.script_extensions);
    for (const auto& row : t.script_extensions) {
        for (const auto& abbrev : row.value) {
            t.script_extension_abbrevs.insert(abbrev);
        }
    }
    detail::parse_identifier_status(
        identifier_status_text, t.id_allowed_ranges);
    detail::parse_property_value_aliases(
        property_value_aliases_text, t.script_long_to_short);
    detail::parse_case_folding(case_folding_text, t.case_folding);
    detail::parse_default_ignorable(
        derived_core_properties_text, t.default_ignorable_ranges);
    detail::parse_xid_ranges(
        derived_core_properties_text, t.xid_start_ranges,
        t.xid_continue_ranges);
    detail::parse_derived_bidi(
        derived_bidi_class_text, t.bidi_explicit, t.bidi_default);
    detail::parse_east_asian_width(east_asian_width_text, t.east_asian_width);
    detail::parse_joining_type(derived_joining_type_text, t.joining_type);
    return t;
}

inline Tables Tables::load_from_dir(const std::filesystem::path& dir) {
    return parse(
        detail::read_file(dir / "UnicodeData.txt"),
        detail::read_file(dir / "CompositionExclusions.txt"),
        detail::read_file(dir / "Scripts.txt"),
        detail::read_file(dir / "ScriptExtensions.txt"),
        detail::read_file(dir / "IdentifierStatus.txt"),
        detail::read_file(dir / "PropertyValueAliases.txt"),
        detail::read_file(dir / "CaseFolding.txt"),
        detail::read_file(dir / "DerivedCoreProperties.txt"),
        detail::read_file(dir / "DerivedBidiClass.txt"),
        detail::read_file(dir / "EastAsianWidth.txt"),
        detail::read_file(dir / "DerivedJoiningType.txt"));
}

// ─────────────────────────────────────────────────────────────────────
// Public accessors
// ─────────────────────────────────────────────────────────────────────

inline std::uint8_t ccc(const Tables& t, std::uint32_t cp) {
    return detail::ccc_lookup(t.ucd, cp);
}

// Joining_Type for one codepoint. The file's `@missing` line declares
// Non_Joining over the whole space, so an unlisted codepoint is Non_Joining.
inline JoiningType joining_type(const Tables& t, std::uint32_t cp) {
    std::size_t lo = 0;
    std::size_t hi = t.joining_type.size();
    while (lo < hi) {
        std::size_t mid = lo + (hi - lo) / 2;
        const auto& row = t.joining_type[mid];
        if (cp < row.lo) {
            hi = mid;
        } else if (cp > row.hi) {
            lo = mid + 1;
        } else {
            return row.cls;
        }
    }
    return JoiningType::NonJoining;
}

// True iff cp has Canonical_Combining_Class 9, the Virama used to request an
// explicit conjunct in scripts like Devanagari.
inline bool is_virama(const Tables& t, std::uint32_t cp) {
    return ccc(t, cp) == 9;
}

// Full Bidi_Class lookup (strong distinction only), mirroring
// Unicode.Generated.DerivedBidiClass.lookup: (1) binary-search the sorted
// explicit ranges — a hit wins; (2) otherwise scan the `@missing` default
// ranges in file order, last match winning; (3) otherwise L.
// UAX #11 East_Asian_Width lookup: binary-search the sorted ranges.  A miss
// returns N, which is the file's own `@missing` declaration over the whole
// codepoint space, not a fallback — hence no default vector to scan.
inline EastAsianWidth east_asian_width(const Tables& t, std::uint32_t cp) {
    std::size_t lo = 0;
    std::size_t hi = t.east_asian_width.size();
    while (lo < hi) {
        std::size_t mid = lo + (hi - lo) / 2;
        const EawRange& r = t.east_asian_width[mid];
        if (cp < r.lo) {
            hi = mid;
        } else if (cp > r.hi) {
            lo = mid + 1;
        } else {
            return r.cls;
        }
    }
    return EastAsianWidth::N;
}

inline BidiStrong bidi_strong(const Tables& t, std::uint32_t cp) {
    // Binary search the sorted explicit ranges.
    std::size_t lo = 0;
    std::size_t hi = t.bidi_explicit.size();
    while (lo < hi) {
        std::size_t mid = lo + (hi - lo) / 2;
        const BidiRange& r = t.bidi_explicit[mid];
        if (cp < r.lo) {
            hi = mid;
        } else if (cp > r.hi) {
            lo = mid + 1;
        } else {
            return r.cls;
        }
    }
    // No explicit row: last matching `@missing` default wins, else L.
    BidiStrong result = BidiStrong::L;
    for (const BidiRange& r : t.bidi_default) {
        if (r.lo <= cp && cp <= r.hi) {
            result = r.cls;
        }
    }
    return result;
}

// True iff cp's Bidi_Class is strong RTL (R or AL).
inline bool is_strong_rtl(const Tables& t, std::uint32_t cp) {
    const BidiStrong s = bidi_strong(t, cp);
    return s == BidiStrong::R || s == BidiStrong::Al;
}

// True iff cp's Bidi_Class is strong LTR (L).
inline bool is_strong_ltr(const Tables& t, std::uint32_t cp) {
    return bidi_strong(t, cp) == BidiStrong::L;
}

// Hangul algorithmic decomposition + composition (UAX #15 § 1.3).
inline constexpr std::uint32_t HANGUL_S_BASE = 0xAC00;
inline constexpr std::uint32_t HANGUL_L_BASE = 0x1100;
inline constexpr std::uint32_t HANGUL_V_BASE = 0x1161;
inline constexpr std::uint32_t HANGUL_T_BASE = 0x11A7;
inline constexpr std::uint32_t HANGUL_L_COUNT = 19;
inline constexpr std::uint32_t HANGUL_V_COUNT = 21;
inline constexpr std::uint32_t HANGUL_T_COUNT = 28;
inline constexpr std::uint32_t HANGUL_N_COUNT =
    HANGUL_V_COUNT * HANGUL_T_COUNT;
inline constexpr std::uint32_t HANGUL_S_COUNT =
    HANGUL_L_COUNT * HANGUL_N_COUNT;

inline bool hangul_decompose(
    std::uint32_t cp, std::vector<std::uint32_t>& out) {
    if (cp < HANGUL_S_BASE || cp >= HANGUL_S_BASE + HANGUL_S_COUNT) {
        return false;
    }
    const std::uint32_t s_index = cp - HANGUL_S_BASE;
    const std::uint32_t l = HANGUL_L_BASE + s_index / HANGUL_N_COUNT;
    const std::uint32_t v =
        HANGUL_V_BASE + (s_index % HANGUL_N_COUNT) / HANGUL_T_COUNT;
    const std::uint32_t t_index = s_index % HANGUL_T_COUNT;
    out.push_back(l);
    out.push_back(v);
    if (t_index != 0) out.push_back(HANGUL_T_BASE + t_index);
    return true;
}

inline std::optional<std::uint32_t> hangul_compose(
    std::uint32_t a, std::uint32_t b) {
    if (a >= HANGUL_L_BASE && a < HANGUL_L_BASE + HANGUL_L_COUNT
        && b >= HANGUL_V_BASE && b < HANGUL_V_BASE + HANGUL_V_COUNT) {
        const std::uint32_t l_index = a - HANGUL_L_BASE;
        const std::uint32_t v_index = b - HANGUL_V_BASE;
        return HANGUL_S_BASE
             + (l_index * HANGUL_V_COUNT + v_index) * HANGUL_T_COUNT;
    }
    if (a >= HANGUL_S_BASE && a < HANGUL_S_BASE + HANGUL_S_COUNT
        && (a - HANGUL_S_BASE) % HANGUL_T_COUNT == 0
        && b > HANGUL_T_BASE && b < HANGUL_T_BASE + HANGUL_T_COUNT) {
        return a + (b - HANGUL_T_BASE);
    }
    return std::nullopt;
}

inline void decompose_one(
    const Tables& t, std::uint32_t cp,
    std::vector<std::uint32_t>& out) {
    if (hangul_decompose(cp, out)) return;
    auto it = t.ucd.find(cp);
    if (it != t.ucd.end() && !it->second.canonical_decomp.empty()) {
        for (std::uint32_t child : it->second.canonical_decomp) {
            decompose_one(t, child, out);
        }
        return;
    }
    out.push_back(cp);
}

inline std::vector<std::uint32_t> canonical_decompose(
    const Tables& t, std::span<const std::uint32_t> input) {
    std::vector<std::uint32_t> out;
    out.reserve(input.size());
    for (std::uint32_t cp : input) {
        decompose_one(t, cp, out);
    }
    return out;
}

inline void canonical_reorder(
    const Tables& t, std::vector<std::uint32_t>& seq) {
    const std::size_t n = seq.size();
    std::size_t i = 0;
    while (i < n) {
        if (ccc(t, seq[i]) == 0) {
            ++i;
            continue;
        }
        std::size_t j = i;
        while (j < n && ccc(t, seq[j]) != 0) ++j;
        std::stable_sort(
            seq.begin() + static_cast<std::ptrdiff_t>(i),
            seq.begin() + static_cast<std::ptrdiff_t>(j),
            [&](std::uint32_t a, std::uint32_t b) {
                return ccc(t, a) < ccc(t, b);
            });
        i = j;
    }
}

inline std::vector<std::uint32_t> canonical_compose(
    const Tables& t, std::span<const std::uint32_t> seq) {
    std::vector<std::uint32_t> out;
    if (seq.empty()) return out;
    out.reserve(seq.size());
    std::optional<std::size_t> starter_idx;
    int last_ccc = -1;
    for (std::uint32_t cp : seq) {
        const std::uint8_t cp_ccc = ccc(t, cp);
        if (starter_idx) {
            const std::uint32_t starter = out[*starter_idx];
            auto composed = hangul_compose(starter, cp);
            if (!composed) {
                auto it = t.composition_table.find(
                    std::make_pair(starter, cp));
                if (it != t.composition_table.end()) composed = it->second;
            }
            // Blocked check (UAX #15 D115): last_ccc != 0 means a combiner is
            // buffered between the active starter and this candidate. A
            // starter candidate (cp_ccc == 0) is blocked outright by any
            // buffered combiner; a non-starter is blocked when the buffered
            // combiner has CCC >= its own.
            const bool blocked =
                last_ccc != 0
                && (cp_ccc == 0 || last_ccc >= static_cast<int>(cp_ccc));
            if (!blocked && composed) {
                out[*starter_idx] = *composed;
                continue;
            }
        }
        out.push_back(cp);
        if (cp_ccc == 0) {
            starter_idx = out.size() - 1;
            last_ccc = 0;
        } else {
            last_ccc = static_cast<int>(cp_ccc);
        }
    }
    return out;
}

inline std::vector<std::uint32_t> to_nfc(
    const Tables& t, std::span<const std::uint32_t> input) {
    auto seq = canonical_decompose(t, input);
    canonical_reorder(t, seq);
    return canonical_compose(t, seq);
}

/// UAX #15 NFD — canonical decompose + canonical reorder, without
/// the recomposition pass.  Required by the UTS #39 §4 + §5.4
/// confusable-skeleton bracket.
inline std::vector<std::uint32_t> to_nfd(
    const Tables& t, std::span<const std::uint32_t> input) {
    auto seq = canonical_decompose(t, input);
    canonical_reorder(t, seq);
    return seq;
}

// Recursively decompose `cp` using its compatibility mapping when present,
// otherwise its canonical mapping, otherwise Hangul algorithmic
// decomposition — the full decomposition of UAX #15 for NFKD.
inline void compat_decompose_one(
    const Tables& t, std::uint32_t cp,
    std::vector<std::uint32_t>& out) {
    if (hangul_decompose(cp, out)) return;
    auto it = t.ucd.find(cp);
    if (it != t.ucd.end()) {
        if (!it->second.compat_decomp.empty()) {
            for (std::uint32_t child : it->second.compat_decomp) {
                compat_decompose_one(t, child, out);
            }
            return;
        }
        if (!it->second.canonical_decomp.empty()) {
            for (std::uint32_t child : it->second.canonical_decomp) {
                compat_decompose_one(t, child, out);
            }
            return;
        }
    }
    out.push_back(cp);
}

inline std::vector<std::uint32_t> compat_decompose(
    const Tables& t, std::span<const std::uint32_t> input) {
    std::vector<std::uint32_t> out;
    out.reserve(input.size());
    for (std::uint32_t cp : input) {
        compat_decompose_one(t, cp, out);
    }
    return out;
}

/// UAX #15 NFKD — full compatibility decompose + canonical reorder,
/// without the recomposition pass.
inline std::vector<std::uint32_t> to_nfkd(
    const Tables& t, std::span<const std::uint32_t> input) {
    auto seq = compat_decompose(t, input);
    canonical_reorder(t, seq);
    return seq;
}

/// UAX #15 NFKC — NFKD followed by canonical recomposition.
inline std::vector<std::uint32_t> to_nfkc(
    const Tables& t, std::span<const std::uint32_t> input) {
    auto nfkd = to_nfkd(t, input);
    return canonical_compose(t, nfkd);
}

/// UAX #44 Default_Ignorable_Code_Point predicate.  True for
/// zero-width / format-control / soft-hyphen / bidi-control /
/// Mongolian-variation-selector / standard-variation-selector /
/// tag-block codepoints that render as nothing.  Used by
/// letter_skeleton in homoglyph_confusable to strip invisible
/// insertions from typosquat comparison.
inline bool is_default_ignorable(
    const Tables& t, std::uint32_t cp) {
    auto it = std::upper_bound(
        t.default_ignorable_ranges.begin(),
        t.default_ignorable_ranges.end(), cp,
        [](std::uint32_t value,
           const std::pair<std::uint32_t, std::uint32_t>& r) {
            return value < r.first;
        });
    if (it != t.default_ignorable_ranges.begin()) {
        const auto& prev = *(it - 1);
        if (cp <= prev.second) return true;
    }
    return false;
}

/// UCD PropList.txt White_Space predicate.  Hardcoded match
/// since the table is small and stable.  Includes ASCII tab /
/// newline / space, NBSP, NNBSP (U+202F — often abused for
/// invisibility in fonts), space-separator U+2000..U+200A,
/// line / paragraph separators, medium math space, ideographic
/// space.  Used by letter_skeleton to strip whitespace from
/// typosquat comparison.
inline constexpr bool is_white_space(std::uint32_t cp) {
    return (cp >= 0x0009 && cp <= 0x000D)
        || cp == 0x0020
        || cp == 0x0085
        || cp == 0x00A0
        || cp == 0x1680
        || (cp >= 0x2000 && cp <= 0x200A)
        || (cp >= 0x2028 && cp <= 0x2029)
        || cp == 0x202F
        || cp == 0x205F
        || cp == 0x3000;
}

/// Default full case folding (RFC 8265 § 5.2.4 / UCD CaseFolding.txt
/// status C ∪ F) of a codepoint sequence.  Codepoints absent from
/// the table fold to themselves.
inline std::vector<std::uint32_t> case_fold(
    const Tables& t, std::span<const std::uint32_t> input) {
    std::vector<std::uint32_t> out;
    out.reserve(input.size());
    for (std::uint32_t cp : input) {
        auto it = t.case_folding.find(cp);
        if (it == t.case_folding.end()) {
            out.push_back(cp);
        } else {
            for (std::uint32_t r : it->second) out.push_back(r);
        }
    }
    return out;
}

// ─────────────────────────────────────────────────────────────────────
// Scripts / ScriptExtensions / Restriction-level
// ─────────────────────────────────────────────────────────────────────

inline std::string script_of(const Tables& t, std::uint32_t cp) {
    // partition-point upper_bound: first entry with start > cp.
    auto it = std::upper_bound(
        t.scripts.begin(), t.scripts.end(), cp,
        [](std::uint32_t value, const RangeEntry<std::string>& r) {
            return value < r.start;
        });
    if (it != t.scripts.begin()) {
        const auto& prev = *(it - 1);
        if (cp <= prev.end) return prev.value;
    }
    return "Unknown";
}

inline std::string script_long_to_abbrev(
    const Tables& t, const std::string& name) {
    auto it = t.script_long_to_short.find(name);
    if (it == t.script_long_to_short.end()) {
        throw std::runtime_error(
            "script_long_to_abbrev: '" + name
            + "' not in PropertyValueAliases.txt");
    }
    return it->second;
}

inline std::vector<std::string> resolve_scripts(
    const Tables& t, std::uint32_t cp) {
    auto it = std::upper_bound(
        t.script_extensions.begin(), t.script_extensions.end(), cp,
        [](std::uint32_t value,
           const RangeEntry<std::vector<std::string>>& r) {
            return value < r.start;
        });
    if (it != t.script_extensions.begin()) {
        const auto& prev = *(it - 1);
        if (cp <= prev.end) return prev.value;
    }
    // A primary script with no abbreviation in the resolver's vocabulary
    // resolves to the empty set, mirroring `resolveScripts` in
    // `Unicode/ResolvedScripts.lean`. Returning a singleton instead would make
    // every unknown-script codepoint look Single-Script, putting
    // `restriction_level` one rung too strict and hiding `RestrictionLow`.
    const std::string abbrev = script_long_to_abbrev(t, script_of(t, cp));
    if (t.script_extension_abbrevs.count(abbrev) != 0) return {abbrev};
    return {};
}

inline bool is_common_script(const Tables& t, std::uint32_t cp) {
    return script_of(t, cp) == "Common";
}
inline bool is_inherited_script(const Tables& t, std::uint32_t cp) {
    return script_of(t, cp) == "Inherited";
}
inline bool is_ignored_for_intersection(const Tables& t, std::uint32_t cp) {
    return is_common_script(t, cp) || is_inherited_script(t, cp);
}

inline std::vector<std::string> string_script_union(
    const Tables& t, std::span<const std::uint32_t> input) {
    std::vector<std::string> acc;
    for (std::uint32_t cp : input) {
        if (is_ignored_for_intersection(t, cp)) continue;
        for (const auto& s : resolve_scripts(t, cp)) {
            if (std::find(acc.begin(), acc.end(), s) == acc.end()) {
                acc.push_back(s);
            }
        }
    }
    return acc;
}

inline bool is_id_allowed(const Tables& t, std::uint32_t cp) {
    auto it = std::upper_bound(
        t.id_allowed_ranges.begin(), t.id_allowed_ranges.end(), cp,
        [](std::uint32_t value,
           const std::pair<std::uint32_t, std::uint32_t>& r) {
            return value < r.first;
        });
    if (it != t.id_allowed_ranges.begin()) {
        const auto& prev = *(it - 1);
        if (cp <= prev.second) return true;
    }
    return false;
}

// ─────────────────────────────────────────────────────────────────────
// UAX #31 default identifier + UTS #39 whole-string admissibility,
// mirroring Unicode.Identifier / the Rust ucd reference. XID_Start /
// XID_Continue come from DerivedCoreProperties.txt (parsed above);
// is_id_allowed is the per-codepoint UTS #39 Identifier_Status test.
// ─────────────────────────────────────────────────────────────────────

namespace detail {

inline bool in_ranges(
    const std::vector<std::pair<std::uint32_t, std::uint32_t>>& ranges,
    std::uint32_t cp) {
    for (const auto& r : ranges) {
        if (r.first <= cp && cp <= r.second) return true;
    }
    return false;
}

}  // namespace detail

inline bool is_xid_start(const Tables& t, std::uint32_t cp) {
    return detail::in_ranges(t.xid_start_ranges, cp);
}

inline bool is_xid_continue(const Tables& t, std::uint32_t cp) {
    return detail::in_ranges(t.xid_continue_ranges, cp);
}

// UAX #31 default identifier start: XID_Start or U+005F LOW LINE.
inline bool is_default_id_start(const Tables& t, std::uint32_t cp) {
    return is_xid_start(t, cp) || cp == 0x005F;
}

// UAX #31 default identifier continue: XID_Continue.
inline bool is_default_id_continue(const Tables& t, std::uint32_t cp) {
    return is_xid_continue(t, cp);
}

// True iff cps is a well-formed UAX #31 default identifier: a non-empty
// sequence whose first codepoint is a default-id start and whose remaining
// codepoints are default-id continues.
inline bool is_default_identifier(
    const Tables& t, std::span<const std::uint32_t> cps) {
    if (cps.empty()) return false;
    if (!is_default_id_start(t, cps.front())) return false;
    for (std::size_t i = 1; i < cps.size(); ++i) {
        if (!is_default_id_continue(t, cps[i])) return false;
    }
    return true;
}

// True iff cps is a well-formed default identifier AND every codepoint has
// Identifier_Status = Allowed per UTS #39 (the whole-string admissibility
// predicate isAllowedIdentifier).
inline bool is_allowed_identifier(
    const Tables& t, std::span<const std::uint32_t> cps) {
    if (!is_default_identifier(t, cps)) return false;
    for (std::uint32_t cp : cps) {
        if (!is_id_allowed(t, cp)) return false;
    }
    return true;
}

inline bool is_ascii_only(std::span<const std::uint32_t> cps) {
    for (std::uint32_t cp : cps) {
        if (cp >= 0x80u) return false;
    }
    return true;
}

namespace detail {

inline std::vector<std::string> intersect_many(
    const std::vector<std::vector<std::string>>& sets) {
    if (sets.empty()) return {};
    std::vector<std::string> acc = sets.front();
    for (std::size_t i = 1; i < sets.size(); ++i) {
        std::vector<std::string> next;
        for (const auto& s : acc) {
            if (std::find(sets[i].begin(), sets[i].end(), s)
                != sets[i].end()) {
                next.push_back(s);
            }
        }
        acc = std::move(next);
    }
    return acc;
}

}  // namespace detail

inline std::vector<std::string> string_resolved_scripts(
    const Tables& t, std::span<const std::uint32_t> cps) {
    std::vector<std::vector<std::string>> sets;
    for (std::uint32_t cp : cps) {
        if (is_ignored_for_intersection(t, cp)) continue;
        sets.push_back(resolve_scripts(t, cp));
    }
    if (sets.empty()) return {};
    return detail::intersect_many(sets);
}

inline bool is_single_script(
    const Tables& t, std::span<const std::uint32_t> cps) {
    if (is_ascii_only(cps)) return false;
    return !string_resolved_scripts(t, cps).empty();
}

namespace detail {

inline bool intersects_str(
    const std::vector<std::string>& a,
    const std::vector<std::string>& b) {
    for (const auto& x : a) {
        if (std::find(b.begin(), b.end(), x) != b.end()) return true;
    }
    return false;
}

inline bool all_within_covered(
    const Tables& t, std::span<const std::uint32_t> cps,
    const std::vector<std::string>& covered) {
    for (std::uint32_t cp : cps) {
        if (is_ignored_for_intersection(t, cp)) continue;
        auto r = resolve_scripts(t, cp);
        if (r.empty() || !intersects_str(r, covered)) return false;
    }
    return true;
}

}  // namespace detail

inline bool is_covered_cjk(
    const Tables& t, std::span<const std::uint32_t> cps) {
    static const std::vector<std::string> japanese =
        {"Latn", "Hani", "Hira", "Kana"};
    static const std::vector<std::string> chinese =
        {"Latn", "Hani", "Bopo"};
    static const std::vector<std::string> korean =
        {"Latn", "Hani", "Hang"};
    return detail::all_within_covered(t, cps, japanese)
        || detail::all_within_covered(t, cps, chinese)
        || detail::all_within_covered(t, cps, korean);
}

inline bool is_highly_restrictive(
    const Tables& t, std::span<const std::uint32_t> cps) {
    return is_single_script(t, cps) || is_covered_cjk(t, cps);
}

inline bool is_moderately_restrictive_shape(
    const Tables& t, std::span<const std::uint32_t> cps) {
    std::optional<std::string> other;
    for (std::uint32_t cp : cps) {
        if (is_ignored_for_intersection(t, cp)) continue;
        auto r = resolve_scripts(t, cp);
        if (r.empty()) return false;
        if (std::find(r.begin(), r.end(), std::string("Latn")) != r.end()) {
            continue;
        }
        const std::string s = r.front();
        if (s == "Cyrl" || s == "Grek") return false;
        if (!other) {
            other = s;
        } else if (s != *other) {
            return false;
        }
    }
    return other.has_value();
}

inline bool is_minimally_restrictive(
    const Tables& t, std::span<const std::uint32_t> cps) {
    for (std::uint32_t cp : cps) {
        if (!is_id_allowed(t, cp)) return false;
    }
    return true;
}

inline RestrictionLevel restriction_level(
    const Tables& t, std::span<const std::uint32_t> cps) {
    if (is_ascii_only(cps))                  return RestrictionLevel::AsciiOnly;
    if (is_single_script(t, cps))            return RestrictionLevel::SingleScript;
    if (is_highly_restrictive(t, cps))       return RestrictionLevel::HighlyRestrictive;
    if (is_moderately_restrictive_shape(t, cps))
                                             return RestrictionLevel::ModeratelyRestrictive;
    if (is_minimally_restrictive(t, cps))    return RestrictionLevel::MinimallyRestrictive;
    return RestrictionLevel::Unrestricted;
}

}  // namespace unicode_cpp::security::ucd

#endif  // UNICODE_CPP_SECURITY_IDENTITY_UCD_HPP
