#pragma once

// bip39-canonical: BIP-39 mnemonic canonicalisation + wordlist checks, mirroring
// Unicode.Security.Crypto.Bip39Canonical. Canonical form is NFKD ->
// to_lower(default) -> collapse BIP-39 whitespace -> trim; detect runs six
// probes in priority order over the input and its canonical words.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include "unicode_cpp/security/identity/casing.hpp"
#include "unicode_cpp/security/identity/ucd.hpp"

namespace unicode_cpp::security::bip39 {

namespace ucd = unicode_cpp::security::ucd;
namespace casing = unicode_cpp::security::casing;

// Declaration order matches Unicode.Generated.BIP39.allLanguages (English
// first, so a multi-wordlist-covered input resolves to English).
inline constexpr std::array<const char*, 10> kLanguages = {
    "english", "japanese", "korean", "spanish", "chinese_simplified",
    "chinese_traditional", "french", "italian", "czech", "portuguese"};

struct Bip39Data {
    // One entry per language, in kLanguages order; each set holds the UTF-8
    // encodings of the 2,048 words.
    std::vector<std::pair<std::string, std::unordered_set<std::string>>> wordlists;

    static Bip39Data load_from_dir(const std::filesystem::path& dir) {
        Bip39Data d;
        for (const char* lang : kLanguages) {
            std::string raw = ucd::detail::read_file(
                dir / "bip39" / (std::string(lang) + ".txt"));
            std::unordered_set<std::string> set;
            std::size_t start = 0;
            while (start <= raw.size()) {
                std::size_t nl = raw.find('\n', start);
                std::size_t end = nl == std::string::npos ? raw.size() : nl;
                std::string line = raw.substr(start, end - start);
                if (!line.empty() && line.back() == '\r') {
                    line.pop_back();
                }
                if (!line.empty()) {
                    set.insert(line);
                }
                if (nl == std::string::npos) {
                    break;
                }
                start = nl + 1;
            }
            d.wordlists.emplace_back(lang, std::move(set));
        }
        return d;
    }
};

struct Detection {
    std::optional<std::string> sub;       // nullopt = clear
    std::vector<std::size_t> positions;
    std::optional<std::string> language;  // set when clear
    std::vector<std::uint32_t> canonical;
    std::size_t word_count = 0;
};

namespace detail {

inline void append_utf8(std::string& out, std::uint32_t cp) {
    if (cp < 0x80) {
        out.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

inline std::string cps_to_utf8(const std::vector<std::uint32_t>& cps) {
    std::string out;
    for (auto cp : cps) {
        append_utf8(out, cp);
    }
    return out;
}

inline bool is_bip39_whitespace(std::uint32_t cp) {
    return cp == 0x0020 || cp == 0x3000;
}

inline std::vector<std::uint32_t> collapse_whitespace(
    const std::vector<std::uint32_t>& cps) {
    std::vector<std::uint32_t> out;
    bool in_ws = false;
    for (auto cp : cps) {
        if (is_bip39_whitespace(cp)) {
            if (!in_ws) {
                out.push_back(0x0020);
            }
            in_ws = true;
        } else {
            out.push_back(cp);
            in_ws = false;
        }
    }
    return out;
}

inline std::vector<std::uint32_t> trim_spaces(
    const std::vector<std::uint32_t>& cps) {
    std::size_t start = 0;
    std::size_t end = cps.size();
    while (start < end && cps[start] == 0x0020) {
        ++start;
    }
    while (end > start && cps[end - 1] == 0x0020) {
        --end;
    }
    return std::vector<std::uint32_t>(cps.begin() + start, cps.begin() + end);
}

inline std::vector<std::vector<std::uint32_t>> split_words(
    const std::vector<std::uint32_t>& cps) {
    std::vector<std::vector<std::uint32_t>> words;
    std::vector<std::uint32_t> current;
    for (auto cp : cps) {
        if (cp == 0x0020) {
            if (!current.empty()) {
                words.push_back(std::move(current));
                current.clear();
            }
        } else {
            current.push_back(cp);
        }
    }
    if (!current.empty()) {
        words.push_back(std::move(current));
    }
    return words;
}

}  // namespace detail

inline std::vector<std::uint32_t> bip39_canonical(
    const ucd::Tables& t, const casing::CasingData& cd,
    std::span<const std::uint32_t> input) {
    auto nfkd = ucd::to_nfkd(t, input);
    auto lowered = casing::to_lower(cd, t, casing::Locale::Default, nfkd);
    return detail::trim_spaces(detail::collapse_whitespace(lowered));
}

// Detect a non-canonical or wordlist-mismatched BIP-39 mnemonic. Six probes in
// priority order (first hit wins), mirroring Bip39Canonical.detect.
inline Detection detect(
    const ucd::Tables& t, const casing::CasingData& cd, const Bip39Data& bd,
    std::span<const std::uint32_t> input) {
    Detection result;
    result.canonical = bip39_canonical(t, cd, input);
    auto words = detail::split_words(result.canonical);
    result.word_count = words.size();

    // trailingWhitespace
    std::size_t trailing = 0;
    for (std::size_t i = input.size(); i-- > 0;) {
        if (detail::is_bip39_whitespace(input[i])) {
            ++trailing;
        } else {
            break;
        }
    }
    if (trailing > 0) {
        result.sub = "TrailingWhitespace";
        result.positions = {input.size() - trailing};
        return result;
    }
    // mixedCase
    for (std::size_t i = 0; i < input.size(); ++i) {
        if (input[i] >= 0x41 && input[i] <= 0x5A) {
            result.sub = "MixedCase";
            result.positions = {i};
            return result;
        }
    }
    // whitespaceAnomaly (leading or consecutive run)
    for (std::size_t i = 0; i < input.size(); ++i) {
        if (detail::is_bip39_whitespace(input[i])) {
            if (i == 0
                || (i + 1 < input.size()
                    && detail::is_bip39_whitespace(input[i + 1]))) {
                result.sub = "WhitespaceAnomaly";
                result.positions = {i};
                return result;
            }
        }
    }
    // nonNFKD
    auto nfkd = ucd::to_nfkd(t, input);
    bool same = nfkd.size() == input.size();
    if (same) {
        for (std::size_t i = 0; i < nfkd.size(); ++i) {
            if (nfkd[i] != input[i]) {
                same = false;
                break;
            }
        }
    }
    if (!same) {
        std::size_t n = std::min(nfkd.size(), input.size());
        std::size_t pos = n;
        for (std::size_t i = 0; i < n; ++i) {
            if (input[i] != nfkd[i]) {
                pos = i;
                break;
            }
        }
        result.sub = "NonNFKD";
        result.positions = {pos};
        return result;
    }
    // wordlistMismatch
    for (std::size_t idx = 0; idx < words.size(); ++idx) {
        std::string key = detail::cps_to_utf8(words[idx]);
        bool found = false;
        for (const auto& entry : bd.wordlists) {
            if (entry.second.count(key) != 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            result.sub = "WordlistMismatch";
            result.positions = {idx};
            return result;
        }
    }
    // clear(unique language) else languageAmbiguous
    for (const auto& entry : bd.wordlists) {
        bool all = true;
        for (const auto& word : words) {
            if (entry.second.count(detail::cps_to_utf8(word)) == 0) {
                all = false;
                break;
            }
        }
        if (all) {
            result.language = entry.first;
            return result;
        }
    }
    result.sub = "LanguageAmbiguous";
    return result;
}

}  // namespace unicode_cpp::security::bip39
