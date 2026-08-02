#pragma once

// skin-tone-variation-forgery — skin-tone modifier and variation-selector abuse
// on emoji bases per UTS #51 (the identity-layer detector).
//
// Direct port of Unicode/Security/Identity/SkinToneVariationForgery.lean,
// transliterated byte-faithfully from the verified Rust reference
// skin_tone_variation_forgery.rs.
//
// Threat model. Tier A₁. An adversary places a skin-tone modifier on a codepoint
// that does NOT bear Emoji_Modifier_Base, stacks multiple skin-tones on one base,
// or forces a text-style render on an emoji-default codepoint via U+FE0E (VS15) —
// sometimes to hide a payload-bearing glyph in plain sight.
//
// Distinct from VariationSelectorPayload (pair-aligned VS runs that decode to
// bytes): this catches the orthogonal case of semantic VS / skin-tone misuse on a
// single base. Both can fire on the same input.
//
// It reuses the port's own emoji property tables (the bundled emoji-data.txt) and
// the port's own skin-tone predicate, never a host emoji library. The skin-tone
// modifier set is EmojiZwjIntegrity's is_emoji_modifier (U+1F3FB..U+1F3FF); the
// Emoji_Modifier_Base and Emoji_Presentation property rows are parsed from the
// same already-bundled emoji-data.txt.
//
// Sub-threats (priority order):
//   1. StackedSkinTones      a base immediately followed by >= 2 skin-tone modifiers.
//   2. InvalidSkinToneTarget a skin-tone modifier on a non-Emoji_Modifier_Base.
//   3. ForcedTextStyle       U+FE0E on an Emoji_Presentation codepoint.

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

#include "unicode_cpp/security/identity/emoji_zwj_integrity.hpp"
#include "unicode_cpp/security/identity/ucd.hpp"

namespace unicode_cpp::security::identity::skin_tone_variation_forgery {

namespace ucd = unicode_cpp::security::ucd;
namespace ezwj = unicode_cpp::security::identity::emoji_zwj_integrity;

// ─────────────────────────────────────────────────────────────────────
// §1 Sub-threat types
// ─────────────────────────────────────────────────────────────────────

// A base at base_pos followed by >= 2 skin-tone modifiers (the first two are
// captured in modifiers).
struct StackedSkinTones {
    // Position of the base codepoint.
    std::size_t base_pos;
    // The first two stacked skin-tone modifiers.
    std::vector<std::uint32_t> modifiers;
};

// A skin-tone modifier_cp at base_pos + 1 on a non-modifier-base base_cp.
struct InvalidSkinToneTarget {
    // Position of the (invalid) base codepoint.
    std::size_t base_pos;
    // The base codepoint that lacks Emoji_Modifier_Base.
    std::uint32_t base_cp;
    // The skin-tone modifier codepoint.
    std::uint32_t modifier_cp;
};

// A U+FE0E at base_pos + 1 forcing text-style on an Emoji_Presentation base_cp.
struct ForcedTextStyle {
    // Position of the Emoji_Presentation codepoint.
    std::size_t base_pos;
    // The Emoji_Presentation codepoint forced to text style.
    std::uint32_t base_cp;
};

using SubThreat =
    std::variant<StackedSkinTones, InvalidSkinToneTarget, ForcedTextStyle>;

// Fixture-row tag string for this sub-threat (matches SubThreat.tag). Every
// alternative is handled explicitly by an overload; the variant makes the
// dispatch exhaustive with no catch-all.
inline std::string_view sub_threat_tag(const SubThreat& sub) {
    struct Visitor {
        std::string_view operator()(const StackedSkinTones&) const {
            return "StackedSkinTones";
        }
        std::string_view operator()(const InvalidSkinToneTarget&) const {
            return "InvalidSkinToneTarget";
        }
        std::string_view operator()(const ForcedTextStyle&) const {
            return "ForcedTextStyle";
        }
    };
    return std::visit(Visitor{}, sub);
}

// Top-level classification. sub is nullopt for a Clear input, else the sub-threat
// that fired, the implicated positions, and the (always-empty for this detector)
// decoded-byte projection — kept for shape parity with the Lean
// Classification.hazard.
struct Classification {
    std::optional<SubThreat> sub;
    std::vector<std::size_t> positions;
    std::vector<std::uint8_t> decoded;

    // True iff the classification is Clear.
    bool is_clear() const { return !sub.has_value(); }

    // Human-facing tag for a hazard, or nullopt when clear.
    std::optional<std::string_view> tag() const {
        if (!sub.has_value()) {
            return std::nullopt;
        }
        return sub_threat_tag(*sub);
    }
};

// The structured output of detect (mirrors the Lean Verdict).
struct Verdict {
    // The scanned input codepoints.
    std::vector<std::uint32_t> input;
    // The classification verdict.
    Classification classify;
    // Count of skin-tone modifier codepoints.
    std::size_t skin_tone_count;
    // Count of U+FE0E (VS15) codepoints.
    std::size_t variation_selector15_count;
    // Count of U+FE0F (VS16) codepoints.
    std::size_t variation_selector16_count;
};

// ─────────────────────────────────────────────────────────────────────
// §2 Emoji property tables (bundled data/emoji-data.txt)
// ─────────────────────────────────────────────────────────────────────

namespace detail {

// Parse the closed intervals for a single emoji property from emoji-data.txt.
// Each non-comment row is `<range> ; <property> # <comment>`; we keep only rows
// whose property field matches property exactly. Mirrors the port's existing
// emoji-data.txt property-interval parser (AiWatermarkDetectability's
// parse_emoji_ranges), generalized over the target property.
inline std::vector<std::pair<std::uint32_t, std::uint32_t>> parse_emoji_property(
    std::string_view text, std::string_view property) {
    std::vector<std::pair<std::uint32_t, std::uint32_t>> out;
    ucd::detail::for_each_line(text, [&](std::string_view raw_line) {
        std::string_view stripped =
            ucd::detail::strip_comment_and_trim(raw_line);
        if (stripped.empty()) {
            return;
        }
        std::size_t semi = stripped.find(';');
        if (semi == std::string_view::npos) {
            return;
        }
        std::string_view range_field =
            ucd::detail::trim(stripped.substr(0, semi));
        std::string_view prop_rest = stripped.substr(semi + 1);
        std::size_t semi2 = prop_rest.find(';');
        std::string_view prop_field =
            semi2 == std::string_view::npos ? prop_rest
                                            : prop_rest.substr(0, semi2);
        if (ucd::detail::trim(prop_field) != property) {
            return;
        }
        std::size_t dots = range_field.find("..");
        if (dots == std::string_view::npos) {
            if (auto single = ucd::detail::parse_hex_u32(range_field)) {
                out.push_back({*single, *single});
            }
            return;
        }
        auto lo = ucd::detail::parse_hex_u32(range_field.substr(0, dots));
        auto hi = ucd::detail::parse_hex_u32(range_field.substr(dots + 2));
        if (lo && hi) {
            out.push_back({*lo, *hi});
        }
    });
    return out;
}

inline bool ranges_contain(
    const std::vector<std::pair<std::uint32_t, std::uint32_t>>& ranges,
    std::uint32_t cp) {
    for (const auto& r : ranges) {
        if (r.first <= cp && cp <= r.second) {
            return true;
        }
    }
    return false;
}

}  // namespace detail

// The Emoji_Modifier_Base and Emoji_Presentation interval tables, loaded once
// from the bundled emoji-data.txt.
struct EmojiPropertyTable {
    std::vector<std::pair<std::uint32_t, std::uint32_t>> modifier_base;
    std::vector<std::pair<std::uint32_t, std::uint32_t>> presentation;

    static EmojiPropertyTable parse(std::string_view text) {
        EmojiPropertyTable table;
        table.modifier_base =
            detail::parse_emoji_property(text, "Emoji_Modifier_Base");
        table.presentation =
            detail::parse_emoji_property(text, "Emoji_Presentation");
        return table;
    }

    static EmojiPropertyTable load_from_dir(
        const std::filesystem::path& dir) {
        return parse(ucd::detail::read_file(dir / "emoji-data.txt"));
    }

    // True iff cp has Emoji_Modifier_Base per emoji-data.txt.
    bool is_skin_tone_base(std::uint32_t cp) const {
        return detail::ranges_contain(modifier_base, cp);
    }

    // True iff cp has Emoji_Presentation per emoji-data.txt.
    bool is_emoji_presentation(std::uint32_t cp) const {
        return detail::ranges_contain(presentation, cp);
    }
};

// ─────────────────────────────────────────────────────────────────────
// §3 Core predicates
// ─────────────────────────────────────────────────────────────────────

// True iff cp is an emoji skin-tone modifier. Reuses the port's own predicate
// (EmojiZwjIntegrity's is_emoji_modifier, U+1F3FB..U+1F3FF) — no host library.
inline bool is_skin_tone(std::uint32_t cp) {
    return ezwj::is_emoji_modifier(cp);
}

// True iff cp is U+FE0E (VS15, text-style variation selector).
inline bool is_vs15(std::uint32_t cp) { return cp == 0xFE0E; }

// True iff cp is U+FE0F (VS16, emoji-style variation selector).
inline bool is_vs16(std::uint32_t cp) { return cp == 0xFE0F; }

// ─────────────────────────────────────────────────────────────────────
// §4 Sub-detectors
// ─────────────────────────────────────────────────────────────────────

namespace detail {

// First position p whose next two codepoints are both skin-tone modifiers, as
// (base_pos, [mod1, mod2]).
inline std::optional<std::pair<std::size_t, std::vector<std::uint32_t>>>
first_stacked_skin_tones(std::span<const std::uint32_t> input) {
    for (std::size_t i = 0; i < input.size(); ++i) {
        if (i + 2 < input.size()) {
            const std::uint32_t m1 = input[i + 1];
            const std::uint32_t m2 = input[i + 2];
            if (is_skin_tone(m1) && is_skin_tone(m2)) {
                return std::pair<std::size_t, std::vector<std::uint32_t>>{
                    i, std::vector<std::uint32_t>{m1, m2}};
            }
        }
    }
    return std::nullopt;
}

// First skin-tone modifier whose preceding codepoint is NOT Emoji_Modifier_Base,
// as (base_pos, base_cp, modifier_cp).
inline std::optional<std::tuple<std::size_t, std::uint32_t, std::uint32_t>>
first_invalid_skin_tone_target(const EmojiPropertyTable& props,
                               std::span<const std::uint32_t> input) {
    for (std::size_t i = 0; i < input.size(); ++i) {
        if (i + 1 < input.size()) {
            const std::uint32_t cp = input[i + 1];
            if (is_skin_tone(cp) && !props.is_skin_tone_base(input[i])) {
                return std::tuple<std::size_t, std::uint32_t, std::uint32_t>{
                    i, input[i], cp};
            }
        }
    }
    return std::nullopt;
}

// First U+FE0E whose preceding codepoint has Emoji_Presentation, as
// (base_pos, base_cp).
inline std::optional<std::pair<std::size_t, std::uint32_t>>
first_forced_text_style(const EmojiPropertyTable& props,
                        std::span<const std::uint32_t> input) {
    for (std::size_t i = 0; i < input.size(); ++i) {
        if (i + 1 < input.size()) {
            const std::uint32_t cp = input[i + 1];
            if (is_vs15(cp) && props.is_emoji_presentation(input[i])) {
                return std::pair<std::size_t, std::uint32_t>{i, input[i]};
            }
        }
    }
    return std::nullopt;
}

inline std::size_t skin_tone_count(std::span<const std::uint32_t> input) {
    std::size_t count = 0;
    for (std::uint32_t cp : input) {
        if (is_skin_tone(cp)) {
            ++count;
        }
    }
    return count;
}

inline std::size_t vs15_count(std::span<const std::uint32_t> input) {
    std::size_t count = 0;
    for (std::uint32_t cp : input) {
        if (is_vs15(cp)) {
            ++count;
        }
    }
    return count;
}

inline std::size_t vs16_count(std::span<const std::uint32_t> input) {
    std::size_t count = 0;
    for (std::uint32_t cp : input) {
        if (is_vs16(cp)) {
            ++count;
        }
    }
    return count;
}

}  // namespace detail

// ─────────────────────────────────────────────────────────────────────
// §5 Top-level detection
// ─────────────────────────────────────────────────────────────────────

// The SkinToneVariationForgery detection function. The Emoji_Modifier_Base and
// Emoji_Presentation predicates come from the bundled EmojiPropertyTable props;
// the skin-tone predicate is the port's own is_emoji_modifier.
inline Verdict detect(const EmojiPropertyTable& props,
                      std::span<const std::uint32_t> input) {
    const std::size_t stc = detail::skin_tone_count(input);
    const std::size_t v15 = detail::vs15_count(input);
    const std::size_t v16 = detail::vs16_count(input);

    Classification classification;
    if (auto stacked = detail::first_stacked_skin_tones(input)) {
        // Priority 1: a base followed by two stacked skin tones.
        const auto& [base_pos, modifiers] = *stacked;
        std::vector<std::size_t> positions;
        for (std::size_t i = 0; i < modifiers.size(); ++i) {
            positions.push_back(base_pos + 1 + i);
        }
        classification.sub =
            SubThreat{StackedSkinTones{base_pos, modifiers}};
        classification.positions = std::move(positions);
    } else if (auto invalid =
                   detail::first_invalid_skin_tone_target(props, input)) {
        // Priority 2: a skin tone on a non-modifier-base.
        const auto [base_pos, base_cp, modifier_cp] = *invalid;
        classification.sub =
            SubThreat{InvalidSkinToneTarget{base_pos, base_cp, modifier_cp}};
        classification.positions = {base_pos + 1};
    } else if (auto forced =
                   detail::first_forced_text_style(props, input)) {
        // Priority 3: VS15 forcing text style on an emoji-presentation cp.
        const auto [base_pos, base_cp] = *forced;
        classification.sub = SubThreat{ForcedTextStyle{base_pos, base_cp}};
        classification.positions = {base_pos + 1};
    } else {
        classification = Classification{std::nullopt, {}, {}};
    }

    Verdict verdict;
    verdict.input = std::vector<std::uint32_t>(input.begin(), input.end());
    verdict.classify = std::move(classification);
    verdict.skin_tone_count = stc;
    verdict.variation_selector15_count = v15;
    verdict.variation_selector16_count = v16;
    return verdict;
}

}  // namespace unicode_cpp::security::identity::skin_tone_variation_forgery
