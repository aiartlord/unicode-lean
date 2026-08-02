#pragma once

// ai-watermark-detectability — character-level detector for inputs carrying
// codepoint patterns consistent with a known AI watermark scheme. Answers the
// question: does this input contain markers attributable to a watermarking
// protocol?
//
// Direct port of Unicode/Security/Crypto/AiWatermarkDetectability.lean,
// transliterated from the verified Rust reference
// ai_watermark_detectability.rs.
//
// Threat model — provenance-attribution attacker. An input either (a) carries
// an AI provider's watermark codepoints (a legitimate provenance marker) or
// (b) carries injected markers that impersonate a provider's scheme to
// discredit the content as AI-generated. Character-level detection alone
// cannot distinguish (a) from (b); the detector reports the matched scheme and
// leaves provider-specific authentication to downstream code.
//
// Probe inventory (priority order, first match wins):
//
//   1. adversarial              — NNBSP count >= 3 at arithmetic-progression positions.
//   2. gpt5ZwspModulo           — ZWSP count >= 3 at arithmetic-progression positions.
//   3. unknown                  — invisible markers from >= 2 distinct categories.
//   4. nnbspBoundary            — single-category NNBSP.
//   5. variationSelectorCarrier — VS NOT adjacent to an emoji codepoint.
//   6. zwjNonEmoji              — ZWJ NOT adjacent to an emoji codepoint.
//   7. smartQuoteAlternation    — paired curly quotes, no ASCII straight quotes.
//   8. emDashPattern            — em-dashes, no ASCII hyphen-minus.
//   9. statisticalTokenChoice   — input contains an AI-favored lexical pattern.
//  10. defaultIgnorableCarrier  — single-category residual Default_Ignorable.
//
// The Emoji property table is bundled in the port's own data/emoji-data.txt
// (UTS #51 17.0, byte-identical to the UCD source the Lean spec cites); the
// adjacency probe parses the Emoji rows from it, never a host emoji library.
// The Default_Ignorable predicate reuses the port's own ucd:: table, never a
// host normalizer.

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include "unicode_cpp/security/identity/ucd.hpp"

namespace unicode_cpp::security::crypto::ai_watermark_detectability {

namespace ucd = unicode_cpp::security::ucd;

// ─────────────────────────────────────────────────────────────────────
// §1 Types
// ─────────────────────────────────────────────────────────────────────

// The conceptual watermark cue class a sub-threat probes for, drawn from the
// fixed vocabulary in Unicode.Generated.WatermarkSchemes.CueClass. Ported here
// because the port exposes no generated watermark-schemes module.
enum class CueClass : std::uint8_t {
    // A codepoint-frequency bias toward a pinned "green list" of tokens.
    GreenListBias,
    // A fixed-period or carrier-byte channel surfacing a pseudorandom function.
    PseudorandomSeq,
    // A stylistic-distribution drift away from natural human writing.
    SemanticDrift,
};

// Sub-threats this detector can fire. Each variant carries the position payload
// the conformance harness's attribution column reads back.

// Single-category NNBSP (U+202F) markers; marker_count is how many.
struct NnbspBoundary {
    std::size_t marker_count;
};

// Variation selector(s) not adjacent to an emoji; marker_count is how many.
struct VariationSelectorCarrier {
    std::size_t marker_count;
};

// ZWJ(s) not adjacent to an emoji; marker_count is how many.
struct ZwjNonEmoji {
    std::size_t marker_count;
};

// Residual Default_Ignorable markers; marker_count is how many.
struct DefaultIgnorableCarrier {
    std::size_t marker_count;
};

// ZWSP (U+200B) markers at arithmetic-progression positions; first_pos is the
// first ZWSP position.
struct Gpt5ZwspModulo {
    std::size_t first_pos;
};

// Em-dash (U+2014) stylistic signature; first_pos is the first em-dash.
struct EmDashPattern {
    std::size_t first_pos;
};

// Paired curly-quote stylistic signature; first_pos is the first quote.
struct SmartQuoteAlternation {
    std::size_t first_pos;
};

// AI-favored lexical pattern hit; first_pos is the match start.
struct StatisticalTokenChoice {
    std::size_t first_pos;
};

// Over-regular marker placement impersonating a scheme; impersonated_scheme
// names the surfaced scheme, first_pos the first marker position.
struct Adversarial {
    std::string impersonated_scheme;
    std::size_t first_pos;
};

// Multi-category invisible-marker mixing; anomaly_marker is the total
// invisible-marker count (attribution to a single scheme fails).
struct Unknown {
    std::size_t anomaly_marker;
};

using SubThreat =
    std::variant<NnbspBoundary, VariationSelectorCarrier, ZwjNonEmoji,
                 DefaultIgnorableCarrier, Gpt5ZwspModulo, EmDashPattern,
                 SmartQuoteAlternation, StatisticalTokenChoice, Adversarial,
                 Unknown>;

// Human-facing classification tag for this sub-threat.
inline std::string_view sub_threat_tag(const SubThreat& sub) {
    struct Visitor {
        std::string_view operator()(const NnbspBoundary&) const {
            return "NnbspBoundary";
        }
        std::string_view operator()(const VariationSelectorCarrier&) const {
            return "VariationSelectorCarrier";
        }
        std::string_view operator()(const ZwjNonEmoji&) const {
            return "ZwjNonEmoji";
        }
        std::string_view operator()(const DefaultIgnorableCarrier&) const {
            return "DefaultIgnorableCarrier";
        }
        std::string_view operator()(const Gpt5ZwspModulo&) const {
            return "Gpt5ZwspModulo";
        }
        std::string_view operator()(const EmDashPattern&) const {
            return "EmDashPattern";
        }
        std::string_view operator()(const SmartQuoteAlternation&) const {
            return "SmartQuoteAlternation";
        }
        std::string_view operator()(const StatisticalTokenChoice&) const {
            return "StatisticalTokenChoice";
        }
        std::string_view operator()(const Adversarial&) const {
            return "Adversarial";
        }
        std::string_view operator()(const Unknown&) const { return "Unknown"; }
    };
    return std::visit(Visitor{}, sub);
}

// Map this sub-threat to the conceptual watermark cue class it probes for.
// Marker-encoded sub-threats route to PseudorandomSeq; vocabulary-bias to
// GreenListBias; stylistic-distribution to SemanticDrift; Unknown (multi-
// category mixing) implicates no single scheme.
inline std::optional<CueClass> sub_threat_cue_class(const SubThreat& sub) {
    struct Visitor {
        std::optional<CueClass> operator()(const NnbspBoundary&) const {
            return CueClass::PseudorandomSeq;
        }
        std::optional<CueClass> operator()(
            const VariationSelectorCarrier&) const {
            return CueClass::PseudorandomSeq;
        }
        std::optional<CueClass> operator()(const ZwjNonEmoji&) const {
            return CueClass::PseudorandomSeq;
        }
        std::optional<CueClass> operator()(
            const DefaultIgnorableCarrier&) const {
            return CueClass::PseudorandomSeq;
        }
        std::optional<CueClass> operator()(const Gpt5ZwspModulo&) const {
            return CueClass::PseudorandomSeq;
        }
        std::optional<CueClass> operator()(const EmDashPattern&) const {
            return CueClass::SemanticDrift;
        }
        std::optional<CueClass> operator()(const SmartQuoteAlternation&) const {
            return CueClass::SemanticDrift;
        }
        std::optional<CueClass> operator()(const StatisticalTokenChoice&) const {
            return CueClass::GreenListBias;
        }
        std::optional<CueClass> operator()(const Adversarial&) const {
            return CueClass::PseudorandomSeq;
        }
        std::optional<CueClass> operator()(const Unknown&) const {
            return std::nullopt;
        }
    };
    return std::visit(Visitor{}, sub);
}

// Top-level classification. sub is nullopt for a clear input (semantically
// noWatermark), else the sub-threat that fired and its implicated positions.
struct Classification {
    std::optional<SubThreat> sub;
    std::vector<std::size_t> positions;

    // True iff no watermark marker was detected.
    bool is_clear() const { return !sub.has_value(); }

    // Human-facing tag for a hazard, or nullopt when clear.
    std::optional<std::string_view> tag() const {
        if (!sub.has_value()) {
            return std::nullopt;
        }
        return sub_threat_tag(*sub);
    }
};

// AiWatermarkDetectability verdict — the structured output of detect.
// marker_count is the count of codepoints matching the fired scheme's probe
// (0 when clear).
struct Verdict {
    std::vector<std::uint32_t> input;
    Classification classify;
    std::size_t marker_count;
};

// Optional context for the modulo-probe tolerances. Each field controls how
// strictly the corresponding probe checks its arithmetic-progression
// condition; the defaults of 0 require exact equality of consecutive gaps.
struct Context {
    // ZWSP-modulo tolerance. 0 requires the ZWSP-position arithmetic
    // progression to be exact. k > 0 accepts position gaps within +/- k of the
    // first gap, catching modulo schedules with light jitter.
    std::size_t zwsp_modulo_tolerance = 0;
    // NNBSP-arithmetic tolerance (the adversarial probe). Same semantic as
    // zwsp_modulo_tolerance but for the NNBSP positions.
    std::size_t adversarial_tolerance = 0;
};

// ─────────────────────────────────────────────────────────────────────
// §2 Emoji property table (bundled data/emoji-data.txt, Emoji rows)
// ─────────────────────────────────────────────────────────────────────

namespace detail {

// Parse the Emoji (Emoji=Yes) closed intervals from emoji-data.txt. Each
// non-comment row is `<range> ; <property> # <comment>`; we keep only rows
// whose property is exactly Emoji.
inline std::vector<std::pair<std::uint32_t, std::uint32_t>> parse_emoji_ranges(
    std::string_view text) {
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
        if (ucd::detail::trim(prop_field) != "Emoji") {
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

}  // namespace detail

// The Emoji=Yes interval table, loaded once from the bundled emoji-data.txt.
struct EmojiTable {
    std::vector<std::pair<std::uint32_t, std::uint32_t>> ranges;

    static EmojiTable parse(std::string_view text) {
        return EmojiTable{detail::parse_emoji_ranges(text)};
    }

    static EmojiTable load_from_dir(const std::filesystem::path& dir) {
        return parse(ucd::detail::read_file(dir / "emoji-data.txt"));
    }

    // True iff cp has the Emoji = Yes property per emoji-data.txt.
    bool is_emoji(std::uint32_t cp) const {
        for (const auto& r : ranges) {
            if (r.first <= cp && cp <= r.second) {
                return true;
            }
        }
        return false;
    }
};

// ─────────────────────────────────────────────────────────────────────
// §3 Codepoint probes
// ─────────────────────────────────────────────────────────────────────

namespace detail {

// True iff cp is U+202F NARROW NO-BREAK SPACE.
inline bool is_nnbsp(std::uint32_t cp) { return cp == 0x202F; }

// True iff cp is U+200D ZERO WIDTH JOINER.
inline bool is_zwj(std::uint32_t cp) { return cp == 0x200D; }

// True iff cp is a Variation Selector — the basic block U+FE00..U+FE0F
// (VS1..VS16) or the Plane-14 IVS block U+E0100..U+E01EF (VS17..VS256).
inline bool is_variation_selector(std::uint32_t cp) {
    return (cp >= 0xFE00 && cp <= 0xFE0F) || (cp >= 0xE0100 && cp <= 0xE01EF);
}

// True iff cp is U+200B ZERO WIDTH SPACE.
inline bool is_zwsp(std::uint32_t cp) { return cp == 0x200B; }

// True iff cp is U+2014 EM DASH.
inline bool is_em_dash(std::uint32_t cp) { return cp == 0x2014; }

// True iff cp is U+002D HYPHEN-MINUS (ASCII).
inline bool is_hyphen_minus(std::uint32_t cp) { return cp == 0x002D; }

// True iff cp is one of the four "curly" quotation marks: U+2018 / U+2019
// (single open/close) and U+201C / U+201D (double open/close).
inline bool is_curly_quote(std::uint32_t cp) {
    return cp == 0x2018 || cp == 0x2019 || cp == 0x201C || cp == 0x201D;
}

// True iff cp is an ASCII straight quote — U+0022 (double) or U+0027 (single /
// apostrophe).
inline bool is_straight_quote(std::uint32_t cp) {
    return cp == 0x0022 || cp == 0x0027;
}

// True iff input[i] is adjacent (immediate predecessor OR immediate successor)
// to an emoji codepoint. Two-sided check, single pass. Used by the VS and ZWJ
// probes to exclude legitimate emoji-context occurrences.
inline bool is_adjacent_to_emoji(const EmojiTable& emoji,
                                 std::span<const std::uint32_t> input,
                                 std::size_t i) {
    bool prev_is_emoji = false;
    if (i != 0 && i - 1 < input.size()) {
        prev_is_emoji = emoji.is_emoji(input[i - 1]);
    }
    bool next_is_emoji = false;
    if (i + 1 < input.size()) {
        next_is_emoji = emoji.is_emoji(input[i + 1]);
    }
    return prev_is_emoji || next_is_emoji;
}

// All positions in input matching predicate p.
template <typename P>
inline std::vector<std::size_t> all_positions(
    P p, std::span<const std::uint32_t> input) {
    std::vector<std::size_t> out;
    for (std::size_t i = 0; i < input.size(); ++i) {
        if (p(input[i])) {
            out.push_back(i);
        }
    }
    return out;
}

// True iff positions forms an arithmetic progression with all consecutive gaps
// within tolerance of the first gap. Empty + singleton lists are vacuously
// arithmetic. positions is assumed ascending (produced by all_positions), so
// gaps are non-negative.
inline bool positions_are_arithmetic_within(
    const std::vector<std::size_t>& positions, std::size_t tolerance) {
    if (positions.size() < 2) {
        return true;
    }
    const std::size_t first_gap = positions[1] - positions[0];
    for (std::size_t i = 0; i + 1 < positions.size(); ++i) {
        const std::size_t gap = positions[i + 1] - positions[i];
        if (!(gap <= first_gap + tolerance && first_gap <= gap + tolerance)) {
            return false;
        }
    }
    return true;
}

// First start-position at which pattern appears as a contiguous sub-slice of
// input, or nullopt if absent.
inline std::optional<std::size_t> contains_sublist(
    const std::vector<std::uint32_t>& pattern,
    std::span<const std::uint32_t> input) {
    if (pattern.empty() || pattern.size() > input.size()) {
        return std::nullopt;
    }
    const std::size_t max_start = input.size() - pattern.size();
    for (std::size_t start = 0; start <= max_start; ++start) {
        bool equal = true;
        for (std::size_t k = 0; k < pattern.size(); ++k) {
            if (input[start + k] != pattern[k]) {
                equal = false;
                break;
            }
        }
        if (equal) {
            return start;
        }
    }
    return std::nullopt;
}

// The "AI-favored" lexical-pattern catalog (each word as its codepoint
// sequence), transcribed verbatim from the pinned aiFavoredVocabulary literal
// in the Lean spec (parsed from Ucd/Security/AiFavoredVocabulary.txt and
// drift-gated there against a fresh parse).
inline const std::vector<std::vector<std::uint32_t>>& ai_favored_vocabulary() {
    static const std::vector<std::vector<std::uint32_t>> vocab = {
        {100, 101, 108, 118, 101},
        {100, 101, 108, 118, 105, 110, 103},
        {116, 97, 112, 101, 115, 116, 114, 121},
        {105, 110, 116, 114, 105, 99, 97, 116, 101},
        {110, 117, 97, 110, 99, 101, 100},
        {109, 111, 114, 101, 111, 118, 101, 114},
        {102, 117, 114, 116, 104, 101, 114, 109, 111, 114, 101},
        {114, 101, 97, 108, 109},
        {101, 108, 117, 99, 105, 100, 97, 116, 101},
        {115, 104, 111, 119, 99, 97, 115, 105, 110, 103},
        {117, 110, 100, 101, 114, 115, 99, 111, 114, 101, 115},
        {117, 110, 100, 101, 114, 115, 99, 111, 114, 101, 100},
        {112, 105, 118, 111, 116, 97, 108},
        {98, 111, 108, 115, 116, 101, 114},
        {109, 117, 108, 116, 105, 102, 97, 99, 101, 116, 101, 100},
        {116, 101, 115, 116, 97, 109, 101, 110, 116},
        {102, 111, 115, 116, 101, 114},
        {104, 111, 108, 105, 115, 116, 105, 99},
        {112, 97, 114, 97, 100, 105, 103, 109},
        {116, 114, 97, 110, 115, 102, 111, 114, 109, 97, 116, 105, 118, 101},
        {115, 112, 101, 97, 114, 104, 101, 97, 100},
        {109, 101, 116, 105, 99, 117, 108, 111, 117, 115},
        {109, 101, 116, 105, 99, 117, 108, 111, 117, 115, 108, 121},
        {101, 109, 112, 111, 119, 101, 114},
        {101, 109, 112, 111, 119, 101, 114, 105, 110, 103},
        {112, 114, 111, 102, 111, 117, 110, 100},
        {112, 114, 111, 102, 111, 117, 110, 100, 108, 121},
        {99, 111, 109, 112, 101, 108, 108, 105, 110, 103},
        {99, 111, 109, 112, 114, 101, 104, 101, 110, 115, 105, 118, 101},
        {99, 114, 117, 99, 105, 97, 108},
        {100, 97, 117, 110, 116, 105, 110, 103},
        {114, 111, 98, 117, 115, 116},
        {115, 116, 114, 101, 97, 109, 108, 105, 110, 101},
        {101, 110, 114, 105, 99, 104},
        {101, 120, 101, 109, 112, 108, 105, 102, 121},
        {99, 97, 112, 116, 105, 118, 97, 116, 105, 110, 103},
        {100, 105, 115, 99, 101, 114, 110, 105, 110, 103},
        {109, 101, 115, 109, 101, 114, 105, 122, 101},
        {105, 110, 116, 114, 105, 99, 97, 116, 101, 108, 121},
        {105, 109, 98, 117, 101},
        {112, 108, 97, 121, 115, 32, 97, 32, 99, 114, 117, 99, 105, 97, 108,
         32, 114, 111, 108, 101},
        {112, 108, 97, 121, 115, 32, 97, 32, 112, 105, 118, 111, 116, 97, 108,
         32, 114, 111, 108, 101},
        {105, 116, 32, 105, 115, 32, 105, 109, 112, 111, 114, 116, 97, 110,
         116, 32, 116, 111, 32, 110, 111, 116, 101},
        {105, 116, 32, 105, 115, 32, 119, 111, 114, 116, 104, 32, 110, 111,
         116, 105, 110, 103},
        {105, 110, 32, 99, 111, 110, 99, 108, 117, 115, 105, 111, 110},
        {105, 110, 32, 101, 115, 115, 101, 110, 99, 101},
        {100, 101, 108, 118, 101, 32, 105, 110, 116, 111},
        {100, 101, 108, 118, 105, 110, 103, 32, 105, 110, 116, 111},
        {116, 97, 112, 101, 115, 116, 114, 121, 32, 111, 102},
        {114, 101, 97, 108, 109, 32, 111, 102},
    };
    return vocab;
}

}  // namespace detail

// ─────────────────────────────────────────────────────────────────────
// §4 Top-level detection
// ─────────────────────────────────────────────────────────────────────

// The detection function. Runs every probe in the fixed priority order
// (most-specific first); the first hit wins. See the module header for the
// probe inventory and the ordering rationale. The Default_Ignorable predicate
// comes from the port's ucd:: table t; the emoji-adjacency exclusion from the
// bundled EmojiTable.
inline Verdict detect_with_context(const ucd::Tables& t,
                                   const EmojiTable& emoji, const Context& ctx,
                                   std::span<const std::uint32_t> input) {
    auto nnbsp_positions = detail::all_positions(detail::is_nnbsp, input);
    const std::size_t nnbsp_count = nnbsp_positions.size();

    // Probe 1: adversarial — NNBSP too-regular.
    const bool adversarial_fires =
        nnbsp_count >= 3 &&
        detail::positions_are_arithmetic_within(nnbsp_positions,
                                                ctx.adversarial_tolerance);

    // Probe 2: gpt5ZwspModulo — ZWSP arithmetic progression.
    auto zwsp_positions = detail::all_positions(detail::is_zwsp, input);
    const std::size_t zwsp_count = zwsp_positions.size();
    const bool zwsp_modulo_fires =
        zwsp_count >= 3 &&
        detail::positions_are_arithmetic_within(zwsp_positions,
                                                ctx.zwsp_modulo_tolerance);

    auto vs_all_pos =
        detail::all_positions(detail::is_variation_selector, input);
    std::vector<std::size_t> vs_non_emoji_pos;
    for (std::size_t i : vs_all_pos) {
        if (!detail::is_adjacent_to_emoji(emoji, input, i)) {
            vs_non_emoji_pos.push_back(i);
        }
    }
    const std::size_t vs_non_emoji_count = vs_non_emoji_pos.size();

    auto zwj_all_pos = detail::all_positions(detail::is_zwj, input);
    std::vector<std::size_t> zwj_non_emoji_pos;
    for (std::size_t i : zwj_all_pos) {
        if (!detail::is_adjacent_to_emoji(emoji, input, i)) {
            zwj_non_emoji_pos.push_back(i);
        }
    }
    const std::size_t zwj_non_emoji_count = zwj_non_emoji_pos.size();

    // Probe 7: smartQuoteAlternation — curly quotes only.
    auto curly_positions = detail::all_positions(detail::is_curly_quote, input);
    const std::size_t curly_count = curly_positions.size();
    bool has_straight_quote = false;
    for (std::uint32_t cp : input) {
        if (detail::is_straight_quote(cp)) {
            has_straight_quote = true;
            break;
        }
    }
    const bool smart_quote_fires = curly_count >= 2 && !has_straight_quote;

    // Probe 8: emDashPattern — em-dashes without hyphen-minus.
    auto em_dash_positions = detail::all_positions(detail::is_em_dash, input);
    const std::size_t em_dash_count = em_dash_positions.size();
    bool has_hyphen_minus = false;
    for (std::uint32_t cp : input) {
        if (detail::is_hyphen_minus(cp)) {
            has_hyphen_minus = true;
            break;
        }
    }
    const bool em_dash_fires = em_dash_count >= 2 && !has_hyphen_minus;

    // Probe 9: statisticalTokenChoice — scan the pinned vocabulary. Each word
    // is compared as a contiguous sub-slice of the input.
    std::optional<std::size_t> vocab_hit;
    for (const auto& pattern : detail::ai_favored_vocabulary()) {
        if (auto pos = detail::contains_sublist(pattern, input)) {
            vocab_hit = pos;
            break;
        }
    }

    // Residual default-ignorables (excluding VS and ZWJ, handled above).
    auto is_residual_di = [&](std::uint32_t cp) {
        return ucd::is_default_ignorable(t, cp) &&
               !detail::is_variation_selector(cp) && !detail::is_zwj(cp);
    };
    auto di_positions = detail::all_positions(is_residual_di, input);
    const std::size_t di_count = di_positions.size();

    // Probe 3: unknown — invisible markers from >= 2 distinct categories.
    const std::size_t category_count =
        (nnbsp_count > 0 ? 1u : 0u) + (vs_non_emoji_count > 0 ? 1u : 0u) +
        (zwj_non_emoji_count > 0 ? 1u : 0u) + (di_count > 0 ? 1u : 0u);
    const bool unknown_fires = category_count >= 2;
    const std::size_t total_invisible_count =
        nnbsp_count + vs_non_emoji_count + zwj_non_emoji_count + di_count;

    Classification classification;
    std::size_t fired_count = 0;

    if (adversarial_fires) {
        const std::size_t first_pos =
            nnbsp_positions.empty() ? 0 : nnbsp_positions.front();
        classification.sub =
            SubThreat{Adversarial{std::string("nnbspBoundary"), first_pos}};
        classification.positions = nnbsp_positions;
        fired_count = nnbsp_count;
    } else if (zwsp_modulo_fires) {
        const std::size_t first_pos =
            zwsp_positions.empty() ? 0 : zwsp_positions.front();
        classification.sub = SubThreat{Gpt5ZwspModulo{first_pos}};
        classification.positions = zwsp_positions;
        fired_count = zwsp_count;
    } else if (unknown_fires) {
        std::vector<std::size_t> all_invisible_pos;
        for (std::size_t idx = 0; idx < input.size(); ++idx) {
            const std::uint32_t cp = input[idx];
            if (detail::is_nnbsp(cp) || detail::is_variation_selector(cp) ||
                detail::is_zwj(cp) || ucd::is_default_ignorable(t, cp)) {
                all_invisible_pos.push_back(idx);
            }
        }
        classification.sub = SubThreat{Unknown{total_invisible_count}};
        classification.positions = std::move(all_invisible_pos);
        fired_count = total_invisible_count;
    } else if (nnbsp_count > 0) {
        classification.sub = SubThreat{NnbspBoundary{nnbsp_count}};
        classification.positions = nnbsp_positions;
        fired_count = nnbsp_count;
    } else if (vs_non_emoji_count > 0) {
        classification.sub =
            SubThreat{VariationSelectorCarrier{vs_non_emoji_count}};
        classification.positions = vs_non_emoji_pos;
        fired_count = vs_non_emoji_count;
    } else if (zwj_non_emoji_count > 0) {
        classification.sub = SubThreat{ZwjNonEmoji{zwj_non_emoji_count}};
        classification.positions = zwj_non_emoji_pos;
        fired_count = zwj_non_emoji_count;
    } else if (smart_quote_fires) {
        const std::size_t first_pos =
            curly_positions.empty() ? 0 : curly_positions.front();
        classification.sub = SubThreat{SmartQuoteAlternation{first_pos}};
        classification.positions = curly_positions;
        fired_count = curly_count;
    } else if (em_dash_fires) {
        const std::size_t first_pos =
            em_dash_positions.empty() ? 0 : em_dash_positions.front();
        classification.sub = SubThreat{EmDashPattern{first_pos}};
        classification.positions = em_dash_positions;
        fired_count = em_dash_count;
    } else if (vocab_hit.has_value()) {
        classification.sub = SubThreat{StatisticalTokenChoice{*vocab_hit}};
        classification.positions = {*vocab_hit};
        fired_count = 1;
    } else if (di_count > 0) {
        classification.sub = SubThreat{DefaultIgnorableCarrier{di_count}};
        classification.positions = di_positions;
        fired_count = di_count;
    } else {
        classification.sub = std::nullopt;
        classification.positions = {};
        fired_count = 0;
    }

    Verdict verdict;
    verdict.input = std::vector<std::uint32_t>(input.begin(), input.end());
    verdict.classify = std::move(classification);
    verdict.marker_count = fired_count;
    return verdict;
}

// Convenience wrapper over detect_with_context with the empty context —
// exact-arithmetic settings (zwsp_modulo_tolerance = 0,
// adversarial_tolerance = 0).
inline Verdict detect(const ucd::Tables& t, const EmojiTable& emoji,
                      std::span<const std::uint32_t> input) {
    return detect_with_context(t, emoji, Context{}, input);
}

}  // namespace unicode_cpp::security::crypto::ai_watermark_detectability
