#pragma once

// RendererDivergence — detection of codepoint/sequence shapes known to render
// differently across font + terminal + browser stacks (the display-layer
// detector, reason layer D).
//
// Byte-faithful transliteration of the verified Rust reference
// renderer_divergence.rs, itself a port of
// Unicode/Security/Display/RendererDivergence.lean.
//
// Threat model. An adversary crafts content that renders one way in the
// auditor's renderer (a benign glyph or an empty span) and a different way in
// the consumer's renderer (a misleading glyph, a wider glyph, or a different
// sequence). This is the "fingerprint stability" family — clear inputs render
// the same across the renderer cohort the Standard documents as stable.
//
// What the detector draws. A heuristic three-value split, surfaced through the
// universal clear/hazard carrier: an input is clear when none of the documented
// variance triggers fire, and otherwise is classified by the first trigger in
// priority order — combining-mark stack overflow, variation-selector presence,
// an unregistered ZWJ shape, fullwidth/halfwidth display, or mixed direction.
// It reuses the port's own tables — the variation-selector set
// (variation_selector_payload::is_variation_selector), the grapheme Extend
// class (segmentation::is_grapheme_extend), the RGI ZWJ registry
// (emoji_zwj_integrity::RgiTable::is_registered_zwj_sequence), and the strong
// Bidi_Class distinction (ucd::is_strong_ltr / is_strong_rtl) — never a host
// rendering or shaping library.
//
// Sub-threats (priority order):
//   1. CombiningStackOverflow   Zalgo-like combining-mark stack >= 4 on a base.
//   2. VariationSelectorVariance any variation selector present.
//   3. UnregisteredZwjVariance  ZWJ-containing input not in the RGI ZWJ set.
//   4. FullwidthVariance        a fullwidth/halfwidth codepoint present.
//   5. MixedDirectionVariance   both strong-LTR and strong-RTL codepoints.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include "unicode_cpp/security/covert/variation_selector_payload.hpp"
#include "unicode_cpp/security/identity/emoji_zwj_integrity.hpp"
#include "unicode_cpp/security/identity/ucd.hpp"
#include "unicode_cpp/segmentation/grapheme.hpp"

namespace unicode_cpp::security::display::renderer_divergence {

namespace vsp = unicode_cpp::security::variation_selector_payload;
namespace ezwj = unicode_cpp::security::identity::emoji_zwj_integrity;
namespace ucd = unicode_cpp::security::ucd;
namespace segmentation = unicode_cpp::segmentation;

// ─────────────────────────────────────────────────────────────────────
// §1 Constants
// ─────────────────────────────────────────────────────────────────────

// The combining-mark stack depth (on a single base) at or beyond which the
// input is treated as a Zalgo-style rendering-variance hazard.
inline constexpr std::size_t MIN_COMBINING_STACK = 4;

// The ZERO WIDTH JOINER codepoint.
inline constexpr std::uint32_t ZWJ = 0x200D;

// ─────────────────────────────────────────────────────────────────────
// §2 Sub-threat types
// ─────────────────────────────────────────────────────────────────────

// A combining-mark stack of stack_len marks on the base at base_pos.
struct CombiningStackOverflow {
    // Position of the base the stack sits on.
    std::size_t base_pos;
    // The stack depth tested (>= MIN_COMBINING_STACK).
    std::size_t stack_len;
};

// A variation selector at first_vs_pos (codepoint first_vs_cp).
struct VariationSelectorVariance {
    // Position of the first variation selector.
    std::size_t first_vs_pos;
    // Codepoint of the first variation selector.
    std::uint32_t first_vs_cp;
};

// A ZWJ-containing input not present in the registered RGI ZWJ set.
struct UnregisteredZwjVariance {
    // Position of the first ZWJ.
    std::size_t first_zwj_pos;
};

// A fullwidth/halfwidth codepoint at first_fw_pos (codepoint first_fw_cp).
struct FullwidthVariance {
    // Position of the first fullwidth/halfwidth codepoint.
    std::size_t first_fw_pos;
    // The fullwidth/halfwidth codepoint.
    std::uint32_t first_fw_cp;
};

// Both strong-LTR and strong-RTL codepoints in one input.
struct MixedDirectionVariance {
    // Count of strong-LTR codepoints.
    std::size_t ltr_count;
    // Count of strong-RTL codepoints.
    std::size_t rtl_count;
};

using SubThreat =
    std::variant<CombiningStackOverflow, VariationSelectorVariance,
                 UnregisteredZwjVariance, FullwidthVariance,
                 MixedDirectionVariance>;

// Fixture-row tag string for this sub-threat (matches SubThreat.tag). Every
// alternative is handled explicitly by an overload; the variant makes the
// dispatch exhaustive with no catch-all.
inline std::string_view sub_threat_tag(const SubThreat& sub) {
    struct Visitor {
        std::string_view operator()(const CombiningStackOverflow&) const {
            return "CombiningStackOverflow";
        }
        std::string_view operator()(const VariationSelectorVariance&) const {
            return "VariationSelectorVariance";
        }
        std::string_view operator()(const UnregisteredZwjVariance&) const {
            return "UnregisteredZwjVariance";
        }
        std::string_view operator()(const FullwidthVariance&) const {
            return "FullwidthVariance";
        }
        std::string_view operator()(const MixedDirectionVariance&) const {
            return "MixedDirectionVariance";
        }
    };
    return std::visit(Visitor{}, sub);
}

// Top-level classification (stable = Clear). sub is nullopt for a Clear input,
// else the sub-threat that fired, the implicated positions, and the
// (always-empty for this detector) decoded-byte projection — kept for shape
// parity with the Lean Classification.hazard.
struct Classification {
    std::optional<SubThreat> sub;
    std::vector<std::size_t> positions;
    std::vector<std::uint8_t> decoded;

    // True iff the classification is Clear (i.e. stable).
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
    // Count of variation selectors.
    std::size_t vs_count;
    // Count of combining (Extend) marks.
    std::size_t combining_count;
    // Count of fullwidth/halfwidth codepoints.
    std::size_t fullwidth_count;
    // Whether the input contains any ZWJ.
    bool has_zwj;
    // Count of strong-LTR codepoints.
    std::size_t strong_ltr_count;
    // Count of strong-RTL codepoints.
    std::size_t strong_rtl_count;
};

// ─────────────────────────────────────────────────────────────────────
// §3 Core predicates
// ─────────────────────────────────────────────────────────────────────

// True iff cp is a variation selector (reuses the port's own predicate).
inline bool is_variation_selector(std::uint32_t cp) {
    return vsp::is_variation_selector(cp);
}

// True iff cp is the ZWJ codepoint.
inline bool is_zwj(std::uint32_t cp) { return cp == ZWJ; }

// True iff cp is in the Halfwidth/Fullwidth Forms block.
inline bool is_fullwidth_halfwidth(std::uint32_t cp) {
    return cp >= 0xFF01 && cp <= 0xFFEF;
}

// True iff cp has Grapheme_Cluster_Break = Extend (reuses the port's table).
inline bool is_grapheme_extend(std::uint32_t cp) {
    return segmentation::is_grapheme_extend(cp);
}

// ─────────────────────────────────────────────────────────────────────
// §4 Sub-detectors
// ─────────────────────────────────────────────────────────────────────

namespace detail {

inline std::size_t count_vs(std::span<const std::uint32_t> input) {
    std::size_t n = 0;
    for (std::uint32_t cp : input) {
        if (is_variation_selector(cp)) {
            ++n;
        }
    }
    return n;
}

inline std::size_t count_combining(std::span<const std::uint32_t> input) {
    std::size_t n = 0;
    for (std::uint32_t cp : input) {
        if (is_grapheme_extend(cp)) {
            ++n;
        }
    }
    return n;
}

inline std::size_t count_fullwidth(std::span<const std::uint32_t> input) {
    std::size_t n = 0;
    for (std::uint32_t cp : input) {
        if (is_fullwidth_halfwidth(cp)) {
            ++n;
        }
    }
    return n;
}

inline bool input_has_zwj(std::span<const std::uint32_t> input) {
    for (std::uint32_t cp : input) {
        if (is_zwj(cp)) {
            return true;
        }
    }
    return false;
}

inline std::size_t count_strong_ltr(const ucd::Tables& t,
                                    std::span<const std::uint32_t> input) {
    std::size_t n = 0;
    for (std::uint32_t cp : input) {
        if (ucd::is_strong_ltr(t, cp)) {
            ++n;
        }
    }
    return n;
}

inline std::size_t count_strong_rtl(const ucd::Tables& t,
                                    std::span<const std::uint32_t> input) {
    std::size_t n = 0;
    for (std::uint32_t cp : input) {
        if (ucd::is_strong_rtl(t, cp)) {
            ++n;
        }
    }
    return n;
}

// Position and codepoint of the first variation selector.
inline std::optional<std::pair<std::size_t, std::uint32_t>> first_vs_pos(
    std::span<const std::uint32_t> input) {
    for (std::size_t idx = 0; idx < input.size(); ++idx) {
        if (is_variation_selector(input[idx])) {
            return std::pair<std::size_t, std::uint32_t>{idx, input[idx]};
        }
    }
    return std::nullopt;
}

// Position of the first ZWJ.
inline std::optional<std::size_t> first_zwj_pos(
    std::span<const std::uint32_t> input) {
    for (std::size_t idx = 0; idx < input.size(); ++idx) {
        if (is_zwj(input[idx])) {
            return idx;
        }
    }
    return std::nullopt;
}

// Position and codepoint of the first fullwidth/halfwidth codepoint.
inline std::optional<std::pair<std::size_t, std::uint32_t>> first_fullwidth_pos(
    std::span<const std::uint32_t> input) {
    for (std::size_t idx = 0; idx < input.size(); ++idx) {
        if (is_fullwidth_halfwidth(input[idx])) {
            return std::pair<std::size_t, std::uint32_t>{idx, input[idx]};
        }
    }
    return std::nullopt;
}

// The first base position (a non-Extend codepoint) immediately followed by
// exactly min_stack consecutive Extend codepoints. Returns
// (base_pos, min_stack) on hit.
inline std::optional<std::pair<std::size_t, std::size_t>> first_combining_stack(
    std::span<const std::uint32_t> input, std::size_t min_stack) {
    for (std::size_t idx = 0; idx < input.size(); ++idx) {
        if (!is_grapheme_extend(input[idx])) {
            std::size_t following = 0;
            for (std::size_t j = idx + 1;
                 j < input.size() && following < min_stack; ++j) {
                if (!is_grapheme_extend(input[j])) {
                    break;
                }
                ++following;
            }
            if (following == min_stack) {
                return std::pair<std::size_t, std::size_t>{idx, min_stack};
            }
        }
    }
    return std::nullopt;
}

}  // namespace detail

// ─────────────────────────────────────────────────────────────────────
// §5 Top-level detection
// ─────────────────────────────────────────────────────────────────────

// The RendererDivergence detection function. The registered RGI set comes from
// the bundled RgiTable rgi; the strong Bidi_Class distinction reads the bundled
// ucd::Tables t — matching how the identity- and display-family detectors are
// provisioned in this port.
inline Verdict detect(const ezwj::RgiTable& rgi, const ucd::Tables& t,
                      std::span<const std::uint32_t> input) {
    const std::size_t vs_count = detail::count_vs(input);
    const std::size_t combining_count = detail::count_combining(input);
    const std::size_t fullwidth_count = detail::count_fullwidth(input);
    const bool has_zwj = detail::input_has_zwj(input);
    const std::size_t ltr_count = detail::count_strong_ltr(t, input);
    const std::size_t rtl_count = detail::count_strong_rtl(t, input);

    Classification classification;

    // Priority 1: combining-mark stack overflow (Zalgo).
    if (auto stack = detail::first_combining_stack(input, MIN_COMBINING_STACK)) {
        const auto [base_pos, stack_len] = *stack;
        classification.sub =
            SubThreat{CombiningStackOverflow{base_pos, stack_len}};
        classification.positions = {base_pos};
    } else if (auto vs = detail::first_vs_pos(input)) {
        // Priority 2: any variation selector triggers presentation variance.
        const auto [pos, cp] = *vs;
        classification.sub = SubThreat{VariationSelectorVariance{pos, cp}};
        classification.positions = {pos};
    } else if (has_zwj && !rgi.is_registered_zwj_sequence(input)) {
        // Priority 3: ZWJ-containing input not in the registered RGI set.
        if (auto zwj = detail::first_zwj_pos(input)) {
            classification.sub = SubThreat{UnregisteredZwjVariance{*zwj}};
            classification.positions = {*zwj};
        } else {
            classification = Classification{std::nullopt, {}, {}};
        }
    } else if (auto fw = detail::first_fullwidth_pos(input)) {
        // Priority 4: fullwidth/halfwidth.
        const auto [pos, cp] = *fw;
        classification.sub = SubThreat{FullwidthVariance{pos, cp}};
        classification.positions = {pos};
    } else if (ltr_count > 0 && rtl_count > 0) {
        // Priority 5: mixed direction.
        classification.sub =
            SubThreat{MixedDirectionVariance{ltr_count, rtl_count}};
        classification.positions = {};
    } else {
        classification = Classification{std::nullopt, {}, {}};
    }

    Verdict verdict;
    verdict.input = std::vector<std::uint32_t>(input.begin(), input.end());
    verdict.classify = std::move(classification);
    verdict.vs_count = vs_count;
    verdict.combining_count = combining_count;
    verdict.fullwidth_count = fullwidth_count;
    verdict.has_zwj = has_zwj;
    verdict.strong_ltr_count = ltr_count;
    verdict.strong_rtl_count = rtl_count;
    return verdict;
}

}  // namespace unicode_cpp::security::display::renderer_divergence
