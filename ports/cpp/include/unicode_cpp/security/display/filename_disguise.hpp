#pragma once

// FilenameDisguise — detection of filename/extension disguise attacks where the
// visible extension differs from the byte extension (the display-layer detector,
// reason layer D).
//
// Byte-faithful transliteration of the verified Rust reference implementation
// (itself a port of the Lean specification).
//
// Threat model. An adversary delivers a file whose rendered name looks like a
// benign type (document.txt) but whose actual byte extension is executable — the
// canonical attack inserts U+202E RIGHT-TO-LEFT OVERRIDE so document<RLO>txt.exe
// renders as "document exe.txt".
//
// Detection is presentation- and language-agnostic: it surfaces every codepoint
// that could cause display-vs-byte divergence in the filename — any bidi
// format-control anywhere, and any fullwidth/halfwidth or combining (grapheme
// Extend) codepoint in the extension region (after the last dot). Native-RTL
// names with no bidi controls clear. It reuses the port's own predicates (the
// bidi-format-control set, the grapheme Extend class, the fullwidth range),
// never a host filesystem or rendering library.
//
// Sub-threats (priority order):
//   1. RloFlip             any bidi format-control in the input.
//   2. WidthClassExt       a fullwidth/halfwidth codepoint in the extension.
//   3. CombiningInExt      a combining (Extend) codepoint in the extension.
//   4. MultipleExtensions  >= 3 dots (advisory; e.g. legitimate .tar.gz.sig).

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include "unicode_cpp/security/covert/bidi_control_balance.hpp"
#include "unicode_cpp/segmentation/grapheme.hpp"

namespace unicode_cpp::security::display::filename_disguise {

namespace bcb = unicode_cpp::security::bidi_control_balance;
namespace segmentation = unicode_cpp::segmentation;

// ─────────────────────────────────────────────────────────────────────
// §1 Sub-threat types
// ─────────────────────────────────────────────────────────────────────

// A bidi format-control at position (codepoint control_cp).
struct RloFlip {
    // Position of the first bidi format-control.
    std::size_t position;
    // The bidi format-control codepoint.
    std::uint32_t control_cp;
};

// A fullwidth/halfwidth codepoint in the extension, at position.
struct WidthClassExt {
    // Position of the fullwidth/halfwidth codepoint.
    std::size_t position;
    // The fullwidth/halfwidth codepoint.
    std::uint32_t cp;
};

// A combining (grapheme Extend) codepoint in the extension, at position.
struct CombiningInExt {
    // Position of the combining codepoint.
    std::size_t position;
    // The combining codepoint.
    std::uint32_t cp;
};

// Three or more dot separators (advisory).
struct MultipleExtensions {
    // The number of dot separators.
    std::size_t dot_count;
};

// Sub-threat enumeration for FilenameDisguise, in priority order.
using SubThreat =
    std::variant<RloFlip, WidthClassExt, CombiningInExt, MultipleExtensions>;

// Fixture-row tag string for this sub-threat (matches SubThreat.tag). Every
// alternative is handled explicitly by an overload; the variant makes the
// dispatch exhaustive with no catch-all.
inline std::string_view sub_threat_tag(const SubThreat& sub) {
    struct Visitor {
        std::string_view operator()(const RloFlip&) const { return "RloFlip"; }
        std::string_view operator()(const WidthClassExt&) const {
            return "WidthClassExt";
        }
        std::string_view operator()(const CombiningInExt&) const {
            return "CombiningInExt";
        }
        std::string_view operator()(const MultipleExtensions&) const {
            return "MultipleExtensions";
        }
    };
    return std::visit(Visitor{}, sub);
}

// Top-level classification (Clear = no disguise trigger). sub is nullopt for a
// Clear input, else the sub-threat that fired, the implicated positions, and the
// (always-empty for this detector) decoded-byte projection — kept for shape
// parity with the Lean Classification.hazard.
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
    // Positions of every dot separator.
    std::vector<std::size_t> dot_positions;
    // Position of the last dot (the extension separator), if any.
    std::optional<std::size_t> last_dot_pos;
    // Count of bidi format-controls anywhere in the input.
    std::size_t bidi_control_count;
    // Count of fullwidth/halfwidth codepoints in the extension region.
    std::size_t fullwidth_in_ext;
    // Count of combining (Extend) codepoints in the extension region.
    std::size_t combining_in_ext;
};

// ─────────────────────────────────────────────────────────────────────
// §2 Core predicates
// ─────────────────────────────────────────────────────────────────────

// True iff cp is U+002E FULL STOP (the extension separator).
inline bool is_ascii_dot(std::uint32_t cp) { return cp == 0x002E; }

// True iff cp is in the Halfwidth and Fullwidth Forms block.
inline bool is_fullwidth_halfwidth(std::uint32_t cp) {
    return cp >= 0xFF01 && cp <= 0xFFEF;
}

// True iff cp is a bidi format-control (reuses the port's own predicate).
inline bool is_bidi_format_control(std::uint32_t cp) {
    return bcb::is_bidi_format_control(cp);
}

// True iff cp has Grapheme_Cluster_Break = Extend (reuses the port's table).
inline bool is_grapheme_extend(std::uint32_t cp) {
    return segmentation::is_grapheme_extend(cp);
}

// ─────────────────────────────────────────────────────────────────────
// §3 Sub-detectors
// ─────────────────────────────────────────────────────────────────────

namespace detail {

// Positions of every dot in input.
inline std::vector<std::size_t> dot_positions(
    std::span<const std::uint32_t> input) {
    std::vector<std::size_t> out;
    for (std::size_t idx = 0; idx < input.size(); ++idx) {
        if (is_ascii_dot(input[idx])) {
            out.push_back(idx);
        }
    }
    return out;
}

// Position and codepoint of the first bidi format-control.
inline std::optional<std::pair<std::size_t, std::uint32_t>> first_bidi_control(
    std::span<const std::uint32_t> input) {
    for (std::size_t idx = 0; idx < input.size(); ++idx) {
        if (is_bidi_format_control(input[idx])) {
            return std::pair<std::size_t, std::uint32_t>{idx, input[idx]};
        }
    }
    return std::nullopt;
}

// Position and codepoint of the first fullwidth/halfwidth codepoint at or after
// start.
inline std::optional<std::pair<std::size_t, std::uint32_t>> first_fullwidth_from(
    std::span<const std::uint32_t> input, std::size_t start) {
    for (std::size_t idx = 0; idx < input.size(); ++idx) {
        if (idx >= start && is_fullwidth_halfwidth(input[idx])) {
            return std::pair<std::size_t, std::uint32_t>{idx, input[idx]};
        }
    }
    return std::nullopt;
}

// Position and codepoint of the first Extend codepoint at or after start.
inline std::optional<std::pair<std::size_t, std::uint32_t>> first_extend_from(
    std::span<const std::uint32_t> input, std::size_t start) {
    for (std::size_t idx = 0; idx < input.size(); ++idx) {
        if (idx >= start && is_grapheme_extend(input[idx])) {
            return std::pair<std::size_t, std::uint32_t>{idx, input[idx]};
        }
    }
    return std::nullopt;
}

// Count of fullwidth/halfwidth codepoints at or after start.
inline std::size_t count_fullwidth_from(std::span<const std::uint32_t> input,
                                        std::size_t start) {
    std::size_t n = 0;
    for (std::size_t idx = 0; idx < input.size(); ++idx) {
        if (idx >= start && is_fullwidth_halfwidth(input[idx])) {
            ++n;
        }
    }
    return n;
}

// Count of Extend codepoints at or after start.
inline std::size_t count_extend_from(std::span<const std::uint32_t> input,
                                     std::size_t start) {
    std::size_t n = 0;
    for (std::size_t idx = 0; idx < input.size(); ++idx) {
        if (idx >= start && is_grapheme_extend(input[idx])) {
            ++n;
        }
    }
    return n;
}

// Count of bidi format-controls anywhere in the input.
inline std::size_t count_bidi_control(std::span<const std::uint32_t> input) {
    std::size_t n = 0;
    for (std::uint32_t cp : input) {
        if (is_bidi_format_control(cp)) {
            ++n;
        }
    }
    return n;
}

}  // namespace detail

// ─────────────────────────────────────────────────────────────────────
// §4 Top-level detection
// ─────────────────────────────────────────────────────────────────────

// The FilenameDisguise detection function. Returns a structured verdict over
// the codepoint sequence input.
inline Verdict detect(std::span<const std::uint32_t> input) {
    std::vector<std::size_t> dots = detail::dot_positions(input);
    std::optional<std::size_t> last_dot;
    if (!dots.empty()) {
        last_dot = dots.back();
    }
    const std::size_t ext_start =
        last_dot.has_value() ? *last_dot + 1 : input.size();
    const std::size_t bidi_count = detail::count_bidi_control(input);
    const std::size_t fw_in_ext = detail::count_fullwidth_from(input, ext_start);
    const std::size_t ext_in_ext = detail::count_extend_from(input, ext_start);

    Classification classification;

    if (auto bidi = detail::first_bidi_control(input)) {
        // Priority 1: any bidi format-control.
        const auto [pos, ctl_cp] = *bidi;
        classification.sub = SubThreat{RloFlip{pos, ctl_cp}};
        classification.positions = {pos};
    } else if (auto fw = detail::first_fullwidth_from(input, ext_start)) {
        // Priority 2: fullwidth/halfwidth in the extension.
        const auto [pos, cp] = *fw;
        classification.sub = SubThreat{WidthClassExt{pos, cp}};
        classification.positions = {pos};
    } else if (auto ext = detail::first_extend_from(input, ext_start)) {
        // Priority 3: combining mark in the extension.
        const auto [pos, cp] = *ext;
        classification.sub = SubThreat{CombiningInExt{pos, cp}};
        classification.positions = {pos};
    } else if (dots.size() >= 3) {
        // Priority 4: three or more extensions (advisory).
        classification.sub = SubThreat{MultipleExtensions{dots.size()}};
        classification.positions = dots;
    } else {
        // No disguise trigger present — the documented terminal Clear branch.
        classification = Classification{std::nullopt, {}, {}};
    }

    Verdict verdict;
    verdict.input = std::vector<std::uint32_t>(input.begin(), input.end());
    verdict.classify = std::move(classification);
    verdict.dot_positions = std::move(dots);
    verdict.last_dot_pos = last_dot;
    verdict.bidi_control_count = bidi_count;
    verdict.fullwidth_in_ext = fw_in_ext;
    verdict.combining_in_ext = ext_in_ext;
    return verdict;
}

}  // namespace unicode_cpp::security::display::filename_disguise
