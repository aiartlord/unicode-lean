#pragma once

// SourceDisplayDivergence — the aggregate "what a reviewer sees differs from
// what the machine runs" detector (the display-layer detector, reason layer D).
//
// Byte-faithful transliteration of the verified Rust reference
// source_display_divergence.rs, itself a port of
// Unicode/Security/Display/SourceDisplayDivergence.lean (detect +
// buildClassification).
//
// Threat model. Tier D1. A single covert or identity trick may be
// individually benign-looking, but any hit means the rendered source diverges
// from its logical content; two or more is a strong compound signal. This
// detector runs the five constituent detectors on the same codepoint stream
// and aggregates: zero fire → clear, exactly one → pass-through that family's
// tag, two or more → Compound. Every constituent fires region-agnostically —
// payloads inside string literals or comments count.
//
// It reuses the port's own five constituent detectors — nothing new is
// introduced here (no table, no predicate, no host library): tag_block_payload,
// variation_selector_payload, zero_width_payload, bidi_control_balance, and
// homoglyph_confusable. A constituent "fired" iff its verdict kind is not Clear.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "unicode_cpp/security/calculus.hpp"
#include "unicode_cpp/security/covert/bidi_control_balance.hpp"
#include "unicode_cpp/security/covert/tag_block_payload.hpp"
#include "unicode_cpp/security/covert/variation_selector_payload.hpp"
#include "unicode_cpp/security/covert/zero_width_payload.hpp"
#include "unicode_cpp/security/identity/homoglyph_confusable.hpp"

namespace unicode_cpp::security::display::source_display_divergence {

namespace tag_block_payload = unicode_cpp::security::tag_block_payload;
namespace variation_selector_payload =
    unicode_cpp::security::variation_selector_payload;
namespace zero_width_payload = unicode_cpp::security::zero_width_payload;
namespace bidi_control_balance = unicode_cpp::security::bidi_control_balance;
namespace homoglyph_confusable = unicode_cpp::security::homoglyph_confusable;

// One source-display-divergence scan result. sub is nullopt for a clear input;
// a single constituent hit passes through its family tag; two or more yield
// "Compound". Positions are empty at this layer by the Lean spec (the
// per-family verdicts carry them), so this result carries only the sub-threat.
struct Detection {
    std::optional<std::string> sub;

    // True iff the aggregate verdict is Clear (no constituent fired).
    bool is_clear() const { return !sub.has_value(); }

    // Human-facing tag for a hazard, or nullopt when clear.
    std::optional<std::string_view> tag() const {
        if (!sub.has_value()) {
            return std::nullopt;
        }
        return std::string_view{*sub};
    }
};

// True iff a constituent classification fired (i.e. is not Clear).
constexpr bool fired(ClassificationKind kind) {
    return kind != ClassificationKind::Clear;
}

// Aggregate the five constituent detectors into a single D1 verdict. The
// homoglyph constituent reads the caller-owned identity database (reused, not
// reparsed), matching how the identity- and boundary-family detectors are
// provisioned in this port; the other four constituents are pure over the
// codepoint stream.
inline Detection detect(const homoglyph_confusable::Database& db,
                        std::span<const std::uint32_t> input) {
    // Constituent family tags in canonical aggregation order: tag-block,
    // variation-selector, zero-width, bidi-control, homoglyph. Each detect is
    // called explicitly by name — no catch-all iteration over a family enum.
    std::vector<std::string_view> fires;
    if (fired(tag_block_payload::detect(input).kind)) {
        fires.push_back("TagBlock");
    }
    if (fired(variation_selector_payload::detect(input).kind)) {
        fires.push_back("VariationSelector");
    }
    if (fired(zero_width_payload::detect(input).kind)) {
        fires.push_back("ZeroWidth");
    }
    if (fired(bidi_control_balance::detect(input).kind)) {
        fires.push_back("BidiControl");
    }
    if (fired(homoglyph_confusable::detect(input, db).kind)) {
        fires.push_back("IdentifierHomoglyph");
    }

    Detection out;
    if (fires.empty()) {
        // Zero fired → clear.
        out.sub = std::nullopt;
    } else if (fires.size() == 1) {
        // Exactly one fired → pass through that family's tag.
        out.sub = std::string{fires.front()};
    } else {
        // Two or more fired → compound.
        out.sub = std::string{"Compound"};
    }
    return out;
}

}  // namespace unicode_cpp::security::display::source_display_divergence
