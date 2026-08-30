#pragma once

// IdentifierFormDrift — cross-layer identifier × form drift (boundary-layer
// detector, reason layer X).
//
// Byte-faithful transliteration of the verified Rust reference implementation
// (itself a port of the Lean specification).
//
// Threat model. Tier A₂ two-system bypass. An identity validator and a form
// normalizer disagree about a codepoint: stage A runs the UTS #39
// Identifier_Status check before normalisation and rejects, say, U+1D44E
// MATHEMATICAL ITALIC SMALL A (Restricted); stage B normalises first and then
// runs the same check, seeing U+0061 'a' (Allowed) and accepting. The attacker
// controls which stage processes the input and exploits the disagreement. The
// same shape covers fullwidth (U+FF21), circled (U+24B6), ligature (U+FB01),
// and Roman-numeral (U+2163) compatibility forms.
//
// The detector fires on the form transition itself — it reports every input
// position whose Identifier_Status differs from the Identifier_Status of that
// codepoint's NFKD head. This is orthogonal to the single-form
// identity-spoofing detectors (which examine the input under one form) and
// stronger than a form-of-input fold (it asks whether the identifier verdict
// changes, not whether any output bit changes).
//
// Note on Hangul: precomposed syllables are Allowed while their NFKD-head jamos
// are Restricted, so pure Korean text fires; callers intending to accept Korean
// identifiers should apply NFC before evaluating admissibility.
//
// It reuses the port's own UTS #39 Identifier_Status predicate
// (ucd::is_id_allowed) and NFKD pipeline (ucd::to_nfkd), never a host
// normalization or identifier library.
//
// Sub-threat (direction-agnostic):
//   IdentifierStatusShift — the first input position whose Identifier_Status
//   differs from its NFKD-head's. The verdict carries the total shift count.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

#include "unicode_cpp/security/identity/ucd.hpp"

namespace unicode_cpp::security::boundary::identifier_form_drift {

namespace ucd = unicode_cpp::security::ucd;

// ─────────────────────────────────────────────────────────────────────
// §1 Sub-threat types
// ─────────────────────────────────────────────────────────────────────

// The sub-threat enumeration for IdentifierFormDrift. There is exactly one
// sub-threat, so the enum carries a single kind; the tag dispatch is still
// explicit (a switch with a throwing unreachable default).
enum class SubThreatKind : std::uint8_t { IdentifierStatusShift };

// A codepoint at base_pos whose Identifier_Status differs from its NFKD-head's
// (codepoint cp).
struct SubThreat {
    // Which sub-threat fired (always IdentifierStatusShift for this detector).
    SubThreatKind kind;
    // Position of the first status-shifting codepoint.
    std::size_t base_pos;
    // The status-shifting codepoint.
    std::uint32_t cp;
};

// Fixture-row tag string for this sub-threat (matches SubThreat.tag). The
// switch enumerates every kind explicitly; the default arm is unreachable and
// throws so a future added kind cannot silently fall through.
inline std::string_view sub_threat_tag(const SubThreat& sub) {
    switch (sub.kind) {
    case SubThreatKind::IdentifierStatusShift:
        return "IdentifierStatusShift";
    }
    throw std::logic_error(
        "IdentifierFormDrift: unreachable SubThreat kind");
}

// Top-level classification (Clear = no status shift present). sub is nullopt
// for a Clear input, else the sub-threat that fired, the implicated positions,
// and the (always-empty for this detector) decoded-byte projection — kept for
// shape parity with the Lean Classification.hazard.
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
    // Total count of positions whose status shifts under NFKD.
    std::size_t shift_count;
};

// ─────────────────────────────────────────────────────────────────────
// §2 Core predicates
// ─────────────────────────────────────────────────────────────────────

// Identifier_Status = Allowed of the first codepoint of cp's NFKD form, or
// cp's own status when NFKD is empty (defensive — to_nfkd is total and returns
// at least [cp]). Reuses the port's own UTS #39 predicate (ucd::is_id_allowed)
// and NFKD pipeline (ucd::to_nfkd).
inline bool nfkd_head_allowed(const ucd::Tables& t, std::uint32_t cp) {
    const std::uint32_t one[] = {cp};
    const std::vector<std::uint32_t> nfkd = ucd::to_nfkd(t, one);
    if (nfkd.empty()) {
        return ucd::is_id_allowed(t, cp);
    }
    return ucd::is_id_allowed(t, nfkd.front());
}

// ─────────────────────────────────────────────────────────────────────
// §3 Sub-detectors
// ─────────────────────────────────────────────────────────────────────

namespace detail {

// First input position whose is_id_allowed differs from its NFKD-head's.
inline std::optional<std::pair<std::size_t, std::uint32_t>> first_status_shift(
    const ucd::Tables& t, std::span<const std::uint32_t> input) {
    for (std::size_t idx = 0; idx < input.size(); ++idx) {
        const std::uint32_t cp = input[idx];
        if (!ucd::is_id_allowed(t, cp) && nfkd_head_allowed(t, cp)) {
            return std::pair<std::size_t, std::uint32_t>{idx, cp};
        }
    }
    return std::nullopt;
}

// Total count of input positions where the per-cp status shifts under NFKD.
inline std::size_t status_shift_count(const ucd::Tables& t,
                                      std::span<const std::uint32_t> input) {
    std::size_t n = 0;
    for (const std::uint32_t cp : input) {
        if (!ucd::is_id_allowed(t, cp) && nfkd_head_allowed(t, cp)) {
            ++n;
        }
    }
    return n;
}

}  // namespace detail

// ─────────────────────────────────────────────────────────────────────
// §4 Top-level detection
// ─────────────────────────────────────────────────────────────────────

// The IdentifierFormDrift detection function. Returns a structured verdict over
// the codepoint sequence input.
inline Verdict detect(const ucd::Tables& t,
                      std::span<const std::uint32_t> input) {
    Classification classification;
    if (auto shift = detail::first_status_shift(t, input)) {
        const auto [pos, cp] = *shift;
        classification.sub =
            SubThreat{SubThreatKind::IdentifierStatusShift, pos, cp};
        classification.positions = {pos};
    } else {
        classification = Classification{std::nullopt, {}, {}};
    }

    Verdict verdict;
    verdict.input = std::vector<std::uint32_t>(input.begin(), input.end());
    verdict.classify = std::move(classification);
    verdict.shift_count = detail::status_shift_count(t, input);
    return verdict;
}

}  // namespace unicode_cpp::security::boundary::identifier_form_drift
