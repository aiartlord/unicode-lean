#pragma once

// AdmissibilityFormDrift — cross-layer identifier-admissibility × form drift
// (boundary-layer detector, reason layer X).
//
// Byte-faithful transliteration of the verified Rust reference implementation
// (itself a port of the Lean specification).
//
// Fires on inputs whose UTS #39 whole-string is_allowed_identifier verdict
// differs between the input and its NFKC form. This is the string-level
// complement of IdentifierFormDrift (which scans Identifier_Status against the
// per-codepoint NFKD head): here the whole-string admissibility predicate is
// evaluated twice — once on the input, once on to_nfkc(input). The two are not
// redundant. In particular, a sequence of decomposed Hangul jamos passes the
// per-codepoint scan cleanly (each jamo has identity NFKD and Restricted status
// on both sides) but fires here: the jamo sequence is rejected by
// is_allowed_identifier, while its NFKC composition into a precomposed Hangul
// syllable is accepted.
//
// It reuses the port's own UTS #39 admissibility predicate
// (ucd::is_allowed_identifier = UAX #31 default identifier ∧ every codepoint
// Allowed) and NFKC pipeline (ucd::to_nfkc), never a host normalization or
// identifier library.
//
// Sub-threat (direction-agnostic):
//   AdmissibilityFormDrift — is_allowed_identifier(input) !=
//   is_allowed_identifier(to_nfkc(input)). The pair of booleans is carried so
//   the verdict records which direction the drift goes; no position is reported
//   because the predicate is whole-string.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

#include "unicode_cpp/security/identity/ucd.hpp"

namespace unicode_cpp::security::boundary::admissibility_form_drift {

namespace ucd = unicode_cpp::security::ucd;

// ─────────────────────────────────────────────────────────────────────
// §1 Sub-threat types
// ─────────────────────────────────────────────────────────────────────

// The sub-threat enumeration for AdmissibilityFormDrift. There is exactly one
// sub-threat, so the enum carries a single kind; the tag dispatch is still
// explicit (a switch with a throwing unreachable default).
enum class SubThreatKind : std::uint8_t { AdmissibilityFormDrift };

// The whole-string admissibility verdict differs between the input and its
// NFKC form; the two booleans record the direction of the drift.
struct SubThreat {
    // Which sub-threat fired (always AdmissibilityFormDrift for this detector).
    SubThreatKind kind;
    // is_allowed_identifier(input).
    bool input_admissible;
    // is_allowed_identifier(to_nfkc(input)).
    bool nfkc_admissible;
};

// Fixture-row tag string for this sub-threat (matches SubThreat.tag). The
// switch enumerates every kind explicitly; the default arm is unreachable and
// throws so a future added kind cannot silently fall through.
inline std::string_view sub_threat_tag(const SubThreat& sub) {
    switch (sub.kind) {
    case SubThreatKind::AdmissibilityFormDrift:
        return "AdmissibilityFormDrift";
    }
    throw std::logic_error(
        "AdmissibilityFormDrift: unreachable SubThreat kind");
}

// Top-level classification (Clear = the admissibility verdict agrees across
// forms). sub is nullopt for a Clear input, else the sub-threat that fired, the
// implicated positions (always empty; the predicate is whole-string), and the
// (always-empty here) decoded-byte projection — kept for shape parity with the
// Lean Classification.hazard.
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
    // is_allowed_identifier(input).
    bool input_admissible;
    // is_allowed_identifier(to_nfkc(input)).
    bool nfkc_admissible;
};

// ─────────────────────────────────────────────────────────────────────
// §2 Top-level detection
// ─────────────────────────────────────────────────────────────────────

// The AdmissibilityFormDrift detection function. Returns a structured verdict
// over the codepoint sequence input. Reuses the port's own to_nfkc and
// is_allowed_identifier; the classification is Clear iff the two admissibility
// verdicts agree.
inline Verdict detect(const ucd::Tables& t,
                      std::span<const std::uint32_t> input) {
    const std::vector<std::uint32_t> nfkc = ucd::to_nfkc(t, input);
    const bool in_ok = ucd::is_allowed_identifier(t, input);
    const bool nfkc_ok = ucd::is_allowed_identifier(
        t, std::span<const std::uint32_t>{nfkc.data(), nfkc.size()});

    Classification classification;
    if (in_ok == nfkc_ok) {
        classification = Classification{std::nullopt, {}, {}};
    } else {
        classification.sub = SubThreat{
            SubThreatKind::AdmissibilityFormDrift, in_ok, nfkc_ok};
        classification.positions = {};
        classification.decoded = {};
    }

    Verdict verdict;
    verdict.input = std::vector<std::uint32_t>(input.begin(), input.end());
    verdict.classify = std::move(classification);
    verdict.input_admissible = in_ok;
    verdict.nfkc_admissible = nfkc_ok;
    return verdict;
}

}  // namespace unicode_cpp::security::boundary::admissibility_form_drift
