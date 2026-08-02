#pragma once

// hash-input-stability — detection of inputs that are not in canonical
// hash-input form. Per UTS #39 §6.1 + RFC 4880 / 9580 + RFC 8785, an input
// hashed by a signer must be byte-identical to the input hashed by the
// verifier; if the two ends pick different canonical forms (NFC vs NFD, trim
// policy, line-ending convention) the resulting hashes diverge silently while
// both sides believe they signed the same content.
//
// Direct port of Unicode/Security/Crypto/HashInputStability.lean, transliterated
// from the verified Rust reference hash_input_stability.rs. The canonical
// (hash-stable) form is trim_trailing(to_nfc(input)), where trim_trailing strips
// only ASCII whitespace {U+0020, U+0009, U+000A, U+000D}; Unicode whitespace
// (U+00A0, U+2000..U+200A, U+3000) is content and is not stripped. NFC is the
// port's ucd::to_nfc, never a host normalizer.
//
// Six probes run in strict priority order (first hit wins):
//
//   1. encodingMismatch         (context: declared_encoding)
//   2. webhookSignatureDrift    (context: server_bytes)
//   3. auditLogReinterpretation (context: as_written)
//   4. signedMessageRule        (context: rfc_rule)
//   5. trailingWhitespace       (bare input)
//   6. normalizationDrift       (bare input)
//   7. clear
//
// Context-specific probes fire first because they carry more precise threat
// information than the generic probes. detect is the convenience wrapper
// detect_with_context(Context{}, input) that leaves the four context-bearing
// probes silent.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "unicode_cpp/security/identity/ucd.hpp"

namespace unicode_cpp::security::crypto::hash_input_stability {

namespace ucd = unicode_cpp::security::ucd;

// ─────────────────────────────────────────────────────────────────────
// §1 Types
// ─────────────────────────────────────────────────────────────────────

// RFC canonicalisation profiles that the signedMessageRule probe checks
// against. Each variant names a specific canonicalisation rule from a
// published RFC; callers pass one as Context::rfc_rule to opt the probe in.
enum class RfcRule : std::uint8_t {
    // RFC 4880 §5.2.4 — detached signatures normalise trailing whitespace;
    // trailing whitespace in the body causes signature mismatch.
    Pgp4880TrailingWhitespace,
    // RFC 9580 (current OpenPGP) — line-endings normalise to CRLF before
    // signing; a bare LF or bare CR violates the canonicalisation rule.
    Pgp9580LineEnding,
    // RFC 8785 §3.2.5 — JSON Canonicalization Scheme requires strings to be in
    // NFC before serialisation.
    Rfc8785NfcRequirement,
    // RFC 8259 §7 — JSON strings must escape control characters
    // (U+0000..U+001F); unescaped control bytes in a string violate.
    Rfc8259ControlChar,
    // RFC 7515 §2 — JWS Base64URL encoding; any character outside
    // [A-Za-z0-9_-] is a canonicalisation violation.
    Rfc7515JwsBase64Url,
    // RFC 6376 §3.4.4 — DKIM relaxed body canonicalization collapses internal
    // whitespace runs to a single SP; a multi-char internal whitespace run
    // indicates the canonicalisation has not been applied.
    Rfc6376DkimRelaxed,
    // RFC 5751 §3.1.1 — S/MIME canonical text; like PGP 9580, a bare LF or
    // bare CR (not part of a CRLF pair) violates.
    Rfc5751SmimeLineEnding,
};

// Fixture-string identifier for an RfcRule — used by the conformance
// harness's attribution parser to round-trip rule selections.
inline std::string_view tag(RfcRule rule) {
    switch (rule) {
    case RfcRule::Pgp4880TrailingWhitespace:
        return "pgp4880TrailingWhitespace";
    case RfcRule::Pgp9580LineEnding:
        return "pgp9580LineEnding";
    case RfcRule::Rfc8785NfcRequirement:
        return "rfc8785NfcRequirement";
    case RfcRule::Rfc8259ControlChar:
        return "rfc8259ControlChar";
    case RfcRule::Rfc7515JwsBase64Url:
        return "rfc7515JwsBase64Url";
    case RfcRule::Rfc6376DkimRelaxed:
        return "rfc6376DkimRelaxed";
    case RfcRule::Rfc5751SmimeLineEnding:
        return "rfc5751SmimeLineEnding";
    }
    return "pgp4880TrailingWhitespace";
}

// Inverse of tag. Returns nullopt for unrecognised strings.
inline std::optional<RfcRule> from_tag(std::string_view rule_tag) {
    if (rule_tag == "pgp4880TrailingWhitespace") {
        return RfcRule::Pgp4880TrailingWhitespace;
    }
    if (rule_tag == "pgp9580LineEnding") {
        return RfcRule::Pgp9580LineEnding;
    }
    if (rule_tag == "rfc8785NfcRequirement") {
        return RfcRule::Rfc8785NfcRequirement;
    }
    if (rule_tag == "rfc8259ControlChar") {
        return RfcRule::Rfc8259ControlChar;
    }
    if (rule_tag == "rfc7515JwsBase64Url") {
        return RfcRule::Rfc7515JwsBase64Url;
    }
    if (rule_tag == "rfc6376DkimRelaxed") {
        return RfcRule::Rfc6376DkimRelaxed;
    }
    if (rule_tag == "rfc5751SmimeLineEnding") {
        return RfcRule::Rfc5751SmimeLineEnding;
    }
    return std::nullopt;
}

// Sub-threats this detector can fire. Two probes fire from the raw input
// alone (TrailingWhitespace, NormalizationDrift); the other four require the
// corresponding Context field to be set.

// Input diverges from its NFC form; first_divergent_pos is the first diverging
// codepoint index.
struct NormalizationDrift {
    std::size_t first_divergent_pos;
};

// Input has trailing ASCII whitespace; count is how many codepoints.
struct TrailingWhitespace {
    std::size_t count;
};

// Declared encoding disagrees with the codepoint array (or the array holds an
// invalid scalar).
struct EncodingMismatch {
    std::string declared_enc;
    std::string detected_enc;
};

// Input violates the named RFC's canonicalisation rule at first_pos.
struct SignedMessageRule {
    std::string rfc_rule;
    std::size_t first_pos;
};

// The re-read input differs from Context::as_written at first_divergent_pos.
struct AuditLogReinterpretation {
    std::size_t first_divergent_pos;
};

// The client input differs from Context::server_bytes at first_pos.
struct WebhookSignatureDrift {
    std::size_t first_pos;
};

using SubThreat =
    std::variant<NormalizationDrift, TrailingWhitespace, EncodingMismatch,
                 SignedMessageRule, AuditLogReinterpretation,
                 WebhookSignatureDrift>;

// Human-facing classification tag for this sub-threat.
inline std::string_view sub_threat_tag(const SubThreat& sub) {
    struct Visitor {
        std::string_view operator()(const NormalizationDrift&) const {
            return "NormalizationDrift";
        }
        std::string_view operator()(const TrailingWhitespace&) const {
            return "TrailingWhitespace";
        }
        std::string_view operator()(const EncodingMismatch&) const {
            return "EncodingMismatch";
        }
        std::string_view operator()(const SignedMessageRule&) const {
            return "SignedMessageRule";
        }
        std::string_view operator()(const AuditLogReinterpretation&) const {
            return "AuditLogReinterpretation";
        }
        std::string_view operator()(const WebhookSignatureDrift&) const {
            return "WebhookSignatureDrift";
        }
    };
    return std::visit(Visitor{}, sub);
}

// Context passed to detect_with_context to enable the four context-bearing
// probes. Each field is nullopt by default — the empty context is the identity
// case: detect_with_context(Context{}, input) equals detect(input).
struct Context {
    // The encoding label the caller claims their input is in. When set and not
    // (case-insensitively) UTF-8, fires encodingMismatch immediately.
    std::optional<std::string> declared_encoding;
    // The RFC canonicalisation rule the caller is operating under. When set,
    // scans input for violations and fires signedMessageRule.
    std::optional<RfcRule> rfc_rule;
    // The original "as-written" form of an audit-log entry whose re-read is
    // input. When set, fires auditLogReinterpretation on first divergence.
    std::optional<std::vector<std::uint32_t>> as_written;
    // The server-side recomputed bytes for a webhook signature. When set, fires
    // webhookSignatureDrift on first divergence against input.
    std::optional<std::vector<std::uint32_t>> server_bytes;
};

// Top-level classification. sub is nullopt for a clear input (already
// hash-stable under every enabled probe), else the sub-threat that fired and
// its implicated positions.
struct Classification {
    std::optional<SubThreat> sub;
    std::vector<std::size_t> positions;

    // True iff the input is clear.
    bool is_clear() const { return !sub.has_value(); }

    // Human-facing tag for a hazard, or nullopt when clear.
    std::optional<std::string_view> tag() const {
        if (!sub.has_value()) {
            return std::nullopt;
        }
        return sub_threat_tag(*sub);
    }
};

// Verdict — the structured output of detect. stable_size is the codepoint count
// of the hash-stable canonical form; downstream callers compare it against
// input.len() to size the byte-drift their hash sees.
struct Verdict {
    std::vector<std::uint32_t> input;
    Classification classify;
    std::vector<std::uint32_t> stable_form;
    std::size_t stable_size;
};

namespace detail {

// ─────────────────────────────────────────────────────────────────────
// §3 Canonicalisation pipeline
// ─────────────────────────────────────────────────────────────────────

// True iff cp is an ASCII whitespace codepoint that line-oriented hash-input
// protocols treat as framing rather than content: U+0020 SPACE, U+0009 TAB,
// U+000A LF, U+000D CR.
inline bool is_ascii_whitespace(std::uint32_t cp) {
    return cp == 0x0020 || cp == 0x0009 || cp == 0x000A || cp == 0x000D;
}

// Count of trailing ASCII whitespace codepoints in input.
inline std::size_t count_trailing_whitespace(std::span<const std::uint32_t> input) {
    std::size_t count = 0;
    for (std::size_t i = input.size(); i-- > 0;) {
        if (is_ascii_whitespace(input[i])) {
            ++count;
        } else {
            break;
        }
    }
    return count;
}

// Strip trailing ASCII whitespace.
inline std::vector<std::uint32_t> trim_trailing(std::span<const std::uint32_t> input) {
    const std::size_t keep = input.size() - count_trailing_whitespace(input);
    return std::vector<std::uint32_t>(input.begin(), input.begin() + static_cast<std::ptrdiff_t>(keep));
}

// ─────────────────────────────────────────────────────────────────────
// §5 Priority position-finder
// ─────────────────────────────────────────────────────────────────────

// First position at which a and b diverge, or the length of the shared prefix
// when one strictly extends the other. nullopt when identical.
inline std::optional<std::size_t> first_array_divergence(
    std::span<const std::uint32_t> a, std::span<const std::uint32_t> b) {
    const std::size_t common = std::min(a.size(), b.size());
    for (std::size_t i = 0; i < common; ++i) {
        if (a[i] != b[i]) {
            return i;
        }
    }
    if (a.size() != b.size()) {
        return common;
    }
    return std::nullopt;
}

// ─────────────────────────────────────────────────────────────────────
// §6 Context-bearing probes
// ─────────────────────────────────────────────────────────────────────

// Lower-case an ASCII letter (U+0041..U+005A → U+0061..U+007A).
inline std::uint32_t ascii_lower(std::uint32_t cp) {
    if (cp >= 0x41 && cp <= 0x5A) {
        return cp + 0x20;
    }
    return cp;
}

// True iff label (after ASCII case-fold) names UTF-8: accepts "utf-8", "UTF-8",
// "UTF8", "utf8". Non-ASCII bytes pass through unchanged, so they can never
// match either target — identical to the Rust scalar-wise fold.
inline bool is_utf8_label(std::string_view label) {
    std::string normalised;
    normalised.reserve(label.size());
    for (char ch : label) {
        const auto byte = static_cast<std::uint32_t>(static_cast<unsigned char>(ch));
        normalised.push_back(static_cast<char>(ascii_lower(byte)));
    }
    return normalised == "utf-8" || normalised == "utf8";
}

// True iff cp is a valid Unicode scalar value: in [0, 0x10FFFF] and not a
// surrogate [0xD800, 0xDFFF].
inline bool is_valid_scalar(std::uint32_t cp) {
    return cp <= 0x10FFFF && !(cp >= 0xD800 && cp <= 0xDFFF);
}

// First position in input holding a codepoint that is not a valid Unicode
// scalar, or nullopt if every codepoint is valid.
inline std::optional<std::size_t> first_invalid_scalar(std::span<const std::uint32_t> input) {
    for (std::size_t i = 0; i < input.size(); ++i) {
        if (!is_valid_scalar(input[i])) {
            return i;
        }
    }
    return std::nullopt;
}

// Probe: encodingMismatch. Validity is dispatched first — an invalid scalar
// fires with detected_enc = "invalid" regardless of the declared label;
// otherwise a non-UTF-8 label fires with detected_enc = "utf-8" at position 0.
struct EncodingHit {
    std::string declared;
    std::string detected;
    std::size_t first_pos;
};

inline std::optional<EncodingHit> encoding_mismatch_probe(
    std::string_view declared, std::span<const std::uint32_t> input) {
    if (auto pos = first_invalid_scalar(input)) {
        return EncodingHit{std::string(declared), "invalid", *pos};
    }
    if (is_utf8_label(declared)) {
        return std::nullopt;
    }
    return EncodingHit{std::string(declared), "utf-8", 0};
}

// Probe: signedMessageRule for pgp4880TrailingWhitespace. Same condition as
// trailingWhitespace; returns the first position of the trailing run.
inline std::optional<std::size_t> pgp4880_violation(std::span<const std::uint32_t> input) {
    const std::size_t trailing = count_trailing_whitespace(input);
    if (trailing > 0) {
        return input.size() - trailing;
    }
    return std::nullopt;
}

// Probe: signedMessageRule for pgp9580LineEnding. First bare LF (U+000A not
// preceded by CR) or bare CR (U+000D not followed by LF).
inline std::optional<std::size_t> pgp9580_violation(std::span<const std::uint32_t> input) {
    for (std::size_t i = 0; i < input.size(); ++i) {
        const std::uint32_t cp = input[i];
        if (cp == 0x000A) {
            // LF: violating iff not preceded by CR.
            const bool preceded_by_cr = i > 0 && input[i - 1] == 0x000D;
            if (!preceded_by_cr) {
                return i;
            }
        } else if (cp == 0x000D) {
            // CR: violating iff not followed by LF.
            const bool followed_by_lf = i + 1 < input.size() && input[i + 1] == 0x000A;
            if (!followed_by_lf) {
                return i;
            }
        }
    }
    return std::nullopt;
}

// Probe: signedMessageRule for rfc8785NfcRequirement. Same condition as
// normalizationDrift; returns the first NFC divergence position.
inline std::optional<std::size_t> rfc8785_violation(
    const ucd::Tables& t, std::span<const std::uint32_t> input) {
    const auto nfc = ucd::to_nfc(t, input);
    return first_array_divergence(input, std::span<const std::uint32_t>(nfc));
}

// Probe: signedMessageRule for rfc8259ControlChar. First C0 control
// (U+0000..U+001F) — the JSON-permitted whitespace still requires escaping, so
// it also counts.
inline std::optional<std::size_t> rfc8259_violation(std::span<const std::uint32_t> input) {
    for (std::size_t i = 0; i < input.size(); ++i) {
        if (input[i] <= 0x1F) {
            return i;
        }
    }
    return std::nullopt;
}

// True iff cp is in the JWS Base64URL alphabet [A-Za-z0-9_-].
inline bool is_base64_url(std::uint32_t cp) {
    return (cp >= 0x41 && cp <= 0x5A)      // A-Z
           || (cp >= 0x61 && cp <= 0x7A)   // a-z
           || (cp >= 0x30 && cp <= 0x39)   // 0-9
           || cp == 0x2D                   // '-'
           || cp == 0x5F;                  // LOW LINE
}

// Probe: signedMessageRule for rfc7515JwsBase64Url. First codepoint outside
// [A-Za-z0-9_-].
inline std::optional<std::size_t> rfc7515_violation(std::span<const std::uint32_t> input) {
    for (std::size_t i = 0; i < input.size(); ++i) {
        if (!is_base64_url(input[i])) {
            return i;
        }
    }
    return std::nullopt;
}

// True iff cp is DKIM whitespace: U+0020 SPACE or U+0009 HTAB.
inline bool is_dkim_whitespace(std::uint32_t cp) {
    return cp == 0x20 || cp == 0x09;
}

// Probe: signedMessageRule for rfc6376DkimRelaxed. Position of the second
// whitespace codepoint in the first internal whitespace run longer than one.
inline std::optional<std::size_t> rfc6376_violation(std::span<const std::uint32_t> input) {
    for (std::size_t i = 0; i < input.size(); ++i) {
        if (is_dkim_whitespace(input[i]) && i > 0 && is_dkim_whitespace(input[i - 1])) {
            return i;
        }
    }
    return std::nullopt;
}

// Probe: signedMessageRule for rfc5751SmimeLineEnding. Reuses the PGP 9580
// bare-line-ending rule.
inline std::optional<std::size_t> rfc5751_violation(std::span<const std::uint32_t> input) {
    return pgp9580_violation(input);
}

// Dispatch the RFC-rule probe. First violation position, or nullopt if clean.
inline std::optional<std::size_t> rfc_rule_violation(
    const ucd::Tables& t, RfcRule rule, std::span<const std::uint32_t> input) {
    switch (rule) {
    case RfcRule::Pgp4880TrailingWhitespace:
        return pgp4880_violation(input);
    case RfcRule::Pgp9580LineEnding:
        return pgp9580_violation(input);
    case RfcRule::Rfc8785NfcRequirement:
        return rfc8785_violation(t, input);
    case RfcRule::Rfc8259ControlChar:
        return rfc8259_violation(input);
    case RfcRule::Rfc7515JwsBase64Url:
        return rfc7515_violation(input);
    case RfcRule::Rfc6376DkimRelaxed:
        return rfc6376_violation(input);
    case RfcRule::Rfc5751SmimeLineEnding:
        return rfc5751_violation(input);
    }
    return std::nullopt;
}

struct RfcHit {
    RfcRule rule;
    std::size_t pos;
};

// The priority resolver: first hit wins, in the spec's fixed order.
inline Classification classify(std::optional<EncodingHit> encoding_hit,
                               std::optional<std::size_t> webhook_hit,
                               std::optional<std::size_t> audit_hit,
                               std::optional<RfcHit> rfc_hit,
                               std::size_t trailing_count, std::size_t input_len,
                               std::optional<std::size_t> non_nfc_pos) {
    if (encoding_hit.has_value()) {
        return Classification{
            SubThreat{EncodingMismatch{std::move(encoding_hit->declared),
                                       std::move(encoding_hit->detected)}},
            {encoding_hit->first_pos}};
    }
    if (webhook_hit.has_value()) {
        return Classification{SubThreat{WebhookSignatureDrift{*webhook_hit}},
                              {*webhook_hit}};
    }
    if (audit_hit.has_value()) {
        return Classification{SubThreat{AuditLogReinterpretation{*audit_hit}},
                              {*audit_hit}};
    }
    if (rfc_hit.has_value()) {
        return Classification{
            SubThreat{SignedMessageRule{std::string(tag(rfc_hit->rule)),
                                        rfc_hit->pos}},
            {rfc_hit->pos}};
    }
    if (trailing_count > 0) {
        const std::size_t p = input_len - trailing_count;
        return Classification{SubThreat{TrailingWhitespace{trailing_count}}, {p}};
    }
    if (non_nfc_pos.has_value()) {
        return Classification{SubThreat{NormalizationDrift{*non_nfc_pos}},
                              {*non_nfc_pos}};
    }
    return Classification{std::nullopt, {}};
}

}  // namespace detail

// ─────────────────────────────────────────────────────────────────────
// §4 Canonicalisation entry point
// ─────────────────────────────────────────────────────────────────────

// The hash-stable form of an input: NFC then trim, in spec order.
inline std::vector<std::uint32_t> hash_stable(
    const ucd::Tables& t, std::span<const std::uint32_t> input) {
    const auto nfc = ucd::to_nfc(t, input);
    return detail::trim_trailing(std::span<const std::uint32_t>(nfc));
}

// ─────────────────────────────────────────────────────────────────────
// §7 Top-level detection
// ─────────────────────────────────────────────────────────────────────

// The full detection function. Runs all six probes in priority order, with the
// context-bearing probes ahead of the generic ones.
inline Verdict detect_with_context(
    const ucd::Tables& t, const Context& ctx, std::span<const std::uint32_t> input) {
    auto stable = hash_stable(t, input);

    // Probe 1: encodingMismatch.
    std::optional<detail::EncodingHit> encoding_hit;
    if (ctx.declared_encoding.has_value()) {
        encoding_hit = detail::encoding_mismatch_probe(*ctx.declared_encoding, input);
    }

    // Probe 2: webhookSignatureDrift.
    std::optional<std::size_t> webhook_hit;
    if (ctx.server_bytes.has_value()) {
        webhook_hit = detail::first_array_divergence(
            input, std::span<const std::uint32_t>(*ctx.server_bytes));
    }

    // Probe 3: auditLogReinterpretation.
    std::optional<std::size_t> audit_hit;
    if (ctx.as_written.has_value()) {
        audit_hit = detail::first_array_divergence(
            std::span<const std::uint32_t>(*ctx.as_written), input);
    }

    // Probe 4: signedMessageRule.
    std::optional<detail::RfcHit> rfc_hit;
    if (ctx.rfc_rule.has_value()) {
        if (auto pos = detail::rfc_rule_violation(t, *ctx.rfc_rule, input)) {
            rfc_hit = detail::RfcHit{*ctx.rfc_rule, *pos};
        }
    }

    // Probe 5: trailingWhitespace.
    const std::size_t trailing_count = detail::count_trailing_whitespace(input);

    // Probe 6: normalizationDrift.
    const auto nfc = ucd::to_nfc(t, input);
    const std::optional<std::size_t> non_nfc_pos =
        detail::first_array_divergence(input, std::span<const std::uint32_t>(nfc));

    auto classification = detail::classify(std::move(encoding_hit), webhook_hit,
                                           audit_hit, rfc_hit, trailing_count,
                                           input.size(), non_nfc_pos);

    Verdict verdict;
    verdict.stable_size = stable.size();
    verdict.stable_form = std::move(stable);
    verdict.classify = std::move(classification);
    verdict.input = std::vector<std::uint32_t>(input.begin(), input.end());
    return verdict;
}

// Convenience wrapper over detect_with_context with the empty context —
// equivalent to running only the two bare-input probes (trailingWhitespace,
// normalizationDrift).
inline Verdict detect(const ucd::Tables& t, std::span<const std::uint32_t> input) {
    return detect_with_context(t, Context{}, input);
}

}  // namespace unicode_cpp::security::crypto::hash_input_stability
