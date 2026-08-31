// Detection of payloads encoded in zero-width and near-zero-width
// Unicode codepoints.
//
// Threat model.  Tier A1.  Adversary embeds zero-width / no-glyph
// codepoints inside otherwise-normal text to carry a covert binary
// payload, to splice WORD JOINER / byte-order-mark sequences into
// identifiers, or to emit a suspected AI-watermark NNBSP pattern.
//
// Zero-width codepoint inventory:
//
//   U+200B  ZERO WIDTH SPACE                (ZWSP)
//   U+200C  ZERO WIDTH NON-JOINER            (ZWNJ)
//   U+200D  ZERO WIDTH JOINER                (ZWJ)
//   U+200E  LEFT-TO-RIGHT MARK               (LRM)
//   U+200F  RIGHT-TO-LEFT MARK               (RLM)
//   U+2060  WORD JOINER                      (WJ)
//   U+2061..U+2064  invisible math operators
//   U+202F  NARROW NO-BREAK SPACE            (NNBSP)
//   U+FEFF  ZERO WIDTH NO-BREAK SPACE / BOM
//   U+FFF9..U+FFFB  INTERLINEAR ANNOTATION marks
//
// Every zero-width occurrence is recorded, but two of them carry
// meaning a reader depends on and are not treated as suspicious:
// a ZWJ flanked by two codepoints that both participate in some
// registered RGI emoji sequence, and a ZWNJ in an RFC 5892
// Appendix A.1 CONTEXTJ-valid position.  An input whose
// zero-width characters are all sanctioned is clear.

#ifndef UNICODE_CPP_SECURITY_ZERO_WIDTH_PAYLOAD_HPP
#define UNICODE_CPP_SECURITY_ZERO_WIDTH_PAYLOAD_HPP

#include <algorithm>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <variant>
#include <vector>

#include "unicode_cpp/security/calculus.hpp"
#include "unicode_cpp/security/generated/context_tables.hpp"
#include "unicode_cpp/security/identity/emoji_zwj_integrity.hpp"
#include "unicode_cpp/security/identity/ucd.hpp"

namespace unicode_cpp::security::zero_width_payload {

// Sibling-detector codepoint ranges — these ARE
// Default_Ignorable per UAX #44 but are dispatched by their own
// family detector for richer payload-decoding / bidi-stack
// tracking, so we EXCLUDE them from the ZW set to avoid
// double-counting.
//
//   U+FE00..U+FE0F     VariationSelectorPayload
//   U+E0100..U+E01EF   VariationSelectorPayload
//   U+E0000..U+E007F   TagBlockPayload
//   U+202A..U+202E     BidiControlBalance (LRE/RLE/PDF/LRO/RLO)
//   U+2066..U+2069     BidiControlBalance (LRI/RLI/FSI/PDI)
//
// LRM / RLM (U+200E / U+200F) are NOT excluded — they're
// direction markers, not push/pop bidi controls.
constexpr bool is_sibling_handled(std::uint32_t cp) {
    return (cp >= 0xFE00u && cp <= 0xFE0Fu)
        || (cp >= 0xE0100u && cp <= 0xE01EFu)
        || (cp >= 0xE0000u && cp <= 0xE007Fu)
        || (cp >= 0x202Au && cp <= 0x202Eu)
        || (cp >= 0x2066u && cp <= 0x2069u);
}

// UAX #44 Default_Ignorable_Code_Point — hardcoded ranges per
// UCD 17.0.0 DerivedCoreProperties.txt.  Stable across Unicode
// versions; updates require bumping the UCD pin and re-verifying
// this table against the new DerivedCoreProperties.txt.
constexpr bool is_default_ignorable(std::uint32_t cp) {
    return cp == 0x00ADu
        || cp == 0x034Fu
        || cp == 0x061Cu
        || (cp >= 0x115Fu && cp <= 0x1160u)
        || (cp >= 0x17B4u && cp <= 0x17B5u)
        || (cp >= 0x180Bu && cp <= 0x180Fu)
        || (cp >= 0x200Bu && cp <= 0x200Fu)
        || (cp >= 0x202Au && cp <= 0x202Eu)
        || (cp >= 0x2060u && cp <= 0x206Fu)
        || cp == 0x3164u
        || (cp >= 0xFE00u && cp <= 0xFE0Fu)
        || cp == 0xFEFFu
        || cp == 0xFFA0u
        || (cp >= 0xFFF0u && cp <= 0xFFF8u)
        || (cp >= 0x1BCA0u && cp <= 0x1BCA3u)
        || (cp >= 0x1D173u && cp <= 0x1D17Au)
        || (cp >= 0xE0000u && cp <= 0xE0FFFu);
}

constexpr bool is_zero_width(std::uint32_t cp) {
    // Explicit historical set — preserves sub-threat dispatch.
    if (cp == 0x200Bu || cp == 0x200Cu || cp == 0x200Du ||
        cp == 0x200Eu || cp == 0x200Fu) return true;
    if (cp >= 0x2060u && cp <= 0x2064u) return true;
    if (cp == 0x202Fu) return true;
    if (cp == 0xFEFFu) return true;
    if (cp >= 0xFFF9u && cp <= 0xFFFBu) return true;
    // UAX #44 Default_Ignorable — catches every other invisible
    // codepoint, modulo sibling-detector ranges.
    if (is_default_ignorable(cp) && !is_sibling_handled(cp)) return true;
    return false;
}

constexpr bool is_nnbsp(std::uint32_t cp) { return cp == 0x202Fu; }
constexpr bool is_word_joiner(std::uint32_t cp) { return cp == 0x2060u; }
constexpr bool is_annotation(std::uint32_t cp) {
    return cp >= 0xFFF9u && cp <= 0xFFFBu;
}
constexpr bool is_zwj_or_zwsp(std::uint32_t cp) {
    return cp == 0x200Bu || cp == 0x200Du;
}

// Priority-ordered sub-threats:
//   1. AnnotationMisuse    — U+FFF9..U+FFFB present
//   2. WordJoinerInjection — U+2060 present
//   3. AiWatermarkNNBSP    — U+202F count ≥ 2
//   4. BinaryPayload       — ≥ 2 ZWSP/ZWJ occurrences
//   5. BareZeroWidth       — fallback
struct AnnotationMisuse {
    std::size_t count;
};
struct WordJoinerInjection {
    std::size_t count;
};
struct AiWatermarkNNBSP {
    std::size_t count;
};
struct BinaryPayload {
    std::size_t pair_count;
};
struct BareZeroWidth {
    std::uint32_t cp;
};

using SubThreat = std::variant<
    AnnotationMisuse,
    WordJoinerInjection,
    AiWatermarkNNBSP,
    BinaryPayload,
    BareZeroWidth>;

inline std::string sub_threat_tag(const SubThreat& sub) {
    if (std::holds_alternative<AnnotationMisuse>(sub))    return "AnnotationMisuse";
    if (std::holds_alternative<WordJoinerInjection>(sub)) return "WordJoinerInjection";
    if (std::holds_alternative<AiWatermarkNNBSP>(sub))    return "AiWatermarkNNBSP";
    if (std::holds_alternative<BinaryPayload>(sub))       return "BinaryPayload";
    if (std::holds_alternative<BareZeroWidth>(sub))       return "BareZeroWidth";
    return "<unreachable>";
}

struct Verdict {
    ClassificationKind kind;
    std::optional<SubThreat> sub;
    std::vector<std::size_t> zero_width_positions;
};

// Joining_Type from the compiled-in rows, used when the caller supplied no UCD
// directory. The rows are derived from the same DerivedJoiningType.txt the
// Tables path parses, so both readings agree.
inline unicode_cpp::security::ucd::JoiningType embedded_joining_type(
    std::uint32_t cp) {
    const auto& rows = unicode_cpp::security::generated::kJoiningRows;
    std::size_t lo = 0;
    std::size_t hi = rows.size();
    while (lo < hi) {
        std::size_t mid = lo + (hi - lo) / 2;
        if (cp < rows[mid].lo) {
            hi = mid;
        } else if (cp > rows[mid].hi) {
            lo = mid + 1;
        } else {
            return rows[mid].cls;
        }
    }
    return unicode_cpp::security::ucd::JoiningType::NonJoining;
}

// Virama from the compiled-in set: the codepoints with
// Canonical_Combining_Class 9.
inline bool embedded_is_virama(std::uint32_t cp) {
    const auto& set = unicode_cpp::security::generated::kViramaCodepoints;
    return std::binary_search(set.begin(), set.end(), cp);
}

// Registered-RGI membership from the compiled-in alphabet.
inline bool embedded_is_emoji_target(std::uint32_t cp) {
    const auto& set = unicode_cpp::security::generated::kRgiZwjAlphabet;
    return std::binary_search(set.begin(), set.end(), cp);
}

// One Joining_Type reading whether or not a Tables was supplied.
inline unicode_cpp::security::ucd::JoiningType joining_type_of(
    const unicode_cpp::security::ucd::Tables* t, std::uint32_t cp) {
    return t != nullptr ? unicode_cpp::security::ucd::joining_type(*t, cp)
                        : embedded_joining_type(cp);
}

// The Joining_Type of the first non-Transparent codepoint before `i`.
inline std::optional<unicode_cpp::security::ucd::JoiningType> joining_type_before(
    const unicode_cpp::security::ucd::Tables* t,
    std::span<const std::uint32_t> input, std::size_t i) {
    for (std::size_t j = i; j > 0;) {
        --j;
        auto jt = joining_type_of(t, input[j]);
        if (jt != unicode_cpp::security::ucd::JoiningType::Transparent) return jt;
    }
    return std::nullopt;
}

// The Joining_Type of the first non-Transparent codepoint after `i`.
inline std::optional<unicode_cpp::security::ucd::JoiningType> joining_type_after(
    const unicode_cpp::security::ucd::Tables* t,
    std::span<const std::uint32_t> input, std::size_t i) {
    for (std::size_t j = i + 1; j < input.size(); ++j) {
        auto jt = joining_type_of(t, input[j]);
        if (jt != unicode_cpp::security::ucd::JoiningType::Transparent) return jt;
    }
    return std::nullopt;
}

// True iff the ZWNJ at index `i` occupies a position where it is
// orthographically required, by RFC 5892 Appendix A.1: it follows a Virama,
// which is how a Devanagari conjunct is suppressed, or it sits between a left-
// or dual-joining character and a right- or dual-joining one, skipping
// Transparent characters on both sides, which is how a Persian word boundary is
// written inside a cursive run.
//
// A ZWNJ outside such a position carries no orthographic duty and stays
// reportable.
inline bool is_legitimate_zwnj_context(
    const unicode_cpp::security::ucd::Tables* t,
    std::span<const std::uint32_t> input, std::size_t i) {
    namespace u = unicode_cpp::security::ucd;
    if (i > 0) {
        bool prev_is_virama = t != nullptr ? u::is_virama(*t, input[i - 1])
                                           : embedded_is_virama(input[i - 1]);
        if (prev_is_virama) return true;
    }
    auto left = joining_type_before(t, input, i);
    auto right = joining_type_after(t, input, i);
    if (!left.has_value() || !right.has_value()) return false;
    bool left_joins = *left == u::JoiningType::LeftJoining ||
                      *left == u::JoiningType::DualJoining;
    bool right_joins = *right == u::JoiningType::RightJoining ||
                       *right == u::JoiningType::DualJoining;
    return left_joins && right_joins;
}

// True iff the ZWJ at index `i` is flanked by two codepoints that both
// participate in some registered RGI emoji ZWJ sequence. Strictly narrower than
// "is an emoji": a codepoint carrying the Emoji property but appearing in no
// registered sequence does not sanction a ZWJ beside it. A ZWJ in head or tail
// position is never legitimate.
inline bool is_legitimate_zwj_context(
    const unicode_cpp::security::identity::emoji_zwj_integrity::RgiTable* rgi,
    std::span<const std::uint32_t> input, std::size_t i) {
    if (i == 0 || i + 1 >= input.size()) return false;
    if (rgi != nullptr) {
        return rgi->is_emoji_target(input[i - 1]) &&
               rgi->is_emoji_target(input[i + 1]);
    }
    return embedded_is_emoji_target(input[i - 1]) &&
           embedded_is_emoji_target(input[i + 1]);
}

// `tables` and `rgi` are optional. When the caller supplies them the exemptions
// are decided from the loaded UCD; when it does not, they are decided from the
// compiled-in tables in `generated/context_tables.hpp`, which are derived from
// the same three files. Both readings therefore agree, and there is no mode in
// which a legitimate Devanagari or Persian ZWNJ is reported.
inline Verdict detect_with_optional_context(
    std::span<const std::uint32_t> input,
    const unicode_cpp::security::ucd::Tables* tables,
    const unicode_cpp::security::identity::emoji_zwj_integrity::RgiTable* rgi) {
    Verdict v{};
    std::size_t annotation_count = 0;
    std::size_t word_joiner_count = 0;
    std::size_t nnbsp_count = 0;
    std::size_t zwj_zwsp_count = 0;
    std::vector<std::size_t> suspicious;

    for (std::size_t i = 0; i < input.size(); ++i) {
        std::uint32_t cp = input[i];
        if (!is_zero_width(cp)) continue;
        v.zero_width_positions.push_back(i);
        if (is_annotation(cp)) annotation_count += 1;
        else if (is_word_joiner(cp)) word_joiner_count += 1;
        else if (is_nnbsp(cp)) nnbsp_count += 1;
        else if (is_zwj_or_zwsp(cp)) zwj_zwsp_count += 1;
        // The sanctioning model: a ZWJ inside a registered emoji sequence and a
        // ZWNJ in an RFC 5892 CONTEXTJ-valid position both carry meaning a
        // reader depends on, so they are recorded as present but not treated as
        // suspicious.
        bool sanctioned =
            (cp == 0x200D && is_legitimate_zwj_context(rgi, input, i)) ||
            (cp == 0x200C && is_legitimate_zwnj_context(tables, input, i));
        if (!sanctioned) suspicious.push_back(i);
    }

    if (v.zero_width_positions.empty() || suspicious.empty()) {
        v.kind = ClassificationKind::Clear;
        return v;
    }

    v.kind = ClassificationKind::Hazard;
    if (annotation_count > 0) {
        v.sub = AnnotationMisuse{annotation_count};
    } else if (word_joiner_count > 0) {
        v.sub = WordJoinerInjection{word_joiner_count};
    } else if (nnbsp_count >= 2) {
        v.sub = AiWatermarkNNBSP{nnbsp_count};
    } else if (zwj_zwsp_count >= 2) {
        v.sub = BinaryPayload{zwj_zwsp_count / 2};
    } else {
        v.sub = BareZeroWidth{input[suspicious[0]]};
    }
    return v;
}

// Full-fidelity detection: both exemptions are decided from the UCD data.
inline Verdict detect(
    std::span<const std::uint32_t> input,
    const unicode_cpp::security::ucd::Tables& tables,
    const unicode_cpp::security::identity::emoji_zwj_integrity::RgiTable& rgi) {
    return detect_with_optional_context(input, &tables, &rgi);
}

// Detection for a caller holding no UCD directory. Both exemptions still hold,
// decided from the compiled-in tables, so this agrees with `detect` on every
// input.
inline Verdict detect_without_context(std::span<const std::uint32_t> input) {
    return detect_with_optional_context(input, nullptr, nullptr);
}

}  // namespace unicode_cpp::security::zero_width_payload

#endif  // UNICODE_CPP_SECURITY_ZERO_WIDTH_PAYLOAD_HPP
