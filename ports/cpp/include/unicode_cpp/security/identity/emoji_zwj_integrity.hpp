#pragma once

// emoji-zwj-integrity — detection of malformed / unsanctioned emoji ZWJ-sequence
// shapes per UTS #51 (the identity-layer detector I3).
//
// Direct port of Unicode/Security/Identity/EmojiZwjIntegrity.lean, transliterated
// byte-faithfully from the verified Rust reference emoji_zwj_integrity.rs.
//
// Threat model. An adversary crafts an emoji-shaped codepoint sequence
// containing one or more U+200D ZERO WIDTH JOINERs but violating the sanctioned
// RGI ZWJ-sequence shape — by exceeding the RGI length cap, by joining a
// non-emoji codepoint, by emitting adjacent ZWJ pairs, or by overflowing the
// skin-tone count. Any non-RGI ZWJ-containing sequence is renderer-dependent,
// and that renderer divergence is the attack surface.
//
// Sanctioning data. UTS #51 defines the RGI ZWJ sequences in
// emoji-zwj-sequences.txt, bundled in the port's own
// data/emoji-zwj-sequences.txt (never a host emoji library). The registered set
// gives both the exact-match membership test (is_registered_zwj_sequence) and
// the ZWJ *alphabet* — every distinct codepoint occurring at any position of any
// registered sequence, excluding the joiner — which is the canonical
// "what may flank a ZWJ?" predicate.
//
// Algorithm (one pass over input).
//   Phase 1 — collect ZWJ positions and the skin-tone count.
//   Phase 2 — short-circuit Clear if there are no ZWJs and the skin-tone count
//             is at most 1.
//   Phase 3 — a registered RGI sequence is always Clear.
//   Phase 4 — check sub-threats by priority:
//               1. DoubleZWJ            ZWJ-ZWJ adjacency
//               2. NonEmojiInjection    ZWJ adjacent to a non-emoji codepoint
//               3. OverLength           sequence longer than the RGI cap
//               4. SkinToneOverflow     skin-tone count >= 5
//               5. UnregisteredSequence catch-all when ZWJs are present but the
//                                       sequence is not registered.

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

#include "unicode_cpp/security/identity/ucd.hpp"

namespace unicode_cpp::security::identity::emoji_zwj_integrity {

namespace ucd = unicode_cpp::security::ucd;

// ─────────────────────────────────────────────────────────────────────
// §1 Constants
// ─────────────────────────────────────────────────────────────────────

// Conservative cap on the length of a sanctioned RGI ZWJ sequence
// (maxRgiLength in the Lean spec). The longest current entry (a four-person
// family with skin tones) reaches ~13-14 codepoints; 16 is a safe upper bound.
inline constexpr std::size_t MAX_RGI_LENGTH = 16;

// The ZERO WIDTH JOINER codepoint.
inline constexpr std::uint32_t ZWJ = 0x200D;

// ─────────────────────────────────────────────────────────────────────
// §2 Sub-threat types
// ─────────────────────────────────────────────────────────────────────

// ZWJ-ZWJ adjacency; positions are the first ZWJ of each adjacent pair.
struct DoubleZwj {
    std::vector<std::size_t> positions;
};

// A ZWJ flanked by a non-emoji codepoint (or sitting at an input edge).
struct NonEmojiInjection {
    // Position of the offending ZWJ.
    std::size_t zwj_pos;
    // The non-emoji codepoint that flanks it (0 for an edge ZWJ).
    std::uint32_t non_emoji_cp;
};

// The sequence is longer than MAX_RGI_LENGTH.
struct OverLength {
    // The observed sequence length.
    std::size_t length;
    // The RGI length cap that was exceeded.
    std::size_t max_length;
};

// Five or more skin-tone modifiers (the family-emoji maximum is four).
struct SkinToneOverflow {
    // The observed skin-tone modifier count.
    std::size_t count;
};

// ZWJs are present and no other sub-threat matched, but the sequence is not a
// registered RGI ZWJ sequence.
struct UnregisteredSequence {
    // The length of the unregistered ZWJ chain.
    std::size_t chain_len;
};

using SubThreat = std::variant<DoubleZwj, NonEmojiInjection, OverLength,
                               SkinToneOverflow, UnregisteredSequence>;

// Fixture-row tag string for this sub-threat (matches SubThreat.tag). Every
// alternative is handled explicitly by an overload; the variant makes the
// dispatch exhaustive with no catch-all.
inline std::string_view sub_threat_tag(const SubThreat& sub) {
    struct Visitor {
        std::string_view operator()(const DoubleZwj&) const {
            return "DoubleZWJ";
        }
        std::string_view operator()(const NonEmojiInjection&) const {
            return "NonEmojiInjection";
        }
        std::string_view operator()(const OverLength&) const {
            return "OverLength";
        }
        std::string_view operator()(const SkinToneOverflow&) const {
            return "SkinToneOverflow";
        }
        std::string_view operator()(const UnregisteredSequence&) const {
            return "UnregisteredSequence";
        }
    };
    return std::visit(Visitor{}, sub);
}

// Top-level classification. sub is nullopt for a Clear input, else the
// sub-threat that fired, the implicated positions, and the (always-empty for
// this detector) decoded-byte projection — kept for shape parity with the Lean
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
    // Positions of every ZWJ in the input.
    std::vector<std::size_t> zwj_positions;
    // The chain length (0 when there are no ZWJs, else the input length).
    std::size_t chain_length;
    // True iff the input is exactly a registered RGI ZWJ sequence.
    bool is_registered_rgi;
    // Count of skin-tone modifier codepoints (U+1F3FB..U+1F3FF).
    std::size_t skin_tone_count;
};

// ─────────────────────────────────────────────────────────────────────
// §3 RGI ZWJ-sequence data (bundled data/emoji-zwj-sequences.txt)
// ─────────────────────────────────────────────────────────────────────

namespace detail {

// Parse the registered RGI ZWJ sequences from emoji-zwj-sequences.txt. Each
// non-comment row is `<cp> <cp> ... ; RGI_Emoji_ZWJ_Sequence ; <desc> # <cmt>`;
// the codepoint list is the field before the first ';'.
inline std::vector<std::vector<std::uint32_t>> parse_zwj_sequences(
    std::string_view text) {
    std::vector<std::vector<std::uint32_t>> out;
    ucd::detail::for_each_line(text, [&](std::string_view raw_line) {
        std::string_view stripped =
            ucd::detail::strip_comment_and_trim(raw_line);
        if (stripped.empty()) {
            return;
        }
        std::size_t semi = stripped.find(';');
        std::string_view seq_field =
            semi == std::string_view::npos ? stripped
                                           : stripped.substr(0, semi);
        std::vector<std::uint32_t> seq;
        bool parsed_ok = true;
        std::size_t pos = 0;
        while (pos < seq_field.size()) {
            while (pos < seq_field.size() &&
                   std::isspace(static_cast<unsigned char>(seq_field[pos]))) {
                ++pos;
            }
            std::size_t start = pos;
            while (pos < seq_field.size() &&
                   !std::isspace(static_cast<unsigned char>(seq_field[pos]))) {
                ++pos;
            }
            if (start == pos) {
                break;
            }
            std::string_view token = seq_field.substr(start, pos - start);
            if (auto cp = ucd::detail::parse_hex_u32(token)) {
                seq.push_back(*cp);
            } else {
                parsed_ok = false;
                break;
            }
        }
        if (parsed_ok && !seq.empty()) {
            out.push_back(std::move(seq));
        }
    });
    return out;
}

}  // namespace detail

// The registered RGI ZWJ-sequence set and its induced ZWJ alphabet, loaded once
// from the bundled emoji-zwj-sequences.txt.
struct RgiTable {
    std::vector<std::vector<std::uint32_t>> sequences;
    std::unordered_set<std::uint32_t> alphabet;

    static RgiTable parse(std::string_view text) {
        RgiTable table;
        table.sequences = detail::parse_zwj_sequences(text);
        // The ZWJ alphabet: every distinct codepoint occurring at any position
        // of any registered RGI ZWJ sequence, excluding the joiner U+200D.
        for (const auto& seq : table.sequences) {
            for (std::uint32_t cp : seq) {
                if (cp != ZWJ) {
                    table.alphabet.insert(cp);
                }
            }
        }
        return table;
    }

    static RgiTable load_from_dir(const std::filesystem::path& dir) {
        return parse(ucd::detail::read_file(dir / "emoji-zwj-sequences.txt"));
    }

    // True iff cps is exactly a registered RGI ZWJ sequence.
    bool is_registered_zwj_sequence(
        std::span<const std::uint32_t> cps) const {
        for (const auto& seq : sequences) {
            if (seq.size() == cps.size() &&
                std::equal(seq.begin(), seq.end(), cps.begin())) {
                return true;
            }
        }
        return false;
    }

    // True iff cp appears at some position of a registered RGI ZWJ sequence
    // (the canonical "what may flank a ZWJ?" predicate).
    bool is_emoji_target(std::uint32_t cp) const {
        return alphabet.find(cp) != alphabet.end();
    }
};

// ─────────────────────────────────────────────────────────────────────
// §4 Core predicates
// ─────────────────────────────────────────────────────────────────────

// True iff cp is the ZWJ codepoint.
inline bool is_zwj(std::uint32_t cp) { return cp == ZWJ; }

// True iff cp is an emoji skin-tone modifier (U+1F3FB..U+1F3FF). The port's own
// modifier range — no host emoji library.
inline bool is_emoji_modifier(std::uint32_t cp) {
    return cp >= 0x1F3FB && cp <= 0x1F3FF;
}

namespace detail {

// Positions of every ZWJ in input.
inline std::vector<std::size_t> zwj_positions(
    std::span<const std::uint32_t> input) {
    std::vector<std::size_t> out;
    for (std::size_t idx = 0; idx < input.size(); ++idx) {
        if (is_zwj(input[idx])) {
            out.push_back(idx);
        }
    }
    return out;
}

// Count of skin-tone modifier codepoints.
inline std::size_t skin_tone_count(std::span<const std::uint32_t> input) {
    std::size_t count = 0;
    for (std::uint32_t cp : input) {
        if (is_emoji_modifier(cp)) {
            ++count;
        }
    }
    return count;
}

// Positions of the first ZWJ in each ZWJ-ZWJ adjacent pair.
inline std::vector<std::size_t> double_zwj_positions(
    std::span<const std::uint32_t> input) {
    std::vector<std::size_t> out;
    for (std::size_t idx = 0; idx < input.size(); ++idx) {
        if (idx + 1 < input.size()) {
            if (is_zwj(input[idx]) && is_zwj(input[idx + 1])) {
                out.push_back(idx);
            }
        }
    }
    return out;
}

// The first ZWJ position where either neighbour is a non-emoji codepoint, as
// (zwj_pos, offending_cp). A ZWJ at an input edge (no preceding or no following
// codepoint) is itself an injection-class hazard, reported with offending
// codepoint 0.
inline std::optional<std::pair<std::size_t, std::uint32_t>>
first_non_emoji_injection(const RgiTable& rgi,
                          std::span<const std::uint32_t> input) {
    for (std::size_t idx = 0; idx < input.size(); ++idx) {
        if (!is_zwj(input[idx])) {
            continue;
        }
        std::optional<std::uint32_t> prev =
            idx == 0 ? std::nullopt
                     : std::optional<std::uint32_t>{input[idx - 1]};
        std::optional<std::uint32_t> next =
            idx + 1 < input.size()
                ? std::optional<std::uint32_t>{input[idx + 1]}
                : std::nullopt;
        if (prev.has_value() && next.has_value()) {
            if (!rgi.is_emoji_target(*prev)) {
                return std::pair<std::size_t, std::uint32_t>{idx, *prev};
            } else if (!rgi.is_emoji_target(*next)) {
                return std::pair<std::size_t, std::uint32_t>{idx, *next};
            }
        } else {
            // Either the ZWJ has no predecessor, or it has a predecessor but no
            // successor: an edge ZWJ, offending codepoint 0.
            return std::pair<std::size_t, std::uint32_t>{idx, 0};
        }
    }
    return std::nullopt;
}

}  // namespace detail

// ─────────────────────────────────────────────────────────────────────
// §5 Top-level detection
// ─────────────────────────────────────────────────────────────────────

// The EmojiZwjIntegrity detection function. The registered RGI set and the ZWJ
// alphabet come from the bundled RgiTable rgi; the skin-tone predicate is the
// port's own is_emoji_modifier.
inline Verdict detect(const RgiTable& rgi,
                      std::span<const std::uint32_t> input) {
    std::vector<std::size_t> zwjs = detail::zwj_positions(input);
    const std::size_t st_count = detail::skin_tone_count(input);
    const bool is_rgi = rgi.is_registered_zwj_sequence(input);
    const std::size_t chain_len = zwjs.empty() ? 0 : input.size();

    Verdict verdict;
    verdict.input = std::vector<std::uint32_t>(input.begin(), input.end());
    verdict.is_registered_rgi = is_rgi;
    verdict.skin_tone_count = st_count;

    // Phase 2: short-circuit Clear when no ZWJs and skin-tone count <= 1.
    if (zwjs.empty() && st_count <= 1) {
        verdict.classify = Classification{std::nullopt, {}, {}};
        verdict.zwj_positions = {};
        verdict.chain_length = 0;
        return verdict;
    }

    Classification classification;
    if (is_rgi) {
        // Phase 3: a registered RGI sequence is always clear.
        classification = Classification{std::nullopt, {}, {}};
    } else {
        // Phase 4.1: ZWJ-ZWJ adjacency.
        std::vector<std::size_t> dzwj = detail::double_zwj_positions(input);
        if (!dzwj.empty()) {
            classification.sub = SubThreat{DoubleZwj{dzwj}};
            classification.positions = dzwj;
        } else if (auto injection =
                       detail::first_non_emoji_injection(rgi, input)) {
            // Phase 4.2: ZWJ adjacent to a non-emoji codepoint.
            const auto [zwj_pos, offend_cp] = *injection;
            classification.sub =
                SubThreat{NonEmojiInjection{zwj_pos, offend_cp}};
            classification.positions = {zwj_pos};
        } else if (input.size() > MAX_RGI_LENGTH) {
            // Phase 4.3: length cap.
            classification.sub =
                SubThreat{OverLength{input.size(), MAX_RGI_LENGTH}};
            classification.positions = {};
        } else if (st_count >= 5) {
            // Phase 4.4: skin-tone overflow.
            classification.sub = SubThreat{SkinToneOverflow{st_count}};
            classification.positions = {};
        } else if (!zwjs.empty()) {
            // Phase 4.5: catch-all for unregistered ZWJ sequences.
            classification.sub =
                SubThreat{UnregisteredSequence{input.size()}};
            classification.positions = zwjs;
        } else {
            classification = Classification{std::nullopt, {}, {}};
        }
    }

    verdict.classify = std::move(classification);
    verdict.zwj_positions = std::move(zwjs);
    verdict.chain_length = chain_len;
    return verdict;
}

}  // namespace unicode_cpp::security::identity::emoji_zwj_integrity
