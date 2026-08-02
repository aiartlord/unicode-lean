// Stream-Safe-Text-Format-violation detection (F2) — inputs whose consecutive
// non-starter run exceeds the UAX #15 §13 streamSafeLimit of 30. Such an input
// (the canonical "Zalgo" shape, a single base codepoint followed by a long
// combining-mark run) forces unbounded combining-mark buffers in receiver-side
// streaming normalization (to_nfc / to_nfd / to_nfkc / to_nfkd) and is a known
// DoS vector.
//
// Direct port of Unicode/Security/Form/StreamSafeViolation.lean, transliterated
// from the verified Rust reference stream_safe_violation.rs. UAX #15 §13 defines
// Stream-Safe Text Format as the remediation: insert U+034F COMBINING GRAPHEME
// JOINER (a starter) after every 30 consecutive non-starters, which bounds the
// normalization buffer. StreamSafeViolation is the security verdict over the
// same property — distinct from RendererDivergence's combiningStackOverflow (the
// cosmetic 4-mark threshold), this is the spec-mandated DoS-prevention bound.
//
// A codepoint is a non-starter iff its Canonical_Combining_Class is non-zero
// (UAX #15 D49). This module reads CCC from the port's own bundled UCD table via
// ucd::ccc, never a host normalizer.
//
// Sub-threat: StreamSafeOverrun(base_pos, run_len) — the first non-starter run
// whose length exceeds streamSafeLimit. base_pos is the index of that run's
// first non-starter codepoint.
#ifndef UNICODE_CPP_SECURITY_FORM_STREAM_SAFE_VIOLATION_HPP
#define UNICODE_CPP_SECURITY_FORM_STREAM_SAFE_VIOLATION_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include "unicode_cpp/security/identity/ucd.hpp"

namespace unicode_cpp::security::form::stream_safe_violation {

namespace ucd = unicode_cpp::security::ucd;

// ─────────────────────────────────────────────────────────────────────
// §1 Run inventory
// ─────────────────────────────────────────────────────────────────────

// UAX #15 §13 Stream-Safe limit: the maximum number of consecutive non-starters
// permitted before a COMBINING GRAPHEME JOINER must be inserted.
inline constexpr std::size_t STREAM_SAFE_LIMIT = 30;

// True iff cp is a non-starter — a codepoint with non-zero
// Canonical_Combining_Class (UAX #15 D49). Starters have CCC = 0.
inline bool is_non_starter(const ucd::Tables& t, std::uint32_t cp) {
    return ucd::ccc(t, cp) != 0;
}

// Inventory of (start_index, length) for every maximal non-starter run in
// input. Mirrors collectRunsGo: a run opens on the first non-starter, its start
// index is fixed to that codepoint's absolute index, and it closes (emitting its
// (start, length) pair) on the next starter or at end of input.
inline std::vector<std::pair<std::size_t, std::size_t>> non_starter_runs(
    const ucd::Tables& t, std::span<const std::uint32_t> input) {
    std::vector<std::pair<std::size_t, std::size_t>> runs;
    std::optional<std::size_t> cur_start;
    std::size_t cur_len = 0;
    for (std::size_t i = 0; i < input.size(); ++i) {
        if (is_non_starter(t, input[i])) {
            if (!cur_start.has_value()) {
                cur_start = i;
            }
            ++cur_len;
        } else {
            if (cur_start.has_value()) {
                runs.emplace_back(*cur_start, cur_len);
            }
            cur_start = std::nullopt;
            cur_len = 0;
        }
    }
    if (cur_start.has_value()) {
        runs.emplace_back(*cur_start, cur_len);
    }
    return runs;
}

// First non-starter run whose length exceeds STREAM_SAFE_LIMIT, as
// (start_index, length).
inline std::optional<std::pair<std::size_t, std::size_t>> first_overrun(
    const ucd::Tables& t, std::span<const std::uint32_t> input) {
    for (const auto& run : non_starter_runs(t, input)) {
        if (run.second > STREAM_SAFE_LIMIT) {
            return run;
        }
    }
    return std::nullopt;
}

// Longest non-starter run length in input.
inline std::size_t max_run_len(const ucd::Tables& t,
                               std::span<const std::uint32_t> input) {
    std::size_t acc = 0;
    for (const auto& run : non_starter_runs(t, input)) {
        if (run.second > acc) {
            acc = run.second;
        }
    }
    return acc;
}

// Number of distinct non-starter runs that exceed STREAM_SAFE_LIMIT.
inline std::size_t overrun_count(const ucd::Tables& t,
                                 std::span<const std::uint32_t> input) {
    std::size_t acc = 0;
    for (const auto& run : non_starter_runs(t, input)) {
        if (run.second > STREAM_SAFE_LIMIT) {
            ++acc;
        }
    }
    return acc;
}

// Total non-starter codepoints in input (sum of all run lengths).
inline std::size_t total_non_starters(const ucd::Tables& t,
                                      std::span<const std::uint32_t> input) {
    std::size_t acc = 0;
    for (const auto& run : non_starter_runs(t, input)) {
        acc += run.second;
    }
    return acc;
}

// ─────────────────────────────────────────────────────────────────────
// §2 Types
// ─────────────────────────────────────────────────────────────────────

// The first non-starter run whose length exceeds STREAM_SAFE_LIMIT. base_pos is
// the index of the run's first non-starter codepoint; run_len is the run's
// length.
struct StreamSafeOverrun {
    std::size_t base_pos;
    std::size_t run_len;
};

// Sub-threats this detector can fire. Modelled as a variant so the tag visitor
// is exhaustive (the compiler rejects an unhandled alternative — the C++
// analogue of the Rust match with no wildcard arm).
using SubThreat = std::variant<StreamSafeOverrun>;

// Human-facing classification tag for this sub-threat.
inline std::string_view sub_threat_tag(const SubThreat& sub) {
    struct Visitor {
        std::string_view operator()(const StreamSafeOverrun&) const {
            return "StreamSafeOverrun";
        }
    };
    return std::visit(Visitor{}, sub);
}

// Top-level F2 classification. sub is nullopt for a clear input (no non-starter
// run exceeds the Stream-Safe limit), else the sub-threat that fired, its
// implicated positions, and any decoded bytes (always empty for this detector —
// the field mirrors the spec's Classification.hazard shape).
struct Classification {
    std::optional<SubThreat> sub;
    std::vector<std::size_t> positions;
    std::vector<std::uint8_t> decoded;

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

// F2 verdict — the structured output of detect. The run-inventory summaries
// (max_run_len, overrun_count, total_non_starters) are exposed so downstream
// callers can size the buffer pressure a streaming normalizer would see.
struct Verdict {
    std::vector<std::uint32_t> input;
    Classification classify;
    std::size_t max_run_len;
    std::size_t overrun_count;
    std::size_t total_non_starters;
};

// ─────────────────────────────────────────────────────────────────────
// §3 Top-level detection
// ─────────────────────────────────────────────────────────────────────

// The F2 detection function. Fires StreamSafeOverrun on the first non-starter
// run whose length exceeds STREAM_SAFE_LIMIT.
inline Verdict detect(const ucd::Tables& t,
                      std::span<const std::uint32_t> input) {
    Classification classification;
    if (auto overrun = first_overrun(t, input)) {
        classification.sub =
            SubThreat{StreamSafeOverrun{overrun->first, overrun->second}};
        classification.positions = {overrun->first};
        classification.decoded = {};
    }
    return Verdict{
        std::vector<std::uint32_t>{input.begin(), input.end()},
        std::move(classification),
        max_run_len(t, input),
        overrun_count(t, input),
        total_non_starters(t, input),
    };
}

}  // namespace unicode_cpp::security::form::stream_safe_violation

#endif  // UNICODE_CPP_SECURITY_FORM_STREAM_SAFE_VIOLATION_HPP
