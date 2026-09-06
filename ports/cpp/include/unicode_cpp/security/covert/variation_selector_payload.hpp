// Detection of GlassWorm-class invisible payloads encoded in
// Unicode variation selectors.
//
// Threat model.  Tier A1.  Adversary crafts an input consisting
// of one visible base codepoint followed by a sequence of
// variation-selector codepoints (U+FE00..U+FE0F union
// U+E0100..U+E01EF) that the receiving renderer treats as a
// no-op glyph variant but that a downstream string-processing
// layer (e.g. an LLM tokenizer or a clipboard pipeline) preserves
// byte-for-byte.  Decoding pairs of VS codepoints back into bytes
// recovers an arbitrary payload.
//
// Exempts (base, VS) pairs that appear in StandardizedVariants.txt
// and emoji-variation-sequences.txt.  The legal-pair table is
// generated into an installed header so the C++ port remains
// self-contained and does not read repo-relative data files at
// runtime.

#ifndef UNICODE_CPP_SECURITY_VARIATION_SELECTOR_PAYLOAD_HPP
#define UNICODE_CPP_SECURITY_VARIATION_SELECTOR_PAYLOAD_HPP

#include <algorithm>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "unicode_cpp/security/calculus.hpp"
#include "unicode_cpp/security/covert/emoji_property_ranges.hpp"
#include "unicode_cpp/security/covert/variation_selector_pairs.hpp"

namespace unicode_cpp::security::variation_selector_payload {

constexpr bool is_variation_selector(std::uint32_t cp) {
  if (cp >= 0xFE00u && cp <= 0xFE0Fu)
    return true;
  if (cp >= 0xE0100u && cp <= 0xE01EFu)
    return true;
  if (cp >= 0x180Bu && cp <= 0x180Du)
    return true;
  return false;
}

// Decode a single VS codepoint to its nibble value in [0, 255].
// Uses GlassWorm's bit layout: VS1..VS16 = nibbles 0..15,
// VS17..VS256 = nibbles 16..255.  Mongolian FVS codepoints
// (180B..180D) are not part of the GlassWorm-style payload
// alphabet and return std::nullopt.
constexpr std::optional<std::uint32_t> vs_to_nibble(std::uint32_t cp) {
  if (cp >= 0xFE00u && cp <= 0xFE0Fu)
    return cp - 0xFE00u;
  if (cp >= 0xE0100u && cp <= 0xE01EFu)
    return cp - 0xE0100u + 16u;
  return std::nullopt;
}

struct DirectPayload {
  std::string decoded;
};
struct IllegalTarget {
  std::uint32_t target_cp;
  std::uint32_t vs_cp;
};
struct RepeatedBase {
  std::uint32_t base_cp;
  std::size_t vs_count;
};
// A registered selector precedes the suspicious run: payload hiding behind a
// legitimate glyph (Lean `embeddedAfterReg`).
struct EmbeddedAfterRegistered {
  std::size_t registered_end;
  std::size_t payload_start;
};

using SubThreat =
    std::variant<DirectPayload, IllegalTarget, RepeatedBase, EmbeddedAfterRegistered>;

inline std::string sub_threat_tag(const SubThreat &sub) {
  if (std::holds_alternative<DirectPayload>(sub))
    return "DirectPayload";
  if (std::holds_alternative<IllegalTarget>(sub))
    return "IllegalTarget";
  if (std::holds_alternative<RepeatedBase>(sub))
    return "RepeatedBase";
  if (std::holds_alternative<EmbeddedAfterRegistered>(sub))
    return "EmbeddedAfterRegistered";
  return "<unreachable>";
}

struct Verdict {
  ClassificationKind kind;
  std::optional<SubThreat> sub;
  // Every variation-selector position: the census.
  std::vector<std::size_t> vs_positions;
  // The selectors no registered pair or presentation rule sanctions: what the
  // classification localises (Lean `suspiciousPositions`).
  std::vector<std::size_t> suspicious_positions;
  std::vector<std::uint8_t> recovered_bytes;
};

// True iff `cp` carries the Emoji property (emoji-data.txt).
inline bool is_emoji(std::uint32_t cp) {
  for (const auto &range : generated::emoji_property_ranges) {
    if (range.first <= cp && cp <= range.second)
      return true;
  }
  return false;
}

namespace detail {

inline std::vector<std::uint8_t>
decode_vs_run(std::span<const std::uint32_t> input,
              std::span<const std::size_t> positions) {
  std::vector<std::uint8_t> out;
  std::optional<std::uint32_t> high;
  for (std::size_t p : positions) {
    auto n = vs_to_nibble(input[p]);
    if (!n)
      continue;
    if (!high) {
      high = *n;
    } else {
      out.push_back(static_cast<std::uint8_t>((*high << 4) | *n));
      high = std::nullopt;
    }
  }
  return out;
}

inline bool all_same_vs(std::span<const std::uint32_t> input,
                        std::span<const std::size_t> positions) {
  if (positions.empty())
    return true;
  std::uint32_t cp0 = input[positions[0]];
  for (std::size_t p : positions) {
    if (input[p] != cp0)
      return false;
  }
  return true;
}

inline std::string lossy_ascii(std::span<const std::uint8_t> bytes) {
  std::string s;
  for (std::uint8_t b : bytes) {
    if ((b >= 0x20 && b <= 0x7E) || b == 0x09 || b == 0x0A || b == 0x0D) {
      s.push_back(static_cast<char>(b));
    } else {
      s.push_back('?');
    }
  }
  return s;
}

inline bool is_registered_variation_pair(std::uint32_t base, std::uint32_t vs) {
  const auto pair = std::pair<std::uint32_t, std::uint32_t>{base, vs};
  const auto &pairs = generated::legal_variation_pairs;
  return std::find(pairs.begin(), pairs.end(), pair) != pairs.end();
}

} // namespace detail

// The Lean `classifyVS` registered reading of the selector at `p`: a
// standardized or emoji variation sequence, or VS15 / VS16 on any base with
// the Emoji property. A selector with no predecessor is never registered.
inline bool is_registered_use(std::span<const std::uint32_t> input, std::size_t p) {
  if (p == 0)
    return false;
  const std::uint32_t base = input[p - 1];
  const std::uint32_t vs = input[p];
  return detail::is_registered_variation_pair(base, vs) ||
         ((vs == 0xFE0Fu || vs == 0xFE0Eu) && is_emoji(base));
}

inline Verdict detect(std::span<const std::uint32_t> input) {
  Verdict v{};
  v.kind = ClassificationKind::Clear;
  for (std::size_t i = 0; i < input.size(); ++i) {
    if (is_variation_selector(input[i])) {
      v.vs_positions.push_back(i);
    }
  }

  // Each selector is judged against its predecessor (Lean classifyVS):
  // registered uses are sanctioned wherever they stand and however many; the
  // hazard is the suspicious run alone.
  std::vector<std::size_t> registered;
  std::vector<std::size_t> suspicious;
  for (std::size_t p : v.vs_positions) {
    if (is_registered_use(input, p))
      registered.push_back(p);
    else
      suspicious.push_back(p);
  }
  if (suspicious.empty()) {
    return v;
  }

  v.recovered_bytes = detail::decode_vs_run(input, suspicious);
  v.kind = ClassificationKind::Hazard;

  const std::size_t payload_start = suspicious[0];
  // Priority (Lean pickSubThreat): a registered selector before the
  // suspicious run, then a long single-selector run, then a decodable payload,
  // then the bare illegal target.
  std::optional<std::size_t> registered_end;
  for (std::size_t p : registered) {
    if (p < payload_start)
      registered_end = p;
  }
  if (registered_end) {
    v.sub = EmbeddedAfterRegistered{*registered_end, payload_start};
  } else if (suspicious.size() >= 4 && detail::all_same_vs(input, suspicious)) {
    std::uint32_t base = (payload_start == 0) ? 0u : input[payload_start - 1];
    v.sub = RepeatedBase{base, suspicious.size()};
  } else if (!v.recovered_bytes.empty()) {
    v.sub = DirectPayload{detail::lossy_ascii(v.recovered_bytes)};
  } else {
    std::uint32_t target = (payload_start == 0) ? 0u : input[payload_start - 1];
    v.sub = IllegalTarget{target, input[payload_start]};
  }
  v.suspicious_positions = std::move(suspicious);
  return v;
}

} // namespace unicode_cpp::security::variation_selector_payload

#endif // UNICODE_CPP_SECURITY_VARIATION_SELECTOR_PAYLOAD_HPP
