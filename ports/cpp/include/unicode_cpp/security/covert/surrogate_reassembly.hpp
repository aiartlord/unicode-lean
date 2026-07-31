// Surrogate-reassembly / malformed-byte-stream detection.
//
// Threat model.  Tier C.  An adversary hides intent in a byte
// stream that is not well-formed UTF-8 — an overlong encoding, a
// CESU-8 / surrogate codepoint, a truncated sequence, an invalid
// start or continuation byte, or a value beyond U+10FFFF — betting
// a lenient decoder will "reassemble" it into something the
// security scanner never saw in codepoint form.
//
// Direct port of `Unicode/Security/Covert/SurrogateReassembly.lean`.
// The input codepoint list is treated as a byte stream (one octet
// per entry); the family only applies when every entry is a byte
// (`< 0x100`), matching the `looksLikeByteStream` gate in
// `Unicode/Security/RunAll.lean`.  The verdict projects the first
// UTF-8 violation found by the shared strict decoder
// (`first_invalid_utf8_offset`, reused verbatim) onto a
// covert-layer sub-threat.
//
// The sub-threat tags DIFFER from the malformed-utf8 tags emitted
// by `scan_utf8`: this family surfaces a byte stream smuggled
// through as codepoints, so its tags name the reassembly hazard
// (Overlong, Cesu8, Truncated, InvalidStartByte,
// InvalidContinuation, CodepointBeyondMax) rather than the raw
// `Utf8RejectKind` spelling.

#ifndef UNICODE_CPP_SECURITY_SURROGATE_REASSEMBLY_HPP
#define UNICODE_CPP_SECURITY_SURROGATE_REASSEMBLY_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "unicode_cpp/strict.hpp"
#include "unicode_cpp/utf8.hpp"

namespace unicode_cpp::security::surrogate_reassembly {

// One surrogate-reassembly scan result.  `sub` is `std::nullopt`
// for a clear input (well-formed, or not a byte stream); otherwise
// it carries the sub-threat tag of the first UTF-8 violation and
// its byte offset in `positions`.
struct Detection {
  std::optional<std::string> sub;
  std::vector<std::size_t> positions;
};

// True iff every entry fits in one octet — the `looksLikeByteStream`
// gate.  A codepoint-array input containing any value `>= 0x100` is
// not a byte stream, and running the UTF-8 decoder on it would be
// meaningless.
inline bool looks_like_byte_stream(std::span<const std::uint32_t> input) {
  for (std::uint32_t cp : input) {
    if (cp >= 0x100u)
      return false;
  }
  return true;
}

// Project a `Utf8RejectKind` to its surrogate-reassembly sub-threat
// tag, mirroring `subThreatOfRejectKind` in the Lean spec.
constexpr std::string_view sub_threat_of_reject_kind(Utf8RejectKind kind) {
  switch (kind) {
  case Utf8RejectKind::OverlongEncoding:
    return "Overlong";
  case Utf8RejectKind::SurrogateCodepoint:
    return "Cesu8";
  case Utf8RejectKind::TruncatedSequence:
    return "Truncated";
  case Utf8RejectKind::InvalidStartByte:
    return "InvalidStartByte";
  case Utf8RejectKind::InvalidContinuationByte:
    return "InvalidContinuation";
  case Utf8RejectKind::CodepointBeyondMax:
    return "CodepointBeyondMax";
  }
  return "InvalidStartByte";
}

// Detect a malformed UTF-8 byte stream hidden in a codepoint list.
// Only applies to byte-stream-shaped input (every entry `< 0x100`);
// otherwise clear.  Reports the sub-threat of the first violation
// at its byte offset.
inline Detection detect(std::span<const std::uint32_t> input) {
  if (!looks_like_byte_stream(input)) {
    return Detection{std::nullopt, {}};
  }
  std::vector<std::uint8_t> bytes;
  bytes.reserve(input.size());
  for (std::uint32_t cp : input) {
    bytes.push_back(static_cast<std::uint8_t>(cp));
  }
  const auto invalid = unicode_cpp::first_invalid_utf8_offset(
      std::span<const std::uint8_t>{bytes.data(), bytes.size()});
  if (!invalid) {
    return Detection{std::nullopt, {}};
  }
  return Detection{
      std::string{sub_threat_of_reject_kind(invalid->kind)},
      {invalid->offset},
  };
}

}  // namespace unicode_cpp::security::surrogate_reassembly

#endif  // UNICODE_CPP_SECURITY_SURROGATE_REASSEMBLY_HPP
