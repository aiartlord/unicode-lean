# frozen_string_literal: true

module UnicodeRuby
  # Strict-UTF-8 reject taxonomy.
  #
  # The six variants enumerate every category of byte sequence that a strict
  # RFC 3629 decoder rejects:
  #
  #   - OverlongEncoding       — a multi-byte sequence whose decoded codepoint
  #     is below the minimum for that sequence length.
  #   - SurrogateCodepoint     — a sequence decoding to U+D800..U+DFFF.
  #   - CodepointBeyondMax     — a sequence decoding to a value above U+10FFFF.
  #   - TruncatedSequence      — the byte stream ends mid-codepoint.
  #   - InvalidStartByte       — a byte that cannot begin any UTF-8 codepoint.
  #   - InvalidContinuationByte — a continuation byte whose top two bits are
  #     not `10`.
  module Strict
    # Each reject kind is represented by its stable wire tag string, matching
    # `Utf8RejectKind::tag` in the Rust reference.
    OVERLONG_ENCODING = "OverlongEncoding"
    SURROGATE_CODEPOINT = "SurrogateCodepoint"
    CODEPOINT_BEYOND_MAX = "CodepointBeyondMax"
    TRUNCATED_SEQUENCE = "TruncatedSequence"
    INVALID_START_BYTE = "InvalidStartByte"
    INVALID_CONTINUATION_BYTE = "InvalidContinuationByte"
  end
end
