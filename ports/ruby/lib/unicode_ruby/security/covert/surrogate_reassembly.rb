# frozen_string_literal: true

require_relative "../../utf8"
require_relative "../../strict"

module UnicodeRuby
  module Security
    module Covert
      # Surrogate-reassembly / malformed-byte-stream detection.  The input
      # codepoint list is treated as a byte stream (one octet per entry); the
      # family only applies when every entry is a byte (< 0x100).  The verdict
      # projects the first UTF-8 violation onto a covert-layer sub-threat.
      module SurrogateReassembly
        Detection = Struct.new(:sub, :positions)

        module_function

        # True iff every entry fits in one octet — the looksLikeByteStream gate.
        def looks_like_byte_stream(input)
          input.all? { |cp| cp < 0x100 }
        end

        def sub_threat_of_reject_kind(kind)
          case kind
          when Strict::OVERLONG_ENCODING then "Overlong"
          when Strict::SURROGATE_CODEPOINT then "Cesu8"
          when Strict::TRUNCATED_SEQUENCE then "Truncated"
          when Strict::INVALID_START_BYTE then "InvalidStartByte"
          when Strict::INVALID_CONTINUATION_BYTE then "InvalidContinuation"
          when Strict::CODEPOINT_BEYOND_MAX then "CodepointBeyondMax"
          else
            raise "surrogate_reassembly: unknown reject kind #{kind.inspect}"
          end
        end

        # Any value > 0xFF is clamped to 0xFF (never a valid UTF-8 start byte),
        # mirroring the Lean toBytes helper.
        def detect(input)
          bytes = input.map { |cp| cp > 0xFF ? 0xFF : cp }
          result = Utf8.first_invalid_offset(bytes)
          if result.nil?
            Detection.new(nil, [])
          else
            offset, kind = result
            Detection.new(sub_threat_of_reject_kind(kind), [offset])
          end
        end
      end
    end
  end
end
