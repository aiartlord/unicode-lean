# frozen_string_literal: true

require_relative "strict"

module UnicodeRuby
  # Strict UTF-8 codec — validator, decoder, and encoder.
  #
  # The accepted byte set is exactly the strict RFC 3629 acceptance language:
  # it rejects overlong encodings, surrogate codepoints (U+D800..U+DFFF),
  # codepoints beyond U+10FFFF, truncated multi-byte sequences, invalid start
  # bytes, and invalid continuation bytes.  Bytes are represented as arrays of
  # integers in 0..255.
  module Utf8
    module_function

    # Decoder states:
    #   :start                          — start-of-codepoint state
    #   [:cont, remaining, accum, min_cp] — open multi-byte sequence
    START = :start

    # Process one byte given the current state.  Returns one of:
    #   [:continue, new_state]
    #   [:emit, cp, new_state]
    #   [:reject, kind]
    def decode_step(state, byte)
      n = byte
      if state == START
        if n < 0x80
          [:emit, n, START]
        elsif n < 0xC2
          [:reject, Strict::INVALID_START_BYTE]
        elsif n < 0xE0
          [:continue, [:cont, 1, n & 0x1F, 0x80]]
        elsif n < 0xF0
          [:continue, [:cont, 2, n & 0x0F, 0x800]]
        elsif n < 0xF5
          [:continue, [:cont, 3, n & 0x07, 0x10000]]
        else
          [:reject, Strict::INVALID_START_BYTE]
        end
      else
        _tag, remaining, accum, min_cp = state
        return [:reject, Strict::INVALID_CONTINUATION_BYTE] if n < 0x80 || n >= 0xC0

        nxt = (accum << 6) | (n & 0x3F)
        if remaining == 1
          if nxt < min_cp
            [:reject, Strict::OVERLONG_ENCODING]
          elsif nxt >= 0xD800 && nxt <= 0xDFFF
            [:reject, Strict::SURROGATE_CODEPOINT]
          elsif nxt > 0x10FFFF
            [:reject, Strict::CODEPOINT_BEYOND_MAX]
          else
            [:emit, nxt, START]
          end
        else
          [:continue, [:cont, remaining - 1, nxt, min_cp]]
        end
      end
    end

    # The first byte offset at which the strict UTF-8 state machine rejects, as
    # `[offset, kind]`, or `nil` when the entire input is valid UTF-8.  For
    # OverlongEncoding the offset is the start byte of the offending sequence.
    # TruncatedSequence reports an offset equal to the input length.
    def first_invalid_offset(bytes)
      state = START
      seq_start = 0
      bytes.each_with_index do |b, i|
        seq_start = i if state == START
        result = decode_step(state, b)
        case result[0]
        when :continue
          state = result[1]
        when :emit
          state = result[2]
        when :reject
          kind = result[1]
          return [seq_start, kind] if kind == Strict::OVERLONG_ENCODING

          return [i, kind]
        else
          raise "unreachable utf8 step tag: #{result[0].inspect}"
        end
      end
      case state
      when START
        nil
      else
        [bytes.length, Strict::TRUNCATED_SEQUENCE]
      end
    end

    # Whole-input validity predicate.
    def valid?(bytes)
      first_invalid_offset(bytes).nil?
    end

    # Decode a UTF-8 byte array to a codepoint array.  On malformed input the
    # walker yields the longest valid prefix and stops; callers that need
    # explicit failure propagation validate first via first_invalid_offset.
    def decode_to_codepoints(bytes)
      out = []
      state = START
      bytes.each do |b|
        result = decode_step(state, b)
        case result[0]
        when :continue
          state = result[1]
        when :emit
          out << result[1]
          state = result[2]
        when :reject
          return out
        else
          raise "unreachable utf8 step tag: #{result[0].inspect}"
        end
      end
      out
    end

    # Encode a single codepoint as a 1–4 byte UTF-8 sequence.
    def encode_codepoint(cp)
      if cp < 0x80
        [cp]
      elsif cp < 0x800
        [0xC0 | (cp >> 6), 0x80 | (cp & 0x3F)]
      elsif cp < 0x10000
        [0xE0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3F), 0x80 | (cp & 0x3F)]
      else
        [0xF0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3F),
         0x80 | ((cp >> 6) & 0x3F), 0x80 | (cp & 0x3F)]
      end
    end

    # Concatenate the UTF-8 encodings of a codepoint array.
    def encode_codepoints(cps)
      out = []
      cps.each { |cp| out.concat(encode_codepoint(cp)) }
      out
    end
  end
end
