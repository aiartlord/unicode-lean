# frozen_string_literal: true

module UnicodeRuby
  module Security
    module Covert
      # Detection of payloads encoded in zero-width and near-zero-width Unicode
      # codepoints.  The explicit historical set preserves sub-threat dispatch;
      # the UAX #44 Default_Ignorable_Code_Point predicate is the extension that
      # catches every other invisible codepoint, modulo sibling-detector ranges.
      module ZeroWidthPayload
        Verdict = Struct.new(:kind, :sub, :zero_width_positions)

        module_function

        # Sibling-detector ranges dispatched by their own family detector,
        # excluded here to avoid double-counting.
        def sibling_handled?(cp)
          (cp >= 0xFE00 && cp <= 0xFE0F) ||
            (cp >= 0xE0100 && cp <= 0xE01EF) ||
            (cp >= 0xE0000 && cp <= 0xE007F) ||
            (cp >= 0x202A && cp <= 0x202E) ||
            (cp >= 0x2066 && cp <= 0x2069)
        end

        def zero_width?(cp)
          if (cp >= 0x200B && cp <= 0x200F) ||
             (cp >= 0x2060 && cp <= 0x2064) ||
             cp == 0x202F ||
             cp == 0xFEFF ||
             (cp >= 0xFFF9 && cp <= 0xFFFB)
            return true
          end

          Ucd.default_ignorable?(cp) && !sibling_handled?(cp)
        end

        def nnbsp?(cp)
          cp == 0x202F
        end

        def word_joiner?(cp)
          cp == 0x2060
        end

        def annotation?(cp)
          cp >= 0xFFF9 && cp <= 0xFFFB
        end

        def zwj_or_zwsp?(cp)
          cp == 0x200B || cp == 0x200D
        end

        # True iff the ZWJ at index i is flanked by two codepoints that both
        # participate in some registered RGI emoji ZWJ sequence. Strictly
        # narrower than "is an emoji": a codepoint carrying the Emoji property
        # but appearing in no registered sequence does not sanction a ZWJ beside
        # it. A ZWJ in head or tail position is never legitimate.
        def legitimate_zwj_context?(input, i)
          return false if i.zero? || i + 1 >= input.length

          Identity::EmojiZwjIntegrity.emoji_target?(input[i - 1]) &&
            Identity::EmojiZwjIntegrity.emoji_target?(input[i + 1])
        end

        # The Joining_Type of the first non-Transparent codepoint before i.
        def joining_type_before(input, i)
          j = i
          while j > 0
            j -= 1
            jt = Ucd.joining_type(input[j])
            return jt unless jt == Ucd::JoiningType::TRANSPARENT
          end
          nil
        end

        # The Joining_Type of the first non-Transparent codepoint after i.
        def joining_type_after(input, i)
          j = i + 1
          while j < input.length
            jt = Ucd.joining_type(input[j])
            return jt unless jt == Ucd::JoiningType::TRANSPARENT

            j += 1
          end
          nil
        end

        # True iff the ZWNJ at index i occupies a position where it is
        # orthographically required, by RFC 5892 Appendix A.1: it follows a
        # Virama, which is how a Devanagari conjunct is suppressed, or it sits
        # between a left- or dual-joining character and a right- or dual-joining
        # one, skipping Transparent characters on both sides, which is how a
        # Persian word boundary is written inside a cursive run.
        #
        # A ZWNJ outside such a position carries no orthographic duty and stays
        # reportable.
        def legitimate_zwnj_context?(input, i)
          return true if i > 0 && Ucd.virama?(input[i - 1])

          left = joining_type_before(input, i)
          right = joining_type_after(input, i)
          left_ok = left == Ucd::JoiningType::LEFT_JOINING ||
                    left == Ucd::JoiningType::DUAL_JOINING
          right_ok = right == Ucd::JoiningType::RIGHT_JOINING ||
                     right == Ucd::JoiningType::DUAL_JOINING
          left_ok && right_ok
        end

        def detect(input)
          zero_width_positions = []
          suspicious = []
          annotation_count = 0
          word_joiner_count = 0
          nnbsp_count = 0
          zwj_zwsp_count = 0

          input.each_with_index do |cp, i|
            next unless zero_width?(cp)

            zero_width_positions << i
            if annotation?(cp)
              annotation_count += 1
            elsif word_joiner?(cp)
              word_joiner_count += 1
            elsif nnbsp?(cp)
              nnbsp_count += 1
            elsif zwj_or_zwsp?(cp)
              zwj_zwsp_count += 1
            end
            # The sanctioning model: a ZWJ inside a registered emoji sequence
            # and a ZWNJ in an RFC 5892 CONTEXTJ-valid position both carry
            # meaning a reader depends on, so they are recorded as present but
            # not treated as suspicious.
            sanctioned = (cp == 0x200D && legitimate_zwj_context?(input, i)) ||
                         (cp == 0x200C && legitimate_zwnj_context?(input, i))
            suspicious << i unless sanctioned
          end

          if zero_width_positions.empty? || suspicious.empty?
            return Verdict.new(Calculus::ClassificationKind::CLEAR, nil, zero_width_positions)
          end

          sub =
            if annotation_count > 0
              "AnnotationMisuse"
            elsif word_joiner_count > 0
              "WordJoinerInjection"
            elsif nnbsp_count >= 2
              "AiWatermarkNNBSP"
            elsif zwj_zwsp_count >= 2
              "BinaryPayload"
            else
              "BareZeroWidth"
            end

          Verdict.new(Calculus::ClassificationKind::HAZARD, sub, zero_width_positions)
        end
      end
    end
  end
end
