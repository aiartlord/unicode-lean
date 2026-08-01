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

        def detect(input)
          zero_width_positions = []
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
          end

          if zero_width_positions.empty?
            return Verdict.new(Calculus::ClassificationKind::CLEAR, nil, [])
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
