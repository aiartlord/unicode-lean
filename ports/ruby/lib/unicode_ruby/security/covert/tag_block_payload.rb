# frozen_string_literal: true

module UnicodeRuby
  module Security
    module Covert
      # Detection of invisible payloads encoded in the Unicode tag block
      # U+E0000..U+E007F.  Every tag-block occurrence is reportable; the
      # detector attributes the kind of use.
      module TagBlockPayload
        # Structured verdict.  `kind` is a ClassificationKind; `sub` is the
        # sub-threat tag string (or nil for a clear input); `tag_positions`
        # holds the tag-block codepoint offsets; `recovered_ascii` is the
        # decoded ASCII payload.
        Verdict = Struct.new(:kind, :sub, :tag_positions, :recovered_ascii)

        module_function

        def tag_character?(cp)
          cp >= 0xE0000 && cp <= 0xE007F
        end

        def language_tag?(cp)
          cp == 0xE0001
        end

        def cancel_tag?(cp)
          cp == 0xE007F
        end

        # Decode a tag-block codepoint to its ASCII correspondent, or nil.
        def tag_to_ascii(cp)
          return nil unless cp >= 0xE0020 && cp <= 0xE007E

          (cp - 0xE0000).chr(Encoding::UTF_8)
        end

        def decode_tag_run(input, positions)
          s = +""
          positions.each do |p|
            next unless p < input.length

            c = tag_to_ascii(input[p])
            s << c unless c.nil?
          end
          s
        end

        def has_language_tag_prefix(input, tag_positions)
          lang_pos = tag_positions.first
          return nil if lang_pos.nil?
          return nil if lang_pos >= input.length

          if language_tag?(input[lang_pos]) && tag_positions.length >= 2
            lang_pos
          end
        end

        # Priority order (highest first): LanguageTagRevival, DirectAscii,
        # MixedBlock, BareTagPresent.
        def pick_sub_threat(input, tag_positions, decoded)
          lang_pos = has_language_tag_prefix(input, tag_positions)
          return "LanguageTagRevival" unless lang_pos.nil?

          if input.all? { |cp| tag_character?(cp) } && !decoded.empty?
            return "DirectAscii"
          end
          return "MixedBlock" if input.length > tag_positions.length

          "BareTagPresent"
        end

        def detect(input)
          tag_positions = []
          input.each_with_index { |cp, i| tag_positions << i if tag_character?(cp) }

          if tag_positions.empty?
            return Verdict.new(Calculus::ClassificationKind::CLEAR, nil, [], "")
          end

          decoded = decode_tag_run(input, tag_positions)
          sub = pick_sub_threat(input, tag_positions, decoded)
          Verdict.new(Calculus::ClassificationKind::HAZARD, sub, tag_positions, decoded)
        end
      end
    end
  end
end
