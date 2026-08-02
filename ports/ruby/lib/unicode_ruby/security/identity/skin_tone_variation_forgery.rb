# frozen_string_literal: true

require_relative "emoji_zwj_integrity"

module UnicodeRuby
  module Security
    module Identity
      # SkinToneVariationForgery — skin-tone modifier and variation-selector
      # abuse on emoji bases per UTS #51 (identity-layer detector).
      #
      # Byte-faithful port of the verified Rust reference implementation and of
      # the corresponding identity-layer Lean specification.
      #
      # Threat model.  An adversary places a skin-tone modifier on a codepoint
      # that does NOT bear `Emoji_Modifier_Base`, stacks multiple skin-tones on
      # one base, or forces a text-style render on an emoji-default codepoint via
      # `U+FE0E` (VS15) — sometimes to hide a payload-bearing glyph in plain
      # sight.
      #
      # Distinct from VariationSelectorPayload (pair-aligned VS runs that decode
      # to bytes): this catches the orthogonal case of *semantic* VS / skin-tone
      # misuse on a single base.  Both can fire on the same input.
      #
      # Emoji property data.  Skin-tone modifiers reuse this port's own
      # `EmojiZwjIntegrity.emoji_modifier?` (the U+1F3FB..U+1F3FF set).  The
      # `Emoji_Modifier_Base` and `Emoji_Presentation` predicates parse the
      # port's already-bundled `emoji-data.txt` — the same file
      # AiWatermarkDetectability reads — with the port's own text idiom, keeping
      # only the rows whose property field matches the target property.  No host
      # emoji library, no additional data file.
      #
      # Sub-threats (priority order):
      #   1. StackedSkinTones      a base immediately followed by >= 2 skin-tone
      #                            modifiers.
      #   2. InvalidSkinToneTarget a skin-tone modifier on a
      #                            non-`Emoji_Modifier_Base` codepoint.
      #   3. ForcedTextStyle       `U+FE0E` on an `Emoji_Presentation` codepoint.
      module SkinToneVariationForgery
        # A sub-threat this detector can fire.  `kind` is the variant symbol;
        # `base_pos` is the position of the implicated base codepoint;
        # `modifiers` holds the two stacked skin-tone modifiers for
        # StackedSkinTones (empty otherwise); `base_cp` and `modifier_cp` carry
        # the base / modifier codepoints for the pair-based variants (nil when
        # unused).
        SubThreat = Struct.new(:kind, :base_pos, :modifiers, :base_cp, :modifier_cp) do
          # Fixture-row / wire tag string for this sub-threat.
          def tag
            case kind
            when :stacked_skin_tones then "StackedSkinTones"
            when :invalid_skin_tone_target then "InvalidSkinToneTarget"
            when :forced_text_style then "ForcedTextStyle"
            else raise ArgumentError, "unknown sub-threat kind: #{kind.inspect}"
            end
          end
        end

        # Top-level classification.  `sub` is nil when clear; `positions` is the
        # codepoint indices the sub-threat implicates (empty when clear);
        # `decoded` is the decoded-byte projection (always empty for this
        # detector, kept for shape parity with the Lean `Classification.hazard`).
        Classification = Struct.new(:sub, :positions, :decoded) do
          def clear?
            sub.nil?
          end

          def tag
            sub.nil? ? nil : sub.tag
          end
        end

        # The structured output of `detect` (mirrors the Lean `Verdict`).
        # `skin_tone_count` counts U+1F3FB..U+1F3FF; `variation_selector15_count`
        # counts U+FE0E; `variation_selector16_count` counts U+FE0F.
        Verdict = Struct.new(
          :input, :classify, :skin_tone_count,
          :variation_selector15_count, :variation_selector16_count
        )

        module_function

        # ── Sub-threat constructors ────────────────────────────────────────

        # A base at `base_pos` followed by >= 2 skin-tone modifiers.
        def stacked_skin_tones(base_pos, modifiers)
          SubThreat.new(:stacked_skin_tones, base_pos, modifiers, nil, nil)
        end

        # A skin-tone `modifier_cp` at `base_pos + 1` on a non-modifier-base
        # `base_cp`.
        def invalid_skin_tone_target(base_pos, base_cp, modifier_cp)
          SubThreat.new(:invalid_skin_tone_target, base_pos, [], base_cp, modifier_cp)
        end

        # A `U+FE0E` at `base_pos + 1` forcing text-style on an
        # `Emoji_Presentation` `base_cp`.
        def forced_text_style(base_pos, base_cp)
          SubThreat.new(:forced_text_style, base_pos, [], base_cp, nil)
        end

        # ── Classification constructors ────────────────────────────────────

        def clear
          Classification.new(nil, [], [])
        end

        def hazard(sub, positions, decoded)
          Classification.new(sub, positions, decoded)
        end

        # ── Emoji property tables (bundled data/emoji-data.txt) ─────────────

        # Parse a hex codepoint token, or nil when the token is not all-hex.
        def parse_hex(str)
          token = str.strip
          return nil if token.empty?
          return nil unless token.match?(/\A[0-9A-Fa-f]+\z/)

          token.to_i(16)
        end

        # Parse the closed intervals for a single emoji property from
        # emoji-data.txt.  Each non-comment row is `<range> ; <property> #
        # <comment>`; we keep only rows whose property field is exactly
        # `property`.
        def parse_emoji_property(property)
          out = []
          UnicodeRuby.read_data("emoji-data.txt").each_line do |raw|
            line = raw.chomp
            idx = line.index("#")
            body = idx.nil? ? line : line[0...idx]
            stripped = body.strip
            next if stripped.empty?

            fields = stripped.split(";")
            next if fields.length < 2
            next if fields[1].strip != property

            range = fields[0].strip
            sep = range.index("..")
            if sep
              lo = parse_hex(range[0...sep])
              hi = parse_hex(range[(sep + 2)..])
              out << [lo, hi] unless lo.nil? || hi.nil?
            else
              single = parse_hex(range)
              out << [single, single] unless single.nil?
            end
          end
          out
        end

        # Closed intervals with the `Emoji_Modifier_Base` property.
        def emoji_modifier_base_ranges
          @emoji_modifier_base_ranges ||= parse_emoji_property("Emoji_Modifier_Base")
        end

        # Closed intervals with the `Emoji_Presentation` property.
        def emoji_presentation_ranges
          @emoji_presentation_ranges ||= parse_emoji_property("Emoji_Presentation")
        end

        # ── Core predicates ────────────────────────────────────────────────

        # True iff `cp` is an emoji skin-tone modifier (reuses the port's own
        # predicate over U+1F3FB..U+1F3FF).
        def skin_tone?(cp)
          EmojiZwjIntegrity.emoji_modifier?(cp)
        end

        # True iff `cp` has `Emoji_Modifier_Base` per emoji-data.txt.
        def skin_tone_base?(cp)
          emoji_modifier_base_ranges.any? { |lo, hi| lo <= cp && cp <= hi }
        end

        # True iff `cp` has `Emoji_Presentation` per emoji-data.txt.
        def emoji_presentation?(cp)
          emoji_presentation_ranges.any? { |lo, hi| lo <= cp && cp <= hi }
        end

        # True iff `cp` is U+FE0E (VS15, text-style variation selector).
        def vs15?(cp)
          cp == 0xFE0E
        end

        # True iff `cp` is U+FE0F (VS16, emoji-style variation selector).
        def vs16?(cp)
          cp == 0xFE0F
        end

        # ── Sub-detectors ──────────────────────────────────────────────────

        # First position whose next two codepoints are both skin-tone modifiers,
        # as `[base_pos, [mod1, mod2]]`, or nil when none.
        def first_stacked_skin_tones(input)
          (0...input.length).each do |i|
            m1 = input[i + 1]
            m2 = input[i + 2]
            next if m1.nil? || m2.nil?

            return [i, [m1, m2]] if skin_tone?(m1) && skin_tone?(m2)
          end
          nil
        end

        # First skin-tone modifier whose preceding codepoint is NOT
        # `Emoji_Modifier_Base`, as `[base_pos, base_cp, modifier_cp]`, or nil.
        def first_invalid_skin_tone_target(input)
          (0...input.length).each do |i|
            cp = input[i + 1]
            next if cp.nil?

            return [i, input[i], cp] if skin_tone?(cp) && !skin_tone_base?(input[i])
          end
          nil
        end

        # First `U+FE0E` whose preceding codepoint has `Emoji_Presentation`, as
        # `[base_pos, base_cp]`, or nil when none.
        def first_forced_text_style(input)
          (0...input.length).each do |i|
            cp = input[i + 1]
            next if cp.nil?

            return [i, input[i]] if vs15?(cp) && emoji_presentation?(input[i])
          end
          nil
        end

        # Count of skin-tone modifier codepoints.
        def skin_tone_count(input)
          input.count { |cp| skin_tone?(cp) }
        end

        # Count of U+FE0E (VS15) codepoints.
        def vs15_count(input)
          input.count { |cp| vs15?(cp) }
        end

        # Count of U+FE0F (VS16) codepoints.
        def vs16_count(input)
          input.count { |cp| vs16?(cp) }
        end

        # ── Top-level detection ────────────────────────────────────────────

        # The SkinToneVariationForgery detection function.
        def detect(input)
          stc = skin_tone_count(input)
          v15 = vs15_count(input)
          v16 = vs16_count(input)

          classification = classify(input)

          Verdict.new(input.dup, classification, stc, v15, v16)
        end

        # Priority-ordered classification: StackedSkinTones outranks
        # InvalidSkinToneTarget, which outranks ForcedTextStyle, else Clear.
        def classify(input)
          stacked = first_stacked_skin_tones(input)
          unless stacked.nil?
            base_pos, modifiers = stacked
            positions = (0...modifiers.length).map { |i| base_pos + 1 + i }
            return hazard(stacked_skin_tones(base_pos, modifiers), positions, [])
          end

          invalid = first_invalid_skin_tone_target(input)
          unless invalid.nil?
            base_pos, base_cp, modifier_cp = invalid
            return hazard(invalid_skin_tone_target(base_pos, base_cp, modifier_cp), [base_pos + 1], [])
          end

          forced = first_forced_text_style(input)
          unless forced.nil?
            base_pos, base_cp = forced
            return hazard(forced_text_style(base_pos, base_cp), [base_pos + 1], [])
          end

          clear
        end
      end
    end
  end
end
