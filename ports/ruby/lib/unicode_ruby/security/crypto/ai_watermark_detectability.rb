# frozen_string_literal: true

require_relative "../identity/ucd"

module UnicodeRuby
  module Security
    module Crypto
      # ai-watermark-detectability: character-level detector for inputs carrying
      # codepoint patterns consistent with a known AI watermark scheme.  Answers
      # the question: does this input contain markers attributable to a
      # watermarking protocol?
      #
      # Direct port of `Unicode/Security/Crypto/AiWatermarkDetectability.lean`
      # (and the verified Rust reference).
      #
      # Threat model — provenance-attribution attacker.  An input either (a)
      # carries an AI provider's watermark codepoints (a legitimate provenance
      # marker) or (b) carries injected markers that impersonate a provider's
      # scheme to discredit the content as AI-generated.  Character-level
      # detection alone cannot distinguish (a) from (b); the detector reports the
      # matched scheme and leaves provider-specific authentication to downstream
      # code.
      #
      # Probe inventory (priority order, first match wins):
      #
      #   1. adversarial              — NNBSP count >= 3 at arithmetic-progression positions.
      #   2. gpt5ZwspModulo           — ZWSP count >= 3 at arithmetic-progression positions.
      #   3. unknown                  — invisible markers from >= 2 distinct categories.
      #   4. nnbspBoundary            — single-category NNBSP.
      #   5. variationSelectorCarrier — VS NOT adjacent to an emoji codepoint.
      #   6. zwjNonEmoji              — ZWJ NOT adjacent to an emoji codepoint.
      #   7. smartQuoteAlternation    — paired curly quotes, no ASCII straight quotes.
      #   8. emDashPattern            — em-dashes, no ASCII hyphen-minus.
      #   9. statisticalTokenChoice   — input contains an AI-favored lexical pattern.
      #  10. defaultIgnorableCarrier  — single-category residual Default_Ignorable.
      #
      # The Emoji property table is bundled in the port's own
      # `data/emoji-data.txt` (UTS #51 17.0, byte-identical to the UCD source the
      # Lean spec cites); the adjacency probe parses the `Emoji` rows from it,
      # never a host emoji library.  Default_Ignorable membership reuses the
      # port's own UCD table via `Ucd.default_ignorable?`, never a host
      # normalizer.
      module AiWatermarkDetectability
        # The conceptual watermark cue class a sub-threat probes for, drawn from
        # the fixed vocabulary in
        # `Unicode.Generated.WatermarkSchemes.CueClass`.  Mirrored here because
        # the port exposes no generated watermark-schemes module.
        module CueClass
          # A codepoint-frequency bias toward a pinned "green list" of tokens.
          GREEN_LIST_BIAS = :green_list_bias
          # A fixed-period or carrier-byte channel surfacing a pseudorandom function.
          PSEUDORANDOM_SEQ = :pseudorandom_seq
          # A stylistic-distribution drift away from natural human writing.
          SEMANTIC_DRIFT = :semantic_drift
        end

        # A sub-threat this detector can fire.  `tag` is the human-facing
        # classification tag; `data` carries the variant-specific position
        # payload (`marker_count`, `first_pos`, `anomaly_marker`, and — for
        # `Adversarial` — `impersonated_scheme`).
        SubThreat = Struct.new(:tag, :data)

        # Top-level classification.  `sub` is nil when clear; `positions` is the
        # list of codepoint indices the sub-threat implicates (empty when clear).
        Classification = Struct.new(:sub, :positions) do
          def clear?
            sub.nil?
          end

          def tag
            sub.nil? ? nil : sub.tag
          end
        end

        # The structured output of `detect`.  `marker_count` is the count of
        # codepoints matching the fired scheme's probe (0 when clear).
        Verdict = Struct.new(:input, :classify, :marker_count)

        # Optional context for the modulo-probe tolerances.  Each field controls
        # how strictly the corresponding probe checks its arithmetic-progression
        # condition; the defaults of `0` require exact equality of consecutive
        # gaps.  A nil field reads as `0`, so `Context.new` is the exact-equality
        # identity context and `detect_with_context(Context.new, input)` equals
        # `detect(input)`.
        Context = Struct.new(:zwsp_modulo_tolerance, :adversarial_tolerance) do
          # ZWSP-modulo tolerance.  `0` requires the ZWSP-position arithmetic
          # progression to be exact.  `k > 0` accepts position gaps within +/- k
          # of the first gap, catching modulo schedules with light jitter.
          def zwsp_tolerance
            zwsp_modulo_tolerance || 0
          end

          # NNBSP-arithmetic tolerance (the `adversarial` probe).  Same semantic
          # as `zwsp_tolerance` but for the NNBSP positions.
          def adversarial_tolerance_or_zero
            adversarial_tolerance || 0
          end
        end

        module_function

        # ── Sub-threat constructors ────────────────────────────────────────

        # Single-category NNBSP (U+202F) markers; `marker_count` is how many.
        def nnbsp_boundary(marker_count)
          SubThreat.new("NnbspBoundary", { marker_count: marker_count })
        end

        # Variation selector(s) not adjacent to an emoji; `marker_count` is how many.
        def variation_selector_carrier(marker_count)
          SubThreat.new("VariationSelectorCarrier", { marker_count: marker_count })
        end

        # ZWJ(s) not adjacent to an emoji; `marker_count` is how many.
        def zwj_non_emoji(marker_count)
          SubThreat.new("ZwjNonEmoji", { marker_count: marker_count })
        end

        # Residual Default_Ignorable markers; `marker_count` is how many.
        def default_ignorable_carrier(marker_count)
          SubThreat.new("DefaultIgnorableCarrier", { marker_count: marker_count })
        end

        # ZWSP (U+200B) markers at arithmetic-progression positions; `first_pos`
        # is the first ZWSP position.
        def gpt5_zwsp_modulo(first_pos)
          SubThreat.new("Gpt5ZwspModulo", { first_pos: first_pos })
        end

        # Em-dash (U+2014) stylistic signature; `first_pos` is the first em-dash.
        def em_dash_pattern(first_pos)
          SubThreat.new("EmDashPattern", { first_pos: first_pos })
        end

        # Paired curly-quote stylistic signature; `first_pos` is the first quote.
        def smart_quote_alternation(first_pos)
          SubThreat.new("SmartQuoteAlternation", { first_pos: first_pos })
        end

        # AI-favored lexical pattern hit; `first_pos` is the match start.
        def statistical_token_choice(first_pos)
          SubThreat.new("StatisticalTokenChoice", { first_pos: first_pos })
        end

        # Over-regular marker placement impersonating a scheme;
        # `impersonated_scheme` names the surfaced scheme, `first_pos` the first
        # marker position.
        def adversarial(impersonated_scheme, first_pos)
          SubThreat.new("Adversarial", { impersonated_scheme: impersonated_scheme, first_pos: first_pos })
        end

        # Multi-category invisible-marker mixing; `anomaly_marker` is the total
        # invisible-marker count (attribution to a single scheme fails).
        def unknown(anomaly_marker)
          SubThreat.new("Unknown", { anomaly_marker: anomaly_marker })
        end

        # Map a sub-threat to the conceptual watermark cue class it probes for.
        # Marker-encoded sub-threats route to `PseudorandomSeq`; vocabulary-bias
        # to `GreenListBias`; stylistic-distribution to `SemanticDrift`;
        # `Unknown` (multi-category mixing) implicates no single scheme.
        def cue_class(sub)
          case sub.tag
          when "NnbspBoundary", "VariationSelectorCarrier", "ZwjNonEmoji",
               "DefaultIgnorableCarrier", "Gpt5ZwspModulo", "Adversarial"
            CueClass::PSEUDORANDOM_SEQ
          when "EmDashPattern", "SmartQuoteAlternation"
            CueClass::SEMANTIC_DRIFT
          when "StatisticalTokenChoice"
            CueClass::GREEN_LIST_BIAS
          when "Unknown"
            nil
          else
            raise "cue_class: unknown sub-threat #{sub.tag.inspect}"
          end
        end

        # ── Classification constructors ────────────────────────────────────

        def clear
          Classification.new(nil, [])
        end

        def hazard(sub, positions)
          Classification.new(sub, positions)
        end

        # ── Emoji property table (bundled data/emoji-data.txt, Emoji rows) ──

        # Parse the `Emoji` (`Emoji=Yes`) closed intervals from emoji-data.txt.
        # Each non-comment row is `<range> ; <property> # <comment>`; we keep
        # only rows whose property is exactly `Emoji`.
        def emoji_ranges
          @emoji_ranges ||= parse_emoji_ranges
        end

        def parse_emoji_ranges
          out = []
          UnicodeRuby.read_data("emoji-data.txt").each_line do |raw|
            line = raw.chomp
            idx = line.index("#")
            body = idx.nil? ? line : line[0...idx]
            stripped = body.strip
            next if stripped.empty?

            fields = stripped.split(";")
            next if fields.length < 2
            next if fields[1].strip != "Emoji"

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

        # Parse a hex codepoint token, or nil when the token is not all-hex.
        def parse_hex(str)
          token = str.strip
          return nil if token.empty?
          return nil unless token.match?(/\A[0-9A-Fa-f]+\z/)

          token.to_i(16)
        end

        # True iff `cp` has the `Emoji = Yes` property per emoji-data.txt.
        def emoji?(cp)
          emoji_ranges.any? { |lo, hi| lo <= cp && cp <= hi }
        end

        # ── Codepoint probes ───────────────────────────────────────────────

        # True iff `cp` is U+202F NARROW NO-BREAK SPACE.
        def nnbsp?(cp)
          cp == 0x202F
        end

        # True iff `cp` is U+200D ZERO WIDTH JOINER.
        def zwj?(cp)
          cp == 0x200D
        end

        # True iff `cp` is a Variation Selector — the basic block U+FE00..U+FE0F
        # (VS1..VS16) or the Plane-14 IVS block U+E0100..U+E01EF (VS17..VS256).
        def variation_selector?(cp)
          (cp >= 0xFE00 && cp <= 0xFE0F) || (cp >= 0xE0100 && cp <= 0xE01EF)
        end

        # True iff `cp` is Default_Ignorable_Code_Point per
        # DerivedCoreProperties.txt.  Reuses the port's own UCD table, never a
        # host normalizer.
        def default_ignorable?(cp)
          Ucd.default_ignorable?(cp)
        end

        # True iff `cp` is U+200B ZERO WIDTH SPACE.
        def zwsp?(cp)
          cp == 0x200B
        end

        # True iff `cp` is U+2014 EM DASH.
        def em_dash?(cp)
          cp == 0x2014
        end

        # True iff `cp` is U+002D HYPHEN-MINUS (ASCII).
        def hyphen_minus?(cp)
          cp == 0x002D
        end

        # True iff `cp` is one of the four "curly" quotation marks: U+2018 /
        # U+2019 (single open/close) and U+201C / U+201D (double open/close).
        def curly_quote?(cp)
          cp == 0x2018 || cp == 0x2019 || cp == 0x201C || cp == 0x201D
        end

        # True iff `cp` is an ASCII straight quote — U+0022 (double) or U+0027
        # (single / apostrophe).
        def straight_quote?(cp)
          cp == 0x0022 || cp == 0x0027
        end

        # True iff `input[i]` is adjacent (immediate predecessor OR immediate
        # successor) to an emoji codepoint.  Two-sided check, single pass.  Used
        # by the VS and ZWJ probes to exclude legitimate emoji-context
        # occurrences.
        def adjacent_to_emoji?(input, i)
          prev_is_emoji = i.positive? && !input[i - 1].nil? && emoji?(input[i - 1])
          next_cp = input[i + 1]
          next_is_emoji = !next_cp.nil? && emoji?(next_cp)
          prev_is_emoji || next_is_emoji
        end

        # All positions in `input` for which the block is true.
        def all_positions(input)
          out = []
          input.each_index { |i| out << i if yield(input[i]) }
          out
        end

        # True iff `positions` forms an arithmetic progression with all
        # consecutive gaps within `tolerance` of the first gap.  Empty +
        # singleton lists are vacuously arithmetic.  `positions` is assumed
        # ascending (produced by `all_positions`), so gaps are non-negative.
        def positions_arithmetic_within?(positions, tolerance)
          return true if positions.length < 2

          first_gap = positions[1] - positions[0]
          (0...(positions.length - 1)).all? do |i|
            gap = positions[i + 1] - positions[i]
            gap <= first_gap + tolerance && first_gap <= gap + tolerance
          end
        end

        # First start-position at which `pattern` appears as a contiguous
        # sub-slice of `input`, or nil if absent.
        def contains_sublist(pattern, input)
          return nil if pattern.empty? || pattern.length > input.length

          max_start = input.length - pattern.length
          (0..max_start).each do |start|
            return start if input[start, pattern.length] == pattern
          end
          nil
        end

        # The "AI-favored" lexical-pattern catalog (each word as its codepoint
        # sequence), transcribed verbatim from the pinned `aiFavoredVocabulary`
        # literal in the Lean spec (parsed from
        # `Ucd/Security/AiFavoredVocabulary.txt` and drift-gated there against a
        # fresh parse).
        def ai_favored_vocabulary
          [
            [100, 101, 108, 118, 101],
            [100, 101, 108, 118, 105, 110, 103],
            [116, 97, 112, 101, 115, 116, 114, 121],
            [105, 110, 116, 114, 105, 99, 97, 116, 101],
            [110, 117, 97, 110, 99, 101, 100],
            [109, 111, 114, 101, 111, 118, 101, 114],
            [102, 117, 114, 116, 104, 101, 114, 109, 111, 114, 101],
            [114, 101, 97, 108, 109],
            [101, 108, 117, 99, 105, 100, 97, 116, 101],
            [115, 104, 111, 119, 99, 97, 115, 105, 110, 103],
            [117, 110, 100, 101, 114, 115, 99, 111, 114, 101, 115],
            [117, 110, 100, 101, 114, 115, 99, 111, 114, 101, 100],
            [112, 105, 118, 111, 116, 97, 108],
            [98, 111, 108, 115, 116, 101, 114],
            [109, 117, 108, 116, 105, 102, 97, 99, 101, 116, 101, 100],
            [116, 101, 115, 116, 97, 109, 101, 110, 116],
            [102, 111, 115, 116, 101, 114],
            [104, 111, 108, 105, 115, 116, 105, 99],
            [112, 97, 114, 97, 100, 105, 103, 109],
            [116, 114, 97, 110, 115, 102, 111, 114, 109, 97, 116, 105, 118, 101],
            [115, 112, 101, 97, 114, 104, 101, 97, 100],
            [109, 101, 116, 105, 99, 117, 108, 111, 117, 115],
            [109, 101, 116, 105, 99, 117, 108, 111, 117, 115, 108, 121],
            [101, 109, 112, 111, 119, 101, 114],
            [101, 109, 112, 111, 119, 101, 114, 105, 110, 103],
            [112, 114, 111, 102, 111, 117, 110, 100],
            [112, 114, 111, 102, 111, 117, 110, 100, 108, 121],
            [99, 111, 109, 112, 101, 108, 108, 105, 110, 103],
            [99, 111, 109, 112, 114, 101, 104, 101, 110, 115, 105, 118, 101],
            [99, 114, 117, 99, 105, 97, 108],
            [100, 97, 117, 110, 116, 105, 110, 103],
            [114, 111, 98, 117, 115, 116],
            [115, 116, 114, 101, 97, 109, 108, 105, 110, 101],
            [101, 110, 114, 105, 99, 104],
            [101, 120, 101, 109, 112, 108, 105, 102, 121],
            [99, 97, 112, 116, 105, 118, 97, 116, 105, 110, 103],
            [100, 105, 115, 99, 101, 114, 110, 105, 110, 103],
            [109, 101, 115, 109, 101, 114, 105, 122, 101],
            [105, 110, 116, 114, 105, 99, 97, 116, 101, 108, 121],
            [105, 109, 98, 117, 101],
            [112, 108, 97, 121, 115, 32, 97, 32, 99, 114, 117, 99, 105, 97, 108, 32, 114, 111, 108, 101],
            [112, 108, 97, 121, 115, 32, 97, 32, 112, 105, 118, 111, 116, 97, 108, 32, 114, 111, 108, 101],
            [105, 116, 32, 105, 115, 32, 105, 109, 112, 111, 114, 116, 97, 110, 116, 32, 116, 111, 32, 110, 111, 116, 101],
            [105, 116, 32, 105, 115, 32, 119, 111, 114, 116, 104, 32, 110, 111, 116, 105, 110, 103],
            [105, 110, 32, 99, 111, 110, 99, 108, 117, 115, 105, 111, 110],
            [105, 110, 32, 101, 115, 115, 101, 110, 99, 101],
            [100, 101, 108, 118, 101, 32, 105, 110, 116, 111],
            [100, 101, 108, 118, 105, 110, 103, 32, 105, 110, 116, 111],
            [116, 97, 112, 101, 115, 116, 114, 121, 32, 111, 102],
            [114, 101, 97, 108, 109, 32, 111, 102]
          ]
        end

        # ── Top-level detection ────────────────────────────────────────────

        # The detection function.  Runs every probe in the fixed priority order
        # (most-specific first); the first hit wins.  See the module header for
        # the probe inventory and the ordering rationale.
        def detect_with_context(ctx, input)
          nnbsp_positions = all_positions(input) { |cp| nnbsp?(cp) }
          nnbsp_count = nnbsp_positions.length

          # Probe 1: adversarial — NNBSP too-regular.
          adversarial_fires = nnbsp_count >= 3 &&
                              positions_arithmetic_within?(nnbsp_positions, ctx.adversarial_tolerance_or_zero)

          # Probe 2: gpt5ZwspModulo — ZWSP arithmetic progression.
          zwsp_positions = all_positions(input) { |cp| zwsp?(cp) }
          zwsp_count = zwsp_positions.length
          zwsp_modulo_fires = zwsp_count >= 3 &&
                             positions_arithmetic_within?(zwsp_positions, ctx.zwsp_tolerance)

          vs_all_pos = all_positions(input) { |cp| variation_selector?(cp) }
          vs_non_emoji_pos = vs_all_pos.reject { |i| adjacent_to_emoji?(input, i) }
          vs_non_emoji_count = vs_non_emoji_pos.length

          zwj_all_pos = all_positions(input) { |cp| zwj?(cp) }
          zwj_non_emoji_pos = zwj_all_pos.reject { |i| adjacent_to_emoji?(input, i) }
          zwj_non_emoji_count = zwj_non_emoji_pos.length

          # Probe 7: smartQuoteAlternation — curly quotes only.
          curly_positions = all_positions(input) { |cp| curly_quote?(cp) }
          curly_count = curly_positions.length
          has_straight_quote = input.any? { |cp| straight_quote?(cp) }
          smart_quote_fires = curly_count >= 2 && !has_straight_quote

          # Probe 8: emDashPattern — em-dashes without hyphen-minus.
          em_dash_positions = all_positions(input) { |cp| em_dash?(cp) }
          em_dash_count = em_dash_positions.length
          has_hyphen_minus = input.any? { |cp| hyphen_minus?(cp) }
          em_dash_fires = em_dash_count >= 2 && !has_hyphen_minus

          # Probe 9: statisticalTokenChoice — scan the pinned vocabulary.  Each
          # word is compared as a contiguous sub-slice of the input.
          vocab_hit = nil
          ai_favored_vocabulary.each do |pattern|
            pos = contains_sublist(pattern, input)
            unless pos.nil?
              vocab_hit = pos
              break
            end
          end

          # Residual default-ignorables (excluding VS and ZWJ, handled above).
          di_positions = all_positions(input) do |cp|
            default_ignorable?(cp) && !variation_selector?(cp) && !zwj?(cp)
          end
          di_count = di_positions.length

          # Probe 3: unknown — invisible markers from >= 2 distinct categories.
          category_count = (nnbsp_count.positive? ? 1 : 0) +
                           (vs_non_emoji_count.positive? ? 1 : 0) +
                           (zwj_non_emoji_count.positive? ? 1 : 0) +
                           (di_count.positive? ? 1 : 0)
          unknown_fires = category_count >= 2
          total_invisible_count = nnbsp_count + vs_non_emoji_count + zwj_non_emoji_count + di_count

          classification, fired_count =
            if adversarial_fires
              first_pos = nnbsp_positions.first || 0
              [hazard(adversarial("nnbspBoundary", first_pos), nnbsp_positions), nnbsp_count]
            elsif zwsp_modulo_fires
              first_pos = zwsp_positions.first || 0
              [hazard(gpt5_zwsp_modulo(first_pos), zwsp_positions), zwsp_count]
            elsif unknown_fires
              all_invisible_pos = all_positions(input) do |cp|
                nnbsp?(cp) || variation_selector?(cp) || zwj?(cp) || default_ignorable?(cp)
              end
              [hazard(unknown(total_invisible_count), all_invisible_pos), total_invisible_count]
            elsif nnbsp_count.positive?
              [hazard(nnbsp_boundary(nnbsp_count), nnbsp_positions), nnbsp_count]
            elsif vs_non_emoji_count.positive?
              [hazard(variation_selector_carrier(vs_non_emoji_count), vs_non_emoji_pos), vs_non_emoji_count]
            elsif zwj_non_emoji_count.positive?
              [hazard(zwj_non_emoji(zwj_non_emoji_count), zwj_non_emoji_pos), zwj_non_emoji_count]
            elsif smart_quote_fires
              first_pos = curly_positions.first || 0
              [hazard(smart_quote_alternation(first_pos), curly_positions), curly_count]
            elsif em_dash_fires
              first_pos = em_dash_positions.first || 0
              [hazard(em_dash_pattern(first_pos), em_dash_positions), em_dash_count]
            elsif !vocab_hit.nil?
              [hazard(statistical_token_choice(vocab_hit), [vocab_hit]), 1]
            elsif di_count.positive?
              [hazard(default_ignorable_carrier(di_count), di_positions), di_count]
            else
              [clear, 0]
            end

          Verdict.new(input.dup, classification, fired_count)
        end

        # Convenience wrapper over `detect_with_context` with the empty context —
        # exact-arithmetic settings (`zwsp_modulo_tolerance = 0`,
        # `adversarial_tolerance = 0`).
        def detect(input)
          detect_with_context(Context.new, input)
        end
      end
    end
  end
end
