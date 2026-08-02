# frozen_string_literal: true

require_relative "../identity/ucd"

module UnicodeRuby
  module Security
    module Form
      # CaseExpansionMismatch — codepoints whose UAX #21 default-locale case
      # mapping changes the codepoint count (form-layer detector).
      #
      # Byte-faithful port of the verified Rust reference implementation and of
      # its Lean source of truth.
      #
      # Threat model.  Tier A1..A2.  An attacker submits text whose case-mapped
      # form has a different codepoint count than the input.  A receiver that
      # fixes a 16-byte username column and stores `toUpper(username)` overflows
      # when the user picks "ßßßßßßßß" (8 in → 16 stored); a receiver that checks
      # `len(stored) == len(input)` rejects valid case-insensitive logins whose
      # names expand under folding.  Examples: U+00DF ß → "SS", U+FB01 ﬁ → "FI",
      # U+0130 İ → toLower "i̇" (i + U+0307).
      #
      # Distinct from LocaleCaseInversion (case mapping that changes ACROSS
      # locales): this fires on shapes whose mapping is locale-stable but
      # length-changing under the default locale itself.
      #
      # It reuses the port's own UAX #21 case mapping (`Ucd.upper_codepoint` /
      # `Ucd.lower_codepoint`, which evaluate the SpecialCasing context
      # predicates), never a host casing library.
      #
      # Sub-threats (priority order):
      #   1. UpperExpansion — first position whose default `upper_codepoint`
      #      yields > 1 cp.
      #   2. LowerExpansion — first position whose default `lower_codepoint`
      #      yields > 1 cp (reached only when no upper expansion fires first).
      module CaseExpansionMismatch
        # The sub-threat kind discriminant, in priority order.
        module SubKind
          UPPER_EXPANSION = :upper_expansion
          LOWER_EXPANSION = :lower_expansion
        end

        # A sub-threat this detector can fire.  `kind` is the discriminant;
        # `data` carries `base_pos` (position of the expanding codepoint), `cp`
        # (that codepoint), and `expansion_len` (the case-mapped length, > 1).
        # `tag` maps the discriminant to the stable wire tag with an exhaustive
        # switch, raising on the unreachable arm.
        SubThreat = Struct.new(:kind, :data) do
          def tag
            case kind
            when SubKind::UPPER_EXPANSION then "UpperExpansion"
            when SubKind::LOWER_EXPANSION then "LowerExpansion"
            else
              raise "CaseExpansionMismatch::SubThreat#tag: unknown kind #{kind.inspect}"
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
        Verdict = Struct.new(
          :input, :classify,
          :upper_expansion_count, :lower_expansion_count, :max_expansion_len
        )

        module_function

        # ── Sub-threat constructors ────────────────────────────────────────

        def upper_expansion(base_pos, cp, expansion_len)
          SubThreat.new(
            SubKind::UPPER_EXPANSION,
            { base_pos: base_pos, cp: cp, expansion_len: expansion_len }
          )
        end

        def lower_expansion(base_pos, cp, expansion_len)
          SubThreat.new(
            SubKind::LOWER_EXPANSION,
            { base_pos: base_pos, cp: cp, expansion_len: expansion_len }
          )
        end

        # ── Classification constructors ────────────────────────────────────

        def clear
          Classification.new(nil, [], [])
        end

        def hazard(sub, positions, decoded)
          Classification.new(sub, positions, decoded)
        end

        # ── Per-position expansion scan (reuse the port's own casing) ──────

        # The default-locale uppercase expansion length at position `i`,
        # evaluating the SpecialCasing context (preceding codepoints
        # nearest-first, following ones).
        def upper_len_at(input, i)
          rev_prefix = input[0...i].reverse
          suffix = input[(i + 1)..]
          Ucd.upper_codepoint(Ucd::Locale::DEFAULT, rev_prefix, suffix, input[i]).length
        end

        # The default-locale lowercase expansion length at position `i`.
        def lower_len_at(input, i)
          rev_prefix = input[0...i].reverse
          suffix = input[(i + 1)..]
          Ucd.lower_codepoint(Ucd::Locale::DEFAULT, rev_prefix, suffix, input[i]).length
        end

        # First position whose default uppercase mapping expands to > 1 cp, as
        # `[pos, cp, len]`, or nil.
        def first_upper_expansion(input)
          input.each_index do |i|
            len = upper_len_at(input, i)
            return [i, input[i], len] if len > 1
          end
          nil
        end

        # First position whose default lowercase mapping expands to > 1 cp, as
        # `[pos, cp, len]`, or nil.
        def first_lower_expansion(input)
          input.each_index do |i|
            len = lower_len_at(input, i)
            return [i, input[i], len] if len > 1
          end
          nil
        end

        def upper_expansion_count(input)
          count = 0
          input.each_index { |i| count += 1 if upper_len_at(input, i) > 1 }
          count
        end

        def lower_expansion_count(input)
          count = 0
          input.each_index { |i| count += 1 if lower_len_at(input, i) > 1 }
          count
        end

        def max_expansion_len(input)
          max = 0
          input.each_index do |i|
            len = [upper_len_at(input, i), lower_len_at(input, i)].max
            max = len if len > max
          end
          max
        end

        # ── Top-level detection ────────────────────────────────────────────

        # The CaseExpansionMismatch detection function.
        def detect(input)
          upper = first_upper_expansion(input)
          classification =
            if !upper.nil?
              pos, cp, len = upper
              hazard(upper_expansion(pos, cp, len), [pos], [])
            else
              lower = first_lower_expansion(input)
              if !lower.nil?
                pos, cp, len = lower
                hazard(lower_expansion(pos, cp, len), [pos], [])
              else
                clear
              end
            end

          Verdict.new(
            input.dup, classification,
            upper_expansion_count(input),
            lower_expansion_count(input),
            max_expansion_len(input)
          )
        end
      end
    end
  end
end
