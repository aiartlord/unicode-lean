# frozen_string_literal: true

require_relative "../covert/variation_selector_payload"
require_relative "../identity/emoji_zwj_integrity"
require_relative "../identity/ucd"
require_relative "../../segmentation/grapheme"

module UnicodeRuby
  module Security
    module Display
      # RendererDivergence — detection of codepoint/sequence shapes known to
      # render differently across font + terminal + browser stacks (the
      # display-layer detector).
      #
      # Byte-faithful port of the verified Rust reference
      # (`ports/rust/src/security/display/renderer_divergence.rs`) and of
      # `Unicode/Security/Display/RendererDivergence.lean`.
      #
      # Threat model.  An adversary crafts content that renders one way in the
      # auditor's renderer (a benign glyph or an empty span) and a different way
      # in the consumer's renderer (a misleading glyph, a wider glyph, or a
      # different sequence).  This is the "fingerprint stability" family: clear
      # inputs render the same across the renderer cohort the Standard documents
      # as stable.
      #
      # What the detector draws.  A heuristic three-value split, surfaced through
      # the universal clear/hazard carrier.  An input is clear when none of the
      # documented variance triggers fire, and otherwise is classified by the
      # first trigger in priority order.  It reuses the port's own tables — the
      # variation-selector set (`Covert::VariationSelectorPayload`), the grapheme
      # Extend class (`Segmentation::Grapheme`), the RGI ZWJ registry
      # (`Identity::EmojiZwjIntegrity`), and strong-bidi classes (`Ucd`) — never a
      # host rendering or shaping library.
      #
      # Sub-threats (priority order):
      #   1. CombiningStackOverflow    Zalgo-like combining-mark stack >= 4 on a
      #                                base.
      #   2. VariationSelectorVariance any variation selector present.
      #   3. UnregisteredZwjVariance   ZWJ-containing input not in the RGI ZWJ
      #                                set.
      #   4. FullwidthVariance         a fullwidth/halfwidth codepoint present.
      #   5. MixedDirectionVariance    both strong-LTR and strong-RTL codepoints.
      module RendererDivergence
        # The combining-mark stack depth (on a single base) at or beyond which
        # the input is treated as a Zalgo-style rendering-variance hazard.
        MIN_COMBINING_STACK = 4

        # The ZERO WIDTH JOINER codepoint.
        ZWJ = 0x200D

        # A sub-threat this detector can fire.  `tag` is the fixture-row / wire
        # tag string; `data` carries the variant-specific position payload
        # (`base_pos` + `stack_len`, `first_vs_pos` + `first_vs_cp`,
        # `first_zwj_pos`, `first_fw_pos` + `first_fw_cp`, or `ltr_count` +
        # `rtl_count`).
        SubThreat = Struct.new(:tag, :data)

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
          :input, :classify, :vs_count, :combining_count, :fullwidth_count,
          :has_zwj, :strong_ltr_count, :strong_rtl_count
        )

        module_function

        # ── Sub-threat constructors ────────────────────────────────────────

        # A combining-mark stack of `stack_len` marks on the base at `base_pos`.
        def combining_stack_overflow(base_pos, stack_len)
          SubThreat.new("CombiningStackOverflow", { base_pos: base_pos, stack_len: stack_len })
        end

        # A variation selector at `first_vs_pos` (codepoint `first_vs_cp`).
        def variation_selector_variance(first_vs_pos, first_vs_cp)
          SubThreat.new("VariationSelectorVariance", { first_vs_pos: first_vs_pos, first_vs_cp: first_vs_cp })
        end

        # A ZWJ-containing input not present in the registered RGI ZWJ set.
        def unregistered_zwj_variance(first_zwj_pos)
          SubThreat.new("UnregisteredZwjVariance", { first_zwj_pos: first_zwj_pos })
        end

        # A fullwidth/halfwidth codepoint at `first_fw_pos` (codepoint
        # `first_fw_cp`).
        def fullwidth_variance(first_fw_pos, first_fw_cp)
          SubThreat.new("FullwidthVariance", { first_fw_pos: first_fw_pos, first_fw_cp: first_fw_cp })
        end

        # Both strong-LTR and strong-RTL codepoints in one input.
        def mixed_direction_variance(ltr_count, rtl_count)
          SubThreat.new("MixedDirectionVariance", { ltr_count: ltr_count, rtl_count: rtl_count })
        end

        # ── Classification constructors ────────────────────────────────────

        def clear
          Classification.new(nil, [], [])
        end

        def hazard(sub, positions, decoded)
          Classification.new(sub, positions, decoded)
        end

        # ── Core predicates (reuse the port's own tables) ──────────────────

        # True iff `cp` is a variation selector (reuses the port's predicate).
        def variation_selector?(cp)
          Covert::VariationSelectorPayload.variation_selector?(cp)
        end

        # True iff `cp` is the ZWJ codepoint.
        def zwj?(cp)
          cp == ZWJ
        end

        # True iff `cp` is in the Halfwidth/Fullwidth Forms block.
        def fullwidth_halfwidth?(cp)
          cp >= 0xFF01 && cp <= 0xFFEF
        end

        # True iff `cp` has Grapheme_Cluster_Break = Extend (reuses the port's
        # UAX #29 grapheme table).
        def grapheme_extend?(cp)
          Segmentation::Grapheme.lookup_gcb(cp) == :extend
        end

        # ── Sub-detectors ──────────────────────────────────────────────────

        def count_vs(input)
          input.count { |cp| variation_selector?(cp) }
        end

        def count_combining(input)
          input.count { |cp| grapheme_extend?(cp) }
        end

        def count_fullwidth(input)
          input.count { |cp| fullwidth_halfwidth?(cp) }
        end

        def input_has_zwj(input)
          input.any? { |cp| zwj?(cp) }
        end

        def count_strong_ltr(input)
          input.count { |cp| Ucd.strong_ltr?(cp) }
        end

        def count_strong_rtl(input)
          input.count { |cp| Ucd.strong_rtl?(cp) }
        end

        # Position and codepoint of the first variation selector, or nil.
        def first_vs_pos(input)
          input.each_index do |idx|
            return [idx, input[idx]] if variation_selector?(input[idx])
          end
          nil
        end

        # Position of the first ZWJ, or nil.
        def first_zwj_pos(input)
          input.each_index do |idx|
            return idx if zwj?(input[idx])
          end
          nil
        end

        # Position and codepoint of the first fullwidth/halfwidth codepoint, or
        # nil.
        def first_fullwidth_pos(input)
          input.each_index do |idx|
            return [idx, input[idx]] if fullwidth_halfwidth?(input[idx])
          end
          nil
        end

        # The first base position (a non-Extend codepoint) immediately followed
        # by exactly `min_stack` consecutive Extend codepoints.  Returns
        # `[base_pos, min_stack]` on hit, nil otherwise.
        def first_combining_stack(input, min_stack)
          input.each_index do |idx|
            next if grapheme_extend?(input[idx])

            following = input[(idx + 1), min_stack] || []
            if following.length == min_stack && following.all? { |c| grapheme_extend?(c) }
              return [idx, min_stack]
            end
          end
          nil
        end

        # ── Top-level detection ────────────────────────────────────────────

        # The RendererDivergence detection function.
        def detect(input)
          vs_count = count_vs(input)
          combining_count = count_combining(input)
          fullwidth_count = count_fullwidth(input)
          has_zwj = input_has_zwj(input)
          ltr_count = count_strong_ltr(input)
          rtl_count = count_strong_rtl(input)

          Verdict.new(
            input.dup, classify(input, has_zwj, ltr_count, rtl_count),
            vs_count, combining_count, fullwidth_count, has_zwj,
            ltr_count, rtl_count
          )
        end

        # The priority ladder, factored out of `detect`.
        def classify(input, has_zwj, ltr_count, rtl_count)
          # Priority 1: combining-mark stack overflow (Zalgo).
          stack = first_combining_stack(input, MIN_COMBINING_STACK)
          unless stack.nil?
            base_pos, stack_len = stack
            return hazard(combining_stack_overflow(base_pos, stack_len), [base_pos], [])
          end

          # Priority 2: any variation selector triggers presentation variance.
          vs = first_vs_pos(input)
          unless vs.nil?
            pos, cp = vs
            return hazard(variation_selector_variance(pos, cp), [pos], [])
          end

          # Priority 3: ZWJ-containing input not in the registered RGI set.
          if has_zwj && !Identity::EmojiZwjIntegrity.registered_zwj_sequence?(input)
            zwj_pos = first_zwj_pos(input)
            return hazard(unregistered_zwj_variance(zwj_pos), [zwj_pos], []) unless zwj_pos.nil?

            return clear
          end

          # Priority 4: fullwidth/halfwidth.
          fw = first_fullwidth_pos(input)
          unless fw.nil?
            pos, cp = fw
            return hazard(fullwidth_variance(pos, cp), [pos], [])
          end

          # Priority 5: mixed direction.
          if ltr_count.positive? && rtl_count.positive?
            return hazard(mixed_direction_variance(ltr_count, rtl_count), [], [])
          end

          clear
        end
      end
    end
  end
end
