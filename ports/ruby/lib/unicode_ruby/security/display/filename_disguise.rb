# frozen_string_literal: true

require_relative "../covert/bidi_control_balance"
require_relative "../../segmentation/grapheme"

module UnicodeRuby
  module Security
    module Display
      # FilenameDisguise — detection of filename/extension disguise attacks
      # where the visible extension differs from the byte extension (the
      # display-layer detector).
      #
      # Byte-faithful port of the verified Rust reference implementation and of
      # its Lean source of truth.
      #
      # Threat model.  An adversary delivers a file whose rendered name looks
      # like a benign type (`document.txt`) but whose actual byte extension is
      # executable — the canonical attack inserts U+202E RIGHT-TO-LEFT OVERRIDE
      # so `document<RLO>txt.exe` renders as `document exe.txt`.
      #
      # Detection is presentation- and language-agnostic: it surfaces every
      # codepoint that could cause display-vs-byte divergence in the filename —
      # any bidi format-control anywhere, and any fullwidth/halfwidth or
      # combining (grapheme Extend) codepoint in the extension region (after the
      # last `.`).  Native-RTL names with no bidi controls clear.  It reuses the
      # port's own predicates — the bidi format-control set
      # (`Covert::BidiControlBalance`), the grapheme Extend class
      # (`Segmentation::Grapheme`), and the inline fullwidth range — never a host
      # filesystem or rendering library.
      #
      # Sub-threats (priority order):
      #   1. RloFlip            any bidi format-control in the input.
      #   2. WidthClassExt      a fullwidth/halfwidth codepoint in the extension.
      #   3. CombiningInExt     a combining (Extend) codepoint in the extension.
      #   4. MultipleExtensions >= 3 dots (advisory; e.g. `.tar.gz.sig`).
      module FilenameDisguise
        # The three-or-more-dot bound at which the advisory MultipleExtensions
        # sub-threat fires.
        MIN_EXTENSION_DOTS = 3

        # The sub-threat kind discriminants, in priority order.  Each maps to a
        # stable fixture-row / wire tag through `SubThreat#tag`.
        module SubKind
          RLO_FLIP = :rlo_flip
          WIDTH_CLASS_EXT = :width_class_ext
          COMBINING_IN_EXT = :combining_in_ext
          MULTIPLE_EXTENSIONS = :multiple_extensions
        end

        # A sub-threat this detector can fire.  `kind` is the discriminant;
        # `data` carries the variant-specific payload (`position` + `control_cp`
        # for RloFlip, `position` + `cp` for WidthClassExt / CombiningInExt,
        # `dot_count` for MultipleExtensions).  `tag` maps the discriminant to
        # the stable wire tag with an exhaustive switch.
        SubThreat = Struct.new(:kind, :data) do
          def tag
            case kind
            when SubKind::RLO_FLIP then "RloFlip"
            when SubKind::WIDTH_CLASS_EXT then "WidthClassExt"
            when SubKind::COMBINING_IN_EXT then "CombiningInExt"
            when SubKind::MULTIPLE_EXTENSIONS then "MultipleExtensions"
            else
              raise "FilenameDisguise::SubThreat#tag: unknown kind #{kind.inspect}"
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
          :input, :classify, :dot_positions, :last_dot_pos,
          :bidi_control_count, :fullwidth_in_ext, :combining_in_ext
        )

        module_function

        # ── Sub-threat constructors ────────────────────────────────────────

        # A bidi format-control at `position` (codepoint `control_cp`).
        def rlo_flip(position, control_cp)
          SubThreat.new(SubKind::RLO_FLIP, { position: position, control_cp: control_cp })
        end

        # A fullwidth/halfwidth codepoint in the extension at `position`
        # (codepoint `cp`).
        def width_class_ext(position, cp)
          SubThreat.new(SubKind::WIDTH_CLASS_EXT, { position: position, cp: cp })
        end

        # A combining (grapheme Extend) codepoint in the extension at `position`
        # (codepoint `cp`).
        def combining_in_ext(position, cp)
          SubThreat.new(SubKind::COMBINING_IN_EXT, { position: position, cp: cp })
        end

        # Three or more `.` separators (advisory).
        def multiple_extensions(dot_count)
          SubThreat.new(SubKind::MULTIPLE_EXTENSIONS, { dot_count: dot_count })
        end

        # ── Classification constructors ────────────────────────────────────

        def clear
          Classification.new(nil, [], [])
        end

        def hazard(sub, positions, decoded)
          Classification.new(sub, positions, decoded)
        end

        # ── Core predicates (reuse the port's own tables) ──────────────────

        # True iff `cp` is U+002E FULL STOP (the extension separator).
        def ascii_dot?(cp)
          cp == 0x002E
        end

        # True iff `cp` is in the Halfwidth and Fullwidth Forms block.
        def fullwidth_halfwidth?(cp)
          cp >= 0xFF01 && cp <= 0xFFEF
        end

        # True iff `cp` is a bidi format-control (reuses the port's own
        # LRE/RLE/LRO/RLO/PDF/LRI/RLI/FSI/PDI predicate).
        def bidi_format_control?(cp)
          Covert::BidiControlBalance.bidi_format_control?(cp)
        end

        # True iff `cp` has Grapheme_Cluster_Break = Extend (reuses the port's
        # UAX #29 grapheme table).
        def grapheme_extend?(cp)
          Segmentation::Grapheme.lookup_gcb(cp) == :extend
        end

        # ── Sub-detectors ──────────────────────────────────────────────────

        # Positions of every `.` in `input`.
        def dot_positions(input)
          out = []
          input.each_index { |idx| out << idx if ascii_dot?(input[idx]) }
          out
        end

        # Position and codepoint of the first bidi format-control, or nil.
        def first_bidi_control(input)
          input.each_index do |idx|
            return [idx, input[idx]] if bidi_format_control?(input[idx])
          end
          nil
        end

        # Position and codepoint of the first fullwidth/halfwidth codepoint at or
        # after `start`, or nil.
        def first_fullwidth_from(input, start)
          input.each_index do |idx|
            return [idx, input[idx]] if idx >= start && fullwidth_halfwidth?(input[idx])
          end
          nil
        end

        # Position and codepoint of the first Extend codepoint at or after
        # `start`, or nil.
        def first_extend_from(input, start)
          input.each_index do |idx|
            return [idx, input[idx]] if idx >= start && grapheme_extend?(input[idx])
          end
          nil
        end

        # Count of fullwidth/halfwidth codepoints at or after `start`.
        def count_fullwidth_from(input, start)
          count = 0
          input.each_index { |idx| count += 1 if idx >= start && fullwidth_halfwidth?(input[idx]) }
          count
        end

        # Count of Extend codepoints at or after `start`.
        def count_extend_from(input, start)
          count = 0
          input.each_index { |idx| count += 1 if idx >= start && grapheme_extend?(input[idx]) }
          count
        end

        # ── Top-level detection ────────────────────────────────────────────

        # The FilenameDisguise detection function.
        def detect(input)
          dots = dot_positions(input)
          last_dot = dots.last
          ext_start = last_dot.nil? ? input.length : last_dot + 1
          bidi_count = input.count { |cp| bidi_format_control?(cp) }
          fw_in_ext = count_fullwidth_from(input, ext_start)
          ext_in_ext = count_extend_from(input, ext_start)

          Verdict.new(
            input.dup, classify(input, dots, ext_start), dots, last_dot,
            bidi_count, fw_in_ext, ext_in_ext
          )
        end

        # The priority ladder, factored out of `detect`.
        def classify(input, dots, ext_start)
          # Priority 1: any bidi format-control.
          bidi = first_bidi_control(input)
          unless bidi.nil?
            pos, ctl_cp = bidi
            return hazard(rlo_flip(pos, ctl_cp), [pos], [])
          end

          # Priority 2: fullwidth/halfwidth in the extension.
          fw = first_fullwidth_from(input, ext_start)
          unless fw.nil?
            pos, cp = fw
            return hazard(width_class_ext(pos, cp), [pos], [])
          end

          # Priority 3: combining mark in the extension.
          ext = first_extend_from(input, ext_start)
          unless ext.nil?
            pos, cp = ext
            return hazard(combining_in_ext(pos, cp), [pos], [])
          end

          # Priority 4: three or more extensions (advisory).
          if dots.length >= MIN_EXTENSION_DOTS
            return hazard(multiple_extensions(dots.length), dots.dup, [])
          end

          clear
        end
      end
    end
  end
end
