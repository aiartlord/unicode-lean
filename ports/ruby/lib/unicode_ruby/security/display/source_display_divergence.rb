# frozen_string_literal: true

require_relative "../calculus"
require_relative "../covert/tag_block_payload"
require_relative "../covert/variation_selector_payload"
require_relative "../covert/zero_width_payload"
require_relative "bidi_control_purpose"
require_relative "../identity/homoglyph_confusable"

module UnicodeRuby
  module Security
    module Display
      # SourceDisplayDivergence — the aggregate "what a reviewer sees differs
      # from what the machine runs" detector (display / D-layer).
      #
      # Byte-faithful port of the verified Rust reference
      # (`security/display/source_display_divergence.rs`) and of
      # `Unicode/Security/Display/SourceDisplayDivergence.lean`
      # (`detect` + `buildClassification`).
      #
      # Threat model.  A single covert or identity trick may be individually
      # benign-looking, but any hit means the rendered source diverges from its
      # logical content; two or more is a strong compound signal.  This detector
      # runs the five constituent detectors on the same codepoint stream and
      # aggregates: zero fire → clear, exactly one → pass-through that family's
      # tag, two or more → `Compound`.  Every constituent fires
      # region-agnostically — payloads inside string literals or comments count.
      #
      # It is a pure aggregation over the port's own constituent detectors — the
      # tag-block, variation-selector, and zero-width covert channels, the bidi
      # purpose rule (`BidiControlPurpose`), and the homoglyph-confusable
      # identity check — reusing their `detect` and classification kind; it
      # introduces no new table, no new predicate, and no host library.
      module SourceDisplayDivergence
        # The constituent family tags, in canonical aggregation order.  A single
        # non-clear constituent passes its tag through unchanged.
        TAG_BLOCK = "TagBlock"
        VARIATION_SELECTOR = "VariationSelector"
        ZERO_WIDTH = "ZeroWidth"
        BIDI_CONTROL = "BidiControl"
        IDENTIFIER_HOMOGLYPH = "IdentifierHomoglyph"

        # The tag emitted when two or more constituents fire.
        COMPOUND = "Compound"

        # One source-display-divergence scan result.  `sub` is nil for a clear
        # input; a single constituent hit passes through its family tag; two or
        # more yield `"Compound"`.  Positions are empty at this layer by the Lean
        # spec (the per-family verdicts carry them), so this result carries only
        # the sub-threat.
        Detection = Struct.new(:sub) do
          def clear?
            sub.nil?
          end

          def tag
            sub
          end
        end

        module_function

        # True iff a constituent classification kind counts as fired — anything
        # other than a clear verdict.  Explicit over the closed ClassificationKind
        # enum so an unrecognised kind is a loud error, never a silent miss.
        def fired?(kind)
          case kind
          when Calculus::ClassificationKind::CLEAR
            false
          when Calculus::ClassificationKind::HAZARD,
               Calculus::ClassificationKind::COMPOUND,
               Calculus::ClassificationKind::INFORMATIONAL
            true
          else
            raise "SourceDisplayDivergence.fired?: unknown ClassificationKind #{kind.inspect}"
          end
        end

        # Aggregate the five constituent detectors into a single D-layer verdict
        # at the default context: the homoglyph constituent is the whole-input
        # homoglyph verdict. Mirrors the Lean detect.
        def detect(input)
          detect_core(input, fired?(Identity::HomoglyphConfusable.detect(input).kind))
        end

        # Aggregate over a homoglyph verdict already in hand. The scan passes
        # the verdict it produced (per identifier token on running text), so the
        # constituent and the family finding are one reading of the same input;
        # mirrors the Lean `detectCore input homoglyphVerdict`.
        def detect_core(input, homoglyph_fired)
          fires = []

          fires << TAG_BLOCK if fired?(Covert::TagBlockPayload.detect(input).kind)
          fires << VARIATION_SELECTOR if fired?(Covert::VariationSelectorPayload.detect(input).kind)
          fires << ZERO_WIDTH if fired?(Covert::ZeroWidthPayload.detect(input).kind)
          # A purposeless control: unbalanced, or a balanced span enclosing
          # nothing right-to-left in a left-to-right context. A Trojan Source
          # payload balances its controls — an unbalanced run breaks the file it
          # is hiding in — so a constituent built on the balance verdict is
          # blind to the shape the attack takes; a balanced embedding around an
          # Arabic string literal manages that literal and is not a constituent.
          fires << BIDI_CONTROL if BidiControlPurpose.purposeless_control?(input)
          fires << IDENTIFIER_HOMOGLYPH if homoglyph_fired

          Detection.new(aggregate(fires))
        end

        # Collapse the ordered list of fired tags into the sub-threat: none →
        # clear (nil), one → that tag, two or more → `Compound`.
        def aggregate(fires)
          case fires.length
          when 0
            nil
          when 1
            fires[0]
          else
            COMPOUND
          end
        end
      end
    end
  end
end
