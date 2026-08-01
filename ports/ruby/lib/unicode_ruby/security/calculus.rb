# frozen_string_literal: true

module UnicodeRuby
  module Security
    # Shared verdict vocabulary for the Security Conformance Layer.  Per-family
    # modules refine this shared vocabulary into family-specific verdict
    # structures.
    module Calculus
      # The detector modules.  The order is the order in which the aggregator
      # walks them and the priority order callers can rely on when composing
      # verdicts across modules.  Each family's value is its stable wire tag.
      module Family
        MALFORMED_UTF8 = "MalformedUtf8"
        MALFORMED_UTF16 = "MalformedUtf16"
        MALFORMED_UTF32 = "MalformedUtf32"
        TAG_BLOCK_PAYLOAD = "TagBlockPayload"
        VARIATION_SELECTOR_PAYLOAD = "VariationSelectorPayload"
        ZERO_WIDTH_PAYLOAD = "ZeroWidthPayload"
        SURROGATE_REASSEMBLY = "SurrogateReassembly"
        BIDI_CONTROL_BALANCE = "BidiControlBalance"
        NONCHARACTER_CONTROL = "NoncharacterControl"
        HOMOGLYPH_CONFUSABLE = "HomoglyphConfusable"
        MIXED_SCRIPT_ADMISSIBILITY = "MixedScriptAdmissibility"
        EMOJI_ZWJ_INTEGRITY = "EmojiZwjIntegrity"
        SKIN_TONE_VARIATION_FORGERY = "SkinToneVariationForgery"
        SOURCE_DISPLAY_DIVERGENCE = "SourceDisplayDivergence"
        FILENAME_DISGUISE = "FilenameDisguise"
        RTL_INJECTION = "RtlInjection"
        RENDERER_DIVERGENCE = "RendererDivergence"
        NORMALIZATION_BOMB = "NormalizationBomb"
        STREAM_SAFE_VIOLATION = "StreamSafeViolation"
        LOCALE_CASE_INVERSION = "LocaleCaseInversion"
        CASE_EXPANSION_MISMATCH = "CaseExpansionMismatch"
        WIDTH_CLASS_CONFUSION = "WidthClassConfusion"
        NFC_IDEMPOTENCE_WITNESS = "NfcIdempotenceWitness"
        IDENTIFIER_FORM_DRIFT = "IdentifierFormDrift"
        COVERT_DISPLAY_COMPOUND = "CovertDisplayCompound"
        CONFUSABLE_BIDI_COMPOUND = "ConfusableBidiCompound"
        ADMISSIBILITY_FORM_DRIFT = "AdmissibilityFormDrift"
        BIP39_CANONICAL = "Bip39Canonical"
        HASH_INPUT_STABILITY = "HashInputStability"
        AI_WATERMARK_DETECTABILITY = "AiWatermarkDetectability"

        ALL = [
          MALFORMED_UTF8, MALFORMED_UTF16, MALFORMED_UTF32, TAG_BLOCK_PAYLOAD,
          VARIATION_SELECTOR_PAYLOAD, ZERO_WIDTH_PAYLOAD, SURROGATE_REASSEMBLY,
          BIDI_CONTROL_BALANCE, NONCHARACTER_CONTROL, HOMOGLYPH_CONFUSABLE,
          MIXED_SCRIPT_ADMISSIBILITY, EMOJI_ZWJ_INTEGRITY,
          SKIN_TONE_VARIATION_FORGERY, SOURCE_DISPLAY_DIVERGENCE,
          FILENAME_DISGUISE, RTL_INJECTION, RENDERER_DIVERGENCE,
          NORMALIZATION_BOMB, STREAM_SAFE_VIOLATION, LOCALE_CASE_INVERSION,
          CASE_EXPANSION_MISMATCH, WIDTH_CLASS_CONFUSION,
          NFC_IDEMPOTENCE_WITNESS, IDENTIFIER_FORM_DRIFT,
          COVERT_DISPLAY_COMPOUND, CONFUSABLE_BIDI_COMPOUND,
          ADMISSIBILITY_FORM_DRIFT, BIP39_CANONICAL, HASH_INPUT_STABILITY,
          AI_WATERMARK_DETECTABILITY
        ].freeze
      end

      # Ordered severity vocabulary.  Strictly less-than:
      # INFORMATIONAL < LOW < MODERATE < HIGH < CRITICAL.
      module Severity
        INFORMATIONAL = 0
        LOW = 1
        MODERATE = 2
        HIGH = 3
        CRITICAL = 4
      end

      # Five-tier adversary capability hierarchy.  A0 passive observer,
      # A1 local injector, A2 pipeline injector, A3 supply-chain injector,
      # A4 model-adaptive.
      module AdversaryTier
        A0 = 0
        A1 = 1
        A2 = 2
        A3 = 3
        A4 = 4
      end

      # The verdict kind, independent of any family-specific sub-threat payload.
      module ClassificationKind
        CLEAR = :clear
        HAZARD = :hazard
        COMPOUND = :compound
        INFORMATIONAL = :informational
      end

      # The default severity associated with each classification kind.
      def self.default_severity(kind)
        case kind
        when ClassificationKind::CLEAR then Severity::INFORMATIONAL
        when ClassificationKind::HAZARD then Severity::MODERATE
        when ClassificationKind::COMPOUND then Severity::HIGH
        when ClassificationKind::INFORMATIONAL then Severity::INFORMATIONAL
        else
          raise "default_severity: unknown ClassificationKind #{kind.inspect}"
        end
      end

      # A position within a codepoint sequence, optionally enriched with a
      # line / column when the input is source-code shaped.
      HazardPosition = Struct.new(:cp_offset, :line, :column) do
        def initialize(cp_offset:, line: nil, column: nil)
          super(cp_offset, line, column)
        end
      end

      # A flexible attribution dictionary — string keys to string values.
      class KeyValueAttribution
        def initialize
          @entries = []
        end

        attr_reader :entries

        def push(key, value)
          @entries << [key, value]
        end

        def get(key)
          pair = @entries.find { |k, _v| k == key }
          pair.nil? ? nil : pair[1]
        end
      end
    end
  end
end
