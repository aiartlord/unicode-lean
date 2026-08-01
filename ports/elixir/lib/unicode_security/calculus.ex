defmodule UnicodeSecurity.Calculus do
  @moduledoc """
  Shared verdict vocabulary for the Security Conformance Layer.

  Per-family modules import this vocabulary and refine it into family-specific
  verdict structures. Enum vocabularies are atoms; the `Family` order is the
  order in which the aggregator walks the detectors and the priority order
  callers can rely on when composing verdicts.
  """

  @typedoc "Detector family. Order matches the aggregator walk order."
  @type family ::
          :malformed_utf8
          | :malformed_utf16
          | :malformed_utf32
          | :tag_block_payload
          | :variation_selector_payload
          | :zero_width_payload
          | :surrogate_reassembly
          | :bidi_control_balance
          | :noncharacter_control
          | :homoglyph_confusable
          | :mixed_script_admissibility
          | :emoji_zwj_integrity
          | :skin_tone_variation_forgery
          | :source_display_divergence
          | :filename_disguise
          | :rtl_injection
          | :renderer_divergence
          | :normalization_bomb
          | :stream_safe_violation
          | :locale_case_inversion
          | :case_expansion_mismatch
          | :width_class_confusion
          | :nfc_idempotence_witness
          | :identifier_form_drift
          | :covert_display_compound
          | :confusable_bidi_compound
          | :admissibility_form_drift
          | :bip39_canonical
          | :hash_input_stability
          | :ai_watermark_detectability

  @families [
    :malformed_utf8,
    :malformed_utf16,
    :malformed_utf32,
    :tag_block_payload,
    :variation_selector_payload,
    :zero_width_payload,
    :surrogate_reassembly,
    :bidi_control_balance,
    :noncharacter_control,
    :homoglyph_confusable,
    :mixed_script_admissibility,
    :emoji_zwj_integrity,
    :skin_tone_variation_forgery,
    :source_display_divergence,
    :filename_disguise,
    :rtl_injection,
    :renderer_divergence,
    :normalization_bomb,
    :stream_safe_violation,
    :locale_case_inversion,
    :case_expansion_mismatch,
    :width_class_confusion,
    :nfc_idempotence_witness,
    :identifier_form_drift,
    :covert_display_compound,
    :confusable_bidi_compound,
    :admissibility_form_drift,
    :bip39_canonical,
    :hash_input_stability,
    :ai_watermark_detectability
  ]

  @doc "The detector families in aggregator/priority order."
  @spec families() :: [family()]
  def families, do: @families

  @typedoc "Ordered severity vocabulary: informational < low < moderate < high < critical."
  @type severity :: :informational | :low | :moderate | :high | :critical

  @doc "Numeric rank of a severity (0..4)."
  @spec severity_value(severity()) :: 0..4
  def severity_value(:informational), do: 0
  def severity_value(:low), do: 1
  def severity_value(:moderate), do: 2
  def severity_value(:high), do: 3
  def severity_value(:critical), do: 4

  @typedoc "Five-tier adversary capability hierarchy A0..A4."
  @type adversary_tier :: :a0 | :a1 | :a2 | :a3 | :a4

  @doc "Numeric rank of an adversary tier (0..4)."
  @spec adversary_tier_value(adversary_tier()) :: 0..4
  def adversary_tier_value(:a0), do: 0
  def adversary_tier_value(:a1), do: 1
  def adversary_tier_value(:a2), do: 2
  def adversary_tier_value(:a3), do: 3
  def adversary_tier_value(:a4), do: 4

  @typedoc "The verdict kind, independent of any family-specific sub-threat payload."
  @type classification_kind :: :clear | :hazard | :compound | :informational

  @doc "Default severity associated with each classification kind."
  @spec default_severity(classification_kind()) :: severity()
  def default_severity(:clear), do: :informational
  def default_severity(:hazard), do: :moderate
  def default_severity(:compound), do: :high
  def default_severity(:informational), do: :informational
end
