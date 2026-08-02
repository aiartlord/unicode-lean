# frozen_string_literal: true

require_relative "test_helper"

class AiWatermarkDetectabilityTest < Minitest::Test
  include RubyPortTestHelpers

  Aw = UnicodeRuby::Security::Crypto::AiWatermarkDetectability
  CueClass = Aw::CueClass
  Policy = UnicodeRuby::Security::Policy
  Family = UnicodeRuby::Security::Calculus::Family

  # ── (a) shared context-free detector fixture ─────────────────────────────
  #
  # The 24 shared vectors carry no Context, so they exercise `detect` (the
  # exact-arithmetic identity context).  Each hazard tag maps to its stable
  # reason code via the same Policy wiring hash-input-stability uses.

  def code_for(input)
    tag = Aw.detect(input).classify.tag
    tag.nil? ? [] : [Policy.reason_code(Family::AI_WATERMARK_DETECTABILITY, tag)]
  end

  def test_shared_fixture_cases
    fixture = fixture_json("detectors", "ai_watermark_detectability.json")
    assert_equal 1, fixture.fetch("schema")
    assert_equal "ai-watermark-detectability", fixture.fetch("family")

    fixture.fetch("cases").each do |case_data|
      name = case_data.fetch("name")
      codes = code_for(case_data.fetch("input"))
      case_data.fetch("required_findings").each do |required|
        assert_includes codes, required, name
      end
      next unless case_data.fetch("required_findings").empty?

      assert codes.none? { |code| code.include?(".ai-watermark-detectability.") },
             "#{name}: unexpected ai-watermark finding in #{codes.inspect}"
    end
  end

  # ── §4 probe spot checks ─────────────────────────────────────────────────

  def test_is_nnbsp_checks
    assert Aw.nnbsp?(0x202F)
    refute Aw.nnbsp?(0x20)
    refute Aw.nnbsp?(0x3000)
  end

  def test_is_zwj_checks
    assert Aw.zwj?(0x200D)
    refute Aw.zwj?(0x200B)
    refute Aw.zwj?(0x200C)
  end

  def test_is_vs_checks
    assert Aw.variation_selector?(0xFE00)
    assert Aw.variation_selector?(0xFE0F)
    assert Aw.variation_selector?(0xE0100)
    refute Aw.variation_selector?(0x61)
    refute Aw.variation_selector?(0x200D)
  end

  def test_is_default_ignorable_checks
    assert Aw.default_ignorable?(0x200B)
    assert Aw.default_ignorable?(0x200D)
    assert Aw.default_ignorable?(0x00AD)
    refute Aw.default_ignorable?(0x202F)
    refute Aw.default_ignorable?(0x61)
  end

  def test_is_emoji_checks
    assert Aw.emoji?(0x1F600)
    refute Aw.emoji?(0x200D)
    refute Aw.emoji?(0x61)
  end

  def test_is_adjacent_to_emoji
    refute Aw.adjacent_to_emoji?([0x61, 0xFE0F, 0x62], 1)
    assert Aw.adjacent_to_emoji?([0x1F600, 0xFE0F], 1)
    assert Aw.adjacent_to_emoji?([0xFE0F, 0x1F600], 0)
  end

  # ── §6 detect spot checks ────────────────────────────────────────────────

  def tag(input)
    Aw.detect(input).classify.tag
  end

  def test_detect_clear_cases
    assert_nil tag([])
    assert_nil tag([0x61, 0x62, 0x63])
    assert_nil tag([0x4E2D, 0x6587])
  end

  def test_detect_nnbsp_fires
    v = Aw.detect([0x61, 0x202F, 0x62])
    assert_equal "NnbspBoundary", v.classify.tag
    assert_equal [1], v.classify.positions
    assert_equal 1, v.marker_count
  end

  def test_detect_vs_in_plain_text_fires
    v = Aw.detect([0x61, 0xFE0F, 0x62])
    assert_equal "VariationSelectorCarrier", v.classify.tag
    assert_equal 1, v.marker_count
  end

  def test_detect_vs_after_emoji_clear
    assert_nil tag([0x1F600, 0xFE0F])
  end

  def test_detect_zwj_in_plain_text_fires
    v = Aw.detect([0x61, 0x200D, 0x62])
    assert_equal "ZwjNonEmoji", v.classify.tag
    assert_equal 1, v.marker_count
  end

  def test_detect_zwj_emoji_sequence_clear
    assert_nil tag([0x1F469, 0x200D, 0x1F52C])
  end

  def test_detect_soft_hyphen_fires
    v = Aw.detect([0x61, 0x00AD, 0x62])
    assert_equal "DefaultIgnorableCarrier", v.classify.tag
    assert_equal 1, v.marker_count
  end

  def test_detect_zwsp_fires
    v = Aw.detect([0x61, 0x200B, 0x62])
    assert_equal "DefaultIgnorableCarrier", v.classify.tag
    assert_equal 1, v.marker_count
  end

  def test_detect_priority_unknown_over_nnbsp_with_di
    assert_equal "Unknown", tag([0x61, 0x202F, 0x00AD, 0x62])
  end

  def test_detect_priority_unknown_over_vs_with_zwj
    assert_equal "Unknown", tag([0x61, 0xFE0F, 0x200D, 0x62])
  end

  def test_detect_multiple_nnbsp_aggregates
    v = Aw.detect([0x61, 0x202F, 0x62, 0x202F, 0x63])
    assert_equal "NnbspBoundary", v.classify.tag
    assert_equal 2, v.marker_count
    assert_equal [1, 3], v.classify.positions
  end

  # ── §7 refinement-probe spot checks ──────────────────────────────────────

  def test_detect_adversarial_arithmetic_nnbsp
    v = Aw.detect([0x61, 0x202F, 0x62, 0x202F, 0x63, 0x202F, 0x64])
    assert_equal "Adversarial", v.classify.tag
    assert_equal 3, v.marker_count
    assert_equal "nnbspBoundary", v.classify.sub.data[:impersonated_scheme]
  end

  def test_detect_nnbsp_two_below_adversarial_threshold
    assert_equal "NnbspBoundary", tag([0x61, 0x202F, 0x62, 0x202F, 0x63])
  end

  def test_detect_gpt5_zwsp_modulo
    v = Aw.detect([0x61, 0x200B, 0x62, 0x200B, 0x63, 0x200B, 0x64])
    assert_equal "Gpt5ZwspModulo", v.classify.tag
    assert_equal 3, v.marker_count
  end

  def test_detect_zwsp_two_below_modulo_threshold
    assert_equal "DefaultIgnorableCarrier", tag([0x61, 0x200B, 0x62, 0x200B, 0x63])
  end

  def test_detect_smart_quote_alternation
    v = Aw.detect([0x201C, 0x61, 0x62, 0x63, 0x201D])
    assert_equal "SmartQuoteAlternation", v.classify.tag
    assert_equal 2, v.marker_count
  end

  def test_detect_smart_quote_with_straight_clear
    assert_nil tag([0x201C, 0x61, 0x22, 0x201D])
  end

  def test_detect_em_dash_pattern
    v = Aw.detect([0x61, 0x62, 0x20, 0x2014, 0x20, 0x63, 0x64, 0x20, 0x2014, 0x20, 0x65, 0x66])
    assert_equal "EmDashPattern", v.classify.tag
    assert_equal 2, v.marker_count
  end

  def test_detect_em_dash_with_hyphen_clear
    assert_nil tag([0x61, 0x62, 0x2D, 0x63, 0x64, 0x20, 0x2014, 0x20, 0x65, 0x66])
  end

  def test_detect_statistical_token_delve
    v = Aw.detect([0x64, 0x65, 0x6C, 0x76, 0x65])
    assert_equal "StatisticalTokenChoice", v.classify.tag
    assert_equal 1, v.marker_count
  end

  def test_detect_statistical_token_moreover_embedded
    v = Aw.detect([0x3B, 0x20, 0x6D, 0x6F, 0x72, 0x65, 0x6F, 0x76, 0x65, 0x72, 0x2C, 0x20])
    assert_equal "StatisticalTokenChoice", v.classify.tag
    assert_equal [2], v.classify.positions
  end

  def test_detect_unknown_nnbsp_plus_di
    v = Aw.detect([0x61, 0x202F, 0x00AD, 0x62])
    assert_equal "Unknown", v.classify.tag
    assert_equal 2, v.marker_count
  end

  def test_detect_unknown_vs_plus_zwj
    v = Aw.detect([0x61, 0xFE0F, 0x200D, 0x62])
    assert_equal "Unknown", v.classify.tag
    assert_equal 2, v.marker_count
  end

  def test_detect_unknown_nnbsp_plus_zwj
    v = Aw.detect([0x61, 0x202F, 0x200D, 0x62])
    assert_equal "Unknown", v.classify.tag
    assert_equal 2, v.marker_count
  end

  def test_detect_single_category_skips_unknown
    assert_equal "NnbspBoundary", tag([0x61, 0x202F, 0x62])
  end

  def test_detect_priority_adversarial_over_nnbsp
    assert_equal "Adversarial", tag([0x61, 0x202F, 0x62, 0x202F, 0x63, 0x202F, 0x64])
  end

  def test_detect_priority_zwsp_modulo_over_di
    assert_equal "Gpt5ZwspModulo", tag([0x61, 0x200B, 0x62, 0x200B, 0x63, 0x200B, 0x64])
  end

  # ── §8 tolerance-parameterised probes ────────────────────────────────────
  #
  # Transcribed from the Rust reference's two Context-tolerance test vectors
  # (detect_zwsp_jittered_strict_clear / detect_zwsp_jittered_tolerant_fires):
  # ZWSPs at positions 1, 3, 6 (gaps 2, 3).

  def test_detect_zwsp_jittered_strict_clear
    input = [0x61, 0x200B, 0x62, 0x200B, 0x63, 0x64, 0x200B, 0x65]
    assert_equal "DefaultIgnorableCarrier", tag(input)
  end

  def test_detect_zwsp_jittered_tolerant_fires
    input = [0x61, 0x200B, 0x62, 0x200B, 0x63, 0x64, 0x200B, 0x65]
    ctx = Aw::Context.new(1, 0)
    v = Aw.detect_with_context(ctx, input)
    assert_equal "Gpt5ZwspModulo", v.classify.tag
  end

  def test_detect_with_context_default_matches_detect
    d = Aw.detect([0x61, 0x202F, 0x62])
    c = Aw.detect_with_context(Aw::Context.new, [0x61, 0x202F, 0x62])
    assert_equal d.classify.tag, c.classify.tag
    assert_equal d.classify.positions, c.classify.positions
    assert_equal d.marker_count, c.marker_count
  end

  # ── §7 cue-class coverage ────────────────────────────────────────────────

  def test_every_cue_class_is_probed
    classes = [CueClass::GREEN_LIST_BIAS, CueClass::PSEUDORANDOM_SEQ, CueClass::SEMANTIC_DRIFT]
    sub_threats = [
      Aw.nnbsp_boundary(0),
      Aw.variation_selector_carrier(0),
      Aw.zwj_non_emoji(0),
      Aw.default_ignorable_carrier(0),
      Aw.gpt5_zwsp_modulo(0),
      Aw.em_dash_pattern(0),
      Aw.smart_quote_alternation(0),
      Aw.statistical_token_choice(0),
      Aw.adversarial("", 0)
    ]
    classes.each do |cls|
      assert sub_threats.any? { |st| Aw.cue_class(st) == cls },
             "cue class #{cls.inspect} is not probed by any sub-threat"
    end
  end

  def test_unknown_has_no_cue_class
    assert_nil Aw.cue_class(Aw.unknown(0))
  end
end
