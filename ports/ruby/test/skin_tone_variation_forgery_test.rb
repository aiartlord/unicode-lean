# frozen_string_literal: true

require_relative "test_helper"

class SkinToneVariationForgeryTest < Minitest::Test
  include RubyPortTestHelpers

  Stvf = UnicodeRuby::Security::Identity::SkinToneVariationForgery
  Policy = UnicodeRuby::Security::Policy
  Family = UnicodeRuby::Security::Calculus::Family

  # ── (a) shared context-free detector fixture ─────────────────────────────
  #
  # The 8 shared vectors are context-free, so they exercise `detect` directly.
  # Each hazard tag maps to its stable reason code via the same Policy wiring
  # the sibling identity detectors use.

  def code_for(input)
    tag = Stvf.detect(input).classify.tag
    tag.nil? ? [] : [Policy.reason_code(Family::SKIN_TONE_VARIATION_FORGERY, tag)]
  end

  def test_shared_fixture_cases
    fixture = fixture_json("detectors", "skin_tone_variation_forgery.json")
    assert_equal 1, fixture.fetch("schema")
    assert_equal "skin-tone-variation-forgery", fixture.fetch("family")

    fixture.fetch("cases").each do |case_data|
      name = case_data.fetch("name")
      codes = code_for(case_data.fetch("input"))
      case_data.fetch("required_findings").each do |required|
        assert_includes codes, required, name
      end
      next unless case_data.fetch("required_findings").empty?

      assert codes.none? { |code| code.include?(".skin-tone-variation-forgery.") },
             "#{name}: unexpected skin-tone-variation-forgery finding in #{codes.inspect}"
    end
  end

  # ── reason-code wiring ───────────────────────────────────────────────────

  def test_reason_code_is_stable
    assert_equal "unicode.security.I.skin-tone-variation-forgery.StackedSkinTones",
                 Policy.reason_code(Family::SKIN_TONE_VARIATION_FORGERY, "StackedSkinTones")
    assert_equal "unicode.security.I.skin-tone-variation-forgery.ForcedTextStyle",
                 Policy.reason_code(Family::SKIN_TONE_VARIATION_FORGERY, "ForcedTextStyle")
  end

  # ── data-layer sanity (bundled emoji-data.txt property tables) ───────────

  def test_property_predicates
    # U+1F44B waving hand carries Emoji_Modifier_Base.
    assert Stvf.skin_tone_base?(0x1F44B)
    # U+1F600 grinning face is NOT a modifier base, but has Emoji_Presentation.
    refute Stvf.skin_tone_base?(0x1F600)
    assert Stvf.emoji_presentation?(0x1F600)
    # ASCII 'A' has neither property.
    refute Stvf.skin_tone_base?(0x0041)
    refute Stvf.emoji_presentation?(0x0041)
    # Skin-tone modifiers reuse the port's own predicate.
    assert Stvf.skin_tone?(0x1F3FB)
    assert Stvf.skin_tone?(0x1F3FF)
    refute Stvf.skin_tone?(0x1F600)
    # Variation selectors.
    assert Stvf.vs15?(0xFE0E)
    assert Stvf.vs16?(0xFE0F)
    refute Stvf.vs15?(0xFE0F)
  end

  # ── detect spot checks (one per Rust reference test) ─────────────────────

  def tag(input)
    Stvf.detect(input).classify.tag
  end

  def test_detect_empty_clear
    assert Stvf.detect([]).classify.clear?
  end

  def test_detect_ascii_clear
    assert Stvf.detect([0x48, 0x65]).classify.clear?
  end

  def test_detect_plain_emoji_clear
    assert Stvf.detect([0x1F600]).classify.clear?
  end

  def test_detect_wave_skin_tone_clear
    v = Stvf.detect([0x1F44B, 0x1F3FB])
    assert v.classify.clear?
    assert_equal 1, v.skin_tone_count
  end

  def test_detect_stacked_skin_tones
    v = Stvf.detect([0x1F44B, 0x1F3FB, 0x1F3FC])
    assert_equal "StackedSkinTones", v.classify.tag
    assert_equal [1, 2], v.classify.positions
  end

  def test_detect_invalid_target_ascii
    v = Stvf.detect([0x0041, 0x1F3FB])
    assert_equal "InvalidSkinToneTarget", v.classify.tag
    assert_equal [1], v.classify.positions
  end

  def test_detect_invalid_target_smiley
    assert_equal "InvalidSkinToneTarget", tag([0x1F600, 0x1F3FB])
  end

  def test_detect_forced_text_style
    v = Stvf.detect([0x1F600, 0xFE0E])
    assert_equal "ForcedTextStyle", v.classify.tag
    assert_equal [1], v.classify.positions
    assert_equal 1, v.variation_selector15_count
  end

  # ── priority ordering ────────────────────────────────────────────────────

  def test_stacked_beats_invalid_and_forced
    # waving hand + two skin tones + VS15: StackedSkinTones outranks the rest.
    assert_equal "StackedSkinTones", tag([0x1F44B, 0x1F3FB, 0x1F3FC, 0xFE0E])
  end
end
