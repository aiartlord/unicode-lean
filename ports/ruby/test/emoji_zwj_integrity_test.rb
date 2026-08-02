# frozen_string_literal: true

require_relative "test_helper"

class EmojiZwjIntegrityTest < Minitest::Test
  include RubyPortTestHelpers

  Ezwj = UnicodeRuby::Security::Identity::EmojiZwjIntegrity
  Policy = UnicodeRuby::Security::Policy
  Family = UnicodeRuby::Security::Calculus::Family

  # ── (a) shared context-free detector fixture ─────────────────────────────
  #
  # The 12 shared vectors are context-free, so they exercise `detect` directly.
  # Each hazard tag maps to its stable reason code via the same Policy wiring
  # the sibling identity detectors use.

  def code_for(input)
    tag = Ezwj.detect(input).classify.tag
    tag.nil? ? [] : [Policy.reason_code(Family::EMOJI_ZWJ_INTEGRITY, tag)]
  end

  def test_shared_fixture_cases
    fixture = fixture_json("detectors", "emoji_zwj_integrity.json")
    assert_equal 1, fixture.fetch("schema")
    assert_equal "emoji-zwj-integrity", fixture.fetch("family")

    fixture.fetch("cases").each do |case_data|
      name = case_data.fetch("name")
      codes = code_for(case_data.fetch("input"))
      case_data.fetch("required_findings").each do |required|
        assert_includes codes, required, name
      end
      next unless case_data.fetch("required_findings").empty?

      assert codes.none? { |code| code.include?(".emoji-zwj-integrity.") },
             "#{name}: unexpected emoji-zwj-integrity finding in #{codes.inspect}"
    end
  end

  # ── data-layer sanity ────────────────────────────────────────────────────

  def test_is_emoji_modifier_checks
    assert Ezwj.emoji_modifier?(0x1F3FB)
    assert Ezwj.emoji_modifier?(0x1F3FF)
    refute Ezwj.emoji_modifier?(0x1F3FA)
    refute Ezwj.emoji_modifier?(0x1F600)
  end

  def test_zwj_alphabet_admits_heart_rejects_grinning
    # U+2764 HEAVY BLACK HEART appears in couple-with-heart RGI sequences.
    assert Ezwj.emoji_target?(0x2764)
    # U+1F468 MAN appears in family/couple RGI sequences.
    assert Ezwj.emoji_target?(0x1F468)
    # U+1F600 GRINNING FACE appears in no registered RGI ZWJ sequence.
    refute Ezwj.emoji_target?(0x1F600)
    # The joiner itself is excluded from the alphabet.
    refute Ezwj.emoji_target?(Ezwj::ZWJ)
  end

  def test_registered_membership_is_exact
    # MAN + ZWJ + LAPTOP (man technologist) is a registered RGI sequence.
    assert Ezwj.registered_zwj_sequence?([0x1F468, 0x200D, 0x1F4BB])
    # MAN + ZWJ + WOMAN is not a registered RGI sequence.
    refute Ezwj.registered_zwj_sequence?([0x1F468, 0x200D, 0x1F469])
  end

  # ── detect spot checks (one per Rust reference test) ─────────────────────

  def tag(input)
    Ezwj.detect(input).classify.tag
  end

  def test_detect_empty_clear
    v = Ezwj.detect([])
    assert v.classify.clear?
    assert_nil v.classify.tag
    assert_equal [], v.zwj_positions
    assert_equal 0, v.chain_length
    assert_equal 0, v.skin_tone_count
  end

  def test_detect_ascii_clear
    assert Ezwj.detect([0x48, 0x65, 0x6C, 0x6C, 0x6F]).classify.clear?
  end

  def test_detect_plain_emoji_clear
    assert Ezwj.detect([0x1F600]).classify.clear?
  end

  def test_detect_one_skintone_clear
    v = Ezwj.detect([0x1F44B, 0x1F3FB])
    assert v.classify.clear?
    assert_equal 1, v.skin_tone_count
  end

  def test_detect_family_rgi_clear
    v = Ezwj.detect([0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467, 0x200D, 0x1F466])
    assert v.classify.clear?
    assert v.is_registered_rgi
  end

  def test_detect_double_zwj
    v = Ezwj.detect([0x1F600, 0x200D, 0x200D, 0x1F600])
    assert_equal "DoubleZWJ", v.classify.tag
    assert_equal [1], v.classify.positions
  end

  def test_detect_non_emoji_injection
    v = Ezwj.detect([0x1F600, 0x200D, 0x0061])
    assert_equal "NonEmojiInjection", v.classify.tag
  end

  def test_detect_skin_tone_overflow
    v = Ezwj.detect([0x1F44B, 0x1F3FB, 0x1F3FC, 0x1F3FD, 0x1F3FE, 0x1F3FF])
    assert_equal "SkinToneOverflow", v.classify.tag
    assert_equal 5, v.skin_tone_count
  end

  def test_detect_man_laptop_registered_clear
    assert Ezwj.detect([0x1F468, 0x200D, 0x1F4BB]).classify.clear?
  end

  def test_detect_unregistered
    # man + ZWJ + woman: both flanks are in the RGI alphabet but the joined
    # sequence is not registered.
    v = Ezwj.detect([0x1F468, 0x200D, 0x1F469])
    assert_equal "UnregisteredSequence", v.classify.tag
  end

  def test_detect_grinning_laptop_non_emoji_injection
    # grinning face is not a valid ZWJ-join target, so this surfaces as
    # NonEmojiInjection.
    assert_equal "NonEmojiInjection", tag([0x1F600, 0x200D, 0x1F4BB])
  end

  # ── structural checks (follow from the priority ladder) ──────────────────

  def test_over_length_fires_past_cap
    # 9 men joined by 8 ZWJs = 17 codepoints (> MAX_RGI_LENGTH).
    input = []
    9.times do |i|
      input << 0x200D if i.positive?
      input << 0x1F468
    end
    assert_equal 17, input.length
    v = Ezwj.detect(input)
    assert_equal "OverLength", v.classify.tag
    assert_equal 17, v.classify.sub.data[:length]
    assert_equal Ezwj::MAX_RGI_LENGTH, v.classify.sub.data[:max_length]
    assert_equal [], v.classify.positions
  end

  def test_trailing_zwj_is_injection
    v = Ezwj.detect([0x1F468, 0x200D])
    assert_equal "NonEmojiInjection", v.classify.tag
    assert_equal [1], v.classify.positions
  end

  def test_double_zwj_beats_unregistered
    # man ZWJ ZWJ boy — adjacent ZWJs present.
    v = Ezwj.detect([0x1F468, 0x200D, 0x200D, 0x1F466])
    assert_equal "DoubleZWJ", v.classify.tag
  end
end
