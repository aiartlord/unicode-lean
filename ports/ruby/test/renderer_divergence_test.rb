# frozen_string_literal: true

require_relative "test_helper"

class RendererDivergenceTest < Minitest::Test
  include RubyPortTestHelpers

  Rd = UnicodeRuby::Security::Display::RendererDivergence
  Policy = UnicodeRuby::Security::Policy
  Family = UnicodeRuby::Security::Calculus::Family

  # ── (a) shared context-free detector fixture ─────────────────────────────
  #
  # The 9 shared vectors are context-free, so they exercise `detect` directly.
  # Each hazard tag maps to its stable reason code via the same Policy wiring
  # the sibling display detectors use.

  def code_for(input)
    tag = Rd.detect(input).classify.tag
    tag.nil? ? [] : [Policy.reason_code(Family::RENDERER_DIVERGENCE, tag)]
  end

  def test_shared_fixture_cases
    fixture = fixture_json("detectors", "renderer_divergence.json")
    assert_equal 1, fixture.fetch("schema")
    assert_equal "renderer-divergence", fixture.fetch("family")

    fixture.fetch("cases").each do |case_data|
      name = case_data.fetch("name")
      codes = code_for(case_data.fetch("input"))
      case_data.fetch("required_findings").each do |required|
        assert_includes codes, required, name
      end
      next unless case_data.fetch("required_findings").empty?

      assert codes.none? { |code| code.include?(".renderer-divergence.") },
             "#{name}: unexpected renderer-divergence finding in #{codes.inspect}"
    end
  end

  # ── detect spot checks (one per Rust reference test) ─────────────────────

  def tag(input)
    Rd.detect(input).classify.tag
  end

  # `detect_empty_clear`
  def test_detect_empty_clear
    assert Rd.detect([]).classify.clear?
  end

  # `detect_ascii_clear`
  def test_detect_ascii_clear
    assert Rd.detect([0x48, 0x65, 0x6C, 0x6C, 0x6F]).classify.clear?
  end

  # `detect_han_clear`
  def test_detect_han_clear
    assert Rd.detect([0x4E2D, 0x6587]).classify.clear?
  end

  # `detect_vs_variance` — a single VS (FE0F) after an emoji.
  def test_detect_vs_variance
    assert_equal "VariationSelectorVariance", tag([0x1F600, 0xFE0F])
  end

  # `detect_rgi_family_clear` — a registered RGI family ZWJ sequence.
  def test_detect_rgi_family_clear
    v = Rd.detect([0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467, 0x200D, 0x1F466])
    assert v.classify.clear?
    assert v.has_zwj
  end

  # `detect_unregistered_zwj_variance` — man + ZWJ + woman, not in RGI.
  def test_detect_unregistered_zwj_variance
    assert_equal "UnregisteredZwjVariance", tag([0x1F468, 0x200D, 0x1F469])
  end

  # `detect_zalgo_variance` — a 4-deep combining stack.
  def test_detect_zalgo_variance
    v = Rd.detect([0x0061, 0x0301, 0x0302, 0x0303, 0x0304])
    assert_equal "CombiningStackOverflow", v.classify.tag
    assert_equal [0], v.classify.positions
    assert_equal 4, v.combining_count
  end

  # `detect_fullwidth_variance` — fullwidth 'A'.
  def test_detect_fullwidth_variance
    assert_equal "FullwidthVariance", tag([0xFF21])
  end

  # `detect_mixed_direction` — Latin + Hebrew in one input.
  def test_detect_mixed_direction
    v = Rd.detect([0x41, 0x42, 0x05D0, 0x05D1])
    assert_equal "MixedDirectionVariance", v.classify.tag
    assert v.strong_ltr_count.positive?
    assert v.strong_rtl_count.positive?
  end

  # ── priority-ladder structural checks ────────────────────────────────────

  # A combining stack outranks a variation selector present later.
  def test_combining_stack_beats_vs
    v = Rd.detect([0x0061, 0x0301, 0x0302, 0x0303, 0x0304, 0xFE0F])
    assert_equal "CombiningStackOverflow", v.classify.tag
  end

  # Exactly three combining marks is below the stack threshold — no overflow.
  def test_three_marks_below_threshold
    v = Rd.detect([0x0061, 0x0301, 0x0302, 0x0303])
    refute_equal "CombiningStackOverflow", v.classify.tag
  end
end
