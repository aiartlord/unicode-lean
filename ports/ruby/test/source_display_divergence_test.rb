# frozen_string_literal: true

require_relative "test_helper"

class SourceDisplayDivergenceTest < Minitest::Test
  include RubyPortTestHelpers

  Sdd = UnicodeRuby::Security::Display::SourceDisplayDivergence
  Policy = UnicodeRuby::Security::Policy
  Family = UnicodeRuby::Security::Calculus::Family

  # ── (a) shared context-free detector fixture ─────────────────────────────
  #
  # The shared vectors are context-free, so they exercise `detect` directly.
  # Each fired tag maps to its stable reason code via the same Policy wiring
  # the sibling display detectors use.

  def code_for(input)
    tag = Sdd.detect(input).tag
    tag.nil? ? [] : [Policy.reason_code(Family::SOURCE_DISPLAY_DIVERGENCE, tag)]
  end

  def test_shared_fixture_cases
    fixture = fixture_json("detectors", "source_display_divergence.json")
    assert_equal 1, fixture.fetch("schema")
    assert_equal "source-display-divergence", fixture.fetch("family")

    fixture.fetch("cases").each do |case_data|
      name = case_data.fetch("name")
      codes = code_for(case_data.fetch("input"))
      case_data.fetch("required_findings").each do |required|
        assert_includes codes, required, name
      end
      next unless case_data.fetch("required_findings").empty?

      assert codes.none? { |code| code.include?(".source-display-divergence.") },
             "#{name}: unexpected source-display-divergence finding in #{codes.inspect}"
    end
  end

  # ── detect spot checks (one per Rust reference test) ─────────────────────

  def sub(input)
    Sdd.detect(input).sub
  end

  # `clear_cases`
  def test_clear_empty
    assert_nil sub([])
  end

  # "Hello world"
  def test_clear_hello_world
    assert_nil sub([0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64])
  end

  # "let x = 1;"
  def test_clear_let_x_1
    assert_nil sub([0x6C, 0x65, 0x74, 0x20, 0x78, 0x20, 0x3D, 0x20, 0x31, 0x3B])
  end

  # `single_fire_passthrough` — tag-encoded "AB".
  def test_single_tag_block
    assert_equal "TagBlock", sub([0xE0041, 0xE0042])
  end

  # A + VS16.
  def test_single_variation_selector
    assert_equal "VariationSelector", sub([0x0041, 0xFE0F])
  end

  # H + ZWSP + i.
  def test_single_zero_width
    assert_equal "ZeroWidth", sub([0x0048, 0x200B, 0x69])
  end

  # RLO + A.
  def test_single_bidi_control
    assert_equal "BidiControl", sub([0x202E, 0x41])
  end

  # "Neth<Cyrillic е>um".
  def test_single_identifier_homoglyph
    assert_equal "IdentifierHomoglyph",
                 sub([0x4E, 0x65, 0x74, 0x68, 0x65, 0x72, 0x0435, 0x75, 0x6D])
  end

  # `two_or_more_is_compound` — A + VS16 + ZWSP.
  def test_compound_vs_plus_zero_width
    assert_equal "Compound", sub([0x0041, 0xFE0F, 0x200B])
  end

  # tag "AB" + ZWSP.
  def test_compound_tag_plus_zero_width
    assert_equal "Compound", sub([0xE0041, 0xE0042, 0x200B])
  end

  # ── structural checks ────────────────────────────────────────────────────

  def test_clear_detection_reports_clear
    assert Sdd.detect([]).clear?
  end

  def test_reason_code_wiring
    assert_equal "unicode.security.D.source-display-divergence.TagBlock",
                 Policy.reason_code(Family::SOURCE_DISPLAY_DIVERGENCE, "TagBlock")
    assert_equal "unicode.security.D.source-display-divergence.Compound",
                 Policy.reason_code(Family::SOURCE_DISPLAY_DIVERGENCE, "Compound")
  end
end
