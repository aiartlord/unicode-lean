# frozen_string_literal: true

require_relative "test_helper"

class IdentifierFormDriftTest < Minitest::Test
  include RubyPortTestHelpers

  Ifd = UnicodeRuby::Security::Boundary::IdentifierFormDrift
  Policy = UnicodeRuby::Security::Policy
  Family = UnicodeRuby::Security::Calculus::Family

  # ── (a) shared context-free detector fixture ─────────────────────────────
  #
  # The 8 shared vectors are context-free, so they exercise `detect` directly.
  # The sole hazard tag maps to its stable reason code via the same Policy
  # wiring the sibling boundary detectors use.

  def code_for(input)
    tag = Ifd.detect(input).classify.tag
    tag.nil? ? [] : [Policy.reason_code(Family::IDENTIFIER_FORM_DRIFT, tag)]
  end

  def test_shared_fixture_cases
    fixture = fixture_json("detectors", "identifier_form_drift.json")
    assert_equal 1, fixture.fetch("schema")
    assert_equal "identifier-form-drift", fixture.fetch("family")

    fixture.fetch("cases").each do |case_data|
      name = case_data.fetch("name")
      codes = code_for(case_data.fetch("input"))
      case_data.fetch("required_findings").each do |required|
        assert_includes codes, required, name
      end
      next unless case_data.fetch("required_findings").empty?

      assert codes.none? { |code| code.include?(".identifier-form-drift.") },
             "#{name}: unexpected identifier-form-drift finding in #{codes.inspect}"
    end
  end

  # ── detect spot checks (one per Rust reference test) ─────────────────────

  def tag(input)
    Ifd.detect(input).classify.tag
  end

  # `detect_empty_clear`
  def test_detect_empty_clear
    assert Ifd.detect([]).classify.clear?
  end

  # `detect_ascii_clear` — "Hello"; every ASCII letter is Allowed, identity NFKD.
  def test_detect_ascii_clear
    v = Ifd.detect([0x48, 0x65, 0x6C, 0x6C, 0x6F])
    assert v.classify.clear?
    assert_equal 0, v.shift_count
  end

  # `detect_greek_alpha_clear` — α is Allowed with identity NFKD.
  def test_detect_greek_alpha_clear
    assert Ifd.detect([0x03B1]).classify.clear?
  end

  # `detect_math_italic_a_shift` — U+1D44E Restricted, NFKD head U+0061 Allowed.
  def test_detect_math_italic_a_shift
    v = Ifd.detect([0x1D44E])
    assert_equal "IdentifierStatusShift", v.classify.tag
    assert_equal [0], v.classify.positions
    assert_equal 1, v.shift_count
  end

  # `detect_fullwidth_A_shift` — U+FF21 Restricted, NFKD head U+0041 Allowed.
  def test_detect_fullwidth_a_shift
    assert_equal "IdentifierStatusShift", tag([0xFF21])
  end

  # Docstring case — U+24B6 CIRCLED LATIN CAPITAL LETTER A → Restricted → Allowed (A).
  def test_detect_circled_a_shift
    assert_equal "IdentifierStatusShift", tag([0x24B6])
  end

  # Docstring case — U+FB01 'ﬁ' ligature → Restricted → Allowed (f).
  def test_detect_fi_ligature_shift
    assert_equal "IdentifierStatusShift", tag([0xFB01])
  end

  # Docstring case — U+2163 ROMAN NUMERAL FOUR → Restricted → Allowed (I).
  def test_detect_roman_iv_shift
    assert_equal "IdentifierStatusShift", tag([0x2163])
  end

  # A shift embedded mid-string reports the first shifting position, not 0.
  def test_detect_reports_first_shift_position
    # "ab" + U+1D44E: positions 0,1 are Allowed/identity, position 2 shifts.
    v = Ifd.detect([0x61, 0x62, 0x1D44E])
    assert_equal [2], v.classify.positions
    assert_equal 1, v.shift_count
  end

  # The composed reason code for the sole sub-threat.
  def test_reason_code_is_stable
    assert_equal(
      "unicode.security.X.identifier-form-drift.IdentifierStatusShift",
      Policy.reason_code(Family::IDENTIFIER_FORM_DRIFT, "IdentifierStatusShift")
    )
  end
end
