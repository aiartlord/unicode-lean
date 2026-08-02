# frozen_string_literal: true

require_relative "test_helper"

class CaseExpansionMismatchTest < Minitest::Test
  include RubyPortTestHelpers

  Cem = UnicodeRuby::Security::Form::CaseExpansionMismatch
  Policy = UnicodeRuby::Security::Policy
  Family = UnicodeRuby::Security::Calculus::Family

  # ── (a) shared context-free detector fixture ─────────────────────────────
  #
  # The 6 shared vectors are context-free, so they exercise `detect` directly.
  # Each hazard tag maps to its stable reason code via the same Policy wiring
  # the sibling form detectors use.

  def code_for(input)
    tag = Cem.detect(input).classify.tag
    tag.nil? ? [] : [Policy.reason_code(Family::CASE_EXPANSION_MISMATCH, tag)]
  end

  def test_shared_fixture_cases
    fixture = fixture_json("detectors", "case_expansion_mismatch.json")
    assert_equal 1, fixture.fetch("schema")
    assert_equal "case-expansion-mismatch", fixture.fetch("family")

    fixture.fetch("cases").each do |case_data|
      name = case_data.fetch("name")
      codes = code_for(case_data.fetch("input"))
      case_data.fetch("required_findings").each do |required|
        assert_includes codes, required, name
      end
      next unless case_data.fetch("required_findings").empty?

      assert codes.none? { |code| code.include?(".case-expansion-mismatch.") },
             "#{name}: unexpected case-expansion-mismatch finding in #{codes.inspect}"
    end
  end

  # ── detect spot checks (one per Rust reference test) ─────────────────────

  def tag(input)
    Cem.detect(input).classify.tag
  end

  # `detect_empty_clear`
  def test_detect_empty_clear
    assert Cem.detect([]).classify.clear?
  end

  # `detect_ascii_clear` — "Hello"; every ASCII cp case-maps to a single cp.
  def test_detect_ascii_clear
    v = Cem.detect([0x48, 0x65, 0x6C, 0x6C, 0x6F])
    assert v.classify.clear?
    assert_equal 1, v.max_expansion_len
  end

  # `detect_sharp_s_upper` — ß (U+00DF) toUpper → "SS".
  def test_detect_sharp_s_upper
    v = Cem.detect([0x00DF])
    assert_equal "UpperExpansion", v.classify.tag
    assert_equal [0], v.classify.positions
    assert_equal 1, v.upper_expansion_count
    assert_equal 2, v.max_expansion_len
  end

  # `detect_fi_ligature_upper` — ﬁ (U+FB01) toUpper → "FI".
  def test_detect_fi_ligature_upper
    assert_equal "UpperExpansion", tag([0xFB01])
  end

  # `detect_dotted_I_lower` — İ (U+0130) toLower under default → "i + 0307";
  # no upper expansion, so the detector falls through to the lower scan.
  def test_detect_dotted_i_lower
    v = Cem.detect([0x0130])
    assert_equal "LowerExpansion", v.classify.tag
    assert_equal 1, v.lower_expansion_count
  end

  # ﬃ (U+FB03) toUpper → "FFI" (length 3) — the expansion length is reported.
  def test_detect_ffi_ligature_len3
    v = Cem.detect([0xFB03])
    assert_equal "UpperExpansion", v.classify.tag
    assert_equal 3, v.max_expansion_len
  end

  # A leading ASCII then ß: the upper expansion is reported at position 1.
  def test_detect_reports_first_expansion_position
    v = Cem.detect([0x61, 0x00DF])
    assert_equal [1], v.classify.positions
  end

  # The composed reason codes for each sub-threat.
  def test_reason_code_is_stable
    assert_equal(
      "unicode.security.F.case-expansion-mismatch.UpperExpansion",
      Policy.reason_code(Family::CASE_EXPANSION_MISMATCH, "UpperExpansion")
    )
    assert_equal(
      "unicode.security.F.case-expansion-mismatch.LowerExpansion",
      Policy.reason_code(Family::CASE_EXPANSION_MISMATCH, "LowerExpansion")
    )
  end
end
