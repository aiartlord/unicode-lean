# frozen_string_literal: true

require_relative "test_helper"

class AdmissibilityFormDriftTest < Minitest::Test
  include RubyPortTestHelpers

  Afd = UnicodeRuby::Security::Boundary::AdmissibilityFormDrift
  Policy = UnicodeRuby::Security::Policy
  Family = UnicodeRuby::Security::Calculus::Family

  # ── (a) shared context-free detector fixture ─────────────────────────────
  #
  # The 4 shared vectors are context-free, so they exercise `detect` directly.
  # The sole hazard tag maps to its stable reason code via the same Policy
  # wiring the sibling boundary detectors use.

  def code_for(input)
    tag = Afd.detect(input).classify.tag
    tag.nil? ? [] : [Policy.reason_code(Family::ADMISSIBILITY_FORM_DRIFT, tag)]
  end

  def test_shared_fixture_cases
    fixture = fixture_json("detectors", "admissibility_form_drift.json")
    assert_equal 1, fixture.fetch("schema")
    assert_equal "admissibility-form-drift", fixture.fetch("family")

    fixture.fetch("cases").each do |case_data|
      name = case_data.fetch("name")
      codes = code_for(case_data.fetch("input"))
      case_data.fetch("required_findings").each do |required|
        assert_includes codes, required, name
      end
      next unless case_data.fetch("required_findings").empty?

      assert codes.none? { |code| code.include?(".admissibility-form-drift.") },
             "#{name}: unexpected admissibility-form-drift finding in #{codes.inspect}"
    end
  end

  # ── detect spot checks (one per Rust reference test) ─────────────────────

  def tag(input)
    Afd.detect(input).classify.tag
  end

  # `detect_empty_clear` — both admissibility calls return false, so they agree.
  def test_detect_empty_clear
    assert Afd.detect([]).classify.clear?
  end

  # `detect_ascii_clear` — "admin"; admissible on both sides (NFKC is identity).
  def test_detect_ascii_clear
    v = Afd.detect([0x61, 0x64, 0x6D, 0x69, 0x6E])
    assert v.classify.clear?
    assert v.input_admissible
    assert v.nfkc_admissible
  end

  # `detect_fi_ligature_drift` — ﬁ (U+FB01) is Restricted (inadmissible), but
  # NFKC decomposes it to "fi" (admissible).  Drift fires.
  def test_detect_fi_ligature_drift
    v = Afd.detect([0xFB01])
    assert_equal "AdmissibilityFormDrift", v.classify.tag
    refute v.input_admissible
    assert v.nfkc_admissible
    assert_equal [], v.classify.positions
  end

  # `detect_jamo_sequence_drift` — decomposed Hangul jamos [U+1112, U+1161,
  # U+11AB] are inadmissible, but NFKC composes them to U+D55C 한 (admissible).
  def test_detect_jamo_sequence_drift
    v = Afd.detect([0x1112, 0x1161, 0x11AB])
    assert_equal "AdmissibilityFormDrift", v.classify.tag
    refute v.input_admissible
    assert v.nfkc_admissible
  end

  # The composed reason code for the sole sub-threat.
  def test_reason_code_is_stable
    assert_equal(
      "unicode.security.X.admissibility-form-drift.AdmissibilityFormDrift",
      Policy.reason_code(Family::ADMISSIBILITY_FORM_DRIFT, "AdmissibilityFormDrift")
    )
  end
end
