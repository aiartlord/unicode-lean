# frozen_string_literal: true

require_relative "test_helper"

class StreamSafeViolationTest < Minitest::Test
  include RubyPortTestHelpers

  StreamSafe = UnicodeRuby::Security::Form::StreamSafeViolation
  Policy = UnicodeRuby::Security::Policy
  Family = UnicodeRuby::Security::Calculus::Family

  ACUTE = 0x0301 # COMBINING ACUTE ACCENT, CCC = 230 (a non-starter).

  # Reason code the detector composes for its single sub-threat.
  def reason_code_for(verdict)
    tag = verdict.classify.tag
    return nil if tag.nil?

    Policy.reason_code(Family::STREAM_SAFE_VIOLATION, tag)
  end

  # Every case in the shared detector fixture must round-trip through detect:
  # its composed reason code matches the fixture's required findings, and a
  # clear case emits no stream-safe reason.
  def test_shared_fixture_cases
    fixture = fixture_json("detectors", "stream_safe_violation.json")
    assert_equal 1, fixture.fetch("schema")
    assert_equal "stream-safe-violation", fixture.fetch("family")

    fixture.fetch("cases").each do |case_data|
      name = case_data.fetch("name")
      verdict = StreamSafe.detect(case_data.fetch("input"))
      code = reason_code_for(verdict)
      required = case_data.fetch("required_findings")

      if required.empty?
        assert verdict.classify.clear?, "#{name}: expected clear"
        assert_nil code, "#{name}: unexpected finding #{code.inspect}"
      else
        refute verdict.classify.clear?, "#{name}: expected hazard"
        assert_equal required, [code], name
      end
    end
  end

  # Build "a" followed by n combining acute accents.
  def a_plus_marks(count)
    [0x61] + ([ACUTE] * count)
  end

  # Exactly 30 marks after a starter is the boundary case — stays clear under
  # strict `>`.
  def test_thirty_marks_boundary_clear
    verdict = StreamSafe.detect(a_plus_marks(30))
    assert verdict.classify.clear?
    assert_nil verdict.classify.tag
    assert_equal 30, verdict.max_run_len
    assert_equal 0, verdict.overrun_count
    assert_equal 30, verdict.total_non_starters
  end

  # 31 marks after a starter fires StreamSafeOverrun with base_pos 1, run_len
  # 31, positions [1].
  def test_thirtyone_marks_overrun
    verdict = StreamSafe.detect(a_plus_marks(31))
    refute verdict.classify.clear?
    assert_equal "StreamSafeOverrun", verdict.classify.tag
    assert_equal [1], verdict.classify.implicated_positions
    assert_equal :stream_safe_overrun, verdict.classify.sub.kind
    assert_equal 1, verdict.classify.sub.base_pos
    assert_equal 31, verdict.classify.sub.run_len
    assert_equal 31, verdict.max_run_len
    assert_equal 1, verdict.overrun_count
    assert_equal 31, verdict.total_non_starters
    assert_equal "unicode.security.F.stream-safe-violation.StreamSafeOverrun",
                 reason_code_for(verdict)
  end

  # Empty and pure-ASCII inputs are clear with zeroed summaries.
  def test_empty_and_ascii_clear
    empty = StreamSafe.detect([])
    assert empty.classify.clear?
    assert_equal 0, empty.max_run_len
    assert_equal 0, empty.total_non_starters

    ascii = StreamSafe.detect([0x48, 0x65, 0x6C, 0x6C, 0x6F])
    assert ascii.classify.clear?
    assert_equal 0, ascii.max_run_len
  end

  # A bare non-starter run that opens at index 0 records its start as 0.
  def test_bare_mark_run_starts_at_zero
    verdict = StreamSafe.detect([ACUTE] * 31)
    assert_equal "StreamSafeOverrun", verdict.classify.tag
    assert_equal [0], verdict.classify.implicated_positions
    assert_equal 31, verdict.max_run_len
    assert_equal 31, verdict.total_non_starters
  end

  # The first overrun wins: a short run before a long run does not shadow it,
  # and the reported base_pos is the long run's start.
  def test_first_overrun_reports_long_run_start
    input = a_plus_marks(5) + [0x62] + ([ACUTE] * 31)
    verdict = StreamSafe.detect(input)
    assert_equal "StreamSafeOverrun", verdict.classify.tag
    assert_equal [7], verdict.classify.implicated_positions
    assert_equal 31, verdict.max_run_len
    assert_equal 1, verdict.overrun_count
    assert_equal 36, verdict.total_non_starters
  end

  # Two separate runs, each under the limit, stay clear but are both summed.
  def test_two_short_runs_clear_totals_summed
    input = a_plus_marks(30) + [0x62] + ([ACUTE] * 30)
    verdict = StreamSafe.detect(input)
    assert verdict.classify.clear?
    assert_equal 30, verdict.max_run_len
    assert_equal 0, verdict.overrun_count
    assert_equal 60, verdict.total_non_starters
  end
end
