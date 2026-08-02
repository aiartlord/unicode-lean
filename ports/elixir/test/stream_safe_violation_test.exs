defmodule UnicodeSecurity.Form.StreamSafeViolationTest do
  use ExUnit.Case, async: false
  alias UnicodeSecurity.Form.StreamSafeViolation
  alias UnicodeSecurity.Policy
  import UnicodeSecurity.TestHelpers

  @acute 0x0301

  defp a_plus_marks(n), do: [0x61 | List.duplicate(@acute, n)]

  test "shared fixture through the form-scan policy path" do
    fixture = fixture_json(Path.join("detectors", "stream_safe_violation.json"))

    Enum.each(fixture["cases"], fn case_data ->
      verdict = Policy.scan_forms("gateway-header", "observe", case_data["input"])
      codes = codes(verdict)

      Enum.each(case_data["required_findings"], fn required ->
        assert required in codes, "#{fixture["family"]}/#{case_data["name"]}"
      end)

      if case_data["required_findings"] == [] do
        needle = "." <> fixture["family"] <> "."

        Enum.each(codes, fn code ->
          refute String.contains?(code, needle), "#{fixture["family"]}/#{case_data["name"]}"
        end)
      end
    end)
  end

  test "reason code matches the fixture required finding" do
    assert Policy.reason_code(:stream_safe_violation, "StreamSafeOverrun") ==
             "unicode.security.F.stream-safe-violation.StreamSafeOverrun"
  end

  test "limit is 30" do
    assert StreamSafeViolation.stream_safe_limit() == 30
  end

  test "empty input is clear" do
    v = StreamSafeViolation.detect([])
    assert v.classify.kind == :clear
    assert v.sub == nil
    assert v.positions == []
    assert v.max_run_len == 0
    assert v.overrun_count == 0
    assert v.total_non_starters == 0
  end

  test "pure ASCII is clear" do
    v = StreamSafeViolation.detect([0x48, 0x65, 0x6C, 0x6C, 0x6F])
    assert v.classify.kind == :clear
    assert v.max_run_len == 0
    assert v.total_non_starters == 0
  end

  test "one combining mark is clear" do
    v = StreamSafeViolation.detect([0x61, @acute])
    assert v.classify.kind == :clear
    assert v.max_run_len == 1
    assert v.overrun_count == 0
    assert v.total_non_starters == 1
  end

  test "exactly 30 marks is the boundary — stays clear under strict >" do
    v = StreamSafeViolation.detect(a_plus_marks(30))
    assert v.classify.kind == :clear
    assert v.sub == nil
    assert v.max_run_len == 30
    assert v.overrun_count == 0
    assert v.total_non_starters == 30
  end

  test "31 marks fires StreamSafeOverrun at base_pos 1" do
    v = StreamSafeViolation.detect(a_plus_marks(31))
    assert v.classify.kind == :hazard
    assert v.sub == "StreamSafeOverrun"
    assert v.positions == [1]
    assert v.classify.sub == %{tag: "StreamSafeOverrun", base_pos: 1, run_len: 31}
    assert v.max_run_len == 31
    assert v.overrun_count == 1
    assert v.total_non_starters == 31
  end

  test "a bare non-starter run records its start at index 0" do
    v = StreamSafeViolation.detect(List.duplicate(@acute, 31))
    assert v.sub == "StreamSafeOverrun"
    assert v.positions == [0]
    assert v.max_run_len == 31
    assert v.total_non_starters == 31
  end

  test "two short runs stay clear but totals sum" do
    input = a_plus_marks(30) ++ [0x62] ++ List.duplicate(@acute, 30)
    v = StreamSafeViolation.detect(input)
    assert v.classify.kind == :clear
    assert v.max_run_len == 30
    assert v.overrun_count == 0
    assert v.total_non_starters == 60
  end

  test "the first overrun wins and reports the long run's start" do
    input = a_plus_marks(5) ++ [0x62] ++ List.duplicate(@acute, 31)
    v = StreamSafeViolation.detect(input)
    assert v.sub == "StreamSafeOverrun"
    assert v.positions == [7]
    assert v.max_run_len == 31
    assert v.overrun_count == 1
    assert v.total_non_starters == 36
  end
end
