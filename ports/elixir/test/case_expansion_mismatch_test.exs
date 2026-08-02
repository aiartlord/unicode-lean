defmodule UnicodeSecurity.Form.CaseExpansionMismatchTest do
  use ExUnit.Case, async: false
  alias UnicodeSecurity.Form.CaseExpansionMismatch, as: CEM
  alias UnicodeSecurity.Policy
  import UnicodeSecurity.TestHelpers

  # Detector hazard tag for a bare-input detect.
  defp tag(input), do: CEM.detect(input).classify |> CEM.classification_tag()

  # ── Shared context-free fixture through detect ────────────────────────
  # The 6 shared vectors, driven through the policy reason-code machinery
  # exactly as the sibling detectors do.

  test "shared detector fixture" do
    fixture = fixture_json(Path.join("detectors", "case_expansion_mismatch.json"))

    Enum.each(fixture["cases"], fn case_data ->
      input = case_data["input"]
      classify = CEM.detect(input).classify

      code =
        case CEM.classification_tag(classify) do
          nil -> nil
          hazard_tag -> Policy.reason_code(:case_expansion_mismatch, hazard_tag)
        end

      required = case_data["required_findings"]

      Enum.each(required, fn expected ->
        assert code == expected,
               "#{case_data["name"]}: expected #{expected}, got #{inspect(code)}"
      end)

      if required == [] do
        assert code == nil, "#{case_data["name"]}: expected clear, got #{inspect(code)}"
      end
    end)
  end

  # ── The rust reference spot-checks ────────────────────────────────────

  # `detect_empty_clear`
  test "empty is clear" do
    v = CEM.detect([])
    assert CEM.is_clear(v.classify)
    assert v.max_expansion_len == 0
  end

  # `detect_ascii_clear` — "Hello"; every ASCII cp case-maps to a single cp.
  test "ascii Hello is clear" do
    v = CEM.detect([0x48, 0x65, 0x6C, 0x6C, 0x6F])
    assert CEM.is_clear(v.classify)
    assert v.max_expansion_len == 1
  end

  # `detect_sharp_s_upper` — ß (U+00DF) to_upper → "SS".
  test "sharp s upper expansion" do
    v = CEM.detect([0x00DF])
    assert CEM.classification_tag(v.classify) == "UpperExpansion"
    assert CEM.classification_positions(v.classify) == [0]
    assert v.upper_expansion_count == 1
    assert v.max_expansion_len == 2
  end

  # `detect_fi_ligature_upper` — ﬁ (U+FB01) to_upper → "FI".
  test "fi ligature upper expansion" do
    assert tag([0xFB01]) == "UpperExpansion"
  end

  # ﬃ (U+FB03) to_upper → "FFI" (length 3) — the expansion length is reported.
  test "ffi ligature length 3" do
    v = CEM.detect([0xFB03])
    assert CEM.classification_tag(v.classify) == "UpperExpansion"
    assert v.max_expansion_len == 3
  end

  # `detect_dotted_I_lower` — İ (U+0130) to_lower under default → "i + 0307";
  # no upper expansion, so the detector falls through to the lower scan.
  test "dotted capital I lower expansion" do
    v = CEM.detect([0x0130])
    assert CEM.classification_tag(v.classify) == "LowerExpansion"
    assert v.lower_expansion_count == 1
  end

  # A leading ASCII then ß: the upper expansion is reported at position 1.
  test "reports first expansion position" do
    v = CEM.detect([0x61, 0x00DF])
    assert CEM.classification_positions(v.classify) == [1]
  end

  # ── reason-code stability ─────────────────────────────────────────────

  test "reason codes are stable" do
    assert Policy.reason_code(:case_expansion_mismatch, "UpperExpansion") ==
             "unicode.security.F.case-expansion-mismatch.UpperExpansion"

    assert Policy.reason_code(:case_expansion_mismatch, "LowerExpansion") ==
             "unicode.security.F.case-expansion-mismatch.LowerExpansion"
  end
end
