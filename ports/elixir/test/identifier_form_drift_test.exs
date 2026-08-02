defmodule UnicodeSecurity.IdentifierFormDriftTest do
  use ExUnit.Case, async: false
  alias UnicodeSecurity.Boundary.IdentifierFormDrift, as: IFD
  alias UnicodeSecurity.Policy
  import UnicodeSecurity.TestHelpers

  # Detector hazard tag for a bare-input detect.
  defp tag(input), do: IFD.detect(input).classify |> IFD.classification_tag()

  # ── Shared context-free fixture through detect ────────────────────────
  # The 8 shared vectors, driven through the policy reason-code machinery
  # exactly as the sibling boundary/display detectors do.

  test "shared detector fixture" do
    fixture = fixture_json(Path.join("detectors", "identifier_form_drift.json"))

    Enum.each(fixture["cases"], fn case_data ->
      input = case_data["input"]
      classify = IFD.detect(input).classify

      code =
        case IFD.classification_tag(classify) do
          nil -> nil
          hazard_tag -> Policy.reason_code(:identifier_form_drift, hazard_tag)
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
    assert IFD.is_clear(IFD.detect([]).classify)
  end

  # `detect_ascii_clear` — "Hello"; every ASCII letter is Allowed, identity NFKD.
  test "ascii Hello is clear" do
    v = IFD.detect([0x48, 0x65, 0x6C, 0x6C, 0x6F])
    assert IFD.is_clear(v.classify)
    assert v.shift_count == 0
  end

  # `detect_greek_alpha_clear` — α is Allowed with identity NFKD.
  test "greek alpha is clear" do
    assert IFD.is_clear(IFD.detect([0x03B1]).classify)
  end

  # `detect_math_italic_a_shift` — U+1D44E Restricted, NFKD head U+0061 Allowed.
  test "math italic a shifts" do
    v = IFD.detect([0x1D44E])
    assert IFD.classification_tag(v.classify) == "IdentifierStatusShift"
    assert IFD.classification_positions(v.classify) == [0]
    assert v.shift_count == 1
  end

  # `detect_fullwidth_A_shift` — U+FF21 Restricted, NFKD head U+0041 Allowed.
  test "fullwidth A shifts" do
    assert tag([0xFF21]) == "IdentifierStatusShift"
  end

  # `detect_circled_A_shift` — U+24B6 CIRCLED LATIN CAPITAL LETTER A → Restricted → Allowed (A).
  test "circled A shifts" do
    assert tag([0x24B6]) == "IdentifierStatusShift"
  end

  # `detect_fi_ligature_shift` — U+FB01 'ﬁ' ligature → Restricted → Allowed (f).
  test "fi ligature shifts" do
    assert tag([0xFB01]) == "IdentifierStatusShift"
  end

  # `detect_roman_iv_shift` — U+2163 ROMAN NUMERAL FOUR → Restricted → Allowed (I).
  test "roman numeral four shifts" do
    assert tag([0x2163]) == "IdentifierStatusShift"
  end

  # `detect_reports_first_shift_position` — "ab" + U+1D44E: position 2 shifts.
  test "reports first shift position" do
    v = IFD.detect([0x61, 0x62, 0x1D44E])
    assert IFD.classification_positions(v.classify) == [2]
    assert v.shift_count == 1
  end

  # `reason_code_is_stable` — the composed reason code for the sole sub-threat.
  test "reason code is stable" do
    assert Policy.reason_code(:identifier_form_drift, "IdentifierStatusShift") ==
             "unicode.security.X.identifier-form-drift.IdentifierStatusShift"
  end
end
