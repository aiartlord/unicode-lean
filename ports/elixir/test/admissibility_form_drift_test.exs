defmodule UnicodeSecurity.AdmissibilityFormDriftTest do
  use ExUnit.Case, async: false
  alias UnicodeSecurity.Boundary.AdmissibilityFormDrift, as: AFD
  alias UnicodeSecurity.Policy
  import UnicodeSecurity.TestHelpers

  # Detector hazard tag for a bare-input detect.
  defp tag(input), do: AFD.detect(input).classify |> AFD.classification_tag()

  # ── Shared context-free fixture through detect ────────────────────────
  # The 4 shared vectors, driven through the policy reason-code machinery
  # exactly as the sibling boundary/display detectors do.

  test "shared detector fixture" do
    fixture = fixture_json(Path.join("detectors", "admissibility_form_drift.json"))

    Enum.each(fixture["cases"], fn case_data ->
      input = case_data["input"]
      classify = AFD.detect(input).classify

      code =
        case AFD.classification_tag(classify) do
          nil -> nil
          hazard_tag -> Policy.reason_code(:admissibility_form_drift, hazard_tag)
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

  # `detect_empty_clear` — both admissibility calls return false, so they agree.
  test "empty is clear" do
    assert AFD.is_clear(AFD.detect([]).classify)
  end

  # `detect_ascii_clear` — "admin"; admissible on both sides (NFKC is identity).
  test "ascii admin is clear" do
    v = AFD.detect([0x61, 0x64, 0x6D, 0x69, 0x6E])
    assert AFD.is_clear(v.classify)
    assert v.input_admissible
    assert v.nfkc_admissible
  end

  # `detect_fi_ligature_drift` — ﬁ (U+FB01) is Restricted (inadmissible), but
  # NFKC decomposes it to "fi" (admissible). Drift fires.
  test "fi ligature drifts" do
    v = AFD.detect([0xFB01])
    assert AFD.classification_tag(v.classify) == "AdmissibilityFormDrift"
    refute v.input_admissible
    assert v.nfkc_admissible
    assert AFD.classification_positions(v.classify) == []
  end

  # `detect_jamo_sequence_drift` — decomposed Hangul jamos [U+1112, U+1161,
  # U+11AB] are inadmissible, but NFKC composes them to U+D55C 한 (admissible).
  test "jamo sequence drifts" do
    assert tag([0x1112, 0x1161, 0x11AB]) == "AdmissibilityFormDrift"
  end

  # `reason_code_is_stable` — the composed reason code for the sole sub-threat.
  test "reason code is stable" do
    assert Policy.reason_code(:admissibility_form_drift, "AdmissibilityFormDrift") ==
             "unicode.security.X.admissibility-form-drift.AdmissibilityFormDrift"
  end
end
