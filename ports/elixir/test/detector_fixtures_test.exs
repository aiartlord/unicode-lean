defmodule UnicodeSecurity.DetectorFixturesTest do
  use ExUnit.Case, async: false
  alias UnicodeSecurity.Policy
  import UnicodeSecurity.TestHelpers

  @fixtures [
    "tag_block_payload.json",
    "variation_selector_payload.json",
    "zero_width_payload.json",
    "surrogate_reassembly.json",
    "bidi_control_balance.json",
    "noncharacter_control.json",
    "homoglyph_confusable.json",
    "mixed_script_admissibility.json",
    "rtl_injection.json",
    "covert_display_compound.json",
    "confusable_bidi_compound.json"
  ]

  test "shared detector fixtures" do
    Enum.each(@fixtures, fn name ->
      fixture = fixture_json(Path.join("detectors", name))

      Enum.each(fixture["cases"], fn case_data ->
        verdict = Policy.scan("gateway-header", "observe", case_data["input"])
        codes = codes(verdict)

        Enum.each(case_data["required_findings"], fn required ->
          assert required in codes, "#{name}/#{case_data["name"]}"
        end)

        if case_data["required_findings"] == [] do
          needle = "." <> fixture["family"] <> "."

          Enum.each(codes, fn code ->
            refute String.contains?(code, needle), "#{name}/#{case_data["name"]}"
          end)
        end
      end)
    end)
  end
end
