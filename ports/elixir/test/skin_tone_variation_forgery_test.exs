defmodule UnicodeSecurity.SkinToneVariationForgeryTest do
  use ExUnit.Case, async: false
  alias UnicodeSecurity.Identity.SkinToneVariationForgery, as: STVF
  alias UnicodeSecurity.Policy
  import UnicodeSecurity.TestHelpers

  # Detector hazard tag for a bare-input detect.
  defp tag(input), do: STVF.detect(input).classify |> STVF.classification_tag()

  # ── Shared context-free fixture through detect ────────────────────────
  # The 8 shared vectors, driven through the policy reason-code machinery
  # exactly as the sibling identity/display detectors do.

  test "shared detector fixture" do
    fixture = fixture_json(Path.join("detectors", "skin_tone_variation_forgery.json"))

    Enum.each(fixture["cases"], fn case_data ->
      input = case_data["input"]
      classify = STVF.detect(input).classify

      code =
        case STVF.classification_tag(classify) do
          nil -> nil
          hazard_tag -> Policy.reason_code(:skin_tone_variation_forgery, hazard_tag)
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
    assert STVF.is_clear(STVF.detect([]).classify)
  end

  # `detect_ascii_clear` — "He"
  test "ascii is clear" do
    assert STVF.is_clear(STVF.detect([0x48, 0x65]).classify)
  end

  # `detect_plain_emoji_clear` — grinning face
  test "plain emoji is clear" do
    assert STVF.is_clear(STVF.detect([0x1F600]).classify)
  end

  # `detect_wave_skin_tone_clear` — waving hand (a modifier base) + one skin tone.
  test "wave plus single skin tone is clear" do
    v = STVF.detect([0x1F44B, 0x1F3FB])
    assert STVF.is_clear(v.classify)
    assert v.skin_tone_count == 1
  end

  # `detect_stacked_skin_tones` — waving hand + two skin tones.
  test "stacked skin tones" do
    v = STVF.detect([0x1F44B, 0x1F3FB, 0x1F3FC])
    assert STVF.classification_tag(v.classify) == "StackedSkinTones"
    assert STVF.classification_positions(v.classify) == [1, 2]
  end

  # `detect_invalid_target_ascii` — skin tone on ASCII 'A'.
  test "invalid target ascii" do
    v = STVF.detect([0x0041, 0x1F3FB])
    assert STVF.classification_tag(v.classify) == "InvalidSkinToneTarget"
    assert STVF.classification_positions(v.classify) == [1]
  end

  # `detect_invalid_target_smiley` — skin tone on grinning face (not a modifier base).
  test "invalid target smiley" do
    assert tag([0x1F600, 0x1F3FB]) == "InvalidSkinToneTarget"
  end

  # `detect_forced_text_style` — VS15 on grinning face (Emoji_Presentation).
  test "forced text style" do
    v = STVF.detect([0x1F600, 0xFE0E])
    assert STVF.classification_tag(v.classify) == "ForcedTextStyle"
    assert v.variation_selector15_count == 1
  end

  # Reused-predicate sanity.
  test "reused predicates" do
    assert STVF.is_skin_tone?(0x1F3FB)
    assert STVF.is_skin_tone_base?(0x1F44B)
    assert STVF.is_emoji_presentation?(0x1F600)
    refute STVF.is_skin_tone_base?(0x1F600)
  end

  # `reason_code_is_stable` — the composed reason code.
  test "reason code is stable" do
    assert Policy.reason_code(:skin_tone_variation_forgery, "StackedSkinTones") ==
             "unicode.security.I.skin-tone-variation-forgery.StackedSkinTones"
  end
end
