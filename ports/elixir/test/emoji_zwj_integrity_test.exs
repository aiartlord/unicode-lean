defmodule UnicodeSecurity.EmojiZwjIntegrityTest do
  use ExUnit.Case, async: false
  alias UnicodeSecurity.Identity.EmojiZwjIntegrity, as: EZI
  alias UnicodeSecurity.Policy
  import UnicodeSecurity.TestHelpers

  # Detector hazard tag for a bare-input detect.
  defp tag(input), do: EZI.detect(input).classify |> EZI.classification_tag()

  # ── Shared context-free fixture through detect ────────────────────────
  # The 12 shared vectors from
  # `fixtures/security/detectors/emoji_zwj_integrity.json`, driven through the
  # policy reason-code machinery exactly as the sibling identity detectors do.

  test "shared detector fixture" do
    fixture = fixture_json(Path.join("detectors", "emoji_zwj_integrity.json"))

    Enum.each(fixture["cases"], fn case_data ->
      input = case_data["input"]
      classify = EZI.detect(input).classify

      code =
        case EZI.classification_tag(classify) do
          nil -> nil
          hazard_tag -> Policy.reason_code(:emoji_zwj_integrity, hazard_tag)
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

  test "shared detector fixture through Policy.scan" do
    fixture = fixture_json(Path.join("detectors", "emoji_zwj_integrity.json"))

    Enum.each(fixture["cases"], fn case_data ->
      verdict = Policy.scan("gateway-header", "observe", case_data["input"])
      codes = codes(verdict)

      Enum.each(case_data["required_findings"], fn required ->
        assert required in codes, "#{case_data["name"]}"
      end)

      if case_data["required_findings"] == [] do
        needle = "." <> fixture["family"] <> "."

        Enum.each(codes, fn code ->
          refute String.contains?(code, needle), "#{case_data["name"]}"
        end)
      end
    end)
  end

  # ── data-layer sanity (transcribed rust #[test]s) ─────────────────────

  test "is_emoji_modifier_checks" do
    assert EZI.is_emoji_modifier?(0x1F3FB)
    assert EZI.is_emoji_modifier?(0x1F3FF)
    refute EZI.is_emoji_modifier?(0x1F3FA)
    refute EZI.is_emoji_modifier?(0x1F600)
  end

  test "zwj_alphabet_admits_heart_rejects_grinning" do
    # U+2764 HEAVY BLACK HEART appears in couple-with-heart RGI sequences.
    assert EZI.is_emoji_target?(0x2764)
    # U+1F468 MAN appears in family/couple RGI sequences.
    assert EZI.is_emoji_target?(0x1F468)
    # U+1F600 GRINNING FACE appears in no registered RGI ZWJ sequence.
    refute EZI.is_emoji_target?(0x1F600)
    # The joiner itself is excluded from the alphabet.
    refute EZI.is_emoji_target?(EZI.zwj())
  end

  test "registered_membership_is_exact" do
    # MAN + ZWJ + LAPTOP (man technologist) is a registered RGI sequence.
    assert EZI.is_registered_zwj_sequence?([0x1F468, 0x200D, 0x1F4BB])
    # MAN + ZWJ + WOMAN is not a registered RGI sequence.
    refute EZI.is_registered_zwj_sequence?([0x1F468, 0x200D, 0x1F469])
  end

  # ── §5 detect spot checks (one per rust #[test]) ──────────────────────

  test "detect_empty_clear" do
    v = EZI.detect([])
    assert EZI.is_clear(v.classify)
    assert EZI.classification_tag(v.classify) == nil
    assert v.zwj_positions == []
    assert v.chain_length == 0
    assert v.skin_tone_count == 0
  end

  test "detect_ascii_clear" do
    assert EZI.is_clear(EZI.detect([0x48, 0x65, 0x6C, 0x6C, 0x6F]).classify)
  end

  test "detect_plain_emoji_clear" do
    assert EZI.is_clear(EZI.detect([0x1F600]).classify)
  end

  test "detect_one_skintone_clear" do
    v = EZI.detect([0x1F44B, 0x1F3FB])
    assert EZI.is_clear(v.classify)
    assert v.skin_tone_count == 1
  end

  test "detect_family_rgi_clear" do
    v = EZI.detect([0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467, 0x200D, 0x1F466])
    assert EZI.is_clear(v.classify)
    assert v.is_registered_rgi
  end

  test "detect_double_zwj" do
    v = EZI.detect([0x1F600, 0x200D, 0x200D, 0x1F600])
    assert EZI.classification_tag(v.classify) == "DoubleZWJ"
    assert EZI.classification_positions(v.classify) == [1]
  end

  test "detect_non_emoji_injection" do
    v = EZI.detect([0x1F600, 0x200D, 0x0061])
    assert EZI.classification_tag(v.classify) == "NonEmojiInjection"
  end

  test "detect_skin_tone_overflow" do
    v = EZI.detect([0x1F44B, 0x1F3FB, 0x1F3FC, 0x1F3FD, 0x1F3FE, 0x1F3FF])
    assert EZI.classification_tag(v.classify) == "SkinToneOverflow"
    assert v.skin_tone_count == 5
  end

  test "detect_man_laptop_registered_clear" do
    assert EZI.is_clear(EZI.detect([0x1F468, 0x200D, 0x1F4BB]).classify)
  end

  test "detect_unregistered" do
    # man + ZWJ + woman: both flanks are in the RGI alphabet but the joined
    # sequence is not registered.
    v = EZI.detect([0x1F468, 0x200D, 0x1F469])
    assert EZI.classification_tag(v.classify) == "UnregisteredSequence"
  end

  test "detect_grinning_laptop_non_emoji_injection" do
    # grinning face is not a valid ZWJ-join target, so this surfaces as
    # NonEmojiInjection.
    assert tag([0x1F600, 0x200D, 0x1F4BB]) == "NonEmojiInjection"
  end

  # ── structural checks (follow from the priority ladder) ───────────────

  test "over_length_fires_past_cap" do
    # 9 men joined by 8 ZWJs = 17 codepoints (> max_rgi_length).
    input =
      0..8//1
      |> Enum.flat_map(fn i -> if i > 0, do: [0x200D, 0x1F468], else: [0x1F468] end)

    assert length(input) == 17
    v = EZI.detect(input)
    assert EZI.classification_tag(v.classify) == "OverLength"

    assert v.classify == %{
             kind: :hazard,
             sub: %{kind: :over_length, length: 17, max_length: EZI.max_rgi_length()},
             positions: [],
             decoded: []
           }
  end

  test "trailing_zwj_is_injection" do
    v = EZI.detect([0x1F468, 0x200D])
    assert EZI.classification_tag(v.classify) == "NonEmojiInjection"
    assert EZI.classification_positions(v.classify) == [1]
  end

  test "double_zwj_beats_unregistered" do
    # man ZWJ ZWJ boy — adjacent ZWJs present.
    v = EZI.detect([0x1F468, 0x200D, 0x200D, 0x1F466])
    assert EZI.classification_tag(v.classify) == "DoubleZWJ"
  end
end
