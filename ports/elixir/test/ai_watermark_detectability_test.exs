defmodule UnicodeSecurity.AiWatermarkDetectabilityTest do
  use ExUnit.Case, async: false
  alias UnicodeSecurity.Crypto.AiWatermarkDetectability, as: AWD
  alias UnicodeSecurity.Crypto.AiWatermarkDetectability.Context
  alias UnicodeSecurity.Policy
  import UnicodeSecurity.TestHelpers

  # Detector tag for a bare-input detect.
  defp tag(input), do: AWD.detect(input) |> Map.fetch!(:classify) |> AWD.classification_tag()

  # ── Shared context-free fixture through detect ────────────────────────

  test "shared detector fixture" do
    fixture = fixture_json(Path.join("detectors", "ai_watermark_detectability.json"))

    Enum.each(fixture["cases"], fn case_data ->
      input = case_data["input"]
      classify = AWD.detect(input).classify

      # Detector verdict wired through the policy reason-code machinery, exactly
      # as `hash_input_stability` does.
      code =
        case AWD.classification_tag(classify) do
          nil -> nil
          hazard_tag -> Policy.reason_code(:ai_watermark_detectability, hazard_tag)
        end

      required = case_data["required_findings"]

      Enum.each(required, fn expected ->
        assert code == expected, "#{case_data["name"]}: expected #{expected}, got #{inspect(code)}"
      end)

      if required == [] do
        assert code == nil, "#{case_data["name"]}: expected clear, got #{inspect(code)}"
      end
    end)
  end

  # ── §8 tolerance-parameterised probes ─────────────────────────────────
  # Transcribed verbatim from the rust `#[test]` module's two Context-tolerance
  # vectors in `ports/rust/src/security/crypto/ai_watermark_detectability.rs`.

  test "detect_zwsp_jittered_strict_clear" do
    # ZWSPs at 1, 3, 6 (gaps 2, 3). Bare detect (tolerance 0) does not fire
    # gpt5ZwspModulo; falls through to defaultIgnorableCarrier.
    input = [0x61, 0x200B, 0x62, 0x200B, 0x63, 0x64, 0x200B, 0x65]
    assert tag(input) == "DefaultIgnorableCarrier"
  end

  test "detect_zwsp_jittered_tolerant_fires" do
    input = [0x61, 0x200B, 0x62, 0x200B, 0x63, 0x64, 0x200B, 0x65]
    ctx = %Context{zwsp_modulo_tolerance: 1}
    v = AWD.detect_with_context(ctx, input)
    assert AWD.classification_tag(v.classify) == "Gpt5ZwspModulo"
  end

  test "detect_with_context default matches detect" do
    d = AWD.detect([0x61, 0x202F, 0x62])
    c = AWD.detect_with_context(%Context{}, [0x61, 0x202F, 0x62])
    assert c.classify == d.classify
    assert c.marker_count == d.marker_count
  end

  # ── §7 cue-class coverage ─────────────────────────────────────────────

  test "every cue class is probed" do
    classes = [:green_list_bias, :pseudorandom_seq, :semantic_drift]

    sub_threats = [
      %{kind: :nnbsp_boundary, marker_count: 0},
      %{kind: :variation_selector_carrier, marker_count: 0},
      %{kind: :zwj_non_emoji, marker_count: 0},
      %{kind: :default_ignorable_carrier, marker_count: 0},
      %{kind: :gpt5_zwsp_modulo, first_pos: 0},
      %{kind: :em_dash_pattern, first_pos: 0},
      %{kind: :smart_quote_alternation, first_pos: 0},
      %{kind: :statistical_token_choice, first_pos: 0},
      %{kind: :adversarial, impersonated_scheme: "", first_pos: 0}
    ]

    Enum.each(classes, fn cls ->
      assert Enum.any?(sub_threats, fn st -> AWD.cue_class(st) == cls end),
             "cue class #{cls} is not probed by any sub-threat"
    end)
  end

  test "unknown has no cue class" do
    assert AWD.cue_class(%{kind: :unknown, anomaly_marker: 0}) == nil
  end
end
