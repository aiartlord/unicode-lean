defmodule UnicodeSecurity.RendererDivergenceTest do
  use ExUnit.Case, async: false
  alias UnicodeSecurity.Display.RendererDivergence, as: RD
  alias UnicodeSecurity.Policy
  import UnicodeSecurity.TestHelpers

  # Detector hazard tag for a bare-input detect.
  defp tag(input), do: RD.detect(input).classify |> RD.classification_tag()

  # ── Shared context-free fixture through detect ────────────────────────
  # The 9 shared vectors from
  # `fixtures/security/detectors/renderer_divergence.json`, driven through the
  # policy reason-code machinery exactly as the sibling display detectors do.

  test "shared detector fixture" do
    fixture = fixture_json(Path.join("detectors", "renderer_divergence.json"))

    Enum.each(fixture["cases"], fn case_data ->
      input = case_data["input"]
      classify = RD.detect(input).classify

      code =
        case RD.classification_tag(classify) do
          nil -> nil
          hazard_tag -> Policy.reason_code(:renderer_divergence, hazard_tag)
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

  # ── The 9 rust reference spot-checks ──────────────────────────────────

  # `detect_empty_clear`
  test "empty is clear" do
    assert RD.is_clear(RD.detect([]).classify)
  end

  # `detect_ascii_clear`
  test "ascii is clear" do
    assert RD.is_clear(RD.detect([0x48, 0x65, 0x6C, 0x6C, 0x6F]).classify)
  end

  # `detect_han_clear`
  test "han is clear" do
    assert RD.is_clear(RD.detect([0x4E2D, 0x6587]).classify)
  end

  # `detect_vs_variance` — a single VS (FE0F) after an emoji.
  test "variation selector variance" do
    assert tag([0x1F600, 0xFE0F]) == "VariationSelectorVariance"
  end

  # `detect_rgi_family_clear` — a registered RGI family ZWJ sequence.
  test "registered RGI family is clear" do
    v = RD.detect([0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467, 0x200D, 0x1F466])
    assert RD.is_clear(v.classify)
    assert v.has_zwj
  end

  # `detect_unregistered_zwj_variance` — man + ZWJ + woman, not in RGI.
  test "unregistered zwj variance" do
    assert tag([0x1F468, 0x200D, 0x1F469]) == "UnregisteredZwjVariance"
  end

  # `detect_zalgo_variance` — a 4-deep combining stack.
  test "zalgo combining stack overflow" do
    v = RD.detect([0x0061, 0x0301, 0x0302, 0x0303, 0x0304])
    assert RD.classification_tag(v.classify) == "CombiningStackOverflow"
    assert RD.classification_positions(v.classify) == [0]
    assert v.combining_count == 4
  end

  # `detect_fullwidth_variance` — fullwidth 'A'.
  test "fullwidth variance" do
    assert tag([0xFF21]) == "FullwidthVariance"
  end

  # `detect_mixed_direction` — Latin + Hebrew in one input.
  test "mixed direction variance" do
    v = RD.detect([0x41, 0x42, 0x05D0, 0x05D1])
    assert RD.classification_tag(v.classify) == "MixedDirectionVariance"
    assert v.strong_ltr_count > 0 and v.strong_rtl_count > 0
  end

  # ── priority-ladder structural checks ─────────────────────────────────

  # A combining stack outranks a variation selector present later.
  test "combining stack beats variation selector" do
    v = RD.detect([0x0061, 0x0301, 0x0302, 0x0303, 0x0304, 0xFE0F])
    assert RD.classification_tag(v.classify) == "CombiningStackOverflow"
  end

  # Exactly three combining marks is below the stack threshold — no overflow.
  test "three marks below threshold" do
    v = RD.detect([0x0061, 0x0301, 0x0302, 0x0303])
    assert RD.classification_tag(v.classify) != "CombiningStackOverflow"
  end

  # ── policy taxonomy wiring ────────────────────────────────────────────
  # Mirroring the verified rust reference, `RendererDivergence` is registered as
  # a layer-`D` family with reason-code support but is not invoked in the shared
  # `scan` pipeline (whose findings are pinned by the cross-port verdict
  # contract). The registration below is what the reason-code machinery draws on.

  test "renderer-divergence is a layer-D family with the expected reason code" do
    assert Policy.family_layer_code(:renderer_divergence) == "D"
    assert Policy.family_slug(:renderer_divergence) == "renderer-divergence"

    assert Policy.reason_code(:renderer_divergence, "FullwidthVariance") ==
             "unicode.security.D.renderer-divergence.FullwidthVariance"
  end

  # Every sub-threat tag composes into a well-formed reason code, exactly as the
  # shared fixture rows spell them.
  test "each sub-threat tag composes the fixture reason code" do
    tags = [
      "CombiningStackOverflow",
      "VariationSelectorVariance",
      "UnregisteredZwjVariance",
      "FullwidthVariance",
      "MixedDirectionVariance"
    ]

    Enum.each(tags, fn t ->
      assert Policy.reason_code(:renderer_divergence, t) ==
               "unicode.security.D.renderer-divergence.#{t}"
    end)
  end
end
