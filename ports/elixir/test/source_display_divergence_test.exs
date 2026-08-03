defmodule UnicodeSecurity.SourceDisplayDivergenceTest do
  use ExUnit.Case, async: false
  alias UnicodeSecurity.Display.SourceDisplayDivergence, as: SDD
  alias UnicodeSecurity.Policy
  import UnicodeSecurity.TestHelpers

  # Sub-threat tag for a bare-input detect, or `nil` when clear.
  defp tag(input), do: input |> SDD.detect() |> SDD.classification_tag()

  # ── Shared context-free fixture through detect ────────────────────────
  # The 10 shared vectors from
  # `fixtures/security/detectors/source_display_divergence.json`, driven through
  # the policy reason-code machinery exactly as the sibling display detectors do.

  test "shared detector fixture" do
    fixture = fixture_json(Path.join("detectors", "source_display_divergence.json"))

    Enum.each(fixture["cases"], fn case_data ->
      input = case_data["input"]

      code =
        case tag(input) do
          nil -> nil
          hazard_tag -> Policy.reason_code(:source_display_divergence, hazard_tag)
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

  # `clear_cases`
  test "empty is clear" do
    assert tag([]) == nil
  end

  test "hello world is clear" do
    assert tag([0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64]) == nil
  end

  test "let x = 1; is clear" do
    assert tag([0x6C, 0x65, 0x74, 0x20, 0x78, 0x20, 0x3D, 0x20, 0x31, 0x3B]) == nil
  end

  # `single_fire_passthrough`
  test "tag-encoded AB passes through TagBlock" do
    assert tag([0xE0041, 0xE0042]) == "TagBlock"
  end

  test "A + VS16 passes through VariationSelector" do
    assert tag([0x0041, 0xFE0F]) == "VariationSelector"
  end

  test "H + ZWSP + i passes through ZeroWidth" do
    assert tag([0x0048, 0x200B, 0x69]) == "ZeroWidth"
  end

  test "RLO + A passes through BidiControl" do
    assert tag([0x202E, 0x41]) == "BidiControl"
  end

  test "Cyrillic homoglyph passes through IdentifierHomoglyph" do
    assert tag([0x4E, 0x65, 0x74, 0x68, 0x65, 0x72, 0x0435, 0x75, 0x6D]) ==
             "IdentifierHomoglyph"
  end

  # `two_or_more_is_compound`
  test "A + VS16 + ZWSP is Compound" do
    assert tag([0x0041, 0xFE0F, 0x200B]) == "Compound"
  end

  test "tag AB + ZWSP is Compound" do
    assert tag([0xE0041, 0xE0042, 0x200B]) == "Compound"
  end

  # ── accessors + policy taxonomy wiring ────────────────────────────────

  # Clear inputs report clear and carry no positions; hazards carry none either,
  # since the per-family verdicts own the positions at this layer.
  test "clear and hazard accessors" do
    clear = SDD.detect([])
    assert SDD.is_clear(clear)
    assert SDD.classification_positions(clear) == []

    hazard = SDD.detect([0x0041, 0xFE0F])
    refute SDD.is_clear(hazard)
    assert SDD.classification_positions(hazard) == []
  end

  # Mirroring the verified rust reference, `SourceDisplayDivergence` is a
  # standalone layer-`D` family (not invoked in the shared `scan` pipeline). The
  # registration below is what the reason-code machinery draws on.
  test "source-display-divergence is a layer-D family with the expected reason code" do
    assert Policy.family_layer_code(:source_display_divergence) == "D"
    assert Policy.family_slug(:source_display_divergence) == "source-display-divergence"

    assert Policy.reason_code(:source_display_divergence, "Compound") ==
             "unicode.security.D.source-display-divergence.Compound"
  end

  # Every family tag composes into a well-formed reason code, exactly as the
  # shared fixture rows spell them.
  test "each family tag composes the fixture reason code" do
    tags = ["TagBlock", "VariationSelector", "ZeroWidth", "BidiControl", "IdentifierHomoglyph", "Compound"]

    Enum.each(tags, fn t ->
      assert Policy.reason_code(:source_display_divergence, t) ==
               "unicode.security.D.source-display-divergence.#{t}"
    end)
  end
end
