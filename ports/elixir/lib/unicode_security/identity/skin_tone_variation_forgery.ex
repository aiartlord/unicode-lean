defmodule UnicodeSecurity.Identity.SkinToneVariationForgery do
  @moduledoc """
  skin-tone-variation-forgery — skin-tone modifier and variation-selector abuse
  on emoji bases per UTS #51 (the identity-layer detector I).

  Byte-faithful transliteration of the verified Rust reference implementation,
  itself a transcription of the Lean specification.

  Threat model. Tier A₁. An adversary places a skin-tone modifier on a codepoint
  that does NOT bear `Emoji_Modifier_Base`, stacks multiple skin tones on one
  base, or forces a text-style render on an emoji-default codepoint via U+FE0E
  (VS15) — sometimes to hide a payload-bearing glyph in plain sight. Distinct
  from the pair-aligned variation-selector-payload case: this catches the
  orthogonal semantic skin-tone / VS misuse on a single base.

  It reuses the port's own skin-tone predicate (`EmojiZwjIntegrity.is_emoji_modifier?/1`,
  the U+1F3FB..U+1F3FF set) and the already-bundled `priv/data/emoji-data.txt`
  the AiWatermarkDetectability detector reads — the two further properties this
  detector needs, `Emoji_Modifier_Base` and `Emoji_Presentation`, are parsed
  from that same file through a shared property parser. No host emoji library and
  no new data file.

  Sub-threats (priority order):
    1. `StackedSkinTones` — a base immediately followed by >= 2 skin-tone modifiers.
    2. `InvalidSkinToneTarget` — a skin-tone modifier on a non-`Emoji_Modifier_Base`.
    3. `ForcedTextStyle` — U+FE0E on an `Emoji_Presentation` codepoint.
  """

  alias UnicodeSecurity.Data
  alias UnicodeSecurity.Identity.EmojiZwjIntegrity

  @vs15 0xFE0E
  @vs16 0xFE0F

  # ───────────────────────────────────────────────────────────────────
  # §1 Classification tags
  # ───────────────────────────────────────────────────────────────────

  @doc "Fixture-row tag string for a sub-threat map (matches `SubThreat.tag`)."
  def sub_threat_tag(%{kind: :stacked_skin_tones}), do: "StackedSkinTones"
  def sub_threat_tag(%{kind: :invalid_skin_tone_target}), do: "InvalidSkinToneTarget"
  def sub_threat_tag(%{kind: :forced_text_style}), do: "ForcedTextStyle"

  def sub_threat_tag(other),
    do: raise(ArgumentError, "unreachable SkinToneVariationForgery sub-threat: #{inspect(other)}")

  @doc "True iff the classification is `Clear`."
  def is_clear(%{kind: :clear}), do: true
  def is_clear(%{kind: :hazard}), do: false

  @doc "Human-facing tag for a hazard classification, or `nil` when clear."
  def classification_tag(%{kind: :clear}), do: nil
  def classification_tag(%{kind: :hazard, sub: sub}), do: sub_threat_tag(sub)

  @doc "Implicated codepoint positions of a classification (empty when clear)."
  def classification_positions(%{kind: :clear}), do: []
  def classification_positions(%{kind: :hazard, positions: positions}), do: positions

  # ───────────────────────────────────────────────────────────────────
  # §2 Emoji property tables (bundled priv/data/emoji-data.txt)
  # ───────────────────────────────────────────────────────────────────

  # Parse the closed intervals for a single emoji property from emoji-data.txt.
  # Each non-comment row is `<range> ; <property> # <comment>`; keep only rows
  # whose property field matches `property` exactly. Mirrors the AiWatermark
  # emoji-data.txt parser, generalised over the target property.
  defp parse_emoji_property(property) do
    Data.read("emoji-data.txt")
    |> String.split("\n")
    |> Enum.reduce([], fn line, acc ->
      [body | _rest] = String.split(line, "#", parts: 2)

      case String.trim(body) do
        "" ->
          acc

        stripped ->
          case String.split(stripped, ";") do
            [range_field, prop_field | _tail] ->
              if String.trim(prop_field) == property do
                case parse_emoji_range(String.trim(range_field)) do
                  {lo, hi} -> [{lo, hi} | acc]
                  :error -> acc
                end
              else
                acc
              end

            _fewer_fields ->
              acc
          end
      end
    end)
  end

  # Parse a `<lo>..<hi>` or single `<cp>` hex range, or `:error` if malformed.
  defp parse_emoji_range(range) do
    case String.split(range, "..", parts: 2) do
      [a, b] ->
        case {Integer.parse(String.trim(a), 16), Integer.parse(String.trim(b), 16)} do
          {{lo, ""}, {hi, ""}} -> {lo, hi}
          _malformed -> :error
        end

      [single] ->
        case Integer.parse(String.trim(single), 16) do
          {v, ""} -> {v, v}
          _malformed -> :error
        end
    end
  end

  defp emoji_modifier_base_ranges,
    do: Data.cached(:stvf_emoji_modifier_base, fn -> parse_emoji_property("Emoji_Modifier_Base") end)

  defp emoji_presentation_ranges,
    do: Data.cached(:stvf_emoji_presentation, fn -> parse_emoji_property("Emoji_Presentation") end)

  defp in_ranges?(ranges, cp), do: Enum.any?(ranges, fn {lo, hi} -> lo <= cp and cp <= hi end)

  # ───────────────────────────────────────────────────────────────────
  # §3 Core predicates
  # ───────────────────────────────────────────────────────────────────

  @doc "True iff `cp` is an emoji skin-tone modifier (reuses the port's predicate)."
  def is_skin_tone?(cp), do: EmojiZwjIntegrity.is_emoji_modifier?(cp)

  @doc "True iff `cp` has `Emoji_Modifier_Base` per emoji-data.txt."
  def is_skin_tone_base?(cp), do: in_ranges?(emoji_modifier_base_ranges(), cp)

  @doc "True iff `cp` has `Emoji_Presentation` per emoji-data.txt."
  def is_emoji_presentation?(cp), do: in_ranges?(emoji_presentation_ranges(), cp)

  @doc "True iff `cp` is U+FE0E (VS15, text-style variation selector)."
  def is_vs15?(cp), do: cp == @vs15

  @doc "True iff `cp` is U+FE0F (VS16, emoji-style variation selector)."
  def is_vs16?(cp), do: cp == @vs16

  # ───────────────────────────────────────────────────────────────────
  # §4 Sub-detectors
  # ───────────────────────────────────────────────────────────────────

  # First position whose next two codepoints are both skin-tone modifiers, as
  # `{base_pos, [mod1, mod2]}`, or `nil`. The `0..(n - 1)//1` range is empty when
  # `n == 0`, so no `elem/2` is attempted on an empty input.
  defp first_stacked_skin_tones(arr, n) do
    Enum.find_value(0..(n - 1)//1, fn i ->
      m1 = if i + 1 < n, do: elem(arr, i + 1), else: nil
      m2 = if i + 2 < n, do: elem(arr, i + 2), else: nil

      if m1 != nil and m2 != nil and is_skin_tone?(m1) and is_skin_tone?(m2),
        do: {i, [m1, m2]},
        else: nil
    end)
  end

  # First skin-tone modifier whose preceding codepoint is NOT `Emoji_Modifier_Base`,
  # as `{base_pos, base_cp, modifier_cp}`, or `nil`.
  defp first_invalid_skin_tone_target(arr, n) do
    Enum.find_value(0..(n - 1)//1, fn i ->
      cp = if i + 1 < n, do: elem(arr, i + 1), else: nil
      base = elem(arr, i)

      if cp != nil and is_skin_tone?(cp) and not is_skin_tone_base?(base),
        do: {i, base, cp},
        else: nil
    end)
  end

  # First U+FE0E whose preceding codepoint has `Emoji_Presentation`, as
  # `{base_pos, base_cp}`, or `nil`.
  defp first_forced_text_style(arr, n) do
    Enum.find_value(0..(n - 1)//1, fn i ->
      cp = if i + 1 < n, do: elem(arr, i + 1), else: nil
      base = elem(arr, i)

      if cp != nil and is_vs15?(cp) and is_emoji_presentation?(base),
        do: {i, base},
        else: nil
    end)
  end

  # ───────────────────────────────────────────────────────────────────
  # §5 Top-level detection
  # ───────────────────────────────────────────────────────────────────

  @doc """
  The SkinToneVariationForgery detection function. Returns a verdict map
  mirroring the Lean/rust `Verdict`: `input`, `classify`, `skin_tone_count`,
  `variation_selector15_count`, `variation_selector16_count`.
  """
  def detect(input) do
    arr = List.to_tuple(input)
    n = length(input)

    classify =
      case first_stacked_skin_tones(arr, n) do
        {base_pos, modifiers} ->
          positions = Enum.map(0..(length(modifiers) - 1), fn k -> base_pos + 1 + k end)
          hazard(%{kind: :stacked_skin_tones, base_pos: base_pos, modifiers: modifiers}, positions)

        nil ->
          case first_invalid_skin_tone_target(arr, n) do
            {base_pos, base_cp, modifier_cp} ->
              hazard(
                %{
                  kind: :invalid_skin_tone_target,
                  base_pos: base_pos,
                  base_cp: base_cp,
                  modifier_cp: modifier_cp
                },
                [base_pos + 1]
              )

            nil ->
              case first_forced_text_style(arr, n) do
                {base_pos, base_cp} ->
                  hazard(%{kind: :forced_text_style, base_pos: base_pos, base_cp: base_cp}, [
                    base_pos + 1
                  ])

                nil ->
                  %{kind: :clear}
              end
          end
      end

    %{
      input: input,
      classify: classify,
      skin_tone_count: Enum.count(input, &is_skin_tone?/1),
      variation_selector15_count: Enum.count(input, &is_vs15?/1),
      variation_selector16_count: Enum.count(input, &is_vs16?/1)
    }
  end

  defp hazard(sub, positions), do: %{kind: :hazard, sub: sub, positions: positions, decoded: []}
end
