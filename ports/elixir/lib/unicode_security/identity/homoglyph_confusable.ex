defmodule UnicodeSecurity.Identity.HomoglyphConfusable do
  alias UnicodeSecurity.{Data, Ucd, Utf8}

  defstruct kind: :clear,
            sub: nil,
            skeleton: [],
            iterated_skeleton: [],
            restriction_level: :ascii_only,
            matched_targets: [],
            target: nil

  def confusable_source?(cp), do: Map.has_key?(confusables(), cp)

  def skeleton(input) do
    input
    |> Ucd.to_nfd()
    |> Ucd.case_fold()
    |> substitute()
    |> Ucd.case_fold()
    |> Ucd.to_nfd()
  end

  def iterated_skeleton(input) do
    next = skeleton(input)
    if next == input, do: input, else: iterated_skeleton(next)
  end

  def mixed_script_admissibility?(input) do
    length(Ucd.string_script_union(input)) >= 2 and not Ucd.highly_restrictive?(input)
  end

  def mixed_script_subthreat(input) do
    set = input |> Ucd.string_script_union() |> MapSet.new()

    cond do
      MapSet.member?(set, "Latn") and MapSet.member?(set, "Cyrl") -> "LatinCyrillic"
      MapSet.member?(set, "Latn") and MapSet.member?(set, "Grek") -> "LatinGreek"
      true -> "ScriptMixOther"
    end
  end

  def detect(input) do
    skel = skeleton(input)
    iskel = iterated_skeleton(input)
    rl = Ucd.restriction_level(input)
    base = %__MODULE__{skeleton: skel, iterated_skeleton: iskel, restriction_level: rl}

    cond do
      (target = find_target_match(input, iskel)) != nil ->
        %{
          base
          | kind: :hazard,
            sub: %{tag: "TargetMatch", target: target},
            matched_targets: [target],
            target: target
        }

      Enum.any?(input, &math_alphanumeric?/1) ->
        %{base | kind: :hazard, sub: %{tag: "MathAlpha"}}

      Enum.any?(input, &fullwidth_halfwidth?/1) ->
        %{base | kind: :hazard, sub: %{tag: "WidthClass"}}

      Ucd.to_nfc(input) != input ->
        %{base | kind: :hazard, sub: %{tag: "DecompositionSwap"}}

      mixed_script_admissibility?(input) ->
        %{base | kind: :hazard, sub: %{tag: "CrossScriptMix"}}

      rl in [:minimally_restrictive, :unrestricted] ->
        %{base | kind: :hazard, sub: %{tag: "RestrictionLow"}}

      true ->
        base
    end
  end

  defp confusables do
    Data.cached(:confusables_map, fn ->
      Data.read("confusables.txt")
      |> String.split("\n")
      |> Enum.reduce(%{}, fn raw, acc ->
        line = raw |> strip_comment() |> String.trim()

        if line == "" do
          acc
        else
          parts = String.split(line, ";") |> Enum.map(&String.trim/1)

          case parts do
            [src, target | _] ->
              Map.put(
                acc,
                String.to_integer(src, 16),
                target
                |> String.split(~r/\s+/, trim: true)
                |> Enum.map(&String.to_integer(&1, 16))
              )

            _ ->
              acc
          end
        end
      end)
    end)
  end

  defp strip_comment(line), do: line |> String.split("#", parts: 2) |> hd()

  defp substitute(input) do
    map = confusables()
    Enum.flat_map(input, fn cp -> Map.get(map, cp, [cp]) end)
  end

  defp targets do
    Data.cached(:known_attack_targets, fn ->
      Data.read("KnownAttackTargets.txt")
      |> String.split("\n")
      |> Enum.reduce([], fn line, acc ->
        line = String.trim(line)

        if line == "" or String.starts_with?(line, "#") do
          acc
        else
          cps = Utf8.decode_to_codepoints(line)

          [
            %{
              name: line,
              cps: cps,
              letters: letter_skeleton_from_iterated(iterated_skeleton(cps))
            }
            | acc
          ]
        end
      end)
      |> Enum.reverse()
    end)
  end

  defp letter_skeleton_from_iterated(iterated) do
    Enum.filter(iterated, fn cp ->
      Ucd.ccc(cp) == 0 and not Ucd.default_ignorable?(cp) and not Ucd.white_space?(cp)
    end)
  end

  defp find_target_match(input, iterated) do
    letters = letter_skeleton_from_iterated(iterated)

    Enum.find_value(targets(), fn target ->
      if target.cps != input and target.letters == letters, do: target.name, else: nil
    end)
  end

  defp math_alphanumeric?(cp), do: cp >= 0x1D400 and cp <= 0x1D7FF
  defp fullwidth_halfwidth?(cp), do: cp >= 0xFF01 and cp <= 0xFFEF
end
