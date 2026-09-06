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

  # Iteration cap for iterated_skeleton, mirroring the Lean
  # Unicode.Confusables.confusableChainBound: far above the longest chain in the
  # bundled UTS #39 data, so termination is structural, not a data property.
  @confusable_chain_bound 32

  def iterated_skeleton(input), do: iterated_skeleton(input, @confusable_chain_bound)

  defp iterated_skeleton(input, 0), do: input

  defp iterated_skeleton(input, fuel) do
    next = skeleton(input)
    if next == input, do: input, else: iterated_skeleton(next, fuel - 1)
  end

  def mixed_script_admissibility?(input) do
    mixed_script_verdict(input, true) != nil
  end

  @doc """
  The mixed-script sub-threat for `input`, or nil when admissible.

  The rung order is MixedScriptAdmissibility.lean's: a Restricted-status
  codepoint outranks every script question, then the two named Latin pairs,
  then a multi-script mix split by whether it stays inside a CJK covered set,
  and finally an Unrestricted level with no script mix.

  `identifier_field` carries what the caller knows about the field, mirroring
  that module's Context. Phase 1 is sound for an identifier, which cannot
  contain a space, and unsound for a document, where every space and every
  punctuation mark is Restricted.
  """
  def mixed_script_verdict(input, identifier_field) do
    set = input |> Ucd.string_script_union() |> MapSet.new()
    union_size = MapSet.size(set)

    cond do
      identifier_field and Enum.any?(input, fn cp -> not Ucd.id_allowed?(cp) end) ->
        "RestrictedStatusCp"

      MapSet.member?(set, "Latn") and MapSet.member?(set, "Cyrl") ->
        "LatinCyrillic"

      MapSet.member?(set, "Latn") and MapSet.member?(set, "Grek") ->
        "LatinGreek"

      union_size >= 2 and not Ucd.highly_restrictive?(input) ->
        if Ucd.covered_cjk?(input), do: "CjkMix", else: "ScriptMixOther"

      identifier_field and Ucd.restriction_level(input) == :unrestricted ->
        "UnrestrictedLevel"

      true ->
        nil
    end
  end

  def mixed_script_subthreat(input) do
    set = input |> Ucd.string_script_union() |> MapSet.new()

    cond do
      MapSet.member?(set, "Latn") and MapSet.member?(set, "Cyrl") -> "LatinCyrillic"
      MapSet.member?(set, "Latn") and MapSet.member?(set, "Grek") -> "LatinGreek"
      true -> "ScriptMixOther"
    end
  end

  @doc """
  The case-preserving skeleton: NFD, confusable substitution, NFD, with no case
  fold, so `admın` (dotless i) maps to `adrnin` while `ADMIN` stays itself.
  Mirrors the Lean asciiSkeleton.
  """
  def ascii_skeleton(input), do: input |> Ucd.to_nfd() |> substitute() |> Ucd.to_nfd()

  @doc """
  A non-ASCII input whose case-preserving skeleton is all ASCII. Mirrors the
  Lean isAsciiConfusable.
  """
  def ascii_confusable?(input) do
    Enum.any?(input, &(&1 > 0x7F)) and Enum.all?(ascii_skeleton(input), &(&1 <= 0x7F))
  end

  @doc "0-based positions of the non-ASCII codepoints. Mirrors the Lean nonAsciiPositions."
  def non_ascii_positions(input) do
    input
    |> Enum.with_index()
    |> Enum.flat_map(fn {cp, idx} -> if cp > 0x7F, do: [idx], else: [] end)
  end

  @doc "Every script-bearing codepoint of the input is Latin. Mirrors the Lean isLatinOnly."
  def latin_only?(input), do: Ucd.string_script_union(input) == ["Latn"]

  @doc """
  The detection function at the default context (one identifier field).
  Mirrors the Lean detect.
  """
  def detect(input), do: detect_with_context(input, %{running_text: false, identifier_token: false})

  @doc """
  The detection function under a field context (`running_text`: a source line,
  a message or a display name rather than one identifier; `identifier_token`:
  one identifier-shaped token cut out of running text). Rungs in the Lean
  order: target match, math alphanumerics, width class, decomposition swap,
  then the two script rungs (cross-script mix, off on running text; low
  restriction level, off on running text and on a token), then the
  ascii-confusable rung: a non-ASCII input whose case-preserving skeleton is all
  ASCII reads as an ASCII word it is not (`admın` with a dotless i). That rung
  runs on a whole field, and on a token only when the token is Latin-only, so a
  Greek or Cyrillic word in prose is not read as its Latin look-alike.
  """
  def detect_with_context(input, ctx) do
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

      # Priority 5: CrossScriptMix asks the script question only; the
      # Restricted-status rung belongs to the mixed-script family. Off on
      # running text.
      not ctx.running_text and length(Ucd.string_script_union(input)) >= 2 and
          not Ucd.highly_restrictive?(input) ->
        %{base | kind: :hazard, sub: %{tag: "CrossScriptMix"}}

      # Priority 6: RestrictionLow, off on running text and on a token.
      not ctx.running_text and not ctx.identifier_token and
          rl in [:minimally_restrictive, :unrestricted] ->
        %{base | kind: :hazard, sub: %{tag: "RestrictionLow"}}

      # Priority 7: AsciiConfusable, on a whole field, and on a token only when
      # the token is Latin-only.
      not ctx.running_text and (not ctx.identifier_token or latin_only?(input)) and
          ascii_confusable?(input) ->
        %{base | kind: :hazard, sub: %{tag: "AsciiConfusable", skeleton: ascii_skeleton(input)}}

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

  def math_alphanumeric?(cp), do: cp >= 0x1D400 and cp <= 0x1D7FF
  def fullwidth_halfwidth?(cp), do: cp >= 0xFF01 and cp <= 0xFFEF

  @doc """
  The first position at which the input and its NFC form differ, or the
  shorter length when one is a prefix of the other. Mirrors the Lean
  firstDecompositionDiffPos.
  """
  def first_decomposition_diff_pos(input) do
    nfc = Ucd.to_nfc(input)
    shorter = min(length(input), length(nfc))

    Enum.find(0..(shorter - 1)//1, shorter, fn i -> Enum.at(input, i) != Enum.at(nfc, i) end)
  end

  @doc """
  The positions a homoglyph rung implicates: nothing for the whole-input rungs
  (TargetMatch, CrossScriptMix, RestrictionLow), the first math-alphanumeric or
  fullwidth/halfwidth codepoint, the first NFC divergence, and the non-ASCII
  codepoints for the ascii-confusable rung. Mirrors the Lean homoglyphPositions.
  """
  def homoglyph_positions("MathAlpha", input), do: first_position(input, &math_alphanumeric?/1)
  def homoglyph_positions("WidthClass", input), do: first_position(input, &fullwidth_halfwidth?/1)
  def homoglyph_positions("DecompositionSwap", input), do: [first_decomposition_diff_pos(input)]
  def homoglyph_positions("AsciiConfusable", input), do: non_ascii_positions(input)
  def homoglyph_positions(_tag, _input), do: []

  defp first_position(input, pred) do
    case Enum.find_index(input, pred) do
      nil -> []
      i -> [i]
    end
  end

  @doc """
  The positions a mixed-script verdict implicates: the restricted codepoints
  for RestrictedStatusCp, the Cyrillic or Greek codepoints (Common and
  Inherited skipped, as UTS #39 §5.1 skips them from the intersection) for the
  two Latin-mix verdicts, nothing for the whole-input verdicts. Mirrors the
  Lean mixedScriptPositions.
  """
  def mixed_script_positions("RestrictedStatusCp", input) do
    input
    |> Enum.with_index()
    |> Enum.reject(fn {cp, _i} -> Ucd.id_allowed?(cp) end)
    |> Enum.map(fn {_cp, i} -> i end)
  end

  def mixed_script_positions("LatinCyrillic", input), do: positions_for_script(input, "Cyrl")
  def mixed_script_positions("LatinGreek", input), do: positions_for_script(input, "Grek")
  def mixed_script_positions(_sub, _input), do: []

  defp positions_for_script(input, script) do
    input
    |> Enum.with_index()
    |> Enum.filter(fn {cp, _i} ->
      not Ucd.ignored_for_intersection?(cp) and script in Ucd.resolve_scripts(cp)
    end)
    |> Enum.map(fn {_cp, i} -> i end)
  end
end
