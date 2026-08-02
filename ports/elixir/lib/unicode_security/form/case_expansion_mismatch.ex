defmodule UnicodeSecurity.Form.CaseExpansionMismatch do
  @moduledoc """
  case-expansion-mismatch — codepoints whose UAX #21 default-locale case mapping
  changes the codepoint count (the form-layer detector F).

  Byte-faithful transliteration of the verified rust reference implementation of
  the CaseExpansionMismatch detector.

  Threat model. Tier A₁..A₂. An attacker submits text whose case-mapped form has
  a different codepoint count than the input. A receiver that fixes a 16-byte
  username column and stores `to_upper(username)` overflows when the user picks
  "ßßßßßßßß" (8 in → 16 stored); a receiver that checks `len(stored) ==
  len(input)` rejects valid case-insensitive logins whose names expand under
  folding. Examples: U+00DF ß → "SS", U+FB01 ﬁ → "FI", U+0130 İ → to_lower "i̇"
  (i + U+0307).

  Distinct from LocaleCaseInversion (case mapping that changes ACROSS locales):
  this fires on shapes whose mapping is locale-stable but length-changing under
  the default locale itself.

  It reuses the port's own UAX #21 case mapping — `Casing.upper_codepoint` /
  `Casing.lower_codepoint`, which evaluate the SpecialCasing context predicates —
  never a host casing library.

  Sub-threats (priority order):
    1. `UpperExpansion` — first position whose default `upper_codepoint` yields
       > 1 codepoint.
    2. `LowerExpansion` — first position whose default `lower_codepoint` yields
       > 1 codepoint (reached only when no upper expansion fires first).
  """

  alias UnicodeSecurity.Casing

  # ───────────────────────────────────────────────────────────────────
  # §1 Classification tags
  # ───────────────────────────────────────────────────────────────────

  @doc "Fixture-row tag string for a sub-threat map (matches `SubThreat.tag`)."
  def sub_threat_tag(%{kind: :upper_expansion}), do: "UpperExpansion"
  def sub_threat_tag(%{kind: :lower_expansion}), do: "LowerExpansion"

  def sub_threat_tag(other),
    do:
      raise(ArgumentError,
        message: "unreachable CaseExpansionMismatch sub-threat: #{inspect(other)}"
      )

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
  # §2 Per-position expansion scan
  # ───────────────────────────────────────────────────────────────────

  # The default-locale uppercase expansion length at position `i`, evaluating the
  # SpecialCasing context (preceding codepoints nearest-first, following ones).
  defp upper_len_at(input, i) do
    rev_prefix = input |> Enum.take(i) |> Enum.reverse()
    suffix = Enum.drop(input, i + 1)
    length(Casing.upper_codepoint(:default, rev_prefix, suffix, Enum.at(input, i)))
  end

  # The default-locale lowercase expansion length at position `i`.
  defp lower_len_at(input, i) do
    rev_prefix = input |> Enum.take(i) |> Enum.reverse()
    suffix = Enum.drop(input, i + 1)
    length(Casing.lower_codepoint(:default, rev_prefix, suffix, Enum.at(input, i)))
  end

  # First position whose default uppercase mapping expands to > 1 codepoint, as
  # `{index, codepoint, expansion_len}`, or `nil`.
  defp first_upper_expansion(input) do
    input
    |> Enum.with_index()
    |> Enum.find_value(fn {cp, i} ->
      len = upper_len_at(input, i)
      if len > 1, do: {i, cp, len}, else: nil
    end)
  end

  # First position whose default lowercase mapping expands to > 1 codepoint, as
  # `{index, codepoint, expansion_len}`, or `nil`.
  defp first_lower_expansion(input) do
    input
    |> Enum.with_index()
    |> Enum.find_value(fn {cp, i} ->
      len = lower_len_at(input, i)
      if len > 1, do: {i, cp, len}, else: nil
    end)
  end

  # Count of positions whose default uppercase mapping expands.
  defp upper_expansion_count(input) do
    input
    |> Enum.with_index()
    |> Enum.count(fn {_cp, i} -> upper_len_at(input, i) > 1 end)
  end

  # Count of positions whose default lowercase mapping expands.
  defp lower_expansion_count(input) do
    input
    |> Enum.with_index()
    |> Enum.count(fn {_cp, i} -> lower_len_at(input, i) > 1 end)
  end

  # Maximum case-mapped expansion length across all positions (upper or lower);
  # 0 for empty input.
  defp max_expansion_len(input) do
    input
    |> Enum.with_index()
    |> Enum.reduce(0, fn {_cp, i}, acc ->
      max(max(upper_len_at(input, i), lower_len_at(input, i)), acc)
    end)
  end

  # ───────────────────────────────────────────────────────────────────
  # §3 Top-level detection
  # ───────────────────────────────────────────────────────────────────

  @doc """
  The CaseExpansionMismatch detection function. Returns a verdict map mirroring
  the rust `Verdict`: `input`, `classify`, `upper_expansion_count`,
  `lower_expansion_count`, and `max_expansion_len`.
  """
  def detect(input) do
    classify =
      case first_upper_expansion(input) do
        # Priority 1: an uppercase expansion.
        {pos, cp, len} ->
          hazard(%{kind: :upper_expansion, base_pos: pos, cp: cp, expansion_len: len}, [pos])

        nil ->
          case first_lower_expansion(input) do
            # Priority 2: a lowercase expansion.
            {pos, cp, len} ->
              hazard(%{kind: :lower_expansion, base_pos: pos, cp: cp, expansion_len: len}, [pos])

            nil ->
              %{kind: :clear}
          end
      end

    %{
      input: input,
      classify: classify,
      upper_expansion_count: upper_expansion_count(input),
      lower_expansion_count: lower_expansion_count(input),
      max_expansion_len: max_expansion_len(input)
    }
  end

  defp hazard(sub, positions), do: %{kind: :hazard, sub: sub, positions: positions, decoded: []}
end
