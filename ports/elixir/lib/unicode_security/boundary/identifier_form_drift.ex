defmodule UnicodeSecurity.Boundary.IdentifierFormDrift do
  @moduledoc """
  identifier-form-drift — cross-layer identifier × form drift (the boundary-layer
  detector X).

  Byte-faithful transliteration of the verified Rust reference implementation,
  itself a transcription of the Lean specification.

  Threat model. Tier A₂ two-system bypass. An identity validator and a form
  normalizer disagree about a codepoint: stage A runs the UTS #39
  `Identifier_Status` check before normalisation and rejects, say, U+1D44E
  MATHEMATICAL ITALIC SMALL A (Restricted); stage B normalises first and then
  runs the same check, seeing U+0061 'a' (Allowed) and accepting. The attacker
  controls which stage processes the input and exploits the disagreement. The
  same shape covers fullwidth (U+FF21), circled (U+24B6), ligature (U+FB01),
  and Roman-numeral (U+2163) compatibility forms.

  The detector fires on the form transition itself — it reports the first input
  position whose `Identifier_Status` differs from the `Identifier_Status` of
  that codepoint's NFKD head, and the verdict carries the total shift count.

  Note on Hangul: precomposed syllables are Allowed while their NFKD-head jamos
  are Restricted, so pure Korean text fires; callers intending to accept Korean
  identifiers should apply NFC before evaluating admissibility.

  It reuses the port's own UTS #39 `Identifier_Status` predicate (`Ucd.id_allowed?/1`)
  and NFKD pipeline (`Ucd.to_nfkd/1`), never a host normalization or identifier
  library.

  Sub-threat (direction-agnostic):
    `IdentifierStatusShift` — the first input position whose `Identifier_Status`
    differs from its NFKD-head's.
  """

  alias UnicodeSecurity.Ucd

  # ───────────────────────────────────────────────────────────────────
  # §1 Classification tags
  # ───────────────────────────────────────────────────────────────────

  @doc "Fixture-row tag string for a sub-threat map (matches `SubThreat.tag`)."
  def sub_threat_tag(%{kind: :identifier_status_shift}), do: "IdentifierStatusShift"

  def sub_threat_tag(other),
    do: raise(ArgumentError, "unreachable IdentifierFormDrift sub-threat: #{inspect(other)}")

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
  # §2 Core predicates (reuse the port's own tables)
  # ───────────────────────────────────────────────────────────────────

  @doc """
  `Identifier_Status = Allowed` of the first codepoint of `cp`'s NFKD form, or
  `cp`'s own status when NFKD is empty (defensive — `to_nfkd` is total and
  returns at least `[cp]`). Reuses the port's own UTS #39 predicate and NFKD.
  """
  def nfkd_head_allowed(cp) do
    case Ucd.to_nfkd([cp]) do
      [head | _rest] -> Ucd.id_allowed?(head)
      [] -> Ucd.id_allowed?(cp)
    end
  end

  # ───────────────────────────────────────────────────────────────────
  # §3 Sub-detectors
  # ───────────────────────────────────────────────────────────────────

  # First input position whose `id_allowed?` differs from its NFKD-head's, or
  # `nil`.
  defp first_status_shift(input) do
    input
    |> Enum.with_index()
    |> Enum.find_value(fn {cp, idx} ->
      if !Ucd.id_allowed?(cp) and nfkd_head_allowed(cp), do: {idx, cp}, else: nil
    end)
  end

  # Total count of input positions where the per-cp status shifts under NFKD.
  defp status_shift_count(input) do
    Enum.count(input, fn cp -> !Ucd.id_allowed?(cp) and nfkd_head_allowed(cp) end)
  end

  # ───────────────────────────────────────────────────────────────────
  # §4 Top-level detection
  # ───────────────────────────────────────────────────────────────────

  @doc """
  The IdentifierFormDrift detection function. Returns a verdict map mirroring the
  Lean/rust `Verdict`: `input`, `classify`, and `shift_count`.
  """
  def detect(input) do
    classify =
      case first_status_shift(input) do
        {pos, cp} ->
          hazard(%{kind: :identifier_status_shift, base_pos: pos, cp: cp}, [pos])

        nil ->
          %{kind: :clear}
      end

    %{
      input: input,
      classify: classify,
      shift_count: status_shift_count(input)
    }
  end

  defp hazard(sub, positions), do: %{kind: :hazard, sub: sub, positions: positions, decoded: []}
end
