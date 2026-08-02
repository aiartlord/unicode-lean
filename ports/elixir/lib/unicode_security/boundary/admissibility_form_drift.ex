defmodule UnicodeSecurity.Boundary.AdmissibilityFormDrift do
  @moduledoc """
  admissibility-form-drift — cross-layer identifier-admissibility × form drift
  (the boundary-layer detector X).

  Byte-faithful transliteration of the verified Rust reference implementation,
  itself a transcription of the Lean specification.

  Fires on inputs whose UTS #39 whole-string admissibility verdict differs
  between the input and its NFKC form. This is the string-level complement of
  IdentifierFormDrift (which scans `Identifier_Status` against the per-codepoint
  NFKD head): here the whole-string admissibility predicate is evaluated twice —
  once on the input, once on `to_nfkc(input)`. The two are not redundant. In
  particular, a sequence of decomposed Hangul jamos passes the per-codepoint
  scan cleanly (each jamo has identity NFKD and Restricted status on both sides)
  but fires here: the jamo sequence is rejected by `allowed_identifier?`, while
  its NFKC composition into a precomposed Hangul syllable is accepted.

  It reuses the port's own UTS #39 admissibility predicate
  (`Ucd.allowed_identifier?/1` = UAX #31 default identifier ∧ every codepoint
  Allowed) and NFKC pipeline (`Ucd.to_nfkc/1`), never a host normalization or
  identifier library.

  Sub-threat (direction-agnostic):
    `AdmissibilityFormDrift` — `allowed_identifier?(input) !=
    allowed_identifier?(to_nfkc(input))`. The pair of booleans is carried so the
    verdict records which direction the drift goes; no position is reported
    because the predicate is whole-string.
  """

  alias UnicodeSecurity.Ucd

  # ───────────────────────────────────────────────────────────────────
  # §1 Classification tags
  # ───────────────────────────────────────────────────────────────────

  @doc "Fixture-row tag string for a sub-threat map (matches `SubThreat.tag`)."
  def sub_threat_tag(%{kind: :admissibility_form_drift}), do: "AdmissibilityFormDrift"

  def sub_threat_tag(other),
    do: raise(ArgumentError, "unreachable AdmissibilityFormDrift sub-threat: #{inspect(other)}")

  @doc "True iff the classification is `Clear`."
  def is_clear(%{kind: :clear}), do: true
  def is_clear(%{kind: :hazard}), do: false

  @doc "Human-facing tag for a hazard classification, or `nil` when clear."
  def classification_tag(%{kind: :clear}), do: nil
  def classification_tag(%{kind: :hazard, sub: sub}), do: sub_threat_tag(sub)

  @doc "Implicated codepoint positions of a classification (always empty — whole-string)."
  def classification_positions(%{kind: :clear}), do: []
  def classification_positions(%{kind: :hazard, positions: positions}), do: positions

  # ───────────────────────────────────────────────────────────────────
  # §2 Top-level detection
  # ───────────────────────────────────────────────────────────────────

  @doc """
  The AdmissibilityFormDrift detection function. Returns a verdict map mirroring
  the Lean/rust `Verdict`: `input`, `classify`, `input_admissible`, and
  `nfkc_admissible`.
  """
  def detect(input) do
    nfkc = Ucd.to_nfkc(input)
    in_ok = Ucd.allowed_identifier?(input)
    nfkc_ok = Ucd.allowed_identifier?(nfkc)

    classify =
      if in_ok == nfkc_ok do
        %{kind: :clear}
      else
        hazard(
          %{kind: :admissibility_form_drift, input_admissible: in_ok, nfkc_admissible: nfkc_ok},
          []
        )
      end

    %{
      input: input,
      classify: classify,
      input_admissible: in_ok,
      nfkc_admissible: nfkc_ok
    }
  end

  defp hazard(sub, positions), do: %{kind: :hazard, sub: sub, positions: positions, decoded: []}
end
