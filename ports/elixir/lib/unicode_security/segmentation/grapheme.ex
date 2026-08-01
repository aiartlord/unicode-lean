defmodule UnicodeSecurity.Segmentation.Grapheme do
  @moduledoc """
  UAX #29 default extended grapheme cluster segmentation.

  A transcription of the verified port algorithm
  `ports/rust/src/segmentation/grapheme.rs`, itself a transcription of the Lean
  `Unicode.Segmentation.GraphemeBreak.graphemeBreaks`. The active Lean tree
  proves `graphemeBreaks_eq_spec`, relating that algorithm to the declarative
  UAX #29 GB1–GB999 specification. The state fields, rule order, and transition
  below mirror that reference.

  Code points are plain integers; the public entry points operate on integer
  lists (`[non_neg_integer()]`).

  The property tables are grouped by property value (as in the UCD source), not
  globally sorted by code point, so lookups scan linearly for the covering range
  — mirroring the verified Lean `find?`. Each class is a partition, so at most
  one range covers a code point and the first match is the only match.
  """

  alias UnicodeSecurity.Segmentation.GraphemeTables

  defmodule State do
    @moduledoc """
    Running scan state, mirroring the Lean `State`.

      * `prev_class` — Grapheme_Cluster_Break class of the previous code point,
        `nil` before the first code point (start of text).
      * `epic_state` — GB11 left-context, one of `:none`, `:after_ep`,
        `:after_ep_zwj` (mirrors the Lean `EPicState`).
      * `incb_state` — GB9c left-context, one of `:none`, `:consonant`,
        `:linker` (mirrors the Lean `InCBState`).
      * `ri_run` — length of the current Regional_Indicator run.
    """
    defstruct prev_class: nil, epic_state: :none, incb_state: :none, ri_run: 0

    @type t :: %__MODULE__{
            prev_class: atom() | nil,
            epic_state: :none | :after_ep | :after_ep_zwj,
            incb_state: :none | :consonant | :linker,
            ri_run: non_neg_integer()
          }
  end

  @doc """
  Grapheme_Cluster_Break class of `cp`, `:other` when no range covers it.
  """
  @spec lookup_gcb(non_neg_integer()) :: atom()
  def lookup_gcb(cp) do
    case Enum.find(GraphemeTables.gcb_ranges(), fn {lo, hi, _class} -> lo <= cp and cp <= hi end) do
      {_lo, _hi, class} -> class
      nil -> :other
    end
  end

  @doc """
  Indic_Conjunct_Break class of `cp`, `:none` when no range covers it.
  """
  @spec lookup_incb(non_neg_integer()) :: atom()
  def lookup_incb(cp) do
    case Enum.find(GraphemeTables.incb_ranges(), fn {lo, hi, _class} -> lo <= cp and cp <= hi end) do
      {_lo, _hi, class} -> class
      nil -> :none
    end
  end

  @doc """
  Whether `cp` has the Extended_Pictographic property.
  """
  @spec ext_pict?(non_neg_integer()) :: boolean()
  def ext_pict?(cp) do
    Enum.any?(GraphemeTables.extpict_ranges(), fn {lo, hi} -> lo <= cp and cp <= hi end)
  end

  @doc """
  Whether a grapheme cluster break occurs immediately before `cp` given the
  running state. Implements UAX #29 GB1–GB999 in canonical order; the first
  matching rule wins, and the trailing GB999 breaks every otherwise-unmatched
  pair.
  """
  @spec should_break_before(non_neg_integer(), State.t()) :: boolean()
  def should_break_before(_cp, %State{prev_class: nil}) do
    # GB1: sot ÷
    true
  end

  def should_break_before(cp, %State{prev_class: pc} = s) do
    bc = lookup_gcb(cp)
    incb = lookup_incb(cp)
    is_ep = ext_pict?(cp)

    cond do
      # GB3: CR × LF
      pc == :cr and bc == :lf ->
        false

      # GB4: (Control | CR | LF) ÷
      pc == :control or pc == :cr or pc == :lf ->
        true

      # GB5: ÷ (Control | CR | LF)
      bc == :control or bc == :cr or bc == :lf ->
        true

      # GB6: L × (L | V | LV | LVT)
      pc == :l and bc in [:l, :v, :lv, :lvt] ->
        false

      # GB7: (LV | V) × (V | T)
      (pc == :lv or pc == :v) and (bc == :v or bc == :t) ->
        false

      # GB8: (LVT | T) × T
      (pc == :lvt or pc == :t) and bc == :t ->
        false

      # GB9: × (Extend | ZWJ)
      bc == :extend or bc == :zwj ->
        false

      # GB9a: × SpacingMark
      bc == :spacing_mark ->
        false

      # GB9b: Prepend ×
      pc == :prepend ->
        false

      # GB9c: Consonant (Extend | Linker)* Linker (Extend | Linker)* × Consonant
      s.incb_state == :linker and incb == :consonant ->
        false

      # GB11: ExtPict Extend* ZWJ × ExtPict
      s.epic_state == :after_ep_zwj and is_ep ->
        false

      # GB12 / GB13: an odd-parity Regional_Indicator run extends
      bc == :regional_indicator and rem(s.ri_run, 2) == 1 ->
        false

      # GB999: Any ÷ Any
      true ->
        true
    end
  end

  @doc """
  Update the running state after consuming `cp`. Mirrors the Lean `advance`.
  """
  @spec advance(non_neg_integer(), State.t()) :: State.t()
  def advance(cp, %State{} = s) do
    bc = lookup_gcb(cp)
    incb = lookup_incb(cp)
    is_ep = ext_pict?(cp)

    epic_state =
      cond do
        is_ep -> :after_ep
        s.epic_state == :after_ep and bc == :extend -> :after_ep
        s.epic_state == :after_ep and bc == :zwj -> :after_ep_zwj
        true -> :none
      end

    incb_state =
      cond do
        incb == :consonant -> :consonant
        s.incb_state == :consonant and incb == :linker -> :linker
        s.incb_state == :consonant and incb == :extend -> :consonant
        s.incb_state == :linker and incb == :linker -> :linker
        s.incb_state == :linker and incb == :extend -> :linker
        true -> :none
      end

    ri_run =
      if bc == :regional_indicator do
        s.ri_run + 1
      else
        0
      end

    %State{prev_class: bc, epic_state: epic_state, incb_state: incb_state, ri_run: ri_run}
  end

  @doc """
  Boundary mask of length `length(cps) + 1`. Entry `i` is `true` when a grapheme
  cluster break occurs immediately before position `i` — entry `0` is the GB1
  start-of-text break, entry `length(cps)` the GB2 end-of-text break, both always
  `true`. Mirrors the Lean `graphemeBreaks`.
  """
  @spec grapheme_breaks([non_neg_integer()]) :: [boolean()]
  def grapheme_breaks(cps) do
    {rev_breaks, _final_state} =
      Enum.reduce(cps, {[], %State{}}, fn cp, {acc, s} ->
        break? = should_break_before(cp, s)
        {[break? | acc], advance(cp, s)}
      end)

    # GB2: eot ÷ is the always-true final entry.
    Enum.reverse([true | rev_breaks])
  end

  @doc """
  Split `cps` into grapheme clusters (the code points between consecutive
  boundaries).
  """
  @spec grapheme_clusters([non_neg_integer()]) :: [[non_neg_integer()]]
  def grapheme_clusters(cps) do
    breaks = grapheme_breaks(cps)
    # Only the leading `length(cps)` boundary entries are consulted in the loop;
    # the trailing GB2 entry closes the final cluster below.
    break_prefix = Enum.take(breaks, length(cps))

    {rev_out, rev_cur} =
      Enum.zip(cps, break_prefix)
      |> Enum.reduce({[], []}, fn {cp, break?}, {out, cur} ->
        {out, cur} =
          if break? and cur != [] do
            {[Enum.reverse(cur) | out], []}
          else
            {out, cur}
          end

        {out, [cp | cur]}
      end)

    rev_out =
      if rev_cur != [] do
        [Enum.reverse(rev_cur) | rev_out]
      else
        rev_out
      end

    Enum.reverse(rev_out)
  end
end
