defmodule UnicodeSecurity.Segmentation.LineBreak do
  @moduledoc """
  UAX #14 default line breaking.

  A transcription of the Lean algorithm
  `Unicode.Segmentation.LineBreak.lineBreaks`, whose `lineBreaks_length`
  theorem fixes the output shape: one break-opportunity flag per boundary
  position. The rule order, rule bodies and snapshot fields below mirror that
  reference — LB2 through LB31 in UAX #14 R7's canonical order, first match
  winning, the trailing LB31 breaking every otherwise-unmatched pair.

  Where a line may break is a property of a sequence rather than of a code
  point, so the entry point returns a flag per boundary instead of a predicate
  over code points.

  Three mechanisms carry the context the rules read:

    * LB1 is applied at lookup time by `resolved_class/1`, which folds the
      tailorable AI, CJ, SA, SG and XX into the algorithm's working alphabet.
      SA needs General_Category to choose between CM and AL.
    * LB9 — treat X CM* / X ZWJ* as X — is realised through `State`, whose
      fields hold the most recent class that was not CM or ZWJ. LB10, treating
      a leftover CM or ZWJ as AL, is the fallback taken when no such class
      exists.
    * The rules naming a third character — LB15b, LB15c, the LB25 bracket and
      the fourth LB28a sub-rule — read the suffix beginning at the position
      being decided.

  Two departures from the Lean. Its positional reads are `lits[i]!` and
  `cps[i]!`, panicking accessors; here every read comes from a suffix the
  caller already holds, so each one is total. And its `spSinceNoSp` snapshot
  field is written by its fold and read by no rule, so this port omits it.

  Code points are plain integers; the public entry points operate on integer
  lists (`[non_neg_integer()]`).
  """

  alias UnicodeSecurity.Segmentation.LineBreakTables

  # U+2010 HYPHEN, which LB20a and LB21a name explicitly because UCD 17.0
  # moved it from class HY to class HH.
  @hyphen_u2010 0x2010

  # U+25CC DOTTED CIRCLE, which LB28a reads as a stand-in cluster base.
  @dotted_circle 0x25CC

  defmodule State do
    @moduledoc """
    The left-hand context a boundary decision reads: the classes and code
    points of the most recent characters LB9 did not absorb, plus the running
    counters the rules keep. Mirrors the Lean `EffSnapshot`.

      * `eff_prev` — class of the most recent character that was not CM or
        ZWJ, `nil` before the first such character.
      * `eff_prev_cp` — its code point; LB20a, LB21a and LB28a name U+2010 and
        U+25CC.
      * `eff_prev_no_sp` — class of the most recent character that was not CM,
        ZWJ or SP.
      * `eff_prev_prev` — class of the second most recent such character, and
        `eff_prev_prev_cp` its code point.
      * `in_pi_quote_window` — whether an LB15a initial-punctuation quote
        window is open.
      * `ri_run` — length of the current regional-indicator run, for LB30a.
      * `in_nu_chain` — whether an LB25 numeric chain is open.
    """
    defstruct eff_prev: nil,
              eff_prev_cp: nil,
              eff_prev_no_sp: nil,
              eff_prev_prev: nil,
              eff_prev_prev_cp: nil,
              in_pi_quote_window: false,
              ri_run: 0,
              in_nu_chain: false

    @type t :: %__MODULE__{
            eff_prev: atom() | nil,
            eff_prev_cp: non_neg_integer() | nil,
            eff_prev_no_sp: atom() | nil,
            eff_prev_prev: atom() | nil,
            eff_prev_prev_cp: non_neg_integer() | nil,
            in_pi_quote_window: boolean(),
            ri_run: non_neg_integer(),
            in_nu_chain: boolean()
          }
  end

  # ─────────────────────────────────────────────────────────────────────────
  # Property lookups
  #
  # Each table is sorted by first code point and its ranges are disjoint, so
  # the covering range is unique and a bisection finds it. The tables are
  # tuples so `elem/2` indexes them in constant time.
  # ─────────────────────────────────────────────────────────────────────────

  defp bisect_class(table, cp, fallback) do
    bisect_class(table, cp, fallback, 0, tuple_size(table))
  end

  defp bisect_class(_table, _cp, fallback, low, high) when low >= high, do: fallback

  defp bisect_class(table, cp, fallback, low, high) do
    mid = low + div(high - low, 2)
    {first, last, class} = elem(table, mid)

    cond do
      cp < first -> bisect_class(table, cp, fallback, low, mid)
      cp > last -> bisect_class(table, cp, fallback, mid + 1, high)
      true -> class
    end
  end

  defp bisect_member?(table, cp) do
    bisect_member?(table, cp, 0, tuple_size(table))
  end

  defp bisect_member?(_table, _cp, low, high) when low >= high, do: false

  defp bisect_member?(table, cp, low, high) do
    mid = low + div(high - low, 2)
    {first, last} = elem(table, mid)

    cond do
      cp < first -> bisect_member?(table, cp, low, mid)
      cp > last -> bisect_member?(table, cp, mid + 1, high)
      true -> true
    end
  end

  @doc """
  Line_Break class of `cp` before LB1. A code point no range covers is `:xx`,
  the default LineBreak.txt declares in its own
  `@missing: 0000..10FFFF; XX` header.
  """
  @spec raw_class(non_neg_integer()) :: atom()
  def raw_class(cp), do: bisect_class(LineBreakTables.lb_ranges(), cp, :xx)

  @doc """
  General_Category of `cp`, `:cn` when no range covers it — the default
  UnicodeData.txt declares for unassigned code points.
  """
  @spec category_of(non_neg_integer()) :: atom()
  def category_of(cp), do: bisect_class(LineBreakTables.gc_ranges(), cp, :cn)

  @doc """
  East_Asian_Width of `cp`, `:n` when the file omits it.
  """
  @spec width_of(non_neg_integer()) :: atom()
  def width_of(cp), do: bisect_class(LineBreakTables.eaw_ranges(), cp, :n)

  @doc """
  Whether `cp` carries the Extended_Pictographic property, which LB30b reads.
  """
  @spec ext_pict?(non_neg_integer()) :: boolean()
  def ext_pict?(cp), do: bisect_member?(LineBreakTables.extpict_ranges(), cp)

  @doc """
  Line_Break class `cp` carries once LB1 has tailored it.

  AI, SG and XX resolve to AL; CJ to NS; SA to CM when the code point is a
  non-spacing or spacing combining mark and to AL otherwise. Every other class
  is already in the working alphabet.
  """
  @spec resolved_class(non_neg_integer()) :: atom()
  def resolved_class(cp) do
    case raw_class(cp) do
      :ai ->
        :al

      :sg ->
        :al

      :xx ->
        :al

      :cj ->
        :ns

      # LB1 reads only the two combining-mark categories here; an enclosing
      # mark is not among them.
      :sa ->
        if category_of(cp) in [:mn, :mc], do: :cm, else: :al

      resolved ->
        resolved
    end
  end

  # ─────────────────────────────────────────────────────────────────────────
  # Class sets the rules name
  # ─────────────────────────────────────────────────────────────────────────

  # Whether LB9 absorbs this class into the character before it.
  defp cm_zwj?(class), do: class == :cm or class == :zwj

  # Whether a preceding class blocks LB9's absorption, so a following CM or
  # ZWJ stands on its own and LB10 reads it as AL.
  defp blocks_absorb?(class), do: class in [:bk, :cr, :lf, :nl, :sp, :zw]

  # Whether the class is QU and the code point is initial punctuation, the
  # refinement LB15a reads.
  defp pi_quote?(cp, class), do: class == :qu and category_of(cp) == :pi

  # Whether the class is QU and the code point is final punctuation, the
  # refinement LB15b reads.
  defp pf_quote?(cp, class), do: class == :qu and category_of(cp) == :pf

  # Whether `cp` is East_Asian_Width F, W or H, the set LB25 and LB30 read.
  defp east_asian_full_wide?(cp), do: width_of(cp) in [:f, :w, :h]

  # Whether `cp` counts as East Asian for LB19a's tailoring, which treats
  # Ambiguous as East Asian alongside Fullwidth, Wide and Halfwidth. Wider
  # than `east_asian_full_wide?/1`.
  defp east_asian_or_ambiguous?(cp), do: width_of(cp) in [:f, :w, :h, :a]

  # Whether the effective class is present and among `classes`.
  defp eff_in?(nil, _classes), do: false
  defp eff_in?(class, classes), do: class in classes

  # The class a CM or ZWJ takes from what it attaches to under LB9, or AL
  # under LB10 when nothing absorbs it.
  defp effective_class(class, eff_prev) do
    cond do
      not cm_zwj?(class) -> class
      is_nil(eff_prev) -> :al
      blocks_absorb?(eff_prev) -> :al
      true -> class
    end
  end

  @doc """
  One character folded into the context. A character LB9 absorbs leaves the
  context untouched, which is what makes the neighbours it records effective
  rather than literal. Mirrors the Lean `buildSnapshots` step.
  """
  @spec advance(non_neg_integer(), atom(), State.t()) :: State.t()
  def advance(cp, class, %State{} = s) do
    effective = effective_class(class, s.eff_prev)

    if cm_zwj?(effective) do
      s
    else
      %State{
        eff_prev: effective,
        eff_prev_cp: cp,
        eff_prev_no_sp: if(effective == :sp, do: s.eff_prev_no_sp, else: effective),
        eff_prev_prev: s.eff_prev,
        eff_prev_prev_cp: s.eff_prev_cp,
        in_pi_quote_window: quote_window(cp, effective, s),
        ri_run: if(effective == :ri, do: s.ri_run + 1, else: 0),
        in_nu_chain: numeric_chain(effective, s)
      }
    end
  end

  # LB15a opens its window only where an initial-punctuation quote stands
  # outside a word; a space carries an open window forward.
  defp quote_window(cp, effective, %State{} = s) do
    left_context_opens =
      is_nil(s.eff_prev) or
        eff_in?(s.eff_prev, [:bk, :cr, :lf, :nl, :op, :qu, :gl, :sp, :zw])

    cond do
      pi_quote?(cp, effective) and left_context_opens -> true
      effective == :sp -> s.in_pi_quote_window
      true -> false
    end
  end

  defp numeric_chain(effective, %State{} = s) do
    cond do
      effective == :nu -> true
      s.in_nu_chain -> effective in [:sy, :is, :cl, :cp, :pr]
      true -> false
    end
  end

  # ─────────────────────────────────────────────────────────────────────────
  # Lookahead
  # ─────────────────────────────────────────────────────────────────────────

  # The class at the head of a suffix, or nil past its end.
  defp head_class([]), do: nil
  defp head_class([{_cp, class} | _rest]), do: class

  # The code point at the head of a suffix, or nil past its end.
  defp head_cp([]), do: nil
  defp head_cp([{cp, _class} | _rest]), do: cp

  # LB15b holds when the final quote is last, or when what follows it cannot
  # itself open a line.
  defp final_quote_closes?([]), do: true

  defp final_quote_closes?([{_cp, class} | _rest]) do
    class in [:sp, :gl, :wj, :cl, :qu, :cp, :ex, :is, :sy, :bk, :cr, :lf, :nl, :zw]
  end

  # The fourth LB28a sub-rule looks past any CM or ZWJ the cluster absorbs, so
  # the character it tests is the first significant one ahead.
  defp next_significant_vf?(ahead) do
    case Enum.drop_while(ahead, fn {_cp, class} -> cm_zwj?(class) end) do
      [{_cp, class} | _rest] -> class == :vf
      [] -> false
    end
  end

  # ─────────────────────────────────────────────────────────────────────────
  # The rule cascade
  # ─────────────────────────────────────────────────────────────────────────

  @doc """
  Whether a line break opportunity falls immediately before the head of
  `suffix`, given the character before it and the context accumulated from
  everything earlier.

  `suffix` begins at the position being decided, so its head is the current
  character and its tail supplies every lookahead the rules take.
  """
  @spec breaks_before?({non_neg_integer(), atom()}, [{non_neg_integer(), atom()}], State.t()) ::
          boolean()
  def breaks_before?(_prev, [], _state), do: true

  def breaks_before?({prev_cp, prev_class}, [{current_cp, current_class} | ahead], %State{} = s) do
    eff = effective_class(current_class, s.eff_prev)
    left = if cm_zwj?(prev_class), do: s.eff_prev, else: prev_class

    hyphen_left_context_opens =
      is_nil(s.eff_prev_prev) or
        eff_in?(s.eff_prev_prev, [:bk, :cr, :lf, :nl, :sp, :zw, :cb, :gl])

    left_is_aksara_base =
      eff_in?(left, [:ak, :as]) or
        (s.eff_prev_cp == @dotted_circle and s.eff_prev == :al)

    cond do
      # LB4
      prev_class == :bk ->
        true

      # LB5
      prev_class == :cr and current_class == :lf ->
        false

      prev_class in [:cr, :lf, :nl] ->
        true

      # LB6
      current_class in [:bk, :cr, :lf, :nl] ->
        false

      # LB7
      current_class == :sp or current_class == :zw ->
        false

      # LB8
      s.eff_prev_no_sp == :zw ->
        true

      # LB8a
      prev_class == :zwj ->
        false

      # LB9
      cm_zwj?(current_class) and not is_nil(s.eff_prev) and
          not blocks_absorb?(s.eff_prev) ->
        false

      # LB11
      eff == :wj or left == :wj ->
        false

      # LB12
      left == :gl ->
        false

      # LB12a
      eff == :gl and not eff_in?(left, [:sp, :ba, :hy, :hh]) ->
        false

      # LB15c, which UCD 17.0 orders above LB13 and LB15d: break before an IS
      # that opens a number and follows a space, as in "equals .35".
      prev_class == :sp and eff == :is and head_class(ahead) == :nu ->
        true

      # LB13
      eff in [:cl, :cp, :ex, :is, :sy] ->
        false

      # LB14
      s.eff_prev_no_sp == :op ->
        false

      # LB15a
      s.in_pi_quote_window ->
        false

      # LB15b
      pf_quote?(current_cp, eff) and final_quote_closes?(ahead) ->
        false

      # LB15d
      eff == :is ->
        false

      # LB16
      eff == :ns and s.eff_prev_no_sp in [:cl, :cp] ->
        false

      # LB17
      eff == :b2 and s.eff_prev_no_sp == :b2 ->
        false

      # LB18
      prev_class == :sp ->
        true

      # LB19 and LB19a. A quote neither breaks before nor after, except on the
      # OUTER side of an initial or final punctuation quote standing in
      # contiguous East Asian content — there the default break applies, so a
      # line may break at the quote boundary. The inner side stays unbroken,
      # being the boundary inside the quote's own scope.
      eff == :qu and not open_quote_east_asian?(prev_cp, current_cp, eff, ahead) ->
        false

      left == :qu and not close_quote_east_asian?(current_cp, s) ->
        false

      # LB20
      eff == :cb or left == :cb ->
        true

      # LB20.1, UCD 17.0: an explicit hyphen joins a following letter only
      # where its own left context is outside a word. A mid-word HH falls
      # through to LB31.
      left == :hh and eff in [:al, :hl] and hyphen_left_context_opens ->
        false

      # LB20a, with UCD 17.0's right side broadened to HL beside AL.
      eff in [:al, :hl] and hyphen_carries_left?(s) and hyphen_left_context_opens ->
        false

      # LB21
      eff in [:ba, :hy, :hh, :ns] ->
        false

      left == :bb ->
        false

      # LB21a: an HL letter followed by an HY hyphen or U+2010 glues to what
      # comes next unless that is itself HL. A BA does not glue here.
      s.eff_prev_prev == :hl and eff != :hl and hyphen_hy_or_2010?(s) ->
        false

      # LB21b
      eff == :hl and left == :sy ->
        false

      # LB22
      eff == :in ->
        false

      # LB23
      eff == :nu and eff_in?(left, [:al, :hl]) ->
        false

      eff in [:al, :hl] and left == :nu ->
        false

      # LB23a
      eff in [:id, :eb, :em] and left == :pr ->
        false

      eff == :po and eff_in?(left, [:id, :eb, :em]) ->
        false

      # LB24
      eff in [:al, :hl] and eff_in?(left, [:pr, :po]) ->
        false

      eff in [:pr, :po] and eff_in?(left, [:al, :hl]) ->
        false

      # LB25, closing an open numeric chain with a CL or CP suffix and a
      # following PO or PR.
      s.in_nu_chain and eff in [:cl, :cp, :po, :pr] ->
        false

      # LB25, opening a chain
      eff == :nu and eff_in?(left, [:pr, :po, :hy, :op, :is]) ->
        false

      # LB25, chain body
      eff == :nu and left == :nu ->
        false

      # LB25, extending an open chain across a SY
      eff == :nu and left == :sy and s.in_nu_chain ->
        false

      # LB25, bracketed prefix: a PR joins an OP only when the OP itself opens
      # a number, and neither is East Asian Fullwidth, Wide or Halfwidth.
      eff == :op and left == :pr and not east_asian_full_wide?(current_cp) and
        not is_nil(s.eff_prev_cp) and not east_asian_full_wide?(s.eff_prev_cp) and
          head_class(ahead) == :nu ->
        false

      # LB26
      left == :jl and eff in [:jl, :jv, :h2, :h3] ->
        false

      eff_in?(left, [:jv, :h2]) and eff in [:jv, :jt] ->
        false

      eff_in?(left, [:jt, :h3]) and eff == :jt ->
        false

      # LB27
      eff_in?(left, [:jl, :jv, :jt, :h2, :h3]) and eff in [:in, :po] ->
        false

      left == :pr and eff in [:jl, :jv, :jt, :h2, :h3] ->
        false

      # LB28
      eff in [:al, :hl] and eff_in?(left, [:al, :hl]) ->
        false

      # LB28a, the aksara cluster rules. U+25CC DOTTED CIRCLE carries class AL
      # and stands in for a cluster base throughout.
      left == :ap and (eff in [:ak, :as] or current_cp == @dotted_circle) ->
        false

      left_is_aksara_base and eff in [:vf, :vi] ->
        false

      s.eff_prev == :vi and
        (eff_in?(s.eff_prev_prev, [:ak, :as]) or s.eff_prev_prev_cp == @dotted_circle) and
          (eff == :ak or current_cp == @dotted_circle) ->
        false

      left_is_aksara_base and (eff in [:ak, :as] or current_cp == @dotted_circle) and
          next_significant_vf?(ahead) ->
        false

      # LB29
      eff in [:al, :hl] and left == :is ->
        false

      # LB30, where the bracket must not be East Asian Fullwidth, Wide or
      # Halfwidth.
      eff == :op and eff_in?(left, [:al, :hl, :nu]) and
          not east_asian_full_wide?(current_cp) ->
        false

      eff in [:al, :hl, :nu] and left == :cp and not east_asian_full_wide?(prev_cp) ->
        false

      # LB30a
      eff == :ri and rem(s.ri_run, 2) == 1 ->
        false

      # LB30b
      eff == :em and left == :eb ->
        false

      eff == :em and unassigned_pictograph?(s.eff_prev_cp) ->
        false

      # LB31
      true ->
        true
    end
  end

  # LB19a's outer-side exception on an initial-punctuation quote: the left
  # context, the quote and the right context must all be East Asian.
  defp open_quote_east_asian?(prev_cp, current_cp, eff, ahead) do
    pi_quote?(current_cp, eff) and east_asian_or_ambiguous?(prev_cp) and
      east_asian_or_ambiguous?(current_cp) and
      case head_cp(ahead) do
        nil -> false
        next_cp -> east_asian_or_ambiguous?(next_cp)
      end
  end

  # The same exception on a final-punctuation quote, read from the left: the
  # character before the quote, the quote, and the current one.
  defp close_quote_east_asian?(current_cp, %State{} = s) do
    case {s.eff_prev_cp, s.eff_prev_prev_cp} do
      {nil, _before} ->
        false

      {_quote_cp, nil} ->
        false

      {quote_cp, before_quote} ->
        pf_quote?(quote_cp, :qu) and east_asian_or_ambiguous?(before_quote) and
          east_asian_or_ambiguous?(quote_cp) and east_asian_or_ambiguous?(current_cp)
    end
  end

  defp hyphen_carries_left?(%State{} = s) do
    eff_in?(s.eff_prev, [:hy, :hh]) or
      (not is_nil(s.eff_prev) and s.eff_prev_cp == @hyphen_u2010)
  end

  defp hyphen_hy_or_2010?(%State{} = s) do
    s.eff_prev == :hy or (not is_nil(s.eff_prev) and s.eff_prev_cp == @hyphen_u2010)
  end

  defp unassigned_pictograph?(nil), do: false

  defp unassigned_pictograph?(cp), do: ext_pict?(cp) and category_of(cp) == :cn

  # ─────────────────────────────────────────────────────────────────────────
  # Entry points
  # ─────────────────────────────────────────────────────────────────────────

  @doc """
  One break-opportunity flag per boundary of the code point sequence, so a
  sequence of `n` code points yields `n + 1` flags — the shape the Lean
  `lineBreaks_length` theorem fixes.

  Entry `0` is `false`, LB2 forbidding a break at the start of text, and the
  last entry is `true` per LB3, which requires one at the end.
  """
  @spec line_breaks([non_neg_integer()]) :: [boolean()]
  def line_breaks(cps) do
    pairs = Enum.map(cps, fn cp -> {cp, resolved_class(cp)} end)
    # LB3: the end of text always breaks.
    Enum.reverse([true | decide(pairs, nil, %State{}, [])])
  end

  # One decision per position, walking the suffixes so each reads the character
  # before it, the suffix from it onward, and the context accumulated earlier.
  # The suffix is the tail already in hand, so no position is indexed twice.
  defp decide([], _prev, _state, acc), do: acc

  defp decide([{cp, class} | rest] = suffix, prev, %State{} = s, acc) do
    break? =
      case prev do
        # LB2 forbids a break at the start of text.
        nil -> false
        prev_pair -> breaks_before?(prev_pair, suffix, s)
      end

    decide(rest, {cp, class}, advance(cp, class, s), [break? | acc])
  end

  @doc """
  The code point sequence split at every break opportunity — the runs a
  renderer may place on separate lines.
  """
  @spec line_runs([non_neg_integer()]) :: [[non_neg_integer()]]
  def line_runs(cps) do
    breaks = Enum.drop(line_breaks(cps), 1)

    {rev_runs, rev_current} =
      Enum.zip(cps, breaks)
      |> Enum.reduce({[], []}, fn {cp, break?}, {runs, current} ->
        current = [cp | current]

        if break? do
          {[Enum.reverse(current) | runs], []}
        else
          {runs, current}
        end
      end)

    rev_runs =
      if rev_current == [] do
        rev_runs
      else
        [Enum.reverse(rev_current) | rev_runs]
      end

    Enum.reverse(rev_runs)
  end
end
