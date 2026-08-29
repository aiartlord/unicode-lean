defmodule UnicodeSecurity.Form.WidthClassConfusion do
  @moduledoc """
  Width-class-confusion detection — UAX #11 East Asian Width class confusion.

  A Fullwidth (EAW = F) or Halfwidth (EAW = H) codepoint whose NFKD form
  carries a different EAW class is a compatibility-fold homograph:

      U+FF21 'Ａ' (F)  ->  U+0041 'A' (Na)
      U+FF11 '１' (F)  ->  U+0031 '1' (Na)
      U+FF71 'ｱ' (H)  ->  U+30A2 'ア' (W)

  The two-system bypass: a validator that whitelists ASCII rejects `Ａ`, while
  a downstream NFKC step at storage or comparison time folds it to plain `A`,
  so `ＡＤＭＩＮ` claims the username `ADMIN`.

  Distinct from `RendererDivergence`'s FullwidthVariance, which fires on
  F-class codepoints for renderer-cohort reasons; this is the NFKC-fold
  verdict and both can fire on one input independently. Hangul syllables
  decompose to jamos that are still W class, so pure Hangul stays clear.

  Direct port of `Unicode/Security/Form/WidthClassConfusion.lean`.
  """

  alias UnicodeSecurity.Ucd

  @doc """
  Classify a codepoint sequence. A Fullwidth fold takes priority over a
  Halfwidth one, matching the reference's sub-threat order.
  """
  @spec detect([integer()]) :: %{sub: String.t() | nil, positions: [integer()]}
  def detect(cps) do
    case first_fold(cps, :f) do
      pos when is_integer(pos) ->
        %{sub: "FullwidthFold", positions: [pos]}

      nil ->
        case first_fold(cps, :h) do
          pos when is_integer(pos) -> %{sub: "HalfwidthFold", positions: [pos]}
          nil -> %{sub: nil, positions: []}
        end
    end
  end

  # First position whose codepoint has class `want` and folds away from it.
  defp first_fold(cps, want) do
    cps
    |> Enum.with_index()
    |> Enum.find_value(fn {cp, index} ->
      if Ucd.east_asian_width(cp) == want and width_fold?(cp), do: index
    end)
  end

  # True iff the NFKD head of `cp` carries a different EAW class.
  defp width_fold?(cp) do
    case Ucd.to_nfkd([cp]) do
      [] -> false
      [head | _rest] -> Ucd.east_asian_width(head) != Ucd.east_asian_width(cp)
    end
  end
end
