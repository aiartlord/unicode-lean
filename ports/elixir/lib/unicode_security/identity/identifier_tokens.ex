defmodule UnicodeSecurity.Identity.IdentifierTokens do
  @moduledoc """
  Identifier-shaped tokens of a running-text field.

  Direct port of `Unicode/Security/Identity/IdentifierTokens.lean`. A source
  line, a chat message or a display name is not one identifier, but the
  identifier-shaped words inside it are the surface a homoglyph attack targets
  (`scоpe` with a Cyrillic о in `let scоpe = 1;`). A token is a maximal run of
  `XID_Continue` codepoints; everything else (space, punctuation, operators,
  format controls) separates tokens. Each token carries its 0-based start
  position so a finding made on the token can be reported in input coordinates.

  `XID_Continue` is the port's own `Ucd.xid_continue?` over the bundled
  DerivedCoreProperties.txt.
  """

  alias UnicodeSecurity.Ucd

  @doc """
  The maximal `XID_Continue` runs of the input, in input order, as
  `%{start: pos, cps: [...]}` maps.
  """
  def tokens(input) do
    {tokens, open} =
      input
      |> Enum.with_index()
      |> Enum.reduce({[], nil}, fn {cp, idx}, {tokens, open} ->
        cond do
          Ucd.xid_continue?(cp) ->
            case open do
              nil -> {tokens, %{start: idx, cps: [cp]}}
              %{cps: cps} = token -> {tokens, %{token | cps: [cp | cps]}}
            end

          open == nil ->
            {tokens, nil}

          true ->
            {[close(open) | tokens], nil}
        end
      end)

    tokens = if open == nil, do: tokens, else: [close(open) | tokens]
    Enum.reverse(tokens)
  end

  # The open run is carried reversed and flipped on close, as in the Lean.
  defp close(%{cps: cps} = token), do: %{token | cps: Enum.reverse(cps)}

  @doc "Move token-local positions back into input coordinates."
  def shift_positions(start, positions), do: Enum.map(positions, &(&1 + start))
end
