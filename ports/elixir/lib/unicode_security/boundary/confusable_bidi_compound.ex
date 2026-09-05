defmodule UnicodeSecurity.Boundary.ConfusableBidiCompound do
  @moduledoc """
  Confusable-in-bidi-context compound detector (CVE-2021-42574 class). Fires
  only when a confusable source co-locates with a purposeless bidi control
  (`BidiControlPurpose`: unbalanced, or a balanced span enclosing nothing
  right-to-left in a left-to-right context); a balanced embedding around Arabic
  text renders that text as written.
  """

  alias UnicodeSecurity.Covert.BidiControlBalance
  alias UnicodeSecurity.Display.BidiControlPurpose
  alias UnicodeSecurity.Identity.HomoglyphConfusable

  def detect(input) do
    confusable_pos = first_pos(input, &HomoglyphConfusable.confusable_source?/1)

    cond do
      confusable_pos == nil ->
        %{sub: nil, positions: []}

      (override_pos =
         first_purposeless_pos(input, fn cp ->
           BidiControlBalance.opens_embedding?(cp) or BidiControlBalance.pdf?(cp)
         end)) != nil ->
        %{sub: "ConfusableInOverride", positions: [confusable_pos, override_pos]}

      (isolate_pos =
         first_purposeless_pos(input, fn cp ->
           BidiControlBalance.opens_isolate?(cp) or BidiControlBalance.pdi?(cp)
         end)) != nil ->
        %{sub: "ConfusableInIsolate", positions: [confusable_pos, isolate_pos]}

      true ->
        %{sub: nil, positions: []}
    end
  end

  defp first_pos(input, pred),
    do:
      input
      |> Enum.with_index()
      |> Enum.find_value(fn {cp, i} -> if pred.(cp), do: i, else: nil end)

  # The first position of a purposeless bidi control satisfying `pred`, or
  # `nil`. Mirrors the Lean firstOverridePos / firstIsolatePos over the
  # purposeless positions.
  defp first_purposeless_pos(input, pred) do
    input
    |> BidiControlPurpose.purposeless_control_positions()
    |> Enum.find(fn pos -> pred.(Enum.at(input, pos)) end)
  end
end
