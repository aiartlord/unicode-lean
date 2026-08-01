defmodule UnicodeSecurity.Boundary.ConfusableBidiCompound do
  alias UnicodeSecurity.Covert.BidiControlBalance
  alias UnicodeSecurity.Identity.HomoglyphConfusable

  def detect(input) do
    confusable_pos = first_pos(input, &HomoglyphConfusable.confusable_source?/1)

    cond do
      confusable_pos == nil ->
        %{sub: nil, positions: []}

      (override_pos =
         first_pos(input, fn cp ->
           BidiControlBalance.opens_embedding?(cp) or BidiControlBalance.pdf?(cp)
         end)) != nil ->
        %{sub: "ConfusableInOverride", positions: [confusable_pos, override_pos]}

      (isolate_pos =
         first_pos(input, fn cp ->
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
end
