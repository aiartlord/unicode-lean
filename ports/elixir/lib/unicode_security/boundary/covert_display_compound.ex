defmodule UnicodeSecurity.Boundary.CovertDisplayCompound do
  alias UnicodeSecurity.Covert.{BidiControlBalance, VariationSelectorPayload}

  def detect(input) do
    bidi_pos = first_pos(input, &BidiControlBalance.bidi_format_control?/1)

    cond do
      bidi_pos == nil ->
        %{sub: nil, positions: []}

      (vs_pos = first_suspicious_vs_pos(input)) != nil ->
        %{sub: "BidiPlusUnregisteredVs", positions: [bidi_pos, vs_pos]}

      (tag_pos = first_pos(input, fn cp -> cp >= 0xE0000 and cp <= 0xE007F end)) != nil ->
        %{sub: "BidiPlusTagBlock", positions: [bidi_pos, tag_pos]}

      true ->
        %{sub: nil, positions: []}
    end
  end

  defp first_pos(input, pred),
    do:
      input
      |> Enum.with_index()
      |> Enum.find_value(fn {cp, i} -> if pred.(cp), do: i, else: nil end)

  defp first_suspicious_vs_pos(input) do
    input
    |> Enum.with_index()
    |> Enum.find_value(fn {cp, i} ->
      if VariationSelectorPayload.variation_selector?(cp) and
           not (i > 0 and
                  VariationSelectorPayload.registered_variation_pair?(Enum.at(input, i - 1), cp)),
         do: i,
         else: nil
    end)
  end
end
