defmodule UnicodeSecurity.Form.NormalizationBomb do
  alias UnicodeSecurity.Ucd

  @max_nfkd_per_cp 8
  @nfd_ratio_pct 300
  @nfkd_ratio_pct 400

  def detect(input) do
    cond do
      (pos = first_blowup_cp(input)) != nil ->
        %{sub: "SingleCpBlowup", positions: [pos]}

      ratio_pct(input, &Ucd.to_nfkd/1) > @nfkd_ratio_pct ->
        %{sub: "NfkdHighExpansion", positions: []}

      ratio_pct(input, &Ucd.to_nfd/1) > @nfd_ratio_pct ->
        %{sub: "NfdHighExpansion", positions: []}

      true ->
        %{sub: nil, positions: []}
    end
  end

  defp first_blowup_cp(input),
    do:
      input
      |> Enum.with_index()
      |> Enum.find_value(fn {cp, i} ->
        if length(Ucd.to_nfkd([cp])) > @max_nfkd_per_cp, do: i, else: nil
      end)

  defp ratio_pct([], _fun), do: 0
  defp ratio_pct(input, fun), do: div(length(fun.(input)) * 100, length(input))
end
