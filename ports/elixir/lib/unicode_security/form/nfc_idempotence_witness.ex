defmodule UnicodeSecurity.Form.NfcIdempotenceWitness do
  alias UnicodeSecurity.Ucd

  def detect(input) do
    cond do
      (pos = first_divergence(input, Ucd.to_nfc(input))) != nil ->
        %{sub: "NonNfcForm", positions: [pos]}

      (pos = first_divergence(input, Ucd.to_nfkc(input))) != nil ->
        %{sub: "NonNfkcCompatForm", positions: [pos]}

      true ->
        %{sub: nil, positions: []}
    end
  end

  defp first_divergence(a, b) do
    n = min(length(a), length(b))
    pos = Enum.find(0..max(n - 1, 0), fn i -> n > 0 and Enum.at(a, i) != Enum.at(b, i) end)

    cond do
      pos != nil -> pos
      length(a) != length(b) -> n
      true -> nil
    end
  end
end
