defmodule UnicodeSecurity.Covert.SurrogateReassembly do
  alias UnicodeSecurity.Utf8

  def looks_like_byte_stream?(input), do: Enum.all?(input, fn cp -> cp < 0x100 end)

  def detect(input) do
    bytes =
      input |> Enum.map(fn cp -> if cp > 0xFF, do: 0xFF, else: cp end) |> :binary.list_to_bin()

    case Utf8.first_invalid_utf8_offset(bytes) do
      nil -> %{sub: nil, positions: []}
      {offset, kind} -> %{sub: sub_threat(kind), positions: [offset]}
    end
  end

  defp sub_threat(:overlong_encoding), do: "Overlong"
  defp sub_threat(:surrogate_codepoint), do: "Cesu8"
  defp sub_threat(:truncated_sequence), do: "Truncated"
  defp sub_threat(:invalid_start_byte), do: "InvalidStartByte"
  defp sub_threat(:invalid_continuation_byte), do: "InvalidContinuation"
  defp sub_threat(:codepoint_beyond_max), do: "CodepointBeyondMax"
end
