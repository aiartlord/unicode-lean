defmodule UnicodeSecurity.Covert.VariationSelectorPayload do
  alias UnicodeSecurity.Data

  defstruct kind: :clear, sub: nil, vs_positions: [], recovered_bytes: []

  def variation_selector?(cp),
    do:
      (cp >= 0xFE00 and cp <= 0xFE0F) or (cp >= 0xE0100 and cp <= 0xE01EF) or
        (cp >= 0x180B and cp <= 0x180D)

  def vs_to_nibble(cp) when cp >= 0xFE00 and cp <= 0xFE0F, do: cp - 0xFE00
  def vs_to_nibble(cp) when cp >= 0xE0100 and cp <= 0xE01EF, do: cp - 0xE0100 + 16
  def vs_to_nibble(_cp), do: nil

  def sub_threat_tag({:direct_payload, _decoded}), do: "DirectPayload"
  def sub_threat_tag({:illegal_target, _target, _vs}), do: "IllegalTarget"
  def sub_threat_tag({:repeated_base, _base, _count}), do: "RepeatedBase"

  def registered_variation_pair?(base, vs), do: MapSet.member?(legal_pairs(), {base, vs})

  defp legal_pairs do
    Data.cached(:variation_legal_pairs, fn ->
      ["StandardizedVariants.txt", "emoji-variation-sequences.txt"]
      |> Enum.reduce(MapSet.new(), fn file, acc ->
        Data.read(file)
        |> String.split("\n")
        |> Enum.reduce(acc, fn raw, set ->
          body = raw |> strip_comment() |> String.trim()

          if body == "" do
            set
          else
            pair_part = body |> String.split(";", parts: 2) |> hd()
            toks = String.split(String.trim(pair_part), ~r/\s+/, trim: true)

            case toks do
              [base_hex, vs_hex | _] ->
                MapSet.put(set, {String.to_integer(base_hex, 16), String.to_integer(vs_hex, 16)})

              _ ->
                set
            end
          end
        end)
      end)
    end)
  end

  defp strip_comment(line), do: line |> String.split("#", parts: 2) |> hd()

  defp decode_vs_run(input, positions) do
    positions
    |> Enum.reduce({[], nil}, fn p, {bytes, high} ->
      case vs_to_nibble(Enum.at(input, p)) do
        nil -> {bytes, high}
        n when high == nil -> {bytes, n}
        n -> {[Bitwise.band(Bitwise.bor(Bitwise.bsl(high, 4), n), 0xFF) | bytes], nil}
      end
    end)
    |> elem(0)
    |> Enum.reverse()
  end

  defp lossy_ascii(bytes) do
    bytes
    |> Enum.map(fn b ->
      if (b >= 0x20 and b <= 0x7E) or b in [0x09, 0x0A, 0x0D], do: b, else: ??
    end)
    |> List.to_string()
  end

  def detect(input) do
    positions =
      input
      |> Enum.with_index()
      |> Enum.filter(fn {cp, _i} -> variation_selector?(cp) end)
      |> Enum.map(fn {_cp, i} -> i end)

    if positions == [] do
      %__MODULE__{}
    else
      recovered = decode_vs_run(input, positions)

      if length(positions) == 1 do
        p = hd(positions)

        if p > 0 and registered_variation_pair?(Enum.at(input, p - 1), Enum.at(input, p)) do
          %__MODULE__{kind: :clear, vs_positions: positions, recovered_bytes: recovered}
        else
          hazard(input, positions, recovered)
        end
      else
        hazard(input, positions, recovered)
      end
    end
  end

  defp hazard(input, positions, recovered) do
    sub =
      cond do
        length(positions) >= 4 and
            Enum.uniq(Enum.map(positions, &Enum.at(input, &1))) |> length() == 1 ->
          p0 = hd(positions)
          {:repeated_base, if(p0 == 0, do: 0, else: Enum.at(input, p0 - 1)), length(positions)}

        recovered != [] ->
          {:direct_payload, lossy_ascii(recovered)}

        true ->
          p = hd(positions)
          {:illegal_target, if(p == 0, do: 0, else: Enum.at(input, p - 1)), Enum.at(input, p)}
      end

    %__MODULE__{kind: :hazard, sub: sub, vs_positions: positions, recovered_bytes: recovered}
  end
end
