defmodule UnicodeSecurity.Covert.VariationSelectorPayload do
  alias UnicodeSecurity.Crypto.AiWatermarkDetectability
  alias UnicodeSecurity.Data

  defstruct kind: :clear, sub: nil, vs_positions: [], suspicious_positions: [], recovered_bytes: []

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
  def sub_threat_tag({:embedded_after_registered, _registered, _suspicious}), do: "EmbeddedAfterRegistered"

  def registered_variation_pair?(base, vs), do: MapSet.member?(legal_pairs(), {base, vs})

  @doc """
  A selector on `base` is a registered use when the pair is registered
  (StandardizedVariants plus the emoji variation sequences) or when it is
  VS15/VS16 on an Emoji-property base. Mirrors the Lean isRegisteredUse.
  """
  def registered_variation_use?(base, vs) do
    registered_variation_pair?(base, vs) or
      ((vs == 0xFE0E or vs == 0xFE0F) and AiWatermarkDetectability.is_emoji(base))
  end

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

    # Each selector is judged against its predecessor: a registered use is
    # sanctioned wherever it stands and however many, and an input whose
    # selectors are all registered is clear. The hazard is the suspicious run
    # alone. Mirrors the Lean detect.
    registered = Enum.filter(positions, &registered_variation_use_at?(input, &1))
    suspicious = positions -- registered

    if suspicious == [] do
      %__MODULE__{vs_positions: positions}
    else
      hazard(input, positions, registered, suspicious)
    end
  end

  defp registered_variation_use_at?(_input, 0), do: false

  defp registered_variation_use_at?(input, p),
    do: registered_variation_use?(Enum.at(input, p - 1), Enum.at(input, p))

  # Ranked EmbeddedAfterRegistered (a registered use precedes the first
  # suspicious selector), RepeatedBase (at least four suspicious selectors, all
  # the same codepoint), DirectPayload (the nibble pairs over the suspicious
  # selectors recover a byte), else IllegalTarget.
  defp hazard(input, positions, registered, suspicious) do
    recovered = decode_vs_run(input, suspicious)
    p0 = hd(suspicious)
    base = if p0 == 0, do: 0, else: Enum.at(input, p0 - 1)

    sub =
      cond do
        registered != [] and hd(registered) < p0 ->
          {:embedded_after_registered, hd(registered), p0}

        length(suspicious) >= 4 and
            Enum.uniq(Enum.map(suspicious, &Enum.at(input, &1))) |> length() == 1 ->
          {:repeated_base, base, length(suspicious)}

        recovered != [] ->
          {:direct_payload, lossy_ascii(recovered)}

        true ->
          {:illegal_target, base, Enum.at(input, p0)}
      end

    %__MODULE__{
      kind: :hazard,
      sub: sub,
      vs_positions: positions,
      suspicious_positions: suspicious,
      recovered_bytes: recovered
    }
  end
end
