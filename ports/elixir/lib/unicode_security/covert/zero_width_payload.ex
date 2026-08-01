defmodule UnicodeSecurity.Covert.ZeroWidthPayload do
  alias UnicodeSecurity.Ucd

  defstruct kind: :clear, sub: nil, zero_width_positions: []

  def sub_threat_tag({:annotation_misuse, _count}), do: "AnnotationMisuse"
  def sub_threat_tag({:word_joiner_injection, _count}), do: "WordJoinerInjection"
  def sub_threat_tag({:ai_watermark_nnbsp, _count}), do: "AiWatermarkNNBSP"
  def sub_threat_tag({:binary_payload, _pairs}), do: "BinaryPayload"
  def sub_threat_tag({:bare_zero_width, _cp}), do: "BareZeroWidth"

  def sibling_handled?(cp),
    do:
      (cp >= 0xFE00 and cp <= 0xFE0F) or (cp >= 0xE0100 and cp <= 0xE01EF) or
        (cp >= 0xE0000 and cp <= 0xE007F) or (cp >= 0x202A and cp <= 0x202E) or
        (cp >= 0x2066 and cp <= 0x2069)

  def zero_width?(cp) do
    explicit =
      (cp >= 0x200B and cp <= 0x200F) or (cp >= 0x2060 and cp <= 0x2064) or cp == 0x202F or
        cp == 0xFEFF or (cp >= 0xFFF9 and cp <= 0xFFFB)

    explicit or (Ucd.default_ignorable?(cp) and not sibling_handled?(cp))
  end

  defp annotation?(cp), do: cp >= 0xFFF9 and cp <= 0xFFFB
  defp word_joiner?(cp), do: cp == 0x2060
  defp nnbsp?(cp), do: cp == 0x202F
  defp zwj_or_zwsp?(cp), do: cp == 0x200B or cp == 0x200D

  def detect(input) do
    positions =
      input
      |> Enum.with_index()
      |> Enum.filter(fn {cp, _i} -> zero_width?(cp) end)
      |> Enum.map(fn {_cp, i} -> i end)

    if positions == [] do
      %__MODULE__{}
    else
      cps = Enum.map(positions, &Enum.at(input, &1))
      ann = Enum.count(cps, &annotation?/1)
      wj = Enum.count(cps, &word_joiner?/1)
      nnbsp = Enum.count(cps, &nnbsp?/1)
      zw = Enum.count(cps, &zwj_or_zwsp?/1)

      sub =
        cond do
          ann > 0 -> {:annotation_misuse, ann}
          wj > 0 -> {:word_joiner_injection, wj}
          nnbsp >= 2 -> {:ai_watermark_nnbsp, nnbsp}
          zw >= 2 -> {:binary_payload, div(zw, 2)}
          true -> {:bare_zero_width, Enum.at(input, hd(positions))}
        end

      %__MODULE__{kind: :hazard, sub: sub, zero_width_positions: positions}
    end
  end
end
