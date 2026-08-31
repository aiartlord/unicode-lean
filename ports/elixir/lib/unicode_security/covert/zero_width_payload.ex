defmodule UnicodeSecurity.Covert.ZeroWidthPayload do
  alias UnicodeSecurity.Identity.EmojiZwjIntegrity
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

  # True iff the zero-width codepoint at index `i` carries meaning a reader
  # depends on: a ZWJ inside a registered RGI emoji sequence, or a ZWNJ in an
  # RFC 5892 Appendix A.1 CONTEXTJ-valid position.
  defp sanctioned?(input, i) do
    case Enum.at(input, i) do
      0x200D -> legitimate_zwj_context?(input, i)
      0x200C -> legitimate_zwnj_context?(input, i)
      _other -> false
    end
  end

  # A ZWJ is legitimate only when flanked by two codepoints that both
  # participate in some registered RGI emoji ZWJ sequence. This is strictly
  # narrower than "is an emoji": a codepoint carrying the Emoji property but
  # appearing in no registered sequence does not sanction a ZWJ beside it. A ZWJ
  # in head or tail position is never legitimate.
  defp legitimate_zwj_context?(input, i) do
    if i == 0 or i + 1 >= length(input) do
      false
    else
      EmojiZwjIntegrity.is_emoji_target?(Enum.at(input, i - 1)) and
        EmojiZwjIntegrity.is_emoji_target?(Enum.at(input, i + 1))
    end
  end

  # RFC 5892 Appendix A.1: a ZWNJ is orthographically required when it follows a
  # Virama, which is how a Devanagari conjunct is suppressed, or when it sits
  # between a left- or dual-joining character and a right- or dual-joining one,
  # skipping Transparent characters on both sides, which is how a Persian word
  # boundary is written inside a cursive run. A ZWNJ outside such a position
  # carries no orthographic duty and stays reportable.
  defp legitimate_zwnj_context?(input, i) do
    if i > 0 and Ucd.virama?(Enum.at(input, i - 1)) do
      true
    else
      left = joining_type_before(input, i)
      right = joining_type_after(input, i)
      left in [:l, :d] and right in [:r, :d]
    end
  end

  # The Joining_Type of the first non-Transparent codepoint before `i`.
  defp joining_type_before(input, i) do
    input
    |> Enum.take(i)
    |> Enum.reverse()
    |> Enum.map(&Ucd.joining_type/1)
    |> Enum.find(fn jt -> jt != :t end)
  end

  # The Joining_Type of the first non-Transparent codepoint after `i`.
  defp joining_type_after(input, i) do
    input
    |> Enum.drop(i + 1)
    |> Enum.map(&Ucd.joining_type/1)
    |> Enum.find(fn jt -> jt != :t end)
  end

  def detect(input) do
    positions =
      input
      |> Enum.with_index()
      |> Enum.filter(fn {cp, _i} -> zero_width?(cp) end)
      |> Enum.map(fn {_cp, i} -> i end)

    # The sanctioning model: a ZWJ inside a registered emoji sequence and a ZWNJ
    # in an RFC 5892 CONTEXTJ-valid position both carry meaning a reader depends
    # on, so they are recorded as present but not treated as suspicious.
    suspicious = Enum.reject(positions, &sanctioned?(input, &1))

    if positions == [] or suspicious == [] do
      %__MODULE__{zero_width_positions: positions}
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
          true -> {:bare_zero_width, Enum.at(input, hd(suspicious))}
        end

      %__MODULE__{kind: :hazard, sub: sub, zero_width_positions: positions}
    end
  end
end
