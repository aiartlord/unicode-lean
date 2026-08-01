defmodule UnicodeSecurity.Covert.TagBlockPayload do
  @moduledoc """
  Detection of invisible payloads encoded in the Unicode tag block
  U+E0000..U+E007F.

  Threat model: Tier A1 (local injector). The adversary crafts input containing
  tag-block codepoints that pass through string pipelines as zero-width / no-glyph
  characters but carry a recoverable ASCII payload under the decoder
  `tag(c) = c + 0xE0000` for c in [0x20, 0x7E]. No tag-block codepoint has a
  legitimate visible glyph in modern Unicode; every occurrence is reportable and
  the detector attributes the kind of use.

  Sub-threats (tagged tuples), tag via `sub_threat_tag/1`:
  `{:direct_ascii, decoded}`, `{:language_tag_revival, lang_tag_pos, decoded_tail}`,
  `{:mixed_block, tag_count, total_cps}`, `{:bare_tag_present, tag_cp}`.
  """

  defstruct kind: :clear, sub: nil, tag_positions: [], recovered_ascii: ""

  @type t :: %__MODULE__{
          kind: UnicodeSecurity.Calculus.classification_kind(),
          sub: tuple() | nil,
          tag_positions: [non_neg_integer()],
          recovered_ascii: String.t()
        }

  @doc "True iff `cp` is in the Unicode tag block U+E0000..U+E007F."
  @spec tag_character?(integer()) :: boolean()
  def tag_character?(cp), do: cp >= 0xE0000 and cp <= 0xE007F

  @doc "True iff `cp` is LANGUAGE TAG (U+E0001)."
  @spec language_tag?(integer()) :: boolean()
  def language_tag?(cp), do: cp == 0xE0001

  @doc "True iff `cp` is CANCEL TAG (U+E007F)."
  @spec cancel_tag?(integer()) :: boolean()
  def cancel_tag?(cp), do: cp == 0xE007F

  @doc "Decode a printable tag-block codepoint to its ASCII correspondent, else nil."
  @spec tag_to_ascii(integer()) :: integer() | nil
  def tag_to_ascii(cp) when cp >= 0xE0020 and cp <= 0xE007E, do: cp - 0xE0000
  def tag_to_ascii(_cp), do: nil

  @doc "Sub-threat tag string."
  @spec sub_threat_tag(tuple()) :: String.t()
  def sub_threat_tag({:direct_ascii, _decoded}), do: "DirectAscii"
  def sub_threat_tag({:language_tag_revival, _pos, _tail}), do: "LanguageTagRevival"
  def sub_threat_tag({:mixed_block, _count, _total}), do: "MixedBlock"
  def sub_threat_tag({:bare_tag_present, _cp}), do: "BareTagPresent"

  defp decode_tag_run(input, positions) do
    len = length(input)

    positions
    |> Enum.reduce([], fn p, acc ->
      if p < len do
        case tag_to_ascii(Enum.at(input, p)) do
          nil -> acc
          c -> [c | acc]
        end
      else
        acc
      end
    end)
    |> Enum.reverse()
    |> List.to_string()
  end

  @doc "Detect tag-block payloads in a codepoint sequence."
  @spec detect([integer()]) :: t()
  def detect(input) do
    tag_positions =
      input
      |> Enum.with_index()
      |> Enum.filter(fn {cp, _i} -> tag_character?(cp) end)
      |> Enum.map(fn {_cp, i} -> i end)

    case tag_positions do
      [] ->
        %__MODULE__{kind: :clear}

      _ ->
        decoded = decode_tag_run(input, tag_positions)
        first_pos = hd(tag_positions)
        len = length(input)
        first_cp = Enum.at(input, first_pos)

        sub =
          cond do
            first_pos < len and language_tag?(first_cp) and length(tag_positions) >= 2 ->
              tail = Enum.filter(tag_positions, fn p -> p != first_pos end)
              {:language_tag_revival, first_pos, decode_tag_run(input, tail)}

            Enum.all?(input, &tag_character?/1) and decoded != "" ->
              {:direct_ascii, decoded}

            len > length(tag_positions) ->
              {:mixed_block, length(tag_positions), len}

            true ->
              {:bare_tag_present, first_cp}
          end

        %__MODULE__{
          kind: :hazard,
          sub: sub,
          tag_positions: tag_positions,
          recovered_ascii: decoded
        }
    end
  end
end
