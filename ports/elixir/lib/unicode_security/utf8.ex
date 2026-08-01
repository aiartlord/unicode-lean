defmodule UnicodeSecurity.Utf8 do
  @moduledoc """
  Strict UTF-8 codec — validator, decoder, and encoder.

  The accepted byte set is exactly the strict RFC 3629 acceptance language: it
  rejects overlong encodings, surrogate codepoints (U+D800..U+DFFF), codepoints
  beyond U+10FFFF, truncated multi-byte sequences, invalid start bytes, and
  invalid continuation bytes. Acceptance is decided by an explicit state machine
  over raw octets rather than any platform UTF-8 primitive; the accepted byte set
  is closed-form per the spec.

  Reject kinds are the six atoms enumerated by the strict reject taxonomy:
  `:overlong_encoding`, `:surrogate_codepoint`, `:codepoint_beyond_max`,
  `:truncated_sequence`, `:invalid_start_byte`, `:invalid_continuation_byte`.

  Offset convention for `first_invalid_utf8_offset/1`: the returned offset is the
  index of the byte on which the state machine transitions to reject. For
  `:overlong_encoding` the offset is the start byte of the sequence, not the last
  byte consumed. `:truncated_sequence` reports an offset equal to `byte_size`.
  """

  import Bitwise

  @type reject_kind ::
          :overlong_encoding
          | :surrogate_codepoint
          | :codepoint_beyond_max
          | :truncated_sequence
          | :invalid_start_byte
          | :invalid_continuation_byte

  @doc "Stable CamelCase sub-threat tag for a strict UTF-8 reject kind."
  @spec reject_tag(reject_kind()) :: String.t()
  def reject_tag(:overlong_encoding), do: "OverlongEncoding"
  def reject_tag(:surrogate_codepoint), do: "SurrogateCodepoint"
  def reject_tag(:codepoint_beyond_max), do: "CodepointBeyondMax"
  def reject_tag(:truncated_sequence), do: "TruncatedSequence"
  def reject_tag(:invalid_start_byte), do: "InvalidStartByte"
  def reject_tag(:invalid_continuation_byte), do: "InvalidContinuationByte"

  @doc """
  First reject offset as `{offset, kind}`, or `nil` when the input is valid
  UTF-8.
  """
  @spec first_invalid_utf8_offset(binary()) :: {non_neg_integer(), reject_kind()} | nil
  def first_invalid_utf8_offset(data) when is_binary(data) do
    walk(data, 0, 0, :expect_start, byte_size(data))
  end

  # Start state at byte i: record the sequence start.
  defp walk(<<b, rest::binary>>, i, _seq_start, :expect_start, total) do
    case step(:expect_start, b) do
      {:continue, state} -> walk(rest, i + 1, i, state, total)
      {:emit, _cp, state} -> walk(rest, i + 1, i, state, total)
      {:reject, kind} -> {i, kind}
    end
  end

  # Continuation state at byte i: keep the recorded sequence start.
  defp walk(<<b, rest::binary>>, i, seq_start, {:expect_cont, _, _, _} = state, total) do
    case step(state, b) do
      {:continue, next} -> walk(rest, i + 1, seq_start, next, total)
      {:emit, _cp, next} -> walk(rest, i + 1, seq_start, next, total)
      {:reject, :overlong_encoding} -> {seq_start, :overlong_encoding}
      {:reject, kind} -> {i, kind}
    end
  end

  defp walk(<<>>, _i, _seq_start, {:expect_cont, _, _, _}, total),
    do: {total, :truncated_sequence}

  defp walk(<<>>, _i, _seq_start, :expect_start, _total), do: nil

  @doc "Process one byte given the current decoder state."
  @spec step(term(), 0..255) ::
          {:continue, term()} | {:emit, non_neg_integer(), term()} | {:reject, reject_kind()}
  def step(:expect_start, byte) do
    n = band(byte, 0xFF)

    cond do
      n < 0x80 -> {:emit, n, :expect_start}
      n < 0xC2 -> {:reject, :invalid_start_byte}
      n < 0xE0 -> {:continue, {:expect_cont, 1, band(n, 0x1F), 0x80}}
      n < 0xF0 -> {:continue, {:expect_cont, 2, band(n, 0x0F), 0x800}}
      n < 0xF5 -> {:continue, {:expect_cont, 3, band(n, 0x07), 0x10000}}
      true -> {:reject, :invalid_start_byte}
    end
  end

  def step({:expect_cont, remaining, accum, min_cp}, byte) do
    n = band(byte, 0xFF)

    if n < 0x80 or n >= 0xC0 do
      {:reject, :invalid_continuation_byte}
    else
      nxt = bor(bsl(accum, 6), band(n, 0x3F))

      if remaining == 1 do
        cond do
          nxt < min_cp -> {:reject, :overlong_encoding}
          nxt >= 0xD800 and nxt <= 0xDFFF -> {:reject, :surrogate_codepoint}
          nxt > 0x10FFFF -> {:reject, :codepoint_beyond_max}
          true -> {:emit, nxt, :expect_start}
        end
      else
        {:continue, {:expect_cont, remaining - 1, nxt, min_cp}}
      end
    end
  end

  @doc "Whole-input validity predicate."
  @spec valid?(binary()) :: boolean()
  def valid?(data), do: first_invalid_utf8_offset(data) == nil

  @doc """
  Decode a UTF-8 byte string to a codepoint list. Semantically meaningful only
  when the input is valid UTF-8; on malformed input the walker yields the longest
  valid prefix and stops.
  """
  @spec decode_to_codepoints(binary()) :: [non_neg_integer()]
  def decode_to_codepoints(data) when is_binary(data) do
    decode(data, :expect_start, [])
  end

  defp decode(<<b, rest::binary>>, state, acc) do
    case step(state, b) do
      {:continue, next} -> decode(rest, next, acc)
      {:emit, cp, next} -> decode(rest, next, [cp | acc])
      {:reject, _kind} -> Enum.reverse(acc)
    end
  end

  defp decode(<<>>, _state, acc), do: Enum.reverse(acc)

  @doc "Encode a single codepoint as a 1–4 byte UTF-8 sequence."
  @spec encode_codepoint(non_neg_integer()) :: binary()
  def encode_codepoint(cp) when cp < 0x80, do: <<cp>>

  def encode_codepoint(cp) when cp < 0x800 do
    <<bor(0xC0, bsr(cp, 6)), bor(0x80, band(cp, 0x3F))>>
  end

  def encode_codepoint(cp) when cp < 0x10000 do
    <<bor(0xE0, bsr(cp, 12)), bor(0x80, band(bsr(cp, 6), 0x3F)), bor(0x80, band(cp, 0x3F))>>
  end

  def encode_codepoint(cp) do
    <<bor(0xF0, bsr(cp, 18)), bor(0x80, band(bsr(cp, 12), 0x3F)),
      bor(0x80, band(bsr(cp, 6), 0x3F)), bor(0x80, band(cp, 0x3F))>>
  end

  @doc "Concatenate the UTF-8 encodings of a codepoint sequence."
  @spec encode_codepoints([non_neg_integer()]) :: binary()
  def encode_codepoints(cps) do
    cps |> Enum.map(&encode_codepoint/1) |> IO.iodata_to_binary()
  end
end
