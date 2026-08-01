defmodule UnicodeSecurity.OpaqueBlob do
  @moduledoc """
  Opaque text predicate — structurally valid UTF-8, size-bounded.

  No character-class or codepoint filtering beyond UTF-8 validity. Intended for
  callers who apply their own text hardening downstream; hardened identifier and
  printable profiles layer on top of this predicate. Byte sequences are binaries
  in this port.
  """

  alias UnicodeSecurity.Utf8

  defmodule Utf8Blob do
    @moduledoc "A byte sequence carrying its size bound and UTF-8 validity claim."
    @enforce_keys [:value, :max_bytes]
    defstruct [:value, :max_bytes]
    @type t :: %__MODULE__{value: binary(), max_bytes: non_neg_integer()}
  end

  @doc """
  Opaque-blob predicate: structurally valid UTF-8. Named so the "blob" framing
  (no character-class hardening) is explicit at the call site.
  """
  @spec utf8_blob?(binary()) :: boolean()
  def utf8_blob?(data) when is_binary(data), do: Utf8.valid?(data)

  @doc """
  Build a `Utf8Blob` under the size bound `max_bytes`. Returns `nil` when either
  the bound or UTF-8 validity is violated.
  """
  @spec of(binary(), non_neg_integer()) :: Utf8Blob.t() | nil
  def of(data, max_bytes) when is_binary(data) and is_integer(max_bytes) do
    if byte_size(data) > max_bytes or not utf8_blob?(data) do
      nil
    else
      %Utf8Blob{value: data, max_bytes: max_bytes}
    end
  end
end
