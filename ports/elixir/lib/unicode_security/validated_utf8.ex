defmodule UnicodeSecurity.ValidatedUtf8 do
  @moduledoc """
  Refinement type for bytes validated as strict RFC 3629 UTF-8.

  The validity claim is pinned at the module boundary: the only way to build a
  `ValidatedUtf8` is via `validate/1`, which routes through the strict decoder
  state machine. A consumer that wants the raw bytes calls `unwrap/1`, which
  reads as "I am consuming the RFC 3629 claim here". Byte sequences are binaries
  in this port.
  """

  alias UnicodeSecurity.Utf8

  @enforce_keys [:bytes]
  defstruct [:bytes]

  @type t :: %__MODULE__{bytes: binary()}

  @doc """
  Validate `data` and, on success, return a `ValidatedUtf8` carrying the
  RFC 3629 validity claim. Returns `nil` when the bytes fail the strict machine.
  """
  @spec validate(binary()) :: t() | nil
  def validate(data) when is_binary(data) do
    if Utf8.valid?(data), do: %__MODULE__{bytes: data}, else: nil
  end

  @doc "Borrow the validated bytes."
  @spec as_bytes(t()) :: binary()
  def as_bytes(%__MODULE__{bytes: bytes}), do: bytes

  @doc """
  Consume the validity claim, returning the underlying bytes. After this call
  the validity claim is no longer carried at the module boundary.
  """
  @spec unwrap(t()) :: binary()
  def unwrap(%__MODULE__{bytes: bytes}), do: bytes
end
