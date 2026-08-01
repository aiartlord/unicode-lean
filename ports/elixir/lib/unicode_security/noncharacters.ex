defmodule UnicodeSecurity.Noncharacters do
  @moduledoc """
  The 66 designated Unicode noncharacters per UAX #44 §5.6 / Unicode 17.0 §23.7.

  Two categories: the BMP block U+FDD0..U+FDEF (32 codepoints) and the plane ends
  U+nnFFFE / U+nnFFFF for n = 0..16 (34 codepoints). Noncharacters are reserved
  for internal use; conformant Unicode text must not contain them in interchange.
  """

  import Bitwise

  @doc "Whether `cp` is one of the 66 designated Unicode noncharacters."
  @spec noncharacter?(integer()) :: boolean()
  def noncharacter?(cp) do
    cond do
      cp >= 0xFDD0 and cp <= 0xFDEF ->
        true

      cp > 0x10FFFF ->
        false

      true ->
        low16 = band(cp, 0xFFFF)
        low16 == 0xFFFE or low16 == 0xFFFF
    end
  end

  @doc "Enumerate the 66 noncharacters in ascending order."
  @spec all_noncharacters() :: [non_neg_integer()]
  def all_noncharacters do
    bmp = Enum.to_list(0xFDD0..0xFDEF)
    planes = Enum.flat_map(0..16, fn n -> [n * 0x10000 + 0xFFFE, n * 0x10000 + 0xFFFF] end)
    bmp ++ planes
  end
end
