-- Detection and enumeration of the 66 designated Unicode noncharacters per
-- UAX #44 §5.6 / Unicode Standard 17.0 §23.7.
--
--   - BMP block:  U+FDD0 .. U+FDEF                (32 codepoints)
--   - Plane ends: U+nnFFFE / U+nnFFFF for n=0..16 (34 codepoints)

local bit = require("bit")

local M = {}

-- Whether `cp` is one of the 66 designated Unicode noncharacters.
function M.is_noncharacter(cp)
  if cp >= 0xFDD0 and cp <= 0xFDEF then
    return true
  end
  if cp > 0x10FFFF then
    return false
  end
  local low16 = bit.band(cp, 0xFFFF)
  return low16 == 0xFFFE or low16 == 0xFFFF
end

-- Enumerate the 66 noncharacters in ascending order (1-indexed table).
function M.all_noncharacters()
  local out = {}
  for cp = 0xFDD0, 0xFDEF do
    out[#out + 1] = cp
  end
  for n = 0, 16 do
    out[#out + 1] = n * 0x10000 + 0xFFFE
    out[#out + 1] = n * 0x10000 + 0xFFFF
  end
  return out
end

return M
