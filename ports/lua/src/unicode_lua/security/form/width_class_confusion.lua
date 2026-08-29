-- Width-class-confusion detection — UAX #11 East Asian Width class confusion.
--
-- A Fullwidth (EAW = F) or Halfwidth (EAW = H) codepoint whose NFKD form
-- carries a different EAW class is a compatibility-fold homograph:
--
--   U+FF21 'Ａ' (F)  ->  U+0041 'A' (Na)
--   U+FF11 '１' (F)  ->  U+0031 '1' (Na)
--   U+FF71 'ｱ' (H)  ->  U+30A2 'ア' (W)
--
-- The two-system bypass: a validator that whitelists ASCII rejects Ａ, while a
-- downstream NFKC step at storage or comparison time folds it to plain A, so
-- ＡＤＭＩＮ claims the username ADMIN.
--
-- Distinct from renderer_divergence's FullwidthVariance, which fires on
-- F-class codepoints for renderer-cohort reasons; this is the NFKC-fold
-- verdict and both can fire on one input independently. Hangul syllables
-- decompose to jamos that are still W class, so pure Hangul stays clear.
--
-- Direct port of Unicode/Security/Form/WidthClassConfusion.lean.

local ucd = require("unicode_lua.security.identity.ucd")

local M = {}

-- True iff the NFKD head of cp carries a different EAW class.
local function width_fold(cp)
  local folded = ucd.to_nfkd({ cp })
  if #folded == 0 then
    return false
  end
  return ucd.east_asian_width(folded[1]) ~= ucd.east_asian_width(cp)
end

-- First zero-based position whose codepoint has class `want` and folds away.
local function first_fold(input, want)
  for i = 1, #input do
    local cp = input[i]
    if ucd.east_asian_width(cp) == want and width_fold(cp) then
      return i - 1
    end
  end
  return nil
end

-- A Fullwidth fold takes priority over a Halfwidth one, matching the
-- reference's sub-threat order.
function M.detect(input)
  local pos = first_fold(input, ucd.EastAsianWidth.F)
  if pos ~= nil then
    return { sub = "FullwidthFold", positions = { pos } }
  end
  pos = first_fold(input, ucd.EastAsianWidth.H)
  if pos ~= nil then
    return { sub = "HalfwidthFold", positions = { pos } }
  end
  return { sub = nil, positions = {} }
end

return M
