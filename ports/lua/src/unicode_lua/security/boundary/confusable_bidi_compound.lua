-- ConfusableBidiCompound — a confusable source co-located with a purposeless
-- bidi control (CVE-2021-42574 class). Only a purposeless control
-- (BidiControlPurpose: unbalanced, or a balanced span enclosing nothing
-- right-to-left in a left-to-right context) is the display channel this
-- compound pairs with a confusable; a balanced embedding around Arabic text
-- renders that text as written.

local bidi = require("unicode_lua.security.covert.bidi_control_balance")
local bidi_purpose = require("unicode_lua.security.display.bidi_control_purpose")
local homoglyph = require("unicode_lua.security.identity.homoglyph_confusable")

local M = {}

local function override(cp)
  return bidi.opens_embedding(cp) or bidi.is_pdf(cp)
end

local function isolate(cp)
  return bidi.opens_isolate(cp) or bidi.is_pdi(cp)
end

local function first_pos(input, pred)
  for i = 1, #input do
    if pred(input[i]) then
      return i - 1
    end
  end
  return nil
end

-- The first 0-based position of a purposeless bidi control satisfying pred, or
-- nil. Mirrors the Lean firstOverridePos / firstIsolatePos over the purposeless
-- positions.
local function first_purposeless_pos(input, pred)
  for _, pos in ipairs(bidi_purpose.purposeless_control_positions(input)) do
    if pred(input[pos + 1]) then
      return pos
    end
  end
  return nil
end

function M.detect(input)
  local confusable_pos = first_pos(input, homoglyph.confusable_source)
  if confusable_pos == nil then
    return { sub = nil, positions = {} }
  end
  local override_pos = first_purposeless_pos(input, override)
  if override_pos ~= nil then
    return { sub = "ConfusableInOverride", positions = { confusable_pos, override_pos } }
  end
  local isolate_pos = first_purposeless_pos(input, isolate)
  if isolate_pos ~= nil then
    return { sub = "ConfusableInIsolate", positions = { confusable_pos, isolate_pos } }
  end
  return { sub = nil, positions = {} }
end

return M
