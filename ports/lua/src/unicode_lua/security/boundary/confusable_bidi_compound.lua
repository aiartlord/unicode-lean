local bidi = require("unicode_lua.security.covert.bidi_control_balance")
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

function M.detect(input)
  local confusable_pos = first_pos(input, homoglyph.confusable_source)
  if confusable_pos == nil then
    return { sub = nil, positions = {} }
  end
  local override_pos = first_pos(input, override)
  if override_pos ~= nil then
    return { sub = "ConfusableInOverride", positions = { confusable_pos, override_pos } }
  end
  local isolate_pos = first_pos(input, isolate)
  if isolate_pos ~= nil then
    return { sub = "ConfusableInIsolate", positions = { confusable_pos, isolate_pos } }
  end
  return { sub = nil, positions = {} }
end

return M
