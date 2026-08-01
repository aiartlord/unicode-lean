local bidi = require("unicode_lua.security.covert.bidi_control_balance")
local vs = require("unicode_lua.security.covert.variation_selector_payload")

local M = {}

local function tag_block_char(cp)
  return cp >= 0xE0000 and cp <= 0xE007F
end

local function first_bidi_pos(input)
  for i = 1, #input do
    if bidi.is_bidi_format_control(input[i]) then
      return i - 1
    end
  end
  return nil
end

local function first_suspicious_vs_pos(input)
  for i = 1, #input do
    local cp = input[i]
    if vs.is_variation_selector(cp) and not (i > 1 and vs.is_registered_variation_pair(input[i - 1], cp)) then
      return i - 1
    end
  end
  return nil
end

local function first_tag_block_pos(input)
  for i = 1, #input do
    if tag_block_char(input[i]) then
      return i - 1
    end
  end
  return nil
end

function M.detect(input)
  local bidi_pos = first_bidi_pos(input)
  if bidi_pos == nil then
    return { sub = nil, positions = {} }
  end
  local vs_pos = first_suspicious_vs_pos(input)
  if vs_pos ~= nil then
    return { sub = "BidiPlusUnregisteredVs", positions = { bidi_pos, vs_pos } }
  end
  local tag_pos = first_tag_block_pos(input)
  if tag_pos ~= nil then
    return { sub = "BidiPlusTagBlock", positions = { bidi_pos, tag_pos } }
  end
  return { sub = nil, positions = {} }
end

return M
