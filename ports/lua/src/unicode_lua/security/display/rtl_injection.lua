local bidi = require("unicode_lua.security.covert.bidi_control_balance")
local ucd = require("unicode_lua.security.identity.ucd")

local M = {}

local function count_strong_rtl(input)
  local count = 0
  for _, cp in ipairs(input) do
    if ucd.is_strong_rtl(cp) then
      count = count + 1
    end
  end
  return count
end

local function first_bidi_control_pos(input)
  for i = 1, #input do
    if bidi.is_bidi_format_control(input[i]) then
      return i - 1
    end
  end
  return nil
end

local function first_strong_char(input)
  for i = 1, #input do
    local cp = input[i]
    if ucd.is_strong_rtl(cp) then
      return i - 1, true
    elseif ucd.is_strong_ltr(cp) then
      return i - 1, false
    end
  end
  return nil, nil
end

local function first_strong_rtl_pos(input)
  for i = 1, #input do
    if ucd.is_strong_rtl(input[i]) then
      return i - 1
    end
  end
  return nil
end

local function longest_rtl_run(input)
  local longest, longest_start = 0, 0
  local current, current_start = 0, 0
  for i = 1, #input do
    if ucd.is_strong_rtl(input[i]) then
      if current == 0 then
        current_start = i - 1
      end
      current = current + 1
      if current > longest then
        longest = current
        longest_start = current_start
      end
    else
      current = 0
    end
  end
  return longest, longest_start
end

function M.detect(input)
  local strong_rtl = count_strong_rtl(input)
  local run_len, run_start = longest_rtl_run(input)
  local pos = first_bidi_control_pos(input)
  if pos ~= nil then
    return { sub = "RloInLTRField", positions = { pos } }
  end
  local first_pos, is_rtl = first_strong_char(input)
  if first_pos ~= nil and is_rtl then
    return { sub = "FieldTakeover", positions = { first_pos } }
  end
  if strong_rtl == 0 then
    return { sub = nil, positions = {} }
  end
  if run_len >= 4 then
    return { sub = "MixedOverflow", positions = { run_start } }
  end
  pos = first_strong_rtl_pos(input)
  return pos == nil and { sub = nil, positions = {} } or { sub = "StrongRTLInLTR", positions = { pos } }
end

return M
