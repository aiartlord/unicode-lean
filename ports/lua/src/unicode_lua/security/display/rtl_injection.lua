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

-- The declared display direction of the field holding an input. A caller
-- handling Hebrew, Arabic or Persian UI text declares its field right-to-left;
-- every other reading treats the input as a declared-LTR string, under which
-- right-to-left content is itself the hazard.
--
-- Mirrors FieldDirection in Unicode/Security/Display/RtlInjection.lean, that
-- spec's alias for the UAX #9 paragraph-direction vocabulary.
M.FieldDirection = { LTR = "LTR", RTL = "RTL" }

-- Detection in a field whose declared display direction is `direction`.
--
-- A bidi format control reorders what a reviewer sees whichever way the field
-- runs, so Phase 1 holds unconditionally and trumps all.
--
-- Phases 2 and 3 ask whether right-to-left text has taken over or been spliced
-- into a left-to-right field. That question has no premise in a right-to-left
-- field, where right-to-left text is the content. The mirror-image hazard,
-- strong-LTR injection into a right-to-left field, belongs to the separate
-- detector the scope note assigns it to.
function M.detect_with_context(direction, input)
  local strong_rtl = count_strong_rtl(input)
  local run_len, run_start = longest_rtl_run(input)
  -- Phase 1: bidi format-control trumps all, in either direction.
  local pos = first_bidi_control_pos(input)
  if pos ~= nil then
    return { sub = "BidiControlInLTRField", positions = { pos } }
  end
  -- A right-to-left field carrying right-to-left text carries its content.
  if direction == M.FieldDirection.RTL then
    return { sub = nil, positions = {} }
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

-- Detection in a field declared left-to-right, the reading the module scope
-- note fixes for an undeclared field.
function M.detect(input)
  return M.detect_with_context(M.FieldDirection.LTR, input)
end

return M
