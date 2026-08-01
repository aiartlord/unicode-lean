local datapath = require("unicode_lua.datapath")
local calculus = require("unicode_lua.security.calculus")
local ucd = require("unicode_lua.security.identity.ucd")

local ClassificationKind = calculus.ClassificationKind
local M = {}

local _confusables = nil
local _targets = nil

local function trim(s)
  return (s:gsub("^%s*(.-)%s*$", "%1"))
end

local function strip_comment(line)
  local hash = line:find("#", 1, true)
  if hash ~= nil then
    return trim(line:sub(1, hash - 1))
  end
  return trim(line)
end

local function split(s, sep)
  local out = {}
  local start = 1
  while true do
    local i = s:find(sep, start, true)
    if i == nil then
      out[#out + 1] = s:sub(start)
      break
    end
    out[#out + 1] = s:sub(start, i - 1)
    start = i + #sep
  end
  return out
end

local function parse_confusables()
  local out = {}
  for raw in (datapath.read("confusables.txt") .. "\n"):gmatch("([^\n]*)\n") do
    local line = strip_comment(raw)
    if line ~= "" then
      local parts = split(line, ";")
      if #parts >= 2 then
        local src = tonumber(trim(parts[1]), 16)
        local target = {}
        for tok in parts[2]:gmatch("%S+") do
          target[#target + 1] = tonumber(tok, 16)
        end
        if src ~= nil and #target > 0 then
          out[src] = target
        end
      end
    end
  end
  return out
end

local function confusables()
  if _confusables == nil then
    _confusables = parse_confusables()
  end
  return _confusables
end

function M.confusable_source(cp)
  return confusables()[cp] ~= nil
end

local function substitute(input)
  local map = confusables()
  local out = {}
  for _, cp in ipairs(input) do
    local rep = map[cp]
    if rep == nil then
      out[#out + 1] = cp
    else
      for _, r in ipairs(rep) do
        out[#out + 1] = r
      end
    end
  end
  return out
end

function M.skeleton(input)
  return ucd.to_nfd(ucd.case_fold(substitute(ucd.case_fold(ucd.to_nfd(input)))))
end

function M.iterated_skeleton(input)
  local current = { table.unpack(input) }
  while true do
    local next_value = M.skeleton(current)
    if #next_value == #current then
      local same = true
      for i = 1, #current do
        if current[i] ~= next_value[i] then
          same = false
          break
        end
      end
      if same then
        return current
      end
    end
    current = next_value
  end
end

local function letter_skeleton_from_iterated(iterated)
  local out = {}
  for _, cp in ipairs(iterated) do
    if ucd.ccc(cp) == 0 and not ucd.is_default_ignorable(cp) and not ucd.is_white_space(cp) then
      out[#out + 1] = cp
    end
  end
  return out
end

local function arrays_equal(a, b)
  if #a ~= #b then
    return false
  end
  for i = 1, #a do
    if a[i] ~= b[i] then
      return false
    end
  end
  return true
end

local function parse_targets()
  local out = {}
  for raw in (datapath.read("KnownAttackTargets.txt") .. "\n"):gmatch("([^\n]*)\n") do
    local line = trim(raw)
    if line ~= "" and line:sub(1, 1) ~= "#" then
      local cps = {}
      for _, cp in utf8.codes(line) do
        cps[#cps + 1] = cp
      end
      out[#out + 1] = { name = line, cps = cps, letters = letter_skeleton_from_iterated(M.iterated_skeleton(cps)) }
    end
  end
  return out
end

local function targets()
  if _targets == nil then
    _targets = parse_targets()
  end
  return _targets
end

local function find_target_match(input, iterated)
  local input_letters = letter_skeleton_from_iterated(iterated)
  for _, target in ipairs(targets()) do
    if not arrays_equal(target.cps, input) and arrays_equal(target.letters, input_letters) then
      return target.name
    end
  end
  return nil
end

local function math_alphanumeric(cp)
  return cp >= 0x1D400 and cp <= 0x1D7FF
end

local function fullwidth_halfwidth(cp)
  return cp >= 0xFF01 and cp <= 0xFFEF
end

function M.has_mixed_script_admissibility(input)
  local union = ucd.string_script_union(input)
  return #union >= 2 and not ucd.is_highly_restrictive(input)
end

function M.mixed_script_subthreat(input)
  local union = ucd.string_script_union(input)
  local seen = {}
  for _, s in ipairs(union) do
    seen[s] = true
  end
  if seen.Latn and seen.Cyrl then
    return "LatinCyrillic"
  elseif seen.Latn and seen.Grek then
    return "LatinGreek"
  end
  return "ScriptMixOther"
end

function M.detect(input)
  local skel = M.skeleton(input)
  local iskel = M.iterated_skeleton(input)
  local rl = ucd.restriction_level(input)
  local verdict = {
    kind = ClassificationKind.Clear,
    sub = nil,
    skeleton = skel,
    iterated_skeleton = iskel,
    restriction_level = rl,
    matched_targets = {},
    target = nil,
  }

  local target = find_target_match(input, iskel)
  if target ~= nil then
    verdict.kind = ClassificationKind.Hazard
    verdict.sub = { tag = "TargetMatch", target = target }
    verdict.matched_targets = { target }
    verdict.target = target
    return verdict
  end

  for _, cp in ipairs(input) do
    if math_alphanumeric(cp) then
      verdict.kind = ClassificationKind.Hazard
      verdict.sub = { tag = "MathAlpha" }
      return verdict
    end
  end

  for _, cp in ipairs(input) do
    if fullwidth_halfwidth(cp) then
      verdict.kind = ClassificationKind.Hazard
      verdict.sub = { tag = "WidthClass" }
      return verdict
    end
  end

  if not arrays_equal(ucd.to_nfc(input), input) then
    verdict.kind = ClassificationKind.Hazard
    verdict.sub = { tag = "DecompositionSwap" }
    return verdict
  end

  if M.has_mixed_script_admissibility(input) then
    verdict.kind = ClassificationKind.Hazard
    verdict.sub = { tag = "CrossScriptMix" }
    return verdict
  end

  if rl == ucd.RestrictionLevel.MINIMALLY_RESTRICTIVE or rl == ucd.RestrictionLevel.UNRESTRICTED then
    verdict.kind = ClassificationKind.Hazard
    verdict.sub = { tag = "RestrictionLow" }
  end
  return verdict
end

return M
