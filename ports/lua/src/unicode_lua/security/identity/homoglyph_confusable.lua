local datapath = require("unicode_lua.datapath")
local calculus = require("unicode_lua.security.calculus")
local ucd = require("unicode_lua.security.identity.ucd")
local utf8mod = require("unicode_lua.utf8")

-- LuaJIT is Lua 5.1: the 5.3 `utf8` stdlib is absent, so decode data-file
-- lines to codepoints with the port's own UTF-8 decoder.
local function line_codepoints(line)
  local bytes = {}
  for i = 1, #line do
    bytes[i] = line:byte(i)
  end
  return utf8mod.decode_to_codepoints(bytes)
end

local unpack = table.unpack or unpack
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
  local current = { unpack(input) }
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
      local cps = line_codepoints(line)
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
  return M.mixed_script_verdict(input, true) ~= nil
end

function M.mixed_script_subthreat(input)
  return M.mixed_script_verdict(input, true) or "ScriptMixOther"
end

-- The mixed-script sub-threat for input, or nil when admissible.
--
-- The rung order is MixedScriptAdmissibility.lean's: a Restricted-status
-- codepoint outranks every script question, then the two named Latin pairs,
-- then a multi-script mix split by whether it stays inside a CJK covered set,
-- and finally an Unrestricted level with no script mix.
--
-- identifier_field carries what the caller knows about the field, mirroring
-- that module's Context. Phase 1 is sound for an identifier, which cannot
-- contain a space, and unsound for a document, where every space and every
-- punctuation mark is Restricted.
function M.mixed_script_verdict(input, identifier_field)
  if identifier_field then
    for _, cp in ipairs(input) do
      if not ucd.is_id_allowed(cp) then
        return "RestrictedStatusCp"
      end
    end
  end
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
  if #union >= 2 and not ucd.is_highly_restrictive(input) then
    if ucd.is_covered_cjk(input) then
      return "CjkMix"
    end
    return "ScriptMixOther"
  end
  if identifier_field and ucd.restriction_level(input) == ucd.RestrictionLevel.UNRESTRICTED then
    return "UnrestrictedLevel"
  end
  return nil
end

-- The case-preserving skeleton: NFD, confusable substitution, NFD, with no case
-- fold, so admın (dotless i) maps to adrnin while ADMIN stays itself. Mirrors
-- the Lean asciiSkeleton.
function M.ascii_skeleton(input)
  return ucd.to_nfd(substitute(ucd.to_nfd(input)))
end

-- A non-ASCII input whose case-preserving skeleton is all ASCII. Mirrors the
-- Lean isAsciiConfusable.
function M.is_ascii_confusable(input)
  local any_non_ascii = false
  for _, cp in ipairs(input) do
    if cp > 0x7F then
      any_non_ascii = true
    end
  end
  if not any_non_ascii then
    return false
  end
  for _, cp in ipairs(M.ascii_skeleton(input)) do
    if cp > 0x7F then
      return false
    end
  end
  return true
end

-- 0-based positions of the non-ASCII codepoints. Mirrors the Lean
-- nonAsciiPositions.
function M.non_ascii_positions(input)
  local out = {}
  for i = 1, #input do
    if input[i] > 0x7F then
      out[#out + 1] = i - 1
    end
  end
  return out
end

-- Every script-bearing codepoint of the input is Latin. Mirrors the Lean
-- isLatinOnly.
function M.is_latin_only(input)
  local union = ucd.string_script_union(input)
  return #union == 1 and union[1] == "Latn"
end

-- The detection function at the default context (one identifier field).
-- Mirrors the Lean detect.
local function first_position(input, pred)
  for i = 1, #input do
    if pred(input[i]) then
      return { i - 1 }
    end
  end
  return {}
end

-- The first position at which the input and its NFC form differ, or the
-- shorter length when one is a prefix of the other. Mirrors the Lean
-- firstDecompositionDiffPos.
function M.first_decomposition_diff_pos(input)
  local nfc = ucd.to_nfc(input)
  local shorter = math.min(#input, #nfc)
  for i = 1, shorter do
    if input[i] ~= nfc[i] then
      return i - 1
    end
  end
  return shorter
end

-- The positions a homoglyph rung implicates: nothing for the whole-input
-- rungs (TargetMatch, CrossScriptMix, RestrictionLow), the first
-- math-alphanumeric or fullwidth/halfwidth codepoint, the first NFC
-- divergence, and the non-ASCII codepoints for the ascii-confusable rung.
-- Mirrors the Lean homoglyphPositions.
function M.homoglyph_positions(tag, input)
  if tag == "MathAlpha" then
    return first_position(input, math_alphanumeric)
  elseif tag == "WidthClass" then
    return first_position(input, fullwidth_halfwidth)
  elseif tag == "DecompositionSwap" then
    return { M.first_decomposition_diff_pos(input) }
  elseif tag == "AsciiConfusable" then
    return M.non_ascii_positions(input)
  end
  return {}
end

-- The positions whose resolved scripts contain `script`, with Common and
-- Inherited codepoints skipped as UTS #39 §5.1 skips them from the
-- intersection. Mirrors the Lean positionsForScript.
local function positions_for_script(input, script)
  local positions = {}
  for i = 1, #input do
    local cp = input[i]
    if not ucd.is_ignored_for_intersection(cp) then
      for _, s in ipairs(ucd.resolve_scripts(cp)) do
        if s == script then
          positions[#positions + 1] = i - 1
          break
        end
      end
    end
  end
  return positions
end

-- The positions a mixed-script verdict implicates: the restricted codepoints
-- for RestrictedStatusCp, the Cyrillic or Greek codepoints for the two
-- Latin-mix verdicts, nothing for the whole-input verdicts. Mirrors the Lean
-- mixedScriptPositions.
function M.mixed_script_positions(sub, input)
  if sub == "RestrictedStatusCp" then
    local positions = {}
    for i = 1, #input do
      if not ucd.is_id_allowed(input[i]) then
        positions[#positions + 1] = i - 1
      end
    end
    return positions
  elseif sub == "LatinCyrillic" then
    return positions_for_script(input, "Cyrl")
  elseif sub == "LatinGreek" then
    return positions_for_script(input, "Grek")
  end
  return {}
end

function M.detect(input)
  return M.detect_with_context(input, { running_text = false, identifier_token = false })
end

-- The detection function under a field context `ctx` (`running_text`: a source
-- line, a message or a display name rather than one identifier;
-- `identifier_token`: one identifier-shaped token cut out of running text).
-- Rungs in the Lean order: target match, math alphanumerics, width class,
-- decomposition swap, then the two script rungs (cross-script mix, off on
-- running text; low restriction level, off on running text and on a token),
-- then the ascii-confusable rung: a non-ASCII input whose case-preserving
-- skeleton is all ASCII reads as an ASCII word it is not (admın with a dotless
-- i). That rung runs on a whole field, and on a token only when the token is
-- Latin-only, so a Greek or Cyrillic word in prose is not read as its Latin
-- look-alike.
function M.detect_with_context(input, ctx)
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

  -- Priority 5: CrossScriptMix, off on running text. This rung asks the script
  -- question only; the Restricted-status rung belongs to the mixed-script
  -- family, not here.
  local union = ucd.string_script_union(input)
  if not ctx.running_text and #union >= 2 and not ucd.is_highly_restrictive(input) then
    verdict.kind = ClassificationKind.Hazard
    verdict.sub = { tag = "CrossScriptMix" }
    return verdict
  end

  -- Priority 6: RestrictionLow, off on running text and on a token.
  if not ctx.running_text and not ctx.identifier_token
    and (rl == ucd.RestrictionLevel.MINIMALLY_RESTRICTIVE or rl == ucd.RestrictionLevel.UNRESTRICTED) then
    verdict.kind = ClassificationKind.Hazard
    verdict.sub = { tag = "RestrictionLow" }
    return verdict
  end

  -- Priority 7: AsciiConfusable, on a whole field, and on a token only when the
  -- token is Latin-only.
  if not ctx.running_text
    and (not ctx.identifier_token or M.is_latin_only(input))
    and M.is_ascii_confusable(input) then
    verdict.kind = ClassificationKind.Hazard
    verdict.sub = { tag = "AsciiConfusable", skeleton = M.ascii_skeleton(input) }
  end
  return verdict
end

return M
