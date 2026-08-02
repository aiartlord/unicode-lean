-- CaseExpansionMismatch — codepoints whose UAX #21 default-locale case mapping
-- changes the codepoint count (form-layer detector).
--
-- Byte-faithful transliteration of the verified CaseExpansionMismatch reference.
--
-- Threat model.  An attacker submits text whose case-mapped form has a different
-- codepoint count than the input.  A receiver that fixes a username column and
-- stores toUpper(username) overflows on "ßßßß" (each ß → "SS"); one that checks
-- len(stored) == len(input) rejects valid case-insensitive logins whose names
-- expand under folding.  Examples: U+00DF ß → "SS", U+FB01 ﬁ → "FI",
-- U+0130 İ → toLower "i̇" (i + U+0307).
--
-- Distinct from LocaleCaseInversion (mapping that changes ACROSS locales): this
-- fires on shapes whose mapping is locale-stable but length-changing under the
-- default locale itself.  It reuses the port's own UAX #21 case mapping
-- (upper_codepoint / lower_codepoint, which evaluate the SpecialCasing context
-- predicates), never a host casing library.
--
-- Sub-threats (priority order):
--   1. UpperExpansion — first position whose default upper_codepoint yields > 1 cp.
--   2. LowerExpansion — first position whose default lower_codepoint yields > 1 cp
--      (reached only when no upper expansion fires first).

local casing = require("unicode_lua.security.casing")

local M = {}

local Default = casing.Locale.DEFAULT

-- ─────────────────────────────────────────────────────────────────────
-- §2 Per-position expansion scan
-- ─────────────────────────────────────────────────────────────────────

-- Preceding codepoints input[1..i-1], nearest-first (the reversed prefix).
local function rev_prefix_of(input, i)
  local out = {}
  for j = i - 1, 1, -1 do
    out[#out + 1] = input[j]
  end
  return out
end

-- Strictly-following codepoints input[i+1..#input], in order.
local function suffix_of(input, i)
  local out = {}
  for j = i + 1, #input do
    out[#out + 1] = input[j]
  end
  return out
end

-- The default-locale uppercase expansion length at 1-based position i,
-- evaluating the SpecialCasing context.
local function upper_len_at(input, i)
  return #casing.upper_codepoint(Default, rev_prefix_of(input, i), suffix_of(input, i), input[i])
end

-- The default-locale lowercase expansion length at 1-based position i.
local function lower_len_at(input, i)
  return #casing.lower_codepoint(Default, rev_prefix_of(input, i), suffix_of(input, i), input[i])
end

-- First position whose default uppercase mapping expands to > 1 codepoint.
-- Returns 0-based base_pos, cp, expansion_len; or nil when none.
local function first_upper_expansion(input)
  for i = 1, #input do
    local len = upper_len_at(input, i)
    if len > 1 then
      return i - 1, input[i], len
    end
  end
  return nil
end

-- First position whose default lowercase mapping expands to > 1 codepoint.
local function first_lower_expansion(input)
  for i = 1, #input do
    local len = lower_len_at(input, i)
    if len > 1 then
      return i - 1, input[i], len
    end
  end
  return nil
end

local function upper_expansion_count(input)
  local n = 0
  for i = 1, #input do
    if upper_len_at(input, i) > 1 then
      n = n + 1
    end
  end
  return n
end

local function lower_expansion_count(input)
  local n = 0
  for i = 1, #input do
    if lower_len_at(input, i) > 1 then
      n = n + 1
    end
  end
  return n
end

-- Maximum case-mapped expansion length across all positions (upper or lower);
-- 0 for empty input.
local function max_expansion_len(input)
  local m = 0
  for i = 1, #input do
    local u = upper_len_at(input, i)
    local l = lower_len_at(input, i)
    local hi = u
    if l > hi then
      hi = l
    end
    if hi > m then
      m = hi
    end
  end
  return m
end

-- ─────────────────────────────────────────────────────────────────────
-- §1 Sub-threat / classification tags (explicit dispatch, no catch-all)
-- ─────────────────────────────────────────────────────────────────────

-- Fixture-row tag string for a sub-threat.
local function sub_tag(sub)
  if sub.kind == "UpperExpansion" then
    return "UpperExpansion"
  elseif sub.kind == "LowerExpansion" then
    return "LowerExpansion"
  else
    error("case_expansion_mismatch: unreachable sub-threat kind " .. tostring(sub.kind))
  end
end

-- True iff the classification is Clear.
function M.is_clear(verdict)
  local c = verdict.classify
  if c.kind == "clear" then
    return true
  elseif c.kind == "hazard" then
    return false
  else
    error("case_expansion_mismatch: unreachable classification kind " .. tostring(c.kind))
  end
end

-- Human-facing tag for a hazard, or nil when clear.
function M.classification_tag(verdict)
  local c = verdict.classify
  if c.kind == "clear" then
    return nil
  elseif c.kind == "hazard" then
    return sub_tag(c.sub)
  else
    error("case_expansion_mismatch: unreachable classification kind " .. tostring(c.kind))
  end
end

-- Implicated positions (empty when clear).
function M.positions(verdict)
  local c = verdict.classify
  if c.kind == "clear" then
    return {}
  elseif c.kind == "hazard" then
    return c.positions
  else
    error("case_expansion_mismatch: unreachable classification kind " .. tostring(c.kind))
  end
end

-- ─────────────────────────────────────────────────────────────────────
-- §3 Top-level detection
-- ─────────────────────────────────────────────────────────────────────

local function copy_list(t)
  local out = {}
  for _, v in ipairs(t) do
    out[#out + 1] = v
  end
  return out
end

function M.detect(input)
  local classify
  local up_pos, up_cp, up_len = first_upper_expansion(input)
  if up_pos ~= nil then
    -- Priority 1: an uppercase expansion.
    classify = {
      kind = "hazard",
      sub = { kind = "UpperExpansion", base_pos = up_pos, cp = up_cp, expansion_len = up_len },
      positions = { up_pos },
      decoded = {},
    }
  else
    local lo_pos, lo_cp, lo_len = first_lower_expansion(input)
    if lo_pos ~= nil then
      -- Priority 2: a lowercase expansion.
      classify = {
        kind = "hazard",
        sub = { kind = "LowerExpansion", base_pos = lo_pos, cp = lo_cp, expansion_len = lo_len },
        positions = { lo_pos },
        decoded = {},
      }
    else
      classify = { kind = "clear" }
    end
  end

  return {
    input = copy_list(input),
    classify = classify,
    upper_expansion_count = upper_expansion_count(input),
    lower_expansion_count = lower_expansion_count(input),
    max_expansion_len = max_expansion_len(input),
  }
end

return M
