-- UAX #21 case mapping (toLower / toUpper), mirroring `Unicode.Casing`.
--
-- Full case mappings from SpecialCasing.txt (one-to-many and context/locale-
-- dependent rows) combined with the simple case mappings in UnicodeData.txt
-- field 13 (lowercase) / 12 (uppercase).  Context predicates (Final_Sigma,
-- After_Soft_Dotted, More_Above, Not_Before_Dot, After_I) use canonical
-- combining class plus the Cased and Soft_Dotted properties from
-- DerivedCoreProperties.txt.
--
-- Shared primitive: bip39-canonical uses toLower(default); the
-- locale-case-inversion form detector builds on lower_codepoint.

local datapath = require("unicode_lua.datapath")
local ucd = require("unicode_lua.security.identity.ucd")

local ccc = ucd.ccc

local M = {}

-- The locales SpecialCasing.txt distinguishes.  DEFAULT covers everything not
-- tagged Turkish / Azeri / Lithuanian.
local Locale = {
  DEFAULT = "default",
  TURKISH = "turkish",
  AZERI = "azeri",
  LITHUANIAN = "lithuanian",
}
M.Locale = Locale

local LOCALE_CONDITIONS = { tr = true, az = true, lt = true }

-- ─────────────────────────────────────────────────────────────────────
-- Parsing helpers
-- ─────────────────────────────────────────────────────────────────────

local function iter_lines(text)
  return (text .. "\n"):gmatch("([^\n]*)\n")
end

local function trim(s)
  return (s:gsub("^%s*(.-)%s*$", "%1"))
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

local function parse_hex_tokens(s)
  local out = {}
  for tok in s:gmatch("%S+") do
    out[#out + 1] = tonumber(tok, 16)
  end
  return out
end

-- ─────────────────────────────────────────────────────────────────────
-- Data tables
-- ─────────────────────────────────────────────────────────────────────

local _special_rows = nil
local _simple_lower = nil
local _simple_upper = nil
local _cased = nil
local _soft_dotted = nil

local function parse_special_casing()
  local rows = {}
  for raw in iter_lines(datapath.read("SpecialCasing.txt")) do
    local line = trim(split(raw, "#")[1])
    if line ~= "" then
      local fields = split(line, ";")
      if #fields >= 4 then
        local code = tonumber(trim(fields[1]), 16)
        local lower = parse_hex_tokens(fields[2])
        local title = parse_hex_tokens(fields[3])
        local upper = parse_hex_tokens(fields[4])
        local conditions = {}
        if #fields > 4 and trim(fields[5]) ~= "" then
          for tok in trim(fields[5]):gmatch("%S+") do
            conditions[#conditions + 1] = tok
          end
        end
        if rows[code] == nil then
          rows[code] = {}
        end
        local list = rows[code]
        list[#list + 1] = { code = code, lower = lower, title = title, upper = upper, conditions = conditions }
      end
    end
  end
  return rows
end

local function parse_simple_case_mappings()
  local lower = {}
  local upper = {}
  for line in iter_lines(datapath.read("UnicodeData.txt")) do
    if line ~= "" then
      local fields = split(line, ";")
      if #fields >= 15 then
        local cp = tonumber(fields[1], 16)
        if fields[13] ~= "" then
          upper[cp] = tonumber(fields[13], 16)
        end
        if fields[14] ~= "" then
          lower[cp] = tonumber(fields[14], 16)
        end
      end
    end
  end
  return lower, upper
end

local function parse_derived_property(name)
  local out = {}
  for raw in iter_lines(datapath.read("DerivedCoreProperties.txt")) do
    local line = trim(split(raw, "#")[1])
    if line ~= "" then
      local parts = split(line, ";")
      if #parts >= 2 and trim(parts[2]) == name then
        local field = trim(parts[1])
        local dots = field:find("..", 1, true)
        if dots == nil then
          local cp = tonumber(field, 16)
          out[#out + 1] = { cp, cp }
        else
          out[#out + 1] = { tonumber(field:sub(1, dots - 1), 16), tonumber(field:sub(dots + 2), 16) }
        end
      end
    end
  end
  table.sort(out, function(a, b) return a[1] < b[1] end)
  return out
end

local function special_rows()
  if _special_rows == nil then
    _special_rows = parse_special_casing()
  end
  return _special_rows
end

local function simple_maps()
  if _simple_lower == nil then
    _simple_lower, _simple_upper = parse_simple_case_mappings()
  end
  return _simple_lower, _simple_upper
end

local function in_ranges(ranges, cp)
  for _, r in ipairs(ranges) do
    if r[1] <= cp and cp <= r[2] then
      return true
    end
  end
  return false
end

local function is_cased(cp)
  if _cased == nil then
    _cased = parse_derived_property("Cased")
  end
  return in_ranges(_cased, cp)
end

local function is_soft_dotted(cp)
  if _soft_dotted == nil then
    _soft_dotted = parse_derived_property("Soft_Dotted")
  end
  return in_ranges(_soft_dotted, cp)
end

function M.simple_lowercase(cp)
  local lower, _ = simple_maps()
  return lower[cp] or cp
end

function M.simple_uppercase(cp)
  local _, upper = simple_maps()
  return upper[cp] or cp
end

-- ─────────────────────────────────────────────────────────────────────
-- Context predicates (UAX #21).  `rev_prefix` is preceding codepoints
-- nearest-first; `suffix` is the strictly-following ones in order.
-- ─────────────────────────────────────────────────────────────────────

local function more_above_after(suffix)
  for _, cp in ipairs(suffix) do
    local c = ccc(cp)
    if c == 230 then
      return true
    end
    if c == 0 then
      return false
    end
  end
  return false
end

local function after_soft_dotted(rev_prefix)
  for _, cp in ipairs(rev_prefix) do
    if is_soft_dotted(cp) then
      return true
    end
    local c = ccc(cp)
    if c == 0 or c == 230 then
      return false
    end
  end
  return false
end

local function after_i(rev_prefix)
  for _, cp in ipairs(rev_prefix) do
    if cp == 0x0049 then
      return true
    end
    local c = ccc(cp)
    if c == 0 or c == 230 then
      return false
    end
  end
  return false
end

local function before_dot(suffix)
  for _, cp in ipairs(suffix) do
    if cp == 0x0307 then
      return true
    end
    if ccc(cp) == 0 then
      return false
    end
  end
  return false
end

local function has_cased_before(rev_prefix)
  for _, cp in ipairs(rev_prefix) do
    if is_cased(cp) then
      return true
    end
    if ccc(cp) == 0 then
      return false
    end
  end
  return false
end

local function has_cased_after(suffix)
  for _, cp in ipairs(suffix) do
    if is_cased(cp) then
      return true
    end
    if ccc(cp) == 0 then
      return false
    end
  end
  return false
end

local function final_sigma(rev_prefix, suffix)
  return has_cased_before(rev_prefix) and not has_cased_after(suffix)
end

local function has_locale_condition(conds)
  for _, c in ipairs(conds) do
    if LOCALE_CONDITIONS[c] then
      return true
    end
  end
  return false
end

local function locale_matches(loc, conds)
  if not has_locale_condition(conds) then
    return true
  end
  for _, c in ipairs(conds) do
    if (c == "tr" and loc == Locale.TURKISH)
      or (c == "az" and loc == Locale.AZERI)
      or (c == "lt" and loc == Locale.LITHUANIAN) then
      return true
    end
  end
  return false
end

local function conditions_hold(loc, rev_prefix, suffix, conds)
  if not locale_matches(loc, conds) then
    return false
  end
  for _, c in ipairs(conds) do
    if not LOCALE_CONDITIONS[c] then
      local ok
      if c == "Final_Sigma" then
        ok = final_sigma(rev_prefix, suffix)
      elseif c == "Not_Final_Sigma" then
        ok = not final_sigma(rev_prefix, suffix)
      elseif c == "After_Soft_Dotted" then
        ok = after_soft_dotted(rev_prefix)
      elseif c == "More_Above" then
        ok = more_above_after(suffix)
      elseif c == "Not_Before_Dot" then
        ok = not before_dot(suffix)
      elseif c == "After_I" then
        ok = after_i(rev_prefix)
      else
        -- Unrecognised context token — never matches.
        ok = false
      end
      if not ok then
        return false
      end
    end
  end
  return true
end

local function find_special_row(loc, rev_prefix, suffix, cp)
  local candidates = special_rows()[cp]
  if candidates == nil then
    return nil
  end
  -- A conditional row whose conditions hold outranks the unconditional row.
  for _, row in ipairs(candidates) do
    if #row.conditions > 0 and conditions_hold(loc, rev_prefix, suffix, row.conditions) then
      return row
    end
  end
  for _, row in ipairs(candidates) do
    if #row.conditions == 0 then
      return row
    end
  end
  return nil
end

local function copy_list(t)
  local out = {}
  for _, v in ipairs(t) do
    out[#out + 1] = v
  end
  return out
end

function M.lower_codepoint(loc, rev_prefix, suffix, cp)
  local row = find_special_row(loc, rev_prefix, suffix, cp)
  if row ~= nil then
    return copy_list(row.lower)
  end
  return { M.simple_lowercase(cp) }
end

function M.upper_codepoint(loc, rev_prefix, suffix, cp)
  local row = find_special_row(loc, rev_prefix, suffix, cp)
  if row ~= nil then
    return copy_list(row.upper)
  end
  return { M.simple_uppercase(cp) }
end

-- Slice cps[from..#cps] into a new 1-indexed table.
local function suffix_from(cps, from)
  local out = {}
  for i = from, #cps do
    out[#out + 1] = cps[i]
  end
  return out
end

function M.to_lower(loc, cps)
  local out = {}
  local rev_prefix = {}
  for index = 1, #cps do
    local cp = cps[index]
    local suffix = suffix_from(cps, index + 1)
    for _, r in ipairs(M.lower_codepoint(loc, rev_prefix, suffix, cp)) do
      out[#out + 1] = r
    end
    table.insert(rev_prefix, 1, cp)
  end
  return out
end

function M.to_upper(loc, cps)
  local out = {}
  local rev_prefix = {}
  for index = 1, #cps do
    local cp = cps[index]
    local suffix = suffix_from(cps, index + 1)
    for _, r in ipairs(M.upper_codepoint(loc, rev_prefix, suffix, cp)) do
      out[#out + 1] = r
    end
    table.insert(rev_prefix, 1, cp)
  end
  return out
end

return M
