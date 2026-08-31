-- UCD-table-backed support module for the identity-spoofing detector family —
-- NFC/NFD/NFKC/NFKD normalization, default full case folding, script lookup,
-- UTS #39 identifier-status / restriction-level classification.
--
-- All data is loaded once, lazily, from the bundled UCD files under
-- `ports/lua/data/`.  No catchall fallback: parser failures raise, and the
-- spec's `@missing` defaults (CCC = 0 for unlisted codepoints, etc.) are
-- written as explicit branches rather than silent `.get(..., default)`.
--
-- Codepoint sequences are 1-indexed Lua tables of integers.

local datapath = require("unicode_lua.datapath")

local M = {}

-- ─────────────────────────────────────────────────────────────────────
-- Parsing helpers
-- ─────────────────────────────────────────────────────────────────────

local function iter_lines(text)
  return (text .. "\n"):gmatch("([^\n]*)\n")
end

local function trim(s)
  return (s:gsub("^%s*(.-)%s*$", "%1"))
end

local function strip_comment_and_trim(line)
  local hash = line:find("#", 1, true)
  local body = line
  if hash ~= nil then
    body = line:sub(1, hash - 1)
  end
  return trim(body)
end

local function parse_hex(s)
  local v = tonumber(trim(s), 16)
  if v == nil then
    error("parse_hex: not a hex integer: " .. tostring(s))
  end
  return v
end

local function parse_range_field(s)
  s = trim(s)
  local dots = s:find("..", 1, true)
  if dots == nil then
    local cp = parse_hex(s)
    return cp, cp
  end
  return parse_hex(s:sub(1, dots - 1)), parse_hex(s:sub(dots + 2))
end

-- Split preserving empty fields (including trailing ones).
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

local function split_ws(s)
  local out = {}
  for tok in s:gmatch("%S+") do
    out[#out + 1] = tok
  end
  return out
end

-- partition_point: number of leading array entries whose key <= target.
local function partition_point(items, key, target)
  local lo, hi = 1, #items + 1
  while lo < hi do
    local mid = math.floor((lo + hi) / 2)
    if key(items[mid]) <= target then
      lo = mid + 1
    else
      hi = mid
    end
  end
  return lo - 1
end

-- ─────────────────────────────────────────────────────────────────────
-- UnicodeData.txt — CCC + canonical / compatibility decomposition
-- ─────────────────────────────────────────────────────────────────────

local _ucd_table = nil

local function parse_unicode_data()
  local text = datapath.read("UnicodeData.txt")
  local out = {}
  for line in iter_lines(text) do
    if line ~= "" and line:sub(1, 1) ~= "#" then
      local fields = split(line, ";")
      if #fields >= 6 then
        local cp = parse_hex(fields[1])
        local ccc_field = trim(fields[4])
        local ccc = tonumber(ccc_field, 10)
        if ccc == nil then
          error("UnicodeData.txt: CCC field " .. ccc_field .. " for U+" ..
            string.format("%04X", cp) .. " is not an integer")
        end
        local decomp_field = trim(fields[6])
        local canonical_decomp = nil
        local compat_decomp = nil
        if decomp_field ~= "" then
          if decomp_field:sub(1, 1) == "<" then
            local gt = decomp_field:find(">", 1, true)
            local after_tag = decomp_field
            if gt ~= nil then
              after_tag = decomp_field:sub(gt + 1)
            end
            local parts = {}
            for _, tok in ipairs(split_ws(after_tag)) do
              parts[#parts + 1] = parse_hex(tok)
            end
            if #parts > 0 then
              compat_decomp = parts
            end
          else
            local parts = {}
            for _, tok in ipairs(split_ws(decomp_field)) do
              parts[#parts + 1] = parse_hex(tok)
            end
            if #parts > 0 then
              canonical_decomp = parts
            end
          end
        end
        out[cp] = { ccc = ccc, canonical_decomp = canonical_decomp, compat_decomp = compat_decomp }
      end
    end
  end
  return out
end

local function ucd_table()
  if _ucd_table == nil then
    _ucd_table = parse_unicode_data()
  end
  return _ucd_table
end

-- Canonical Combining Class of `cp` (UAX #44 §5.7.4 @missing default 0).
function M.ccc(cp)
  local entry = ucd_table()[cp]
  if entry == nil then
    return 0
  end
  return entry.ccc
end

-- ─────────────────────────────────────────────────────────────────────
-- DerivedBidiClass.txt — strong Bidi_Class lookup (R / AL / L / Other)
-- ─────────────────────────────────────────────────────────────────────

local BidiStrong = { R = "R", AL = "AL", L = "L", OTHER = "Other" }
M.BidiStrong = BidiStrong

local _bidi_table = nil

local function strong_of_short(token)
  if token == "R" then return BidiStrong.R end
  if token == "AL" then return BidiStrong.AL end
  if token == "L" then return BidiStrong.L end
  return BidiStrong.OTHER
end

local function strong_of_long(token)
  if token == "Right_To_Left" then return BidiStrong.R end
  if token == "Arabic_Letter" then return BidiStrong.AL end
  if token == "Left_To_Right" then return BidiStrong.L end
  return BidiStrong.OTHER
end

local function parse_derived_bidi()
  local text = datapath.read("DerivedBidiClass.txt")
  local explicit = {}
  local defaults = {}
  local missing_prefix = "# @missing:"
  for line in iter_lines(text) do
    if line:sub(1, #missing_prefix) == missing_prefix then
      local rest = line:sub(#missing_prefix + 1)
      local semi = rest:find(";", 1, true)
      if semi ~= nil then
        local lo, hi = parse_range_field(rest:sub(1, semi - 1))
        defaults[#defaults + 1] = { lo, hi, strong_of_long(trim(rest:sub(semi + 1))) }
      end
    else
      local body = strip_comment_and_trim(line)
      if body ~= "" then
        local semi = body:find(";", 1, true)
        if semi ~= nil then
          local lo, hi = parse_range_field(body:sub(1, semi - 1))
          explicit[#explicit + 1] = { lo, hi, strong_of_short(trim(body:sub(semi + 1))) }
        end
      end
    end
  end
  table.sort(explicit, function(a, b) return a[1] < b[1] end)
  return { explicit = explicit, defaults = defaults }
end

-- ── EastAsianWidth.txt — UAX #11 East_Asian_Width ─────────────────────────

local EastAsianWidth = { A = "a", F = "f", H = "h", N = "n", NA = "na", W = "w" }
M.EastAsianWidth = EastAsianWidth

local function eaw_of_token(token)
  if token == "A" then return EastAsianWidth.A end
  if token == "F" then return EastAsianWidth.F end
  if token == "H" then return EastAsianWidth.H end
  if token == "Na" then return EastAsianWidth.NA end
  if token == "W" then return EastAsianWidth.W end
  return EastAsianWidth.N
end

local _eaw_table = nil

local function parse_east_asian_width()
  local text = datapath.read("EastAsianWidth.txt")
  local rows = {}
  for line in iter_lines(text) do
    local body = strip_comment_and_trim(line)
    if body ~= "" then
      local semi = body:find(";", 1, true)
      if semi ~= nil then
        local lo, hi = parse_range_field(body:sub(1, semi - 1))
        rows[#rows + 1] = { lo, hi, eaw_of_token(trim(body:sub(semi + 1))) }
      end
    end
  end
  table.sort(rows, function(a, b) return a[1] < b[1] end)
  return rows
end

-- East_Asian_Width for one codepoint. The file's @missing line declares N over
-- the whole space, so an unlisted codepoint is Neutral.
function M.east_asian_width(cp)
  if _eaw_table == nil then
    _eaw_table = parse_east_asian_width()
  end
  local lo, hi = 1, #_eaw_table + 1
  while lo < hi do
    local mid = math.floor((lo + hi) / 2)
    local row = _eaw_table[mid]
    if cp < row[1] then
      hi = mid
    elseif cp > row[2] then
      lo = mid + 1
    else
      return row[3]
    end
  end
  return EastAsianWidth.N
end

-- ── DerivedJoiningType.txt — RFC 5892 Appendix A.1 support ────────────────

-- Joining_Type, the cursive-joining behaviour a character has in scripts like
-- Arabic. RFC 5892 Appendix A.1 uses it to decide whether a ZERO WIDTH
-- NON-JOINER sits in a position its script actually requires.
local JoiningType = {
  JOIN_CAUSING = "c",
  DUAL_JOINING = "d",
  LEFT_JOINING = "l",
  RIGHT_JOINING = "r",
  TRANSPARENT = "t",
  NON_JOINING = "u",
}
M.JoiningType = JoiningType

local function joining_type_of_token(token)
  if token == "C" then return JoiningType.JOIN_CAUSING end
  if token == "D" then return JoiningType.DUAL_JOINING end
  if token == "L" then return JoiningType.LEFT_JOINING end
  if token == "R" then return JoiningType.RIGHT_JOINING end
  if token == "T" then return JoiningType.TRANSPARENT end
  return JoiningType.NON_JOINING
end

local _joining_type_table = nil

local function parse_joining_types()
  local text = datapath.read("DerivedJoiningType.txt")
  local rows = {}
  for line in iter_lines(text) do
    local body = strip_comment_and_trim(line)
    if body ~= "" then
      local semi = body:find(";", 1, true)
      if semi ~= nil then
        local lo, hi = parse_range_field(body:sub(1, semi - 1))
        rows[#rows + 1] = { lo, hi, joining_type_of_token(trim(body:sub(semi + 1))) }
      end
    end
  end
  table.sort(rows, function(a, b) return a[1] < b[1] end)
  return rows
end

-- Joining_Type for one codepoint. The file's @missing line declares Non_Joining
-- over the whole space, so an unlisted codepoint is Non_Joining.
function M.joining_type(cp)
  if _joining_type_table == nil then
    _joining_type_table = parse_joining_types()
  end
  local lo, hi = 1, #_joining_type_table + 1
  while lo < hi do
    local mid = math.floor((lo + hi) / 2)
    local row = _joining_type_table[mid]
    if cp < row[1] then
      hi = mid
    elseif cp > row[2] then
      lo = mid + 1
    else
      return row[3]
    end
  end
  return JoiningType.NON_JOINING
end

-- True iff cp has Canonical_Combining_Class 9, the Virama used to request an
-- explicit conjunct in scripts like Devanagari.
function M.is_virama(cp)
  return M.ccc(cp) == 9
end

local function bidi_table()
  if _bidi_table == nil then
    _bidi_table = parse_derived_bidi()
  end
  return _bidi_table
end

-- Full Bidi_Class lookup (strong distinction): explicit range, then the last
-- matching @missing default, else L.
function M.bidi_strong(cp)
  local t = bidi_table()
  local ex = t.explicit
  local lo, hi = 1, #ex + 1
  while lo < hi do
    local mid = math.floor((lo + hi) / 2)
    local row = ex[mid]
    if cp < row[1] then
      hi = mid
    elseif cp > row[2] then
      lo = mid + 1
    else
      return row[3]
    end
  end
  local result = BidiStrong.L
  for _, row in ipairs(t.defaults) do
    if row[1] <= cp and cp <= row[2] then
      result = row[3]
    end
  end
  return result
end

function M.is_strong_rtl(cp)
  local s = M.bidi_strong(cp)
  return s == BidiStrong.R or s == BidiStrong.AL
end

function M.is_strong_ltr(cp)
  return M.bidi_strong(cp) == BidiStrong.L
end

-- ─────────────────────────────────────────────────────────────────────
-- CompositionExclusions.txt + composition table
-- ─────────────────────────────────────────────────────────────────────

local _exclusions = nil

local function parse_composition_exclusions()
  local text = datapath.read("CompositionExclusions.txt")
  local out = {}
  for line in iter_lines(text) do
    local stripped = strip_comment_and_trim(line)
    if stripped ~= "" then
      out[parse_hex(stripped)] = true
    end
  end
  return out
end

local function composition_exclusions()
  if _exclusions == nil then
    _exclusions = parse_composition_exclusions()
  end
  return _exclusions
end

local _comp_table = nil

local function comp_key(a, b)
  return a * 0x110000 + b
end

local function build_composition_table()
  local table_ = ucd_table()
  local exclusions = composition_exclusions()
  local out = {}
  for cp, entry in pairs(table_) do
    local decomp = entry.canonical_decomp
    if decomp ~= nil and #decomp == 2 and not exclusions[cp] then
      local a, b = decomp[1], decomp[2]
      if M.ccc(a) == 0 then
        out[comp_key(a, b)] = cp
      end
    end
  end
  return out
end

local function composition_table()
  if _comp_table == nil then
    _comp_table = build_composition_table()
  end
  return _comp_table
end

-- ─────────────────────────────────────────────────────────────────────
-- Hangul algorithmic decomposition + composition (UAX #15 §1.3)
-- ─────────────────────────────────────────────────────────────────────

local HANGUL_S_BASE = 0xAC00
local HANGUL_L_BASE = 0x1100
local HANGUL_V_BASE = 0x1161
local HANGUL_T_BASE = 0x11A7
local HANGUL_L_COUNT = 19
local HANGUL_V_COUNT = 21
local HANGUL_T_COUNT = 28
local HANGUL_N_COUNT = HANGUL_V_COUNT * HANGUL_T_COUNT
local HANGUL_S_COUNT = HANGUL_L_COUNT * HANGUL_N_COUNT

local function hangul_decompose(cp, out)
  if not (cp >= HANGUL_S_BASE and cp < HANGUL_S_BASE + HANGUL_S_COUNT) then
    return false
  end
  local s_index = cp - HANGUL_S_BASE
  local l = HANGUL_L_BASE + math.floor(s_index / HANGUL_N_COUNT)
  local v = HANGUL_V_BASE + math.floor((s_index % HANGUL_N_COUNT) / HANGUL_T_COUNT)
  local t_index = s_index % HANGUL_T_COUNT
  out[#out + 1] = l
  out[#out + 1] = v
  if t_index ~= 0 then
    out[#out + 1] = HANGUL_T_BASE + t_index
  end
  return true
end

local function hangul_compose(a, b)
  if HANGUL_L_BASE <= a and a < HANGUL_L_BASE + HANGUL_L_COUNT
      and HANGUL_V_BASE <= b and b < HANGUL_V_BASE + HANGUL_V_COUNT then
    local l_index = a - HANGUL_L_BASE
    local v_index = b - HANGUL_V_BASE
    return HANGUL_S_BASE + (l_index * HANGUL_V_COUNT + v_index) * HANGUL_T_COUNT
  end
  if HANGUL_S_BASE <= a and a < HANGUL_S_BASE + HANGUL_S_COUNT
      and (a - HANGUL_S_BASE) % HANGUL_T_COUNT == 0
      and HANGUL_T_BASE + 1 <= b and b < HANGUL_T_BASE + HANGUL_T_COUNT then
    return a + (b - HANGUL_T_BASE)
  end
  return nil
end

-- ─────────────────────────────────────────────────────────────────────
-- NFC / NFD pipeline
-- ─────────────────────────────────────────────────────────────────────

local function decompose_one(cp, out)
  if hangul_decompose(cp, out) then
    return
  end
  local entry = ucd_table()[cp]
  if entry ~= nil and entry.canonical_decomp ~= nil then
    for _, child in ipairs(entry.canonical_decomp) do
      decompose_one(child, out)
    end
    return
  end
  out[#out + 1] = cp
end

local function canonical_decompose(input_cps)
  local out = {}
  for _, cp in ipairs(input_cps) do
    decompose_one(cp, out)
  end
  return out
end

-- Stable-sort each non-starter run (CCC != 0) by CCC, in place (insertion sort).
local function canonical_reorder(seq)
  local n = #seq
  local i = 1
  while i <= n do
    if M.ccc(seq[i]) == 0 then
      i = i + 1
    else
      local j = i
      while j <= n and M.ccc(seq[j]) ~= 0 do
        j = j + 1
      end
      -- Stable insertion sort of seq[i..j-1] by CCC.
      for k = i + 1, j - 1 do
        local val = seq[k]
        local val_ccc = M.ccc(val)
        local m = k - 1
        while m >= i and M.ccc(seq[m]) > val_ccc do
          seq[m + 1] = seq[m]
          m = m - 1
        end
        seq[m + 1] = val
      end
      i = j
    end
  end
end

local function canonical_compose(seq)
  if #seq == 0 then
    return {}
  end
  local comp = composition_table()
  local out = {}
  local starter_idx = nil
  local last_ccc = -1
  for _, cp in ipairs(seq) do
    local cp_ccc = M.ccc(cp)
    local handled = false
    if starter_idx ~= nil then
      local starter = out[starter_idx]
      local composed = hangul_compose(starter, cp)
      if composed == nil then
        composed = comp[comp_key(starter, cp)]
      end
      local blocked = last_ccc ~= 0 and (cp_ccc == 0 or last_ccc >= cp_ccc)
      if not blocked and composed ~= nil then
        out[starter_idx] = composed
        handled = true
      end
    end
    if not handled then
      out[#out + 1] = cp
      if cp_ccc == 0 then
        starter_idx = #out
        last_ccc = 0
      else
        last_ccc = cp_ccc
      end
    end
  end
  return out
end

function M.to_nfc(input_cps)
  local decomposed = canonical_decompose(input_cps)
  canonical_reorder(decomposed)
  return canonical_compose(decomposed)
end

function M.to_nfd(input_cps)
  local decomposed = canonical_decompose(input_cps)
  canonical_reorder(decomposed)
  return decomposed
end

-- ─────────────────────────────────────────────────────────────────────
-- Full compatibility decomposition (NFKD / NFKC)
-- ─────────────────────────────────────────────────────────────────────

local function compat_decompose_one(cp, out)
  if hangul_decompose(cp, out) then
    return
  end
  local entry = ucd_table()[cp]
  if entry ~= nil then
    if entry.compat_decomp ~= nil then
      for _, child in ipairs(entry.compat_decomp) do
        compat_decompose_one(child, out)
      end
      return
    end
    if entry.canonical_decomp ~= nil then
      for _, child in ipairs(entry.canonical_decomp) do
        compat_decompose_one(child, out)
      end
      return
    end
  end
  out[#out + 1] = cp
end

local function compat_decompose(input_cps)
  local out = {}
  for _, cp in ipairs(input_cps) do
    compat_decompose_one(cp, out)
  end
  return out
end

function M.to_nfkd(input_cps)
  local decomposed = compat_decompose(input_cps)
  canonical_reorder(decomposed)
  return decomposed
end

function M.to_nfkc(input_cps)
  return canonical_compose(M.to_nfkd(input_cps))
end

-- ─────────────────────────────────────────────────────────────────────
-- CaseFolding.txt — default full case folding (RFC 8265 §5.2.4)
-- ─────────────────────────────────────────────────────────────────────

local _case_folding = nil

local function parse_case_folding()
  local text = datapath.read("CaseFolding.txt")
  local out = {}
  for line in iter_lines(text) do
    local stripped = strip_comment_and_trim(line)
    if stripped ~= "" then
      local parts = split(stripped, ";")
      if #parts >= 3 then
        local status = trim(parts[2])
        if status == "C" or status == "F" then
          local src = parse_hex(parts[1])
          local tgt = {}
          for _, tok in ipairs(split_ws(parts[3])) do
            tgt[#tgt + 1] = parse_hex(tok)
          end
          if #tgt > 0 then
            out[src] = tgt
          end
        end
      end
    end
  end
  return out
end

local function case_folding_table()
  if _case_folding == nil then
    _case_folding = parse_case_folding()
  end
  return _case_folding
end

-- Default full case folding (status C ∪ F).  Absent codepoints fold to self.
function M.case_fold(input_cps)
  local t = case_folding_table()
  local out = {}
  for _, cp in ipairs(input_cps) do
    local replacement = t[cp]
    if replacement == nil then
      out[#out + 1] = cp
    else
      for _, r in ipairs(replacement) do
        out[#out + 1] = r
      end
    end
  end
  return out
end

-- ─────────────────────────────────────────────────────────────────────
-- PropertyValueAliases.txt — Script long-name → 4-letter abbrev
-- ─────────────────────────────────────────────────────────────────────

local _script_name_to_abbrev = nil

local function parse_script_name_to_abbrev()
  local text = datapath.read("PropertyValueAliases.txt")
  local out = {}
  for line in iter_lines(text) do
    local stripped = strip_comment_and_trim(line)
    if stripped ~= "" then
      local parts = split(stripped, ";")
      if #parts >= 3 and trim(parts[1]) == "sc" then
        out[trim(parts[3])] = trim(parts[2])
      end
    end
  end
  return out
end

local function script_name_to_abbrev()
  if _script_name_to_abbrev == nil then
    _script_name_to_abbrev = parse_script_name_to_abbrev()
  end
  return _script_name_to_abbrev
end

local function script_long_to_abbrev(name)
  local t = script_name_to_abbrev()
  local v = t[name]
  if v == nil then
    error("script_long_to_abbrev: " .. name .. " not in PropertyValueAliases.txt")
  end
  return v
end

-- ─────────────────────────────────────────────────────────────────────
-- Scripts.txt — codepoint → primary script (long name)
-- ─────────────────────────────────────────────────────────────────────

local _scripts_table = nil

local function parse_scripts()
  local text = datapath.read("Scripts.txt")
  local out = {}
  for line in iter_lines(text) do
    local stripped = strip_comment_and_trim(line)
    if stripped ~= "" then
      local semi = stripped:find(";", 1, true)
      if semi ~= nil then
        local start, endcp = parse_range_field(stripped:sub(1, semi - 1))
        local value = trim(stripped:sub(semi + 1))
        out[#out + 1] = { start = start, endcp = endcp, value = value }
      end
    end
  end
  table.sort(out, function(a, b) return a.start < b.start end)
  return out
end

local function scripts_table()
  if _scripts_table == nil then
    _scripts_table = parse_scripts()
  end
  return _scripts_table
end

function M.script_of(cp)
  local t = scripts_table()
  local idx = partition_point(t, function(r) return r.start end, cp)
  if idx > 0 then
    local entry = t[idx]
    if cp <= entry.endcp then
      return entry.value
    end
  end
  return "Unknown"
end

-- ─────────────────────────────────────────────────────────────────────
-- ScriptExtensions.txt — codepoint → multi-script abbrev list
-- ─────────────────────────────────────────────────────────────────────

local _script_ext_table = nil

local function parse_script_extensions()
  local text = datapath.read("ScriptExtensions.txt")
  local out = {}
  for line in iter_lines(text) do
    local stripped = strip_comment_and_trim(line)
    if stripped ~= "" then
      local semi = stripped:find(";", 1, true)
      if semi ~= nil then
        local start, endcp = parse_range_field(stripped:sub(1, semi - 1))
        local scripts = split_ws(trim(stripped:sub(semi + 1)))
        if #scripts > 0 then
          out[#out + 1] = { start = start, endcp = endcp, value = scripts }
        end
      end
    end
  end
  table.sort(out, function(a, b) return a.start < b.start end)
  return out
end

local function script_extensions_table()
  if _script_ext_table == nil then
    _script_ext_table = parse_script_extensions()
  end
  return _script_ext_table
end

-- Resolved-script abbreviations for `cp`: ScriptExtensions when present, else
-- the single primary script mapped to its 4-letter abbrev.
-- The abbreviations the resolver can name: those occurring in
-- ScriptExtensions.txt. Unicode/ResolvedScripts.lean models the same set as its
-- ScriptAbbrev enum, which is why its scriptToAbbrev is partial over Script. A
-- codepoint whose primary script falls outside this set resolves to no
-- abbreviation on both sides; returning a singleton instead would make every
-- unknown-script codepoint look Single-Script, putting restriction_level one
-- rung too strict and hiding RestrictionLow.
local script_ext_abbrevs_cache = nil
local function script_extension_abbrevs()
  if script_ext_abbrevs_cache == nil then
    script_ext_abbrevs_cache = {}
    for _, row in ipairs(script_extensions_table()) do
      for _, abbrev in ipairs(row.value) do
        script_ext_abbrevs_cache[abbrev] = true
      end
    end
  end
  return script_ext_abbrevs_cache
end

function M.resolve_scripts(cp)
  local ext = script_extensions_table()
  local idx = partition_point(ext, function(r) return r.start end, cp)
  if idx > 0 then
    local entry = ext[idx]
    if cp <= entry.endcp then
      local copy = {}
      for _, s in ipairs(entry.value) do
        copy[#copy + 1] = s
      end
      return copy
    end
  end
  local abbrev = script_long_to_abbrev(M.script_of(cp))
  if script_extension_abbrevs()[abbrev] then
    return { abbrev }
  end
  return {}
end

function M.is_common_script(cp)
  return M.script_of(cp) == "Common"
end

function M.is_inherited_script(cp)
  return M.script_of(cp) == "Inherited"
end

function M.is_ignored_for_intersection(cp)
  return M.is_common_script(cp) or M.is_inherited_script(cp)
end

local function contains(list, x)
  for _, v in ipairs(list) do
    if v == x then
      return true
    end
  end
  return false
end

function M.string_script_union(input_cps)
  local acc = {}
  for _, cp in ipairs(input_cps) do
    if not M.is_ignored_for_intersection(cp) then
      for _, s in ipairs(M.resolve_scripts(cp)) do
        if not contains(acc, s) then
          acc[#acc + 1] = s
        end
      end
    end
  end
  return acc
end

-- ─────────────────────────────────────────────────────────────────────
-- IdentifierStatus.txt — UTS #39 General-Security-Profile Allowed set
-- ─────────────────────────────────────────────────────────────────────

local _id_allowed = nil

local function parse_identifier_status()
  local text = datapath.read("IdentifierStatus.txt")
  local out = {}
  for line in iter_lines(text) do
    local stripped = strip_comment_and_trim(line)
    if stripped ~= "" then
      local semi = stripped:find(";", 1, true)
      if semi ~= nil then
        local status = trim(stripped:sub(semi + 1))
        if status == "Allowed" then
          local lo, hi = parse_range_field(stripped:sub(1, semi - 1))
          out[#out + 1] = { lo, hi }
        end
      end
    end
  end
  table.sort(out, function(a, b) return a[1] < b[1] end)
  return out
end

local function id_allowed_ranges()
  if _id_allowed == nil then
    _id_allowed = parse_identifier_status()
  end
  return _id_allowed
end

function M.is_id_allowed(cp)
  local t = id_allowed_ranges()
  local idx = partition_point(t, function(r) return r[1] end, cp)
  if idx > 0 then
    local entry = t[idx]
    if cp <= entry[2] then
      return true
    end
  end
  return false
end

-- ─────────────────────────────────────────────────────────────────────
-- DerivedCoreProperties.txt — Default_Ignorable_Code_Point ranges
-- ─────────────────────────────────────────────────────────────────────

local _default_ignorable = nil

local function parse_default_ignorable()
  local text = datapath.read("DerivedCoreProperties.txt")
  local out = {}
  for line in iter_lines(text) do
    local stripped = strip_comment_and_trim(line)
    if stripped ~= "" then
      local semi = stripped:find(";", 1, true)
      if semi ~= nil and trim(stripped:sub(semi + 1)) == "Default_Ignorable_Code_Point" then
        local lo, hi = parse_range_field(stripped:sub(1, semi - 1))
        out[#out + 1] = { lo, hi }
      end
    end
  end
  table.sort(out, function(a, b) return a[1] < b[1] end)
  return out
end

local function default_ignorable_ranges()
  if _default_ignorable == nil then
    _default_ignorable = parse_default_ignorable()
  end
  return _default_ignorable
end

function M.is_default_ignorable(cp)
  local t = default_ignorable_ranges()
  local idx = partition_point(t, function(r) return r[1] end, cp)
  if idx > 0 then
    local entry = t[idx]
    if cp <= entry[2] then
      return true
    end
  end
  return false
end

-- ─────────────────────────────────────────────────────────────────────
-- DerivedCoreProperties.txt — UAX #31 XID_Start / XID_Continue ranges
-- ─────────────────────────────────────────────────────────────────────

-- Parse one binary property's ranges from DerivedCoreProperties.txt, mirroring
-- the Default_Ignorable parser above (the only difference is the property name).
local function parse_dcp_property(name)
  local text = datapath.read("DerivedCoreProperties.txt")
  local out = {}
  for line in iter_lines(text) do
    local stripped = strip_comment_and_trim(line)
    if stripped ~= "" then
      local semi = stripped:find(";", 1, true)
      if semi ~= nil and trim(stripped:sub(semi + 1)) == name then
        local lo, hi = parse_range_field(stripped:sub(1, semi - 1))
        out[#out + 1] = { lo, hi }
      end
    end
  end
  table.sort(out, function(a, b) return a[1] < b[1] end)
  return out
end

local _xid_start = nil
local _xid_continue = nil

local function xid_start_ranges()
  if _xid_start == nil then
    _xid_start = parse_dcp_property("XID_Start")
  end
  return _xid_start
end

local function xid_continue_ranges()
  if _xid_continue == nil then
    _xid_continue = parse_dcp_property("XID_Continue")
  end
  return _xid_continue
end

local function in_ranges(ranges, cp)
  local idx = partition_point(ranges, function(r) return r[1] end, cp)
  if idx > 0 then
    local entry = ranges[idx]
    if cp <= entry[2] then
      return true
    end
  end
  return false
end

local function is_xid_start(cp)
  return in_ranges(xid_start_ranges(), cp)
end

local function is_xid_continue(cp)
  return in_ranges(xid_continue_ranges(), cp)
end

-- UAX #31 default identifier start: `XID_Start` or `U+005F LOW LINE`.
local function is_default_id_start(cp)
  return is_xid_start(cp) or cp == 0x005F
end

-- UAX #31 default identifier continue: `XID_Continue`.
local function is_default_id_continue(cp)
  return is_xid_continue(cp)
end

-- True iff `cps` is a well-formed UAX #31 default identifier: a non-empty
-- sequence whose first codepoint is a default-id start and whose remaining
-- codepoints are default-id continues.
function M.is_default_identifier(cps)
  if #cps == 0 then
    return false
  end
  if not is_default_id_start(cps[1]) then
    return false
  end
  for i = 2, #cps do
    if not is_default_id_continue(cps[i]) then
      return false
    end
  end
  return true
end

-- True iff `cps` is a well-formed default identifier AND every codepoint has
-- `Identifier_Status = Allowed` per UTS #39 (the whole-string admissibility
-- predicate `isAllowedIdentifier`).
function M.is_allowed_identifier(cps)
  if not M.is_default_identifier(cps) then
    return false
  end
  for _, cp in ipairs(cps) do
    if not M.is_id_allowed(cp) then
      return false
    end
  end
  return true
end

-- UCD PropList.txt White_Space (hardcoded — small, stable range table).
function M.is_white_space(cp)
  return (cp >= 0x0009 and cp <= 0x000D)
    or cp == 0x0020
    or cp == 0x0085
    or cp == 0x00A0
    or cp == 0x1680
    or (cp >= 0x2000 and cp <= 0x200A)
    or (cp >= 0x2028 and cp <= 0x2029)
    or cp == 0x202F
    or cp == 0x205F
    or cp == 0x3000
end

-- ─────────────────────────────────────────────────────────────────────
-- UTS #39 §5.1 Restriction-level classification
-- ─────────────────────────────────────────────────────────────────────

local RestrictionLevel = {
  ASCII_ONLY = "ASCIIOnly",
  SINGLE_SCRIPT = "SingleScript",
  HIGHLY_RESTRICTIVE = "HighlyRestrictive",
  MODERATELY_RESTRICTIVE = "ModeratelyRestrictive",
  MINIMALLY_RESTRICTIVE = "MinimallyRestrictive",
  UNRESTRICTED = "Unrestricted",
}
M.RestrictionLevel = RestrictionLevel

function M.is_ascii_only(cps)
  for _, cp in ipairs(cps) do
    if cp >= 0x80 then
      return false
    end
  end
  return true
end

local function intersect_many(sets)
  if #sets == 0 then
    return {}
  end
  local acc = {}
  for _, x in ipairs(sets[1]) do
    acc[#acc + 1] = x
  end
  for i = 2, #sets do
    local s = sets[i]
    local next_acc = {}
    for _, x in ipairs(acc) do
      if contains(s, x) then
        next_acc[#next_acc + 1] = x
      end
    end
    acc = next_acc
  end
  return acc
end

function M.string_resolved_scripts(cps)
  local non_ignored = {}
  for _, cp in ipairs(cps) do
    if not M.is_ignored_for_intersection(cp) then
      non_ignored[#non_ignored + 1] = cp
    end
  end
  if #non_ignored == 0 then
    return {}
  end
  local sets = {}
  for _, cp in ipairs(non_ignored) do
    sets[#sets + 1] = M.resolve_scripts(cp)
  end
  return intersect_many(sets)
end

function M.is_single_script(cps)
  return not M.is_ascii_only(cps) and #M.string_resolved_scripts(cps) > 0
end

local COVERED_JAPANESE = { "Latn", "Hani", "Hira", "Kana" }
local COVERED_CHINESE = { "Latn", "Hani", "Bopo" }
local COVERED_KOREAN = { "Latn", "Hani", "Hang" }

local function intersects(a, b)
  for _, x in ipairs(a) do
    if contains(b, x) then
      return true
    end
  end
  return false
end

local function all_within_covered(cps, covered)
  for _, cp in ipairs(cps) do
    if not M.is_ignored_for_intersection(cp) then
      local r = M.resolve_scripts(cp)
      if #r == 0 or not intersects(r, covered) then
        return false
      end
    end
  end
  return true
end

function M.is_covered_cjk(cps)
  return all_within_covered(cps, COVERED_JAPANESE)
    or all_within_covered(cps, COVERED_CHINESE)
    or all_within_covered(cps, COVERED_KOREAN)
end

function M.is_highly_restrictive(cps)
  return M.is_single_script(cps) or M.is_covered_cjk(cps)
end

function M.is_moderately_restrictive_shape(cps)
  local other = nil
  for _, cp in ipairs(cps) do
    if not M.is_ignored_for_intersection(cp) then
      local r = M.resolve_scripts(cp)
      if #r == 0 then
        return false
      end
      if not contains(r, "Latn") then
        local s = r[1]
        if s == "Cyrl" or s == "Grek" then
          return false
        end
        if other == nil then
          other = s
        elseif s ~= other then
          return false
        end
      end
    end
  end
  return other ~= nil
end

function M.is_minimally_restrictive(cps)
  for _, cp in ipairs(cps) do
    if not M.is_id_allowed(cp) then
      return false
    end
  end
  return true
end

function M.restriction_level(cps)
  if M.is_ascii_only(cps) then
    return RestrictionLevel.ASCII_ONLY
  end
  if M.is_single_script(cps) then
    return RestrictionLevel.SINGLE_SCRIPT
  end
  if M.is_highly_restrictive(cps) then
    return RestrictionLevel.HIGHLY_RESTRICTIVE
  end
  if M.is_moderately_restrictive_shape(cps) then
    return RestrictionLevel.MODERATELY_RESTRICTIVE
  end
  if M.is_minimally_restrictive(cps) then
    return RestrictionLevel.MINIMALLY_RESTRICTIVE
  end
  return RestrictionLevel.UNRESTRICTED
end

return M
