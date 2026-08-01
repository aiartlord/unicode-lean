-- UAX #29 default extended grapheme cluster segmentation.
--
-- A transcription of the Rust port `ports/rust/src/segmentation/grapheme.rs`,
-- itself a transcription of the Lean algorithm
-- `Unicode.Segmentation.GraphemeBreak.graphemeBreaks`. The active Lean tree
-- proves `graphemeBreaks_eq_spec`, relating that algorithm to the declarative
-- UAX #29 GB1-GB999 specification. The state fields, rule order, and transition
-- below mirror that reference.
--
-- Code points are 1-indexed integer tables. `grapheme_breaks` returns a boolean
-- mask of length `#cps + 1`: entry `i` is true when a grapheme cluster break
-- occurs immediately before the `i`-th code point (1-indexed), and the final
-- entry `#cps + 1` is the GB2 end-of-text break, always true.

local tables = require("unicode_lua.segmentation.grapheme_tables")

local GCB_RANGES = tables.GCB_RANGES
local INCB_RANGES = tables.INCB_RANGES
local EXTPICT_RANGES = tables.EXTPICT_RANGES

local M = {}

-- The property tables are grouped by property value (as in the UCD source), not
-- globally sorted by code point, so lookups scan linearly for the covering
-- range -- mirroring the verified Lean `find?`. Each class is a partition, so at
-- most one range covers a code point and the first match is the only match.

-- Grapheme_Cluster_Break class of `cp`, "Other" when uncovered.
function M.lookup_gcb(cp)
  for i = 1, #GCB_RANGES do
    local r = GCB_RANGES[i]
    if r[1] <= cp and cp <= r[2] then
      return r[3]
    end
  end
  return "Other"
end

-- Indic_Conjunct_Break class of `cp`, "None" when uncovered.
function M.lookup_incb(cp)
  for i = 1, #INCB_RANGES do
    local r = INCB_RANGES[i]
    if r[1] <= cp and cp <= r[2] then
      return r[3]
    end
  end
  return "None"
end

-- Whether `cp` has the Extended_Pictographic property.
function M.is_ext_pict(cp)
  for i = 1, #EXTPICT_RANGES do
    local r = EXTPICT_RANGES[i]
    if r[1] <= cp and cp <= r[2] then
      return true
    end
  end
  return false
end

-- Running scan state, mirroring the Lean `State`:
--   prev_class  : GCB class string of the previous code point, or nil at sot
--   epic_state  : GB11 left-context, one of "None" / "AfterEp" / "AfterEpZwj"
--   incb_state  : GB9c left-context, one of "None" / "Consonant" / "Linker"
--   ri_run      : count of the current unbroken Regional_Indicator run
local function initial_state()
  return {
    prev_class = nil,
    epic_state = "None",
    incb_state = "None",
    ri_run = 0,
  }
end

-- Whether a grapheme cluster break occurs immediately before `cp` given the
-- running state. Implements UAX #29 GB1-GB999 in canonical order; first match
-- wins, the trailing GB999 breaks every otherwise-unmatched pair.
local function should_break_before(cp, s)
  local bc = M.lookup_gcb(cp)
  local incb = M.lookup_incb(cp)
  local is_ep = M.is_ext_pict(cp)
  local pc = s.prev_class
  if pc == nil then
    return true -- GB1: sot ÷
  elseif pc == "Cr" and bc == "Lf" then
    return false -- GB3: CR × LF
  elseif pc == "Control" or pc == "Cr" or pc == "Lf" then
    return true -- GB4: (Control | CR | LF) ÷
  elseif bc == "Control" or bc == "Cr" or bc == "Lf" then
    return true -- GB5: ÷ (Control | CR | LF)
  elseif pc == "L" and (bc == "L" or bc == "V" or bc == "Lv" or bc == "Lvt") then
    return false -- GB6: L × (L | V | LV | LVT)
  elseif (pc == "Lv" or pc == "V") and (bc == "V" or bc == "T") then
    return false -- GB7: (LV | V) × (V | T)
  elseif (pc == "Lvt" or pc == "T") and bc == "T" then
    return false -- GB8: (LVT | T) × T
  elseif bc == "Extend" or bc == "Zwj" then
    return false -- GB9: × (Extend | ZWJ)
  elseif bc == "SpacingMark" then
    return false -- GB9a: × SpacingMark
  elseif pc == "Prepend" then
    return false -- GB9b: Prepend ×
  elseif s.incb_state == "Linker" and incb == "Consonant" then
    return false -- GB9c: Consonant (Extend|Linker)* Linker (Extend|Linker)* × Consonant
  elseif s.epic_state == "AfterEpZwj" and is_ep then
    return false -- GB11: ExtPict Extend* ZWJ × ExtPict
  elseif bc == "RegionalIndicator" and (s.ri_run % 2) == 1 then
    return false -- GB12/GB13: odd-parity RI run extends
  else
    return true -- GB999: Any ÷ Any
  end
end

-- Update the running state after consuming `cp`. Mirrors the Lean `advance`.
local function advance(cp, s)
  local bc = M.lookup_gcb(cp)
  local incb = M.lookup_incb(cp)
  local is_ep = M.is_ext_pict(cp)

  local epic_state
  if is_ep then
    epic_state = "AfterEp"
  elseif s.epic_state == "AfterEp" and bc == "Extend" then
    epic_state = "AfterEp"
  elseif s.epic_state == "AfterEp" and bc == "Zwj" then
    epic_state = "AfterEpZwj"
  else
    epic_state = "None"
  end

  local incb_state
  if incb == "Consonant" then
    incb_state = "Consonant"
  elseif s.incb_state == "Consonant" and incb == "Linker" then
    incb_state = "Linker"
  elseif s.incb_state == "Consonant" and incb == "Extend" then
    incb_state = "Consonant"
  elseif s.incb_state == "Linker" and incb == "Linker" then
    incb_state = "Linker"
  elseif s.incb_state == "Linker" and incb == "Extend" then
    incb_state = "Linker"
  else
    incb_state = "None"
  end

  local ri_run
  if bc == "RegionalIndicator" then
    ri_run = s.ri_run + 1
  else
    ri_run = 0
  end

  return {
    prev_class = bc,
    epic_state = epic_state,
    incb_state = incb_state,
    ri_run = ri_run,
  }
end

-- Boundary mask of length `#cps + 1`. Entry `i` is true when a grapheme cluster
-- break occurs immediately before the `i`-th code point -- entry `1` is the GB1
-- start-of-text break, entry `#cps + 1` the GB2 end-of-text break, both always
-- true. Mirrors the Lean `graphemeBreaks`.
function M.grapheme_breaks(cps)
  local bs = {}
  local s = initial_state()
  for i = 1, #cps do
    local cp = cps[i]
    bs[i] = should_break_before(cp, s)
    s = advance(cp, s)
  end
  bs[#cps + 1] = true -- GB2: eot ÷
  return bs
end

-- Split `cps` into grapheme clusters (the code points between consecutive
-- boundaries). Returns an array of 1-indexed code point tables.
function M.grapheme_clusters(cps)
  local breaks = M.grapheme_breaks(cps)
  local out = {}
  local cur = {}
  for i = 1, #cps do
    if breaks[i] and #cur > 0 then
      out[#out + 1] = cur
      cur = {}
    end
    cur[#cur + 1] = cps[i]
  end
  if #cur > 0 then
    out[#out + 1] = cur
  end
  return out
end

return M
