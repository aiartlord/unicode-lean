-- UAX #14 default line breaking.
--
-- A port of the Lean algorithm `Unicode.Segmentation.LineBreak.lineBreaks`,
-- whose `lineBreaks_length` theorem fixes the output shape: one
-- break-opportunity flag per boundary position. The rule order, rule bodies,
-- and snapshot fields below mirror that reference -- LB2 through LB31 in
-- UAX #14 R7's canonical order, first match winning, the trailing LB31
-- breaking every otherwise-unmatched pair.
--
-- Where a line may break is a property of a sequence rather than of a code
-- point, so the entry point returns a flag per boundary instead of a predicate
-- over code points. Code points are 1-indexed integer tables, and
-- `line_breaks` returns a boolean mask of length `#cps + 1`: entry `i` is true
-- when a line break opportunity falls immediately before the `i`-th code
-- point. Entry `1` is false, since LB2 forbids a break at the start of text,
-- and entry `#cps + 1` is the LB3 end-of-text break, always true.
--
-- Three mechanisms carry the context the rules read:
--
--   * LB1 is applied at lookup time by `resolved_class`, which folds the
--     tailorable AI, CJ, SA, SG and XX into the algorithm's working alphabet.
--     SA needs General_Category to choose between CM and AL.
--   * LB9 -- treat X CM* / X ZWJ* as X -- is realised through the snapshot,
--     whose fields hold the most recent class that was not CM or ZWJ. LB10,
--     treating a leftover CM or ZWJ as AL, is the fallback taken when no such
--     class exists.
--   * The rules naming a third character -- LB15b, LB15c, the LB25 bracket and
--     the fourth LB28a sub-rule -- read forward from the position being
--     decided.
--
-- Two departures from the Lean. Its positional reads are `lits[i]!` and
-- `cps[i]!`, panicking accessors; here every read indexes a table, which yields
-- nil past the end, so no access can leave the sequence. And its `spSinceNoSp`
-- snapshot field is written by its fold and read by no rule, so this port omits
-- it.
--
-- The two properties UAX #14 needs beyond the Line_Break class --
-- General_Category for LB1's SA resolution, the Pi/Pf quote refinement and
-- LB30b, and East_Asian_Width for LB19a, LB25 and LB30 -- come from the
-- generated tables in `line_break_tables`, so this module takes code points and
-- needs no data directory, as `segmentation/grapheme` does.

local tables = require("unicode_lua.segmentation.line_break_tables")
local grapheme = require("unicode_lua.segmentation.grapheme")

local LB_RANGES = tables.LB_RANGES
local GC_RANGES = tables.GC_RANGES
local EAW_RANGES = tables.EAW_RANGES

local M = {}

-- // property lookups // -----------------------------------------------------

-- The class of the one range covering `cp`, or nil. Every table here is sorted
-- by lower bound and its ranges partition the code space, so the covering
-- range is unique and a binary search finds it.
local function lookup_range(t, cp)
  local lo, hi = 1, #t
  while lo <= hi do
    local mid = lo + ((hi - lo) // 2)
    local r = t[mid]
    if cp < r[1] then
      hi = mid - 1
    elseif cp > r[2] then
      lo = mid + 1
    else
      return r[3]
    end
  end
  return nil
end

-- Raw Line_Break class of `cp`, before LB1. A code point no range covers is
-- "Xx", the default LineBreak.txt's own @missing header declares.
function M.raw_class(cp)
  return lookup_range(LB_RANGES, cp) or "Xx"
end

-- General_Category of `cp`, "Cn" when no range covers it.
function M.general_category(cp)
  return lookup_range(GC_RANGES, cp) or "Cn"
end

-- East_Asian_Width of `cp`, "N" when the file omits it.
function M.east_asian_width_class(cp)
  return lookup_range(EAW_RANGES, cp) or "N"
end

-- // LB1, the tailoring applied at lookup // ---------------------------------

local function compute_resolved_class(cp)
  local raw = M.raw_class(cp)
  if raw == "Ai" or raw == "Sg" or raw == "Xx" then
    return "Al"
  elseif raw == "Cj" then
    return "Ns"
  elseif raw == "Sa" then
    -- LB1 reads only the two combining-mark categories here; an enclosing mark
    -- is not among them.
    local gc = M.general_category(cp)
    if gc == "Mn" or gc == "Mc" then
      return "Cm"
    end
    return "Al"
  end
  return raw
end

-- The Line_Break class `cp` carries once LB1 has tailored it.
--
-- AI, SG and XX resolve to AL; CJ to NS; SA to CM when the code point is a
-- non-spacing or spacing combining mark and to AL otherwise. Every other class
-- is already in the working alphabet.
--
-- Memoized: the corpus asks for the same few hundred code points tens of
-- thousands of times, and each miss costs three binary searches.
local resolved_cache = {}

function M.resolved_class(cp)
  local cached = resolved_cache[cp]
  if cached ~= nil then
    return cached
  end
  local computed = compute_resolved_class(cp)
  resolved_cache[cp] = computed
  return computed
end

-- // class sets the rules name // --------------------------------------------

-- Classes LB9 absorbs into the character before them.
local CM_ZWJ = { Cm = true, Zwj = true }

-- Classes that block LB9's absorption, so a following CM or ZWJ stands on its
-- own and LB10 reads it as AL.
local BLOCKS_ABSORB =
  { Bk = true, Cr = true, Lf = true, Nl = true, Sp = true, Zw = true }

-- The left context in which LB15a opens its initial-punctuation window: an
-- initial quote standing outside a word.
local PI_WINDOW_OPENERS = {
  Bk = true, Cr = true, Lf = true, Nl = true,
  Op = true, Qu = true, Gl = true, Sp = true, Zw = true,
}

-- Classes that keep an open LB25 numeric chain open.
local NU_CHAIN_EXTENDERS =
  { Sy = true, Is = true, Cl = true, Cp = true, Pr = true }

-- Classes that cannot open a line, so an LB15b final quote before one closes
-- rather than breaks.
local QUOTE_CLOSERS = {
  Sp = true, Gl = true, Wj = true, Cl = true, Qu = true, Cp = true,
  Ex = true, Is = true, Sy = true, Bk = true, Cr = true, Lf = true,
  Nl = true, Zw = true,
}

-- The start-of-segment set LB20.1 and LB20a require of a hyphen's own left
-- context.
local HYPHEN_LEFT_OPENERS = {
  Bk = true, Cr = true, Lf = true, Nl = true,
  Sp = true, Zw = true, Cb = true, Gl = true,
}

-- East_Asian_Width values LB25 and LB30 exclude.
local EAST_ASIAN_FULL_WIDE = { F = true, W = true, H = true }

-- The wider set LB19a's tailoring treats as East Asian, Ambiguous included.
local EAST_ASIAN_OR_AMBIGUOUS = { F = true, W = true, H = true, A = true }

-- Classes carrying a mandatory break, which LB6 forbids breaking before.
local MANDATORY = { Bk = true, Cr = true, Lf = true, Nl = true }

-- Hangul syllable classes, for LB26 and LB27.
local HANGUL =
  { Jl = true, Jv = true, Jt = true, H2 = true, H3 = true }

-- U+25CC DOTTED CIRCLE, which LB28a reads as a stand-in cluster base.
local DOTTED_CIRCLE = 0x25CC

-- U+2010 HYPHEN, which LB20a and LB21a name explicitly because UCD 17.0 moved
-- it from class HY to class HH.
local HYPHEN = 0x2010

-- Whether `cls` is present and in `set`.
local function inset(set, cls)
  return cls ~= nil and set[cls] == true
end

-- Whether LB9 absorbs this class into the character before it.
local function is_cm_zwj(cls)
  return inset(CM_ZWJ, cls)
end

-- Whether the class is QU and the code point is initial punctuation, the
-- refinement LB15a reads.
local function is_pi_quote(cp, cls)
  return cls == "Qu" and M.general_category(cp) == "Pi"
end

-- Whether the class is QU and the code point is final punctuation, the
-- refinement LB15b reads.
local function is_pf_quote(cp, cls)
  return cls == "Qu" and M.general_category(cp) == "Pf"
end

-- Whether `cp` is East_Asian_Width F, W or H, the set LB25 and LB30 read.
local function is_east_asian_full_wide(cp)
  return EAST_ASIAN_FULL_WIDE[M.east_asian_width_class(cp)] == true
end

-- Whether `cp` counts as East Asian for LB19a's tailoring.
local function is_east_asian_or_ambiguous(cp)
  return EAST_ASIAN_OR_AMBIGUOUS[M.east_asian_width_class(cp)] == true
end

-- // the left-hand context a boundary decision reads // ----------------------

-- The classes and code points of the most recent characters LB9 did not absorb,
-- plus the running counters the rules keep. Mirrors the Lean `EffSnapshot`:
--   eff_prev          : class of the most recent character that was not CM or ZWJ
--   eff_prev_cp       : its code point -- LB20a, LB21a and LB28a name U+2010 and U+25CC
--   eff_prev_no_sp    : class of the most recent character that was not CM, ZWJ or SP
--   eff_prev_prev     : class of the second most recent such character
--   eff_prev_prev_cp  : its code point
--   in_pi_quote_window: whether an LB15a initial-punctuation window is open
--   ri_run            : length of the current regional-indicator run, for LB30a
--   in_nu_chain       : whether an LB25 numeric chain is open
local function initial_snapshot()
  return {
    eff_prev = nil,
    eff_prev_cp = nil,
    eff_prev_no_sp = nil,
    eff_prev_prev = nil,
    eff_prev_prev_cp = nil,
    in_pi_quote_window = false,
    ri_run = 0,
    in_nu_chain = false,
  }
end

-- The class a CM or ZWJ takes from what it attaches to under LB9, or AL under
-- LB10 when nothing absorbs it.
local function effective_class(cls, eff_prev)
  if not is_cm_zwj(cls) then
    return cls
  end
  if eff_prev == nil then
    return "Al"
  end
  if BLOCKS_ABSORB[eff_prev] == true then
    return "Al"
  end
  return cls
end

-- Fold one character into the context. A character LB9 absorbs leaves the
-- context untouched, which is what makes the neighbours it records effective
-- rather than literal. Mirrors the Lean `buildSnapshots` step.
local function advance(s, cp, cls)
  local effective = effective_class(cls, s.eff_prev)
  if is_cm_zwj(effective) then
    return s
  end

  -- LB15a opens its window only where an initial-punctuation quote stands
  -- outside a word; a space carries an open window forward.
  local left_context_opens =
    s.eff_prev == nil or PI_WINDOW_OPENERS[s.eff_prev] == true
  local in_pi_quote_window
  if is_pi_quote(cp, effective) and left_context_opens then
    in_pi_quote_window = true
  elseif effective == "Sp" then
    in_pi_quote_window = s.in_pi_quote_window
  else
    in_pi_quote_window = false
  end

  local in_nu_chain
  if effective == "Nu" then
    in_nu_chain = true
  elseif s.in_nu_chain then
    in_nu_chain = NU_CHAIN_EXTENDERS[effective] == true
  else
    in_nu_chain = false
  end

  local eff_prev_no_sp
  if effective == "Sp" then
    eff_prev_no_sp = s.eff_prev_no_sp
  else
    eff_prev_no_sp = effective
  end

  local ri_run
  if effective == "Ri" then
    ri_run = s.ri_run + 1
  else
    ri_run = 0
  end

  return {
    eff_prev = effective,
    eff_prev_cp = cp,
    eff_prev_no_sp = eff_prev_no_sp,
    eff_prev_prev = s.eff_prev,
    eff_prev_prev_cp = s.eff_prev_cp,
    in_pi_quote_window = in_pi_quote_window,
    ri_run = ri_run,
    in_nu_chain = in_nu_chain,
  }
end

-- // lookahead // ------------------------------------------------------------

-- The class at `index`, or nil past the end of the sequence.
local function class_at(pairs_, index)
  local entry = pairs_[index]
  if entry == nil then
    return nil
  end
  return entry[2]
end

-- The code point at `index`, or nil past the end of the sequence.
local function cp_at(pairs_, index)
  local entry = pairs_[index]
  if entry == nil then
    return nil
  end
  return entry[1]
end

-- LB15b holds when the final quote is last, or when what follows it cannot
-- itself open a line.
local function final_quote_closes(pairs_, index)
  local nxt = class_at(pairs_, index)
  if nxt == nil then
    return true
  end
  return QUOTE_CLOSERS[nxt] == true
end

-- The fourth LB28a sub-rule looks past any CM or ZWJ the cluster absorbs, so
-- the character it tests is the first significant one ahead.
local function next_significant_is_vf(pairs_, index)
  for i = index, #pairs_ do
    local cls = pairs_[i][2]
    if not is_cm_zwj(cls) then
      return cls == "Vf"
    end
  end
  return false
end

-- // the rule cascade // -----------------------------------------------------

-- Whether a line break opportunity falls immediately before `pairs_[index]`,
-- given the character before it and the context accumulated from everything
-- earlier. `index` is the position being decided, so `index + 1` supplies every
-- lookahead the rules take.
local function breaks_before(pairs_, index, s)
  local current = pairs_[index]
  if current == nil then
    return true -- LB3
  end
  local previous = pairs_[index - 1]
  local prev_cp, prev_class = previous[1], previous[2]
  local current_cp, current_class = current[1], current[2]
  local ahead = index + 1

  local eff = effective_class(current_class, s.eff_prev)
  local left
  if is_cm_zwj(prev_class) then
    left = s.eff_prev
  else
    left = prev_class
  end

  -- LB4
  if prev_class == "Bk" then
    return true
  end
  -- LB5
  if prev_class == "Cr" and current_class == "Lf" then
    return false
  end
  if prev_class == "Cr" or prev_class == "Lf" or prev_class == "Nl" then
    return true
  end
  -- LB6
  if MANDATORY[current_class] == true then
    return false
  end
  -- LB7
  if current_class == "Sp" or current_class == "Zw" then
    return false
  end
  -- LB8
  if s.eff_prev_no_sp == "Zw" then
    return true
  end
  -- LB8a
  if prev_class == "Zwj" then
    return false
  end
  -- LB9
  if is_cm_zwj(current_class) and s.eff_prev ~= nil
     and BLOCKS_ABSORB[s.eff_prev] ~= true then
    return false
  end
  -- LB11
  if eff == "Wj" or left == "Wj" then
    return false
  end
  -- LB12
  if left == "Gl" then
    return false
  end
  -- LB12a
  if eff == "Gl" and not (left == "Sp" or left == "Ba" or left == "Hy"
                          or left == "Hh") then
    return false
  end
  -- LB15c, which UCD 17.0 orders above LB13 and LB15d: break before an IS that
  -- opens a number and follows a space, as in "equals .35".
  if prev_class == "Sp" and eff == "Is" and class_at(pairs_, ahead) == "Nu" then
    return true
  end
  -- LB13
  if eff == "Cl" or eff == "Cp" or eff == "Ex" or eff == "Is"
     or eff == "Sy" then
    return false
  end
  -- LB14
  if s.eff_prev_no_sp == "Op" then
    return false
  end
  -- LB15a
  if s.in_pi_quote_window then
    return false
  end
  -- LB15b
  if is_pf_quote(current_cp, eff) and final_quote_closes(pairs_, ahead) then
    return false
  end
  -- LB15d
  if eff == "Is" then
    return false
  end
  -- LB16
  if eff == "Ns" and (s.eff_prev_no_sp == "Cl" or s.eff_prev_no_sp == "Cp") then
    return false
  end
  -- LB17
  if eff == "B2" and s.eff_prev_no_sp == "B2" then
    return false
  end
  -- LB18
  if prev_class == "Sp" then
    return true
  end
  -- LB19 and LB19a. A quote neither breaks before nor after, except on the
  -- OUTER side of an initial or final punctuation quote standing in contiguous
  -- East Asian content -- there the default break applies, so a line may break
  -- at the quote boundary. The inner side stays unbroken, being the boundary
  -- inside the quote's own scope.
  if eff == "Qu" then
    local next_cp = cp_at(pairs_, ahead)
    local next_east_asian =
      next_cp ~= nil and is_east_asian_or_ambiguous(next_cp)
    local open_quote_in_east_asian =
      is_pi_quote(current_cp, eff) and is_east_asian_or_ambiguous(prev_cp)
      and is_east_asian_or_ambiguous(current_cp) and next_east_asian
    if not open_quote_in_east_asian then
      return false
    end
  end
  if left == "Qu" then
    local quote_cp = s.eff_prev_cp
    local close_quote_in_east_asian =
      quote_cp ~= nil and is_pf_quote(quote_cp, "Qu")
      and s.eff_prev_prev_cp ~= nil
      and is_east_asian_or_ambiguous(s.eff_prev_prev_cp)
      and is_east_asian_or_ambiguous(quote_cp)
      and is_east_asian_or_ambiguous(current_cp)
    if not close_quote_in_east_asian then
      return false
    end
  end
  -- LB20
  if eff == "Cb" or left == "Cb" then
    return true
  end

  -- LB20.1 and LB20a both require the hyphen's own left context to be outside a
  -- word, the same start-of-segment set.
  local hyphen_left_context_opens =
    s.eff_prev_prev == nil or HYPHEN_LEFT_OPENERS[s.eff_prev_prev] == true
  -- LB20.1, UCD 17.0: an explicit hyphen joins a following letter only where
  -- its own left context is outside a word. A mid-word HH falls through to
  -- LB31.
  if left == "Hh" and (eff == "Al" or eff == "Hl")
     and hyphen_left_context_opens then
    return false
  end
  -- LB20a, with UCD 17.0's right side broadened to HL beside AL.
  if eff == "Al" or eff == "Hl" then
    local hyphen_carries_left =
      s.eff_prev == "Hy" or s.eff_prev == "Hh" or s.eff_prev_cp == HYPHEN
    if hyphen_carries_left and hyphen_left_context_opens then
      return false
    end
  end
  -- LB21
  if eff == "Ba" or eff == "Hy" or eff == "Hh" or eff == "Ns" then
    return false
  end
  if left == "Bb" then
    return false
  end
  -- LB21a: an HL letter followed by an HY hyphen or U+2010 glues to what comes
  -- next unless that is itself HL. A BA does not glue here.
  if s.eff_prev_prev == "Hl" and eff ~= "Hl"
     and (s.eff_prev == "Hy" or s.eff_prev_cp == HYPHEN) then
    return false
  end
  -- LB21b
  if eff == "Hl" and left == "Sy" then
    return false
  end
  -- LB22
  if eff == "In" then
    return false
  end
  -- LB23
  if eff == "Nu" and (left == "Al" or left == "Hl") then
    return false
  end
  if (eff == "Al" or eff == "Hl") and left == "Nu" then
    return false
  end
  -- LB23a
  if (eff == "Id" or eff == "Eb" or eff == "Em") and left == "Pr" then
    return false
  end
  if eff == "Po" and (left == "Id" or left == "Eb" or left == "Em") then
    return false
  end
  -- LB24
  if (eff == "Al" or eff == "Hl") and (left == "Pr" or left == "Po") then
    return false
  end
  if (eff == "Pr" or eff == "Po") and (left == "Al" or left == "Hl") then
    return false
  end
  -- LB25, closing an open numeric chain with a CL or CP suffix and a following
  -- PO or PR.
  if s.in_nu_chain and (eff == "Cl" or eff == "Cp" or eff == "Po"
                        or eff == "Pr") then
    return false
  end
  -- LB25, opening a chain
  if eff == "Nu" and (left == "Pr" or left == "Po" or left == "Hy"
                      or left == "Op" or left == "Is") then
    return false
  end
  -- LB25, chain body
  if eff == "Nu" and left == "Nu" then
    return false
  end
  -- LB25, extending an open chain across a SY
  if eff == "Nu" and left == "Sy" and s.in_nu_chain then
    return false
  end
  -- LB25, bracketed prefix: a PR joins an OP only when the OP itself opens a
  -- number, and neither is East Asian Fullwidth, Wide or Halfwidth.
  if eff == "Op" and left == "Pr" and not is_east_asian_full_wide(current_cp)
     and s.eff_prev_cp ~= nil
     and not is_east_asian_full_wide(s.eff_prev_cp)
     and class_at(pairs_, ahead) == "Nu" then
    return false
  end
  -- LB26
  if left == "Jl" and (eff == "Jl" or eff == "Jv" or eff == "H2"
                       or eff == "H3") then
    return false
  end
  if (left == "Jv" or left == "H2") and (eff == "Jv" or eff == "Jt") then
    return false
  end
  if (left == "Jt" or left == "H3") and eff == "Jt" then
    return false
  end
  -- LB27
  if inset(HANGUL, left) and (eff == "In" or eff == "Po") then
    return false
  end
  if left == "Pr" and HANGUL[eff] == true then
    return false
  end
  -- LB28
  if (eff == "Al" or eff == "Hl") and (left == "Al" or left == "Hl") then
    return false
  end

  -- LB28a, the aksara cluster rules. U+25CC DOTTED CIRCLE carries class AL and
  -- stands in for a cluster base throughout.
  local left_is_aksara_base =
    left == "Ak" or left == "As"
    or (s.eff_prev_cp == DOTTED_CIRCLE and s.eff_prev == "Al")
  if left == "Ap" and (eff == "Ak" or eff == "As"
                       or current_cp == DOTTED_CIRCLE) then
    return false
  end
  if left_is_aksara_base and (eff == "Vf" or eff == "Vi") then
    return false
  end
  if s.eff_prev == "Vi"
     and (s.eff_prev_prev == "Ak" or s.eff_prev_prev == "As"
          or s.eff_prev_prev_cp == DOTTED_CIRCLE)
     and (eff == "Ak" or current_cp == DOTTED_CIRCLE) then
    return false
  end
  if left_is_aksara_base
     and (eff == "Ak" or eff == "As" or current_cp == DOTTED_CIRCLE)
     and next_significant_is_vf(pairs_, ahead) then
    return false
  end
  -- LB29
  if (eff == "Al" or eff == "Hl") and left == "Is" then
    return false
  end
  -- LB30, where the bracket must not be East Asian Fullwidth, Wide or
  -- Halfwidth.
  if eff == "Op" and (left == "Al" or left == "Hl" or left == "Nu")
     and not is_east_asian_full_wide(current_cp) then
    return false
  end
  if (eff == "Al" or eff == "Hl" or eff == "Nu") and left == "Cp"
     and not is_east_asian_full_wide(prev_cp) then
    return false
  end
  -- LB30a
  if eff == "Ri" and (s.ri_run % 2) == 1 then
    return false
  end
  -- LB30b
  if eff == "Em" and left == "Eb" then
    return false
  end
  if eff == "Em" and s.eff_prev_cp ~= nil
     and grapheme.is_ext_pict(s.eff_prev_cp)
     and M.general_category(s.eff_prev_cp) == "Cn" then
    return false
  end
  -- LB31
  return true
end

-- // entry points // ---------------------------------------------------------

-- Boundary mask of length `#cps + 1`. Entry `i` is true when a line break
-- opportunity falls immediately before the `i`-th code point -- entry `1` is
-- false per LB2, which forbids a break at the start of text, and entry
-- `#cps + 1` is true per LB3, which requires one at the end. Mirrors the Lean
-- `lineBreaks`, whose `lineBreaks_length` theorem fixes this shape.
function M.line_breaks(cps)
  local classified = {}
  for i = 1, #cps do
    classified[i] = { cps[i], M.resolved_class(cps[i]) }
  end
  local bs = {}
  local s = initial_snapshot()
  for i = 1, #classified do
    if i == 1 then
      bs[i] = false -- LB2
    else
      bs[i] = breaks_before(classified, i, s)
    end
    s = advance(s, classified[i][1], classified[i][2])
  end
  bs[#cps + 1] = true -- LB3
  return bs
end

-- Split `cps` at every break opportunity -- the runs a renderer may place on
-- separate lines. Returns an array of 1-indexed code point tables.
function M.line_runs(cps)
  local breaks = M.line_breaks(cps)
  local out = {}
  local cur = {}
  for i = 1, #cps do
    cur[#cur + 1] = cps[i]
    if breaks[i + 1] then
      out[#out + 1] = cur
      cur = {}
    end
  end
  if #cur > 0 then
    out[#out + 1] = cur
  end
  return out
end

return M
