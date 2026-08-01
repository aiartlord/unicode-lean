-- Detection of Trojan-Source-class bidi-control balance hazards
-- (CVE-2021-42574 / CVE-2021-42694).  A per-type stack yields four independent
-- sub-threats: DepthExceeded, OrphanPop, UnbalancedEmbedding, UnbalancedIsolate.
-- Positions are 0-based codepoint offsets.

local calculus = require("unicode_lua.security.calculus")
local ClassificationKind = calculus.ClassificationKind

local M = {}

-- UAX #9 §3.3.2 cap on the stack-of-stacks depth.
M.UAX_DEPTH_LIMIT = 125

function M.opens_embedding(cp)
  return cp == 0x202A or cp == 0x202B or cp == 0x202D or cp == 0x202E
end

function M.is_pdf(cp)
  return cp == 0x202C
end

function M.opens_isolate(cp)
  return cp == 0x2066 or cp == 0x2067 or cp == 0x2068
end

function M.is_pdi(cp)
  return cp == 0x2069
end

function M.is_bidi_format_control(cp)
  return M.opens_embedding(cp) or M.is_pdf(cp) or M.opens_isolate(cp) or M.is_pdi(cp)
end

-- Returns { kind, sub, bidi_positions (0-based), emb_open_count, emb_pop_count,
-- iso_open_count, iso_pop_count, max_depth }.
function M.detect(input)
  local v = {
    kind = ClassificationKind.Clear,
    sub = nil,
    bidi_positions = {},
    emb_open_count = 0,
    emb_pop_count = 0,
    iso_open_count = 0,
    iso_pop_count = 0,
    max_depth = 0,
  }
  local emb_stack = 0
  local iso_stack = 0
  local orphans = {}

  for idx = 1, #input do
    local cp = input[idx]
    if M.is_bidi_format_control(cp) then
      local i = idx - 1
      v.bidi_positions[#v.bidi_positions + 1] = i
      if M.opens_embedding(cp) then
        emb_stack = emb_stack + 1
        v.emb_open_count = v.emb_open_count + 1
        if emb_stack + iso_stack > v.max_depth then
          v.max_depth = emb_stack + iso_stack
        end
      elseif M.is_pdf(cp) then
        v.emb_pop_count = v.emb_pop_count + 1
        if emb_stack > 0 then
          emb_stack = emb_stack - 1
        else
          orphans[#orphans + 1] = i
        end
      elseif M.opens_isolate(cp) then
        iso_stack = iso_stack + 1
        v.iso_open_count = v.iso_open_count + 1
        if emb_stack + iso_stack > v.max_depth then
          v.max_depth = emb_stack + iso_stack
        end
      elseif M.is_pdi(cp) then
        v.iso_pop_count = v.iso_pop_count + 1
        if iso_stack > 0 then
          iso_stack = iso_stack - 1
        else
          orphans[#orphans + 1] = i
        end
      end
    end
  end

  if #v.bidi_positions == 0 then
    return v
  end

  if v.max_depth > M.UAX_DEPTH_LIMIT then
    v.kind = ClassificationKind.Hazard
    v.sub = { tag = "DepthExceeded", max_depth = v.max_depth }
    return v
  end
  if #orphans > 0 then
    v.kind = ClassificationKind.Hazard
    v.sub = { tag = "OrphanPop", positions = orphans }
    return v
  end
  if emb_stack > 0 then
    v.kind = ClassificationKind.Hazard
    v.sub = { tag = "UnbalancedEmbedding", open_count = v.emb_open_count, pop_count = v.emb_pop_count }
    return v
  end
  if iso_stack > 0 then
    v.kind = ClassificationKind.Hazard
    v.sub = { tag = "UnbalancedIsolate", open_count = v.iso_open_count, pop_count = v.iso_pop_count }
    return v
  end
  return v
end

return M
