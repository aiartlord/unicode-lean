-- Detection of payloads encoded in zero-width and near-zero-width codepoints.
-- The explicit hardcoded set preserves sub-threat dispatch; the UAX #44
-- Default_Ignorable_Code_Point predicate extends coverage to every other
-- invisible codepoint, excluding sibling-detector ranges.  Positions are
-- 0-based codepoint offsets.

local ucd = require("unicode_lua.security.identity.ucd")
local calculus = require("unicode_lua.security.calculus")
local ClassificationKind = calculus.ClassificationKind

local M = {}

-- Sibling-detector ranges excluded from the zero-width set to avoid
-- double-counting (variation selectors, tag block, bidi push/pop controls).
local function is_sibling_handled(cp)
  return (cp >= 0xFE00 and cp <= 0xFE0F)
    or (cp >= 0xE0100 and cp <= 0xE01EF)
    or (cp >= 0xE0000 and cp <= 0xE007F)
    or (cp >= 0x202A and cp <= 0x202E)
    or (cp >= 0x2066 and cp <= 0x2069)
end

function M.is_zero_width(cp)
  if (cp >= 0x200B and cp <= 0x200F)
    or (cp >= 0x2060 and cp <= 0x2064)
    or cp == 0x202F
    or cp == 0xFEFF
    or (cp >= 0xFFF9 and cp <= 0xFFFB) then
    return true
  end
  return ucd.is_default_ignorable(cp) and not is_sibling_handled(cp)
end

function M.is_nnbsp(cp)
  return cp == 0x202F
end

function M.is_word_joiner(cp)
  return cp == 0x2060
end

function M.is_annotation(cp)
  return cp >= 0xFFF9 and cp <= 0xFFFB
end

function M.is_zwj_or_zwsp(cp)
  return cp == 0x200B or cp == 0x200D
end

-- Returns { kind, sub, zero_width_positions (0-based) }.
function M.detect(input)
  local v = { kind = ClassificationKind.Clear, sub = nil, zero_width_positions = {} }
  local annotation_count = 0
  local word_joiner_count = 0
  local nnbsp_count = 0
  local zwj_zwsp_count = 0

  for i = 1, #input do
    local cp = input[i]
    if M.is_zero_width(cp) then
      v.zero_width_positions[#v.zero_width_positions + 1] = i - 1
      if M.is_annotation(cp) then
        annotation_count = annotation_count + 1
      elseif M.is_word_joiner(cp) then
        word_joiner_count = word_joiner_count + 1
      elseif M.is_nnbsp(cp) then
        nnbsp_count = nnbsp_count + 1
      elseif M.is_zwj_or_zwsp(cp) then
        zwj_zwsp_count = zwj_zwsp_count + 1
      end
    end
  end

  if #v.zero_width_positions == 0 then
    return v
  end

  v.kind = ClassificationKind.Hazard
  if annotation_count > 0 then
    v.sub = { tag = "AnnotationMisuse", count = annotation_count }
  elseif word_joiner_count > 0 then
    v.sub = { tag = "WordJoinerInjection", count = word_joiner_count }
  elseif nnbsp_count >= 2 then
    v.sub = { tag = "AiWatermarkNNBSP", count = nnbsp_count }
  elseif zwj_zwsp_count >= 2 then
    v.sub = { tag = "BinaryPayload", pair_count = math.floor(zwj_zwsp_count / 2) }
  else
    v.sub = { tag = "BareZeroWidth", cp = input[v.zero_width_positions[1] + 1] }
  end
  return v
end

return M
