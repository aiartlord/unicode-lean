-- Detection of payloads encoded in zero-width and near-zero-width codepoints.
-- The explicit hardcoded set preserves sub-threat dispatch; the UAX #44
-- Default_Ignorable_Code_Point predicate extends coverage to every other
-- invisible codepoint, excluding sibling-detector ranges.  Positions are
-- 0-based codepoint offsets.

local ucd = require("unicode_lua.security.identity.ucd")
local emoji_zwj_integrity = require("unicode_lua.security.identity.emoji_zwj_integrity")
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

-- True iff the ZWJ at 1-based index i is flanked by two codepoints that both
-- participate in some registered RGI emoji ZWJ sequence. Strictly narrower than
-- "is an emoji": a codepoint carrying the Emoji property but appearing in no
-- registered sequence does not sanction a ZWJ beside it. A ZWJ in head or tail
-- position is never legitimate.
local function is_legitimate_zwj_context(input, i)
  if i == 1 or i + 1 > #input then
    return false
  end
  return emoji_zwj_integrity.is_emoji_target(input[i - 1])
    and emoji_zwj_integrity.is_emoji_target(input[i + 1])
end

-- The Joining_Type of the first non-Transparent codepoint before 1-based i.
local function joining_type_before(input, i)
  local j = i
  while j > 1 do
    j = j - 1
    local jt = ucd.joining_type(input[j])
    if jt ~= ucd.JoiningType.TRANSPARENT then
      return jt
    end
  end
  return nil
end

-- The Joining_Type of the first non-Transparent codepoint after 1-based i.
local function joining_type_after(input, i)
  local j = i + 1
  while j <= #input do
    local jt = ucd.joining_type(input[j])
    if jt ~= ucd.JoiningType.TRANSPARENT then
      return jt
    end
    j = j + 1
  end
  return nil
end

-- True iff the ZWNJ at 1-based index i occupies a position where it is
-- orthographically required, by RFC 5892 Appendix A.1: it follows a Virama,
-- which is how a Devanagari conjunct is suppressed, or it sits between a left-
-- or dual-joining character and a right- or dual-joining one, skipping
-- Transparent characters on both sides, which is how a Persian word boundary is
-- written inside a cursive run.
--
-- A ZWNJ outside such a position carries no orthographic duty and stays
-- reportable.
local function is_legitimate_zwnj_context(input, i)
  if i > 1 and ucd.is_virama(input[i - 1]) then
    return true
  end
  local left = joining_type_before(input, i)
  local right = joining_type_after(input, i)
  local left_ok = left == ucd.JoiningType.LEFT_JOINING
    or left == ucd.JoiningType.DUAL_JOINING
  local right_ok = right == ucd.JoiningType.RIGHT_JOINING
    or right == ucd.JoiningType.DUAL_JOINING
  return left_ok and right_ok
end

-- Returns { kind, sub, zero_width_positions (0-based) }.
function M.detect(input)
  local v = { kind = ClassificationKind.Clear, sub = nil, zero_width_positions = {} }
  local annotation_count = 0
  local word_joiner_count = 0
  local nnbsp_count = 0
  local zwj_zwsp_count = 0
  local suspicious = {}

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
      -- The sanctioning model: a ZWJ inside a registered emoji sequence and a
      -- ZWNJ in an RFC 5892 CONTEXTJ-valid position both carry meaning a reader
      -- depends on, so they are recorded as present but not treated as
      -- suspicious.
      local sanctioned = (cp == 0x200D and is_legitimate_zwj_context(input, i))
        or (cp == 0x200C and is_legitimate_zwnj_context(input, i))
      if not sanctioned then
        suspicious[#suspicious + 1] = i - 1
      end
    end
  end

  if #v.zero_width_positions == 0 or #suspicious == 0 then
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
    v.sub = { tag = "BareZeroWidth", cp = input[suspicious[1] + 1] }
  end
  return v
end

return M
