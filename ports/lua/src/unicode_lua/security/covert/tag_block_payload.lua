-- Detection of invisible payloads encoded in the Unicode tag block
-- U+E0000..U+E007F.  Every occurrence is reportable; the detector attributes
-- the kind of use (direct payload, language-tag prefix, mixed-in text, or
-- isolated single tag).  Positions are 0-based codepoint offsets.

local calculus = require("unicode_lua.security.calculus")
local ClassificationKind = calculus.ClassificationKind

local M = {}

function M.is_tag_character(cp)
  return cp >= 0xE0000 and cp <= 0xE007F
end

function M.is_language_tag(cp)
  return cp == 0xE0001
end

function M.is_cancel_tag(cp)
  return cp == 0xE007F
end

-- Decode a tag-block codepoint to its ASCII correspondent, or nil.
function M.tag_to_ascii(cp)
  if cp >= 0xE0020 and cp <= 0xE007E then
    return string.char(cp - 0xE0000)
  end
  return nil
end

-- `positions` is a 0-based list.
local function decode_tag_run(input, positions)
  local s = {}
  for _, p in ipairs(positions) do
    if p < #input then
      local c = M.tag_to_ascii(input[p + 1])
      if c ~= nil then
        s[#s + 1] = c
      end
    end
  end
  return table.concat(s)
end

local function all_tag_characters(input)
  for _, cp in ipairs(input) do
    if not M.is_tag_character(cp) then
      return false
    end
  end
  return true
end

local function has_language_tag_prefix(input, tag_positions)
  if #tag_positions == 0 then
    return nil
  end
  local lang_pos = tag_positions[1]
  if lang_pos >= #input then
    return nil
  end
  if M.is_language_tag(input[lang_pos + 1]) and #tag_positions >= 2 then
    return lang_pos
  end
  return nil
end

local function pick_sub_threat(input, tag_positions, decoded)
  local lang_pos = has_language_tag_prefix(input, tag_positions)
  if lang_pos ~= nil then
    local tail = {}
    for _, p in ipairs(tag_positions) do
      if p ~= lang_pos then
        tail[#tail + 1] = p
      end
    end
    return { tag = "LanguageTagRevival", lang_tag_pos = lang_pos, decoded_tail = decode_tag_run(input, tail) }
  end
  if all_tag_characters(input) and decoded ~= "" then
    return { tag = "DirectAscii", decoded = decoded }
  end
  if #input > #tag_positions then
    return { tag = "MixedBlock", tag_count = #tag_positions, total_cps = #input }
  end
  return { tag = "BareTagPresent", tag_cp = input[tag_positions[1] + 1] }
end

-- Returns { kind, sub, tag_positions (0-based), recovered_ascii }.
function M.detect(input)
  local tag_positions = {}
  for i = 1, #input do
    if M.is_tag_character(input[i]) then
      tag_positions[#tag_positions + 1] = i - 1
    end
  end

  if #tag_positions == 0 then
    return { kind = ClassificationKind.Clear, sub = nil, tag_positions = {}, recovered_ascii = "" }
  end

  local decoded = decode_tag_run(input, tag_positions)
  local sub = pick_sub_threat(input, tag_positions, decoded)

  return { kind = ClassificationKind.Hazard, sub = sub, tag_positions = tag_positions, recovered_ascii = decoded }
end

return M
