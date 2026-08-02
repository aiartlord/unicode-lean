-- skin-tone-variation-forgery — skin-tone modifier and variation-selector abuse
-- on emoji bases per UTS #51 (the identity-layer detector).
--
-- Direct port of `Unicode/Security/Identity/SkinToneVariationForgery.lean` via
-- the verified Rust reference `skin_tone_variation_forgery.rs`.
--
-- Threat model. An adversary places a skin-tone modifier on a codepoint that
-- does NOT bear `Emoji_Modifier_Base`, stacks multiple skin-tones on one base,
-- or forces a text-style render on an emoji-default codepoint via U+FE0E (VS15)
-- — sometimes to hide a payload-bearing glyph in plain sight.
--
-- Distinct from variation-selector-payload (pair-aligned VS runs that decode to
-- bytes): this catches the orthogonal case of semantic VS / skin-tone misuse on
-- a single base. Both can fire on the same input.
--
-- It reuses the port's own emoji tables — the skin-tone modifier predicate from
-- the emoji-zwj-integrity detector and the bundled `emoji-data.txt` property
-- rows — never a host emoji library.
--
-- Sub-threats (priority order):
--   1. StackedSkinTones      a base immediately followed by >= 2 skin-tone modifiers.
--   2. InvalidSkinToneTarget a skin-tone modifier on a non-`Emoji_Modifier_Base`.
--   3. ForcedTextStyle       U+FE0E on an `Emoji_Presentation` codepoint.
--
-- Codepoint positions are 0-based to mirror the reference.

local datapath = require("unicode_lua.datapath")
local emoji_zwj = require("unicode_lua.security.identity.emoji_zwj_integrity")

local unpack = table.unpack or unpack

local M = {}

-- ─────────────────────────────────────────────────────────────────────
-- §1 Emoji property tables (bundled emoji-data.txt)
-- ─────────────────────────────────────────────────────────────────────

local function iter_lines(text)
  return (text .. "\n"):gmatch("([^\n]*)\n")
end

local function trim(s)
  return (s:gsub("^%s*(.-)%s*$", "%1"))
end

-- Parse the closed intervals for a single emoji property from emoji-data.txt.
-- Each non-comment row is `<range> ; <property> # <comment>`; we keep only rows
-- whose property field matches `property` exactly. Mirrors the emoji-data.txt
-- property-interval parser the ai-watermark-detectability detector already uses.
local function parse_emoji_property(property)
  local out = {}
  for raw_line in iter_lines(datapath.read("emoji-data.txt")) do
    local body = raw_line
    local hash = raw_line:find("#", 1, true)
    if hash ~= nil then
      body = raw_line:sub(1, hash - 1)
    end
    local stripped = trim(body)
    if stripped ~= "" then
      local semi = stripped:find(";", 1, true)
      if semi ~= nil then
        local range_field = trim(stripped:sub(1, semi - 1))
        local prop_field = trim(stripped:sub(semi + 1))
        if prop_field == property then
          local dots = range_field:find("..", 1, true)
          if dots ~= nil then
            local lo = tonumber(trim(range_field:sub(1, dots - 1)), 16)
            local hi = tonumber(trim(range_field:sub(dots + 2)), 16)
            if lo ~= nil and hi ~= nil then
              out[#out + 1] = { lo, hi }
            end
          else
            local single = tonumber(range_field, 16)
            if single ~= nil then
              out[#out + 1] = { single, single }
            end
          end
        end
      end
    end
  end
  return out
end

local _modifier_base_ranges = nil
local _presentation_ranges = nil

local function emoji_modifier_base_ranges()
  if _modifier_base_ranges == nil then
    _modifier_base_ranges = parse_emoji_property("Emoji_Modifier_Base")
  end
  return _modifier_base_ranges
end

local function emoji_presentation_ranges()
  if _presentation_ranges == nil then
    _presentation_ranges = parse_emoji_property("Emoji_Presentation")
  end
  return _presentation_ranges
end

local function in_ranges(ranges, cp)
  for _, range in ipairs(ranges) do
    if range[1] <= cp and cp <= range[2] then
      return true
    end
  end
  return false
end

-- ─────────────────────────────────────────────────────────────────────
-- §2 Core predicates (reuse the port's own emoji tables)
-- ─────────────────────────────────────────────────────────────────────

-- True iff `cp` is an emoji skin-tone modifier (reuses the emoji-zwj-integrity
-- predicate: the U+1F3FB..U+1F3FF set).
local function is_skin_tone(cp)
  return emoji_zwj.is_emoji_modifier(cp)
end
M.is_skin_tone = is_skin_tone

-- True iff `cp` has `Emoji_Modifier_Base` per emoji-data.txt.
local function is_skin_tone_base(cp)
  return in_ranges(emoji_modifier_base_ranges(), cp)
end
M.is_skin_tone_base = is_skin_tone_base

-- True iff `cp` has `Emoji_Presentation` per emoji-data.txt.
local function is_emoji_presentation(cp)
  return in_ranges(emoji_presentation_ranges(), cp)
end
M.is_emoji_presentation = is_emoji_presentation

-- True iff `cp` is U+FE0E (VS15, text-style variation selector).
local function is_vs15(cp)
  return cp == 0xFE0E
end
M.is_vs15 = is_vs15

-- True iff `cp` is U+FE0F (VS16, emoji-style variation selector).
local function is_vs16(cp)
  return cp == 0xFE0F
end
M.is_vs16 = is_vs16

-- ─────────────────────────────────────────────────────────────────────
-- §3 Sub-detectors
-- ─────────────────────────────────────────────────────────────────────

-- `input` stores codepoints 1-based; the detector reasons in 0-based positions.
-- `at(input, idx)` reads the codepoint at 0-based `idx`, or nil past the end.
local function at(input, idx)
  return input[idx + 1]
end

-- First 0-based position `p` whose next two codepoints are both skin-tone
-- modifiers, as `base_pos, { mod1, mod2 }`. Returns nil when none.
local function first_stacked_skin_tones(input)
  for i = 0, #input - 1 do
    local m1 = at(input, i + 1)
    local m2 = at(input, i + 2)
    if m1 ~= nil and m2 ~= nil and is_skin_tone(m1) and is_skin_tone(m2) then
      return i, { m1, m2 }
    end
  end
  return nil, nil
end

-- First skin-tone modifier whose preceding codepoint is NOT `Emoji_Modifier_Base`,
-- as `base_pos, base_cp, modifier_cp`. Returns nil when none.
local function first_invalid_skin_tone_target(input)
  for i = 0, #input - 1 do
    local cp = at(input, i + 1)
    if cp ~= nil and is_skin_tone(cp) and not is_skin_tone_base(at(input, i)) then
      return i, at(input, i), cp
    end
  end
  return nil, nil, nil
end

-- First U+FE0E whose preceding codepoint has `Emoji_Presentation`, as
-- `base_pos, base_cp`. Returns nil when none.
local function first_forced_text_style(input)
  for i = 0, #input - 1 do
    local cp = at(input, i + 1)
    if cp ~= nil and is_vs15(cp) and is_emoji_presentation(at(input, i)) then
      return i, at(input, i)
    end
  end
  return nil, nil
end

local function count_where(input, pred)
  local count = 0
  for i = 1, #input do
    if pred(input[i]) then
      count = count + 1
    end
  end
  return count
end

-- ─────────────────────────────────────────────────────────────────────
-- §4 Top-level detection
-- ─────────────────────────────────────────────────────────────────────

-- The SkinToneVariationForgery detection function. Returns a verdict table
-- mirroring the Lean `Verdict`: `input`, `classify` (`{ kind, sub, positions,
-- decoded }`), `skin_tone_count`, `variation_selector15_count`,
-- `variation_selector16_count`.
function M.detect(input)
  local st_count = count_where(input, is_skin_tone)
  local v15_count = count_where(input, is_vs15)
  local v16_count = count_where(input, is_vs16)

  local classification
  local stacked_pos, stacked_mods = first_stacked_skin_tones(input)
  if stacked_pos ~= nil then
    -- Priority 1: a base followed by two stacked skin tones.
    local positions = {}
    for k = 0, #stacked_mods - 1 do
      positions[#positions + 1] = stacked_pos + 1 + k
    end
    classification = {
      kind = "hazard",
      sub = { tag = "StackedSkinTones", base_pos = stacked_pos, modifiers = stacked_mods },
      positions = positions,
      decoded = {},
    }
  else
    local invalid_pos, invalid_base, invalid_mod = first_invalid_skin_tone_target(input)
    if invalid_pos ~= nil then
      -- Priority 2: a skin tone on a non-modifier-base.
      classification = {
        kind = "hazard",
        sub = {
          tag = "InvalidSkinToneTarget",
          base_pos = invalid_pos,
          base_cp = invalid_base,
          modifier_cp = invalid_mod,
        },
        positions = { invalid_pos + 1 },
        decoded = {},
      }
    else
      local forced_pos, forced_base = first_forced_text_style(input)
      if forced_pos ~= nil then
        -- Priority 3: VS15 forcing text style on an emoji-presentation cp.
        classification = {
          kind = "hazard",
          sub = { tag = "ForcedTextStyle", base_pos = forced_pos, base_cp = forced_base },
          positions = { forced_pos + 1 },
          decoded = {},
        }
      else
        classification = { kind = "clear", sub = nil, positions = {}, decoded = {} }
      end
    end
  end

  local input_copy = {}
  if #input > 0 then
    input_copy = { unpack(input) }
  end

  return {
    input = input_copy,
    classify = classification,
    skin_tone_count = st_count,
    variation_selector15_count = v15_count,
    variation_selector16_count = v16_count,
  }
end

-- True iff the verdict's classification is Clear.
function M.is_clear(verdict)
  return verdict.classify.kind == "clear"
end

-- Human-facing tag for a verdict's classification, or nil when clear.
function M.classification_tag(verdict)
  if verdict.classify.sub == nil then
    return nil
  end
  return verdict.classify.sub.tag
end

return M
