-- ai-watermark-detectability — character-level detector for inputs carrying
-- codepoint patterns consistent with a known AI watermark scheme. Answers the
-- question: does this input contain markers attributable to a watermarking
-- protocol?
--
-- Direct port of `Unicode/Security/Crypto/AiWatermarkDetectability.lean` via
-- the verified Rust reference `ai_watermark_detectability.rs`.
--
-- Threat model — provenance-attribution attacker. An input either (a) carries
-- an AI provider's watermark codepoints (a legitimate provenance marker) or
-- (b) carries injected markers that impersonate a provider's scheme to
-- discredit the content as AI-generated. Character-level detection alone cannot
-- distinguish (a) from (b); the detector reports the matched scheme and leaves
-- provider-specific authentication to downstream code.
--
-- Probe inventory (priority order, first match wins):
--
--   1. adversarial              — NNBSP count >= 3 at arithmetic-progression positions.
--   2. gpt5ZwspModulo           — ZWSP count >= 3 at arithmetic-progression positions.
--   3. unknown                  — invisible markers from >= 2 distinct categories.
--   4. nnbspBoundary            — single-category NNBSP.
--   5. variationSelectorCarrier — VS NOT adjacent to an emoji codepoint.
--   6. zwjNonEmoji              — ZWJ NOT adjacent to an emoji codepoint.
--   7. smartQuoteAlternation    — paired curly quotes, no ASCII straight quotes.
--   8. emDashPattern            — em-dashes, no ASCII hyphen-minus.
--   9. statisticalTokenChoice   — input contains an AI-favored lexical pattern.
--  10. defaultIgnorableCarrier  — single-category residual Default_Ignorable.
--
-- The Emoji property table is bundled in the port's own `data/emoji-data.txt`
-- (UTS #51 17.0, byte-identical to the UCD source the Lean spec cites); the
-- adjacency probe parses the `Emoji` rows from it, never a host emoji library.
-- Codepoint positions are 0-based to mirror the reference.

local datapath = require("unicode_lua.datapath")
local ucd = require("unicode_lua.security.identity.ucd")

local unpack = table.unpack or unpack

local M = {}

-- ─────────────────────────────────────────────────────────────────────
-- §1 Types
-- ─────────────────────────────────────────────────────────────────────

-- The conceptual watermark cue class a sub-threat probes for, drawn from the
-- fixed vocabulary in `Unicode.Generated.WatermarkSchemes.CueClass`.
M.CueClass = {
  -- A codepoint-frequency bias toward a pinned "green list" of tokens.
  GreenListBias = "GreenListBias",
  -- A fixed-period or carrier-byte channel surfacing a pseudorandom function.
  PseudorandomSeq = "PseudorandomSeq",
  -- A stylistic-distribution drift away from natural human writing.
  SemanticDrift = "SemanticDrift",
}

-- Map a sub-threat (a table carrying its `tag`) to the conceptual watermark cue
-- class it probes for. Marker-encoded sub-threats route to `PseudorandomSeq`;
-- vocabulary-bias to `GreenListBias`; stylistic-distribution to `SemanticDrift`;
-- `Unknown` (multi-category mixing) implicates no single scheme.
function M.cue_class(sub)
  local tag = sub.tag
  if tag == "NnbspBoundary"
      or tag == "VariationSelectorCarrier"
      or tag == "ZwjNonEmoji"
      or tag == "DefaultIgnorableCarrier"
      or tag == "Gpt5ZwspModulo" then
    return M.CueClass.PseudorandomSeq
  elseif tag == "EmDashPattern" or tag == "SmartQuoteAlternation" then
    return M.CueClass.SemanticDrift
  elseif tag == "StatisticalTokenChoice" then
    return M.CueClass.GreenListBias
  elseif tag == "Adversarial" then
    return M.CueClass.PseudorandomSeq
  elseif tag == "Unknown" then
    return nil
  end
  error("cue_class: unknown sub-threat tag " .. tostring(tag))
end

-- ─────────────────────────────────────────────────────────────────────
-- §2 Emoji property table (bundled data/emoji-data.txt, Emoji rows)
-- ─────────────────────────────────────────────────────────────────────

local function iter_lines(text)
  return (text .. "\n"):gmatch("([^\n]*)\n")
end

local function trim(s)
  return (s:gsub("^%s*(.-)%s*$", "%1"))
end

local _emoji_ranges = nil

-- Parse the `Emoji` (`Emoji=Yes`) closed intervals from emoji-data.txt. Each
-- non-comment row is `<range> ; <property> # <comment>`; we keep only rows
-- whose property is exactly `Emoji`.
local function parse_emoji_ranges()
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
        if prop_field == "Emoji" then
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

local function emoji_ranges()
  if _emoji_ranges == nil then
    _emoji_ranges = parse_emoji_ranges()
  end
  return _emoji_ranges
end

-- True iff `cp` has the `Emoji = Yes` property per emoji-data.txt.
local function is_emoji(cp)
  for _, range in ipairs(emoji_ranges()) do
    if range[1] <= cp and cp <= range[2] then
      return true
    end
  end
  return false
end

-- ─────────────────────────────────────────────────────────────────────
-- §3 Codepoint probes
-- ─────────────────────────────────────────────────────────────────────

-- True iff `cp` is U+202F NARROW NO-BREAK SPACE.
local function is_nnbsp(cp)
  return cp == 0x202F
end

-- True iff `cp` is U+200D ZERO WIDTH JOINER.
local function is_zwj(cp)
  return cp == 0x200D
end

-- True iff `cp` is a Variation Selector — the basic block U+FE00..U+FE0F
-- (VS1..VS16) or the Plane-14 IVS block U+E0100..U+E01EF (VS17..VS256).
local function is_variation_selector(cp)
  return (cp >= 0xFE00 and cp <= 0xFE0F) or (cp >= 0xE0100 and cp <= 0xE01EF)
end

-- True iff `cp` is Default_Ignorable_Code_Point per DerivedCoreProperties.txt.
-- Reuses the port's own UCD table, never a host normalizer.
local function is_default_ignorable(cp)
  return ucd.is_default_ignorable(cp)
end

-- True iff `cp` is U+200B ZERO WIDTH SPACE.
local function is_zwsp(cp)
  return cp == 0x200B
end

-- True iff `cp` is U+2014 EM DASH.
local function is_em_dash(cp)
  return cp == 0x2014
end

-- True iff `cp` is U+002D HYPHEN-MINUS (ASCII).
local function is_hyphen_minus(cp)
  return cp == 0x002D
end

-- True iff `cp` is one of the four "curly" quotation marks: U+2018 / U+2019
-- (single open/close) and U+201C / U+201D (double open/close).
local function is_curly_quote(cp)
  return cp == 0x2018 or cp == 0x2019 or cp == 0x201C or cp == 0x201D
end

-- True iff `cp` is an ASCII straight quote — U+0022 (double) or U+0027
-- (single / apostrophe).
local function is_straight_quote(cp)
  return cp == 0x0022 or cp == 0x0027
end

-- True iff the 0-based position `i` in `input` is adjacent (immediate
-- predecessor OR immediate successor) to an emoji codepoint. Two-sided check.
-- Used by the VS and ZWJ probes to exclude legitimate emoji-context occurrences.
local function is_adjacent_to_emoji(input, i)
  local prev_is_emoji = false
  if i > 0 then
    local prev = input[i]
    if prev ~= nil then
      prev_is_emoji = is_emoji(prev)
    end
  end
  local next_is_emoji = false
  local nxt = input[i + 2]
  if nxt ~= nil then
    next_is_emoji = is_emoji(nxt)
  end
  return prev_is_emoji or next_is_emoji
end

-- All 0-based positions in `input` matching predicate `p`.
local function all_positions(p, input)
  local out = {}
  for i = 1, #input do
    if p(input[i]) then
      out[#out + 1] = i - 1
    end
  end
  return out
end

-- True iff `positions` forms an arithmetic progression with all consecutive
-- gaps within `tolerance` of the first gap. Empty + singleton lists are
-- vacuously arithmetic. `positions` is assumed ascending (produced by
-- `all_positions`), so gaps are non-negative.
local function positions_are_arithmetic_within(positions, tolerance)
  if #positions < 2 then
    return true
  end
  local first_gap = positions[2] - positions[1]
  for i = 1, #positions - 1 do
    local gap = positions[i + 1] - positions[i]
    if not (gap <= first_gap + tolerance and first_gap <= gap + tolerance) then
      return false
    end
  end
  return true
end

-- First 0-based start-position at which `pattern` appears as a contiguous
-- sub-slice of `input`, or nil if absent.
local function contains_sublist(pattern, input)
  if #pattern == 0 or #pattern > #input then
    return nil
  end
  local max_start = #input - #pattern
  for start = 0, max_start do
    local matches = true
    for k = 1, #pattern do
      if input[start + k] ~= pattern[k] then
        matches = false
        break
      end
    end
    if matches then
      return start
    end
  end
  return nil
end

-- The "AI-favored" lexical-pattern catalog (each word as its codepoint
-- sequence), transcribed verbatim from the pinned `aiFavoredVocabulary` literal
-- in the Lean spec (parsed from `Ucd/Security/AiFavoredVocabulary.txt` and
-- drift-gated there against a fresh parse).
local AI_FAVORED_VOCABULARY = {
  { 100, 101, 108, 118, 101 },
  { 100, 101, 108, 118, 105, 110, 103 },
  { 116, 97, 112, 101, 115, 116, 114, 121 },
  { 105, 110, 116, 114, 105, 99, 97, 116, 101 },
  { 110, 117, 97, 110, 99, 101, 100 },
  { 109, 111, 114, 101, 111, 118, 101, 114 },
  { 102, 117, 114, 116, 104, 101, 114, 109, 111, 114, 101 },
  { 114, 101, 97, 108, 109 },
  { 101, 108, 117, 99, 105, 100, 97, 116, 101 },
  { 115, 104, 111, 119, 99, 97, 115, 105, 110, 103 },
  { 117, 110, 100, 101, 114, 115, 99, 111, 114, 101, 115 },
  { 117, 110, 100, 101, 114, 115, 99, 111, 114, 101, 100 },
  { 112, 105, 118, 111, 116, 97, 108 },
  { 98, 111, 108, 115, 116, 101, 114 },
  { 109, 117, 108, 116, 105, 102, 97, 99, 101, 116, 101, 100 },
  { 116, 101, 115, 116, 97, 109, 101, 110, 116 },
  { 102, 111, 115, 116, 101, 114 },
  { 104, 111, 108, 105, 115, 116, 105, 99 },
  { 112, 97, 114, 97, 100, 105, 103, 109 },
  { 116, 114, 97, 110, 115, 102, 111, 114, 109, 97, 116, 105, 118, 101 },
  { 115, 112, 101, 97, 114, 104, 101, 97, 100 },
  { 109, 101, 116, 105, 99, 117, 108, 111, 117, 115 },
  { 109, 101, 116, 105, 99, 117, 108, 111, 117, 115, 108, 121 },
  { 101, 109, 112, 111, 119, 101, 114 },
  { 101, 109, 112, 111, 119, 101, 114, 105, 110, 103 },
  { 112, 114, 111, 102, 111, 117, 110, 100 },
  { 112, 114, 111, 102, 111, 117, 110, 100, 108, 121 },
  { 99, 111, 109, 112, 101, 108, 108, 105, 110, 103 },
  { 99, 111, 109, 112, 114, 101, 104, 101, 110, 115, 105, 118, 101 },
  { 99, 114, 117, 99, 105, 97, 108 },
  { 100, 97, 117, 110, 116, 105, 110, 103 },
  { 114, 111, 98, 117, 115, 116 },
  { 115, 116, 114, 101, 97, 109, 108, 105, 110, 101 },
  { 101, 110, 114, 105, 99, 104 },
  { 101, 120, 101, 109, 112, 108, 105, 102, 121 },
  { 99, 97, 112, 116, 105, 118, 97, 116, 105, 110, 103 },
  { 100, 105, 115, 99, 101, 114, 110, 105, 110, 103 },
  { 109, 101, 115, 109, 101, 114, 105, 122, 101 },
  { 105, 110, 116, 114, 105, 99, 97, 116, 101, 108, 121 },
  { 105, 109, 98, 117, 101 },
  { 112, 108, 97, 121, 115, 32, 97, 32, 99, 114, 117, 99, 105, 97, 108, 32, 114, 111, 108, 101 },
  { 112, 108, 97, 121, 115, 32, 97, 32, 112, 105, 118, 111, 116, 97, 108, 32, 114, 111, 108, 101 },
  { 105, 116, 32, 105, 115, 32, 105, 109, 112, 111, 114, 116, 97, 110, 116, 32, 116, 111, 32, 110, 111, 116, 101 },
  { 105, 116, 32, 105, 115, 32, 119, 111, 114, 116, 104, 32, 110, 111, 116, 105, 110, 103 },
  { 105, 110, 32, 99, 111, 110, 99, 108, 117, 115, 105, 111, 110 },
  { 105, 110, 32, 101, 115, 115, 101, 110, 99, 101 },
  { 100, 101, 108, 118, 101, 32, 105, 110, 116, 111 },
  { 100, 101, 108, 118, 105, 110, 103, 32, 105, 110, 116, 111 },
  { 116, 97, 112, 101, 115, 116, 114, 121, 32, 111, 102 },
  { 114, 101, 97, 108, 109, 32, 111, 102 },
}

-- ─────────────────────────────────────────────────────────────────────
-- §4 Top-level detection
-- ─────────────────────────────────────────────────────────────────────

-- The detection function. Runs every probe in the fixed priority order
-- (most-specific first); the first hit wins. See the module header for the
-- probe inventory and the ordering rationale. `ctx` carries optional fields
-- `zwsp_modulo_tolerance` and `adversarial_tolerance`; each defaults to 0
-- (exact arithmetic).
function M.detect_with_context(ctx, input)
  local adversarial_tolerance = ctx.adversarial_tolerance or 0
  local zwsp_modulo_tolerance = ctx.zwsp_modulo_tolerance or 0

  local nnbsp_positions = all_positions(is_nnbsp, input)
  local nnbsp_count = #nnbsp_positions

  -- Probe 1: adversarial — NNBSP too-regular.
  local adversarial_fires = nnbsp_count >= 3
    and positions_are_arithmetic_within(nnbsp_positions, adversarial_tolerance)

  -- Probe 2: gpt5ZwspModulo — ZWSP arithmetic progression.
  local zwsp_positions = all_positions(is_zwsp, input)
  local zwsp_count = #zwsp_positions
  local zwsp_modulo_fires = zwsp_count >= 3
    and positions_are_arithmetic_within(zwsp_positions, zwsp_modulo_tolerance)

  local vs_all_pos = all_positions(is_variation_selector, input)
  local vs_non_emoji_pos = {}
  for _, i in ipairs(vs_all_pos) do
    if not is_adjacent_to_emoji(input, i) then
      vs_non_emoji_pos[#vs_non_emoji_pos + 1] = i
    end
  end
  local vs_non_emoji_count = #vs_non_emoji_pos

  local zwj_all_pos = all_positions(is_zwj, input)
  local zwj_non_emoji_pos = {}
  for _, i in ipairs(zwj_all_pos) do
    if not is_adjacent_to_emoji(input, i) then
      zwj_non_emoji_pos[#zwj_non_emoji_pos + 1] = i
    end
  end
  local zwj_non_emoji_count = #zwj_non_emoji_pos

  -- Probe 7: smartQuoteAlternation — curly quotes only.
  local curly_positions = all_positions(is_curly_quote, input)
  local curly_count = #curly_positions
  local has_straight_quote = false
  for i = 1, #input do
    if is_straight_quote(input[i]) then
      has_straight_quote = true
      break
    end
  end
  local smart_quote_fires = curly_count >= 2 and not has_straight_quote

  -- Probe 8: emDashPattern — em-dashes without hyphen-minus.
  local em_dash_positions = all_positions(is_em_dash, input)
  local em_dash_count = #em_dash_positions
  local has_hyphen_minus = false
  for i = 1, #input do
    if is_hyphen_minus(input[i]) then
      has_hyphen_minus = true
      break
    end
  end
  local em_dash_fires = em_dash_count >= 2 and not has_hyphen_minus

  -- Probe 9: statisticalTokenChoice — scan the pinned vocabulary. Each word is
  -- compared as a contiguous sub-slice of the input.
  local vocab_hit = nil
  for _, pattern in ipairs(AI_FAVORED_VOCABULARY) do
    local pos = contains_sublist(pattern, input)
    if pos ~= nil then
      vocab_hit = pos
      break
    end
  end

  -- Residual default-ignorables (excluding VS and ZWJ, handled above).
  local function is_residual_di(cp)
    return is_default_ignorable(cp) and not is_variation_selector(cp) and not is_zwj(cp)
  end
  local di_positions = all_positions(is_residual_di, input)
  local di_count = #di_positions

  -- Probe 3: unknown — invisible markers from >= 2 distinct categories.
  local category_count = 0
  if nnbsp_count > 0 then category_count = category_count + 1 end
  if vs_non_emoji_count > 0 then category_count = category_count + 1 end
  if zwj_non_emoji_count > 0 then category_count = category_count + 1 end
  if di_count > 0 then category_count = category_count + 1 end
  local unknown_fires = category_count >= 2
  local total_invisible_count = nnbsp_count + vs_non_emoji_count + zwj_non_emoji_count + di_count

  local classification
  local fired_count
  if adversarial_fires then
    local first_pos = nnbsp_positions[1] or 0
    classification = {
      kind = "hazard",
      sub = { tag = "Adversarial", impersonated_scheme = "nnbspBoundary", first_pos = first_pos },
      positions = nnbsp_positions,
    }
    fired_count = nnbsp_count
  elseif zwsp_modulo_fires then
    local first_pos = zwsp_positions[1] or 0
    classification = {
      kind = "hazard",
      sub = { tag = "Gpt5ZwspModulo", first_pos = first_pos },
      positions = zwsp_positions,
    }
    fired_count = zwsp_count
  elseif unknown_fires then
    local all_invisible_pos = {}
    for i = 1, #input do
      local cp = input[i]
      if is_nnbsp(cp) or is_variation_selector(cp) or is_zwj(cp) or is_default_ignorable(cp) then
        all_invisible_pos[#all_invisible_pos + 1] = i - 1
      end
    end
    classification = {
      kind = "hazard",
      sub = { tag = "Unknown", anomaly_marker = total_invisible_count },
      positions = all_invisible_pos,
    }
    fired_count = total_invisible_count
  elseif nnbsp_count > 0 then
    classification = {
      kind = "hazard",
      sub = { tag = "NnbspBoundary", marker_count = nnbsp_count },
      positions = nnbsp_positions,
    }
    fired_count = nnbsp_count
  elseif vs_non_emoji_count > 0 then
    classification = {
      kind = "hazard",
      sub = { tag = "VariationSelectorCarrier", marker_count = vs_non_emoji_count },
      positions = vs_non_emoji_pos,
    }
    fired_count = vs_non_emoji_count
  elseif zwj_non_emoji_count > 0 then
    classification = {
      kind = "hazard",
      sub = { tag = "ZwjNonEmoji", marker_count = zwj_non_emoji_count },
      positions = zwj_non_emoji_pos,
    }
    fired_count = zwj_non_emoji_count
  elseif smart_quote_fires then
    local first_pos = curly_positions[1] or 0
    classification = {
      kind = "hazard",
      sub = { tag = "SmartQuoteAlternation", first_pos = first_pos },
      positions = curly_positions,
    }
    fired_count = curly_count
  elseif em_dash_fires then
    local first_pos = em_dash_positions[1] or 0
    classification = {
      kind = "hazard",
      sub = { tag = "EmDashPattern", first_pos = first_pos },
      positions = em_dash_positions,
    }
    fired_count = em_dash_count
  elseif vocab_hit ~= nil then
    classification = {
      kind = "hazard",
      sub = { tag = "StatisticalTokenChoice", first_pos = vocab_hit },
      positions = { vocab_hit },
    }
    fired_count = 1
  elseif di_count > 0 then
    classification = {
      kind = "hazard",
      sub = { tag = "DefaultIgnorableCarrier", marker_count = di_count },
      positions = di_positions,
    }
    fired_count = di_count
  else
    classification = { kind = "clear", sub = nil, positions = {} }
    fired_count = 0
  end

  local input_copy = {}
  if #input > 0 then
    input_copy = { unpack(input) }
  end

  return {
    input = input_copy,
    classify = classification,
    marker_count = fired_count,
  }
end

-- Convenience wrapper over `detect_with_context` with the empty context —
-- exact-arithmetic settings (`zwsp_modulo_tolerance = 0`,
-- `adversarial_tolerance = 0`).
function M.detect(input)
  return M.detect_with_context({}, input)
end

-- Human-facing tag for a verdict's classification, or nil when clear.
function M.classification_tag(verdict)
  if verdict.classify.sub == nil then
    return nil
  end
  return verdict.classify.sub.tag
end

return M
