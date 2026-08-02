-- FilenameDisguise — detection of filename/extension disguise attacks where the
-- visible extension differs from the byte extension (the display-layer
-- detector).
--
-- Byte-faithful transcription of the verified Rust reference implementation,
-- itself a transcription of `Unicode/Security/Display/FilenameDisguise.lean`.
--
-- Threat model. An adversary delivers a file whose rendered name looks like a
-- benign type (`document.txt`) but whose actual byte extension is executable —
-- the canonical attack inserts U+202E RIGHT-TO-LEFT OVERRIDE so
-- `document<RLO>txt.exe` renders as `document exe.txt`.
--
-- What the detector draws. Detection is presentation- and language-agnostic: it
-- surfaces every codepoint that could cause display-vs-byte divergence in the
-- filename — any bidi format-control anywhere, and any fullwidth/halfwidth or
-- combining (grapheme Extend) codepoint in the extension region (after the last
-- `.`). Native-RTL names with no bidi controls clear. It reuses the port's own
-- tables (the BidiControlBalance format-control set, the grapheme-segmentation
-- Extend class, the inlined fullwidth range), never a host filesystem or
-- rendering library.
--
-- Sub-threats (priority order):
--   1. RloFlip            any bidi format-control in the input.
--   2. WidthClassExt      a fullwidth/halfwidth codepoint in the extension.
--   3. CombiningInExt     a combining (Extend) codepoint in the extension.
--   4. MultipleExtensions >= 3 dots (advisory; e.g. legitimate `.tar.gz.sig`).
--
-- Codepoint positions are 0-based to mirror the reference.

local bidi = require("unicode_lua.security.covert.bidi_control_balance")
local grapheme = require("unicode_lua.segmentation.grapheme")

local unpack = table.unpack or unpack

local M = {}

-- ─────────────────────────────────────────────────────────────────────
-- §1 Constants
-- ─────────────────────────────────────────────────────────────────────

-- The count of `.` separators at or beyond which the name is treated as a
-- multiple-extension advisory hazard.
M.MIN_MULTI_EXT = 3

-- ─────────────────────────────────────────────────────────────────────
-- §2 Core predicates (reuse the port's own tables)
-- ─────────────────────────────────────────────────────────────────────

-- True iff `cp` is U+002E FULL STOP (the extension separator).
function M.is_ascii_dot(cp)
  return cp == 0x002E
end

-- True iff `cp` is in the Halfwidth and Fullwidth Forms block.
function M.is_fullwidth_halfwidth(cp)
  return cp >= 0xFF01 and cp <= 0xFFEF
end

-- True iff `cp` is a bidi format-control (reuses the BidiControlBalance
-- predicate over the LRE/RLE/LRO/RLO/PDF/LRI/RLI/FSI/PDI set).
function M.is_bidi_format_control(cp)
  return bidi.is_bidi_format_control(cp)
end

-- True iff `cp` has Grapheme_Cluster_Break = Extend (reuses the grapheme-
-- segmentation GCB table via `lookup_gcb`, exactly as the Rust reference does).
function M.is_grapheme_extend(cp)
  return grapheme.lookup_gcb(cp) == "Extend"
end

-- ─────────────────────────────────────────────────────────────────────
-- §3 Sub-detectors
-- ─────────────────────────────────────────────────────────────────────

-- 0-based positions of every `.` in `input`.
local function dot_positions(input)
  local dots = {}
  for i = 1, #input do
    if M.is_ascii_dot(input[i]) then
      dots[#dots + 1] = i - 1
    end
  end
  return dots
end

-- Position (0-based) and codepoint of the first bidi format-control, or nil.
local function first_bidi_control(input)
  for i = 1, #input do
    if M.is_bidi_format_control(input[i]) then
      return i - 1, input[i]
    end
  end
  return nil, nil
end

-- Position (0-based) and codepoint of the first fullwidth/halfwidth codepoint
-- at or after the 0-based `start`, or nil.
local function first_fullwidth_from(input, start)
  for i = 1, #input do
    local idx = i - 1
    if idx >= start and M.is_fullwidth_halfwidth(input[i]) then
      return idx, input[i]
    end
  end
  return nil, nil
end

-- Position (0-based) and codepoint of the first Extend codepoint at or after
-- the 0-based `start`, or nil.
local function first_extend_from(input, start)
  for i = 1, #input do
    local idx = i - 1
    if idx >= start and M.is_grapheme_extend(input[i]) then
      return idx, input[i]
    end
  end
  return nil, nil
end

-- Count of fullwidth/halfwidth codepoints at or after the 0-based `start`.
local function count_fullwidth_from(input, start)
  local count = 0
  for i = 1, #input do
    if (i - 1) >= start and M.is_fullwidth_halfwidth(input[i]) then
      count = count + 1
    end
  end
  return count
end

-- Count of Extend codepoints at or after the 0-based `start`.
local function count_extend_from(input, start)
  local count = 0
  for i = 1, #input do
    if (i - 1) >= start and M.is_grapheme_extend(input[i]) then
      count = count + 1
    end
  end
  return count
end

-- Count of bidi format-controls anywhere in `input`.
local function count_bidi_control(input)
  local count = 0
  for i = 1, #input do
    if M.is_bidi_format_control(input[i]) then
      count = count + 1
    end
  end
  return count
end

-- ─────────────────────────────────────────────────────────────────────
-- §4 Top-level detection
-- ─────────────────────────────────────────────────────────────────────

-- The FilenameDisguise detection function. Returns a verdict table mirroring
-- the Rust `Verdict`: `input`, `classify` (`{ kind, sub, positions, decoded }`),
-- `dot_positions`, `last_dot_pos`, `bidi_control_count`, `fullwidth_in_ext`,
-- `combining_in_ext`.
function M.detect(input)
  local dots = dot_positions(input)
  local last_dot = nil
  if #dots > 0 then
    last_dot = dots[#dots]
  end
  local ext_start
  if last_dot ~= nil then
    ext_start = last_dot + 1
  else
    ext_start = #input
  end

  local bidi_count = count_bidi_control(input)
  local fw_in_ext = count_fullwidth_from(input, ext_start)
  local ext_in_ext = count_extend_from(input, ext_start)

  local classify
  -- Priority 1: any bidi format-control.
  local bidi_pos, bidi_cp = first_bidi_control(input)
  if bidi_pos ~= nil then
    classify = {
      kind = "Hazard",
      sub = { tag = "RloFlip", position = bidi_pos, control_cp = bidi_cp },
      positions = { bidi_pos },
      decoded = {},
    }
  else
    -- Priority 2: fullwidth/halfwidth in the extension.
    local fw_pos, fw_cp = first_fullwidth_from(input, ext_start)
    if fw_pos ~= nil then
      classify = {
        kind = "Hazard",
        sub = { tag = "WidthClassExt", position = fw_pos, cp = fw_cp },
        positions = { fw_pos },
        decoded = {},
      }
    else
      -- Priority 3: combining mark in the extension.
      local ext_pos, ext_cp = first_extend_from(input, ext_start)
      if ext_pos ~= nil then
        classify = {
          kind = "Hazard",
          sub = { tag = "CombiningInExt", position = ext_pos, cp = ext_cp },
          positions = { ext_pos },
          decoded = {},
        }
      elseif #dots >= M.MIN_MULTI_EXT then
        -- Priority 4: three or more extensions (advisory).
        local dots_copy = { unpack(dots) }
        classify = {
          kind = "Hazard",
          sub = { tag = "MultipleExtensions", dot_count = #dots },
          positions = dots_copy,
          decoded = {},
        }
      else
        classify = { kind = "Clear", sub = nil, positions = {}, decoded = {} }
      end
    end
  end

  local input_copy = {}
  if #input > 0 then
    input_copy = { unpack(input) }
  end

  return {
    input = input_copy,
    classify = classify,
    dot_positions = dots,
    last_dot_pos = last_dot,
    bidi_control_count = bidi_count,
    fullwidth_in_ext = fw_in_ext,
    combining_in_ext = ext_in_ext,
  }
end

-- True iff the verdict's classification is Clear.
function M.is_clear(verdict)
  return verdict.classify.kind == "Clear"
end

-- Human-facing tag for a verdict's classification, or nil when clear. Exhaustive
-- over the four sub-threats; an unknown tag is a construction bug and raises.
function M.classification_tag(verdict)
  local sub = verdict.classify.sub
  if sub == nil then
    return nil
  end
  local tag = sub.tag
  if tag == "RloFlip" then
    return "RloFlip"
  elseif tag == "WidthClassExt" then
    return "WidthClassExt"
  elseif tag == "CombiningInExt" then
    return "CombiningInExt"
  elseif tag == "MultipleExtensions" then
    return "MultipleExtensions"
  else
    error("classification_tag: unknown FilenameDisguise sub-threat " .. tostring(tag))
  end
end

-- Implicated positions (empty when clear).
function M.classification_positions(verdict)
  return verdict.classify.positions
end

return M
