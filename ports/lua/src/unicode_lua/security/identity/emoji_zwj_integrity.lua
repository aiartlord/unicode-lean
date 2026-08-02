-- emoji-zwj-integrity — detection of malformed / unsanctioned emoji ZWJ-sequence
-- shapes per UTS #51 (the identity-layer detector I3).
--
-- Direct port of `Unicode/Security/Identity/EmojiZwjIntegrity.lean` via the
-- verified Rust reference `emoji_zwj_integrity.rs`.
--
-- Threat model. An adversary crafts an emoji-shaped codepoint sequence
-- containing one or more U+200D ZERO WIDTH JOINERs but violating the sanctioned
-- RGI ZWJ-sequence shape — by exceeding the RGI length cap, by joining a
-- non-emoji codepoint, by emitting adjacent ZWJ pairs, or by overflowing the
-- skin-tone count. Any non-RGI ZWJ-containing sequence is renderer-dependent,
-- and that renderer divergence is the attack surface.
--
-- Sanctioning data. UTS #51 defines the RGI ZWJ sequences in
-- `emoji-zwj-sequences.txt`, bundled in the port's own
-- `data/emoji-zwj-sequences.txt` (never a host emoji library). The registered
-- set gives both the exact-match membership test (`is_registered_zwj_sequence`)
-- and the ZWJ *alphabet* — every distinct codepoint occurring at any position
-- of any registered sequence, excluding the joiner — which is the canonical
-- "what may flank a ZWJ?" predicate.
--
-- Algorithm (one pass over `input`).
--   Phase 1 — collect ZWJ positions and the skin-tone count.
--   Phase 2 — short-circuit Clear if there are no ZWJs and the skin-tone count
--             is at most 1.
--   Phase 3 — a registered RGI sequence is always Clear.
--   Phase 4 — check sub-threats by priority: DoubleZWJ -> NonEmojiInjection ->
--             OverLength -> SkinToneOverflow -> UnregisteredSequence.
--
-- Codepoint positions are 0-based to mirror the reference.

local datapath = require("unicode_lua.datapath")

local unpack = table.unpack or unpack

local M = {}

-- ─────────────────────────────────────────────────────────────────────
-- §1 Constants
-- ─────────────────────────────────────────────────────────────────────

-- Conservative cap on the length of a sanctioned RGI ZWJ sequence
-- (`maxRgiLength` in the Lean spec). The longest current entry (a four-person
-- family with skin tones) reaches ~13-14 codepoints; 16 is a safe upper bound.
M.MAX_RGI_LENGTH = 16

-- The ZERO WIDTH JOINER codepoint.
M.ZWJ = 0x200D

-- ─────────────────────────────────────────────────────────────────────
-- §2 RGI ZWJ-sequence data (bundled data/emoji-zwj-sequences.txt)
-- ─────────────────────────────────────────────────────────────────────

local function iter_lines(text)
  return (text .. "\n"):gmatch("([^\n]*)\n")
end

local function trim(s)
  return (s:gsub("^%s*(.-)%s*$", "%1"))
end

local _zwj_sequences = nil
local _zwj_alphabet = nil

-- Parse the registered RGI ZWJ sequences from `emoji-zwj-sequences.txt`. Each
-- non-comment row is `<cp> <cp> ... ; RGI_Emoji_ZWJ_Sequence ; <desc> # <cmt>`;
-- the codepoint list is the field before the first `;`.
local function parse_zwj_sequences()
  local out = {}
  for raw_line in iter_lines(datapath.read("emoji-zwj-sequences.txt")) do
    local body = raw_line
    local hash = raw_line:find("#", 1, true)
    if hash ~= nil then
      body = raw_line:sub(1, hash - 1)
    end
    local stripped = trim(body)
    if stripped ~= "" then
      local semi = stripped:find(";", 1, true)
      local seq_field
      if semi ~= nil then
        seq_field = stripped:sub(1, semi - 1)
      else
        seq_field = stripped
      end
      local seq = {}
      local parsed_ok = true
      for token in seq_field:gmatch("%S+") do
        local cp = tonumber(token, 16)
        if cp == nil then
          parsed_ok = false
          break
        end
        seq[#seq + 1] = cp
      end
      if parsed_ok and #seq > 0 then
        out[#out + 1] = seq
      end
    end
  end
  return out
end

local function zwj_sequences()
  if _zwj_sequences == nil then
    _zwj_sequences = parse_zwj_sequences()
  end
  return _zwj_sequences
end

-- The ZWJ alphabet: every distinct codepoint occurring at any position of any
-- registered RGI ZWJ sequence, excluding the joiner U+200D itself.
local function zwj_alphabet()
  if _zwj_alphabet == nil then
    local set = {}
    for _, seq in ipairs(zwj_sequences()) do
      for _, cp in ipairs(seq) do
        if cp ~= M.ZWJ then
          set[cp] = true
        end
      end
    end
    _zwj_alphabet = set
  end
  return _zwj_alphabet
end

-- True iff `cps` is exactly a registered RGI ZWJ sequence.
function M.is_registered_zwj_sequence(cps)
  for _, seq in ipairs(zwj_sequences()) do
    if #seq == #cps then
      local same = true
      for i = 1, #seq do
        if seq[i] ~= cps[i] then
          same = false
          break
        end
      end
      if same then
        return true
      end
    end
  end
  return false
end

-- True iff `cp` appears at some position of a registered RGI ZWJ sequence (the
-- canonical "what may flank a ZWJ?" predicate).
function M.is_emoji_target(cp)
  return zwj_alphabet()[cp] == true
end

-- ─────────────────────────────────────────────────────────────────────
-- §3 Core predicates
-- ─────────────────────────────────────────────────────────────────────

-- True iff `cp` is the ZWJ codepoint.
local function is_zwj(cp)
  return cp == M.ZWJ
end
M.is_zwj = is_zwj

-- True iff `cp` is an emoji skin-tone modifier (U+1F3FB..U+1F3FF).
local function is_emoji_modifier(cp)
  return cp >= 0x1F3FB and cp <= 0x1F3FF
end
M.is_emoji_modifier = is_emoji_modifier

-- Positions (0-based) of every ZWJ in `input`.
local function zwj_positions(input)
  local out = {}
  for i = 1, #input do
    if is_zwj(input[i]) then
      out[#out + 1] = i - 1
    end
  end
  return out
end

-- Count of skin-tone modifier codepoints.
local function skin_tone_count(input)
  local count = 0
  for i = 1, #input do
    if is_emoji_modifier(input[i]) then
      count = count + 1
    end
  end
  return count
end

-- Positions (0-based) of the first ZWJ in each ZWJ-ZWJ adjacent pair.
local function double_zwj_positions(input)
  local out = {}
  for i = 1, #input do
    local nxt = input[i + 1]
    if nxt ~= nil then
      if is_zwj(input[i]) and is_zwj(nxt) then
        out[#out + 1] = i - 1
      end
    end
  end
  return out
end

-- The first ZWJ position (0-based) where either neighbour is a non-emoji
-- codepoint, as `zwj_pos, offending_cp`. A ZWJ at an input edge (no preceding
-- or no following codepoint) is itself an injection-class hazard, reported with
-- offending codepoint 0. Returns nil when no injection is found.
local function first_non_emoji_injection(input)
  for i = 1, #input do
    if is_zwj(input[i]) then
      local prev
      if i == 1 then
        prev = nil
      else
        prev = input[i - 1]
      end
      local nxt = input[i + 1]
      if prev ~= nil and nxt ~= nil then
        if not M.is_emoji_target(prev) then
          return i - 1, prev
        elseif not M.is_emoji_target(nxt) then
          return i - 1, nxt
        end
      elseif prev == nil then
        return i - 1, 0
      else
        -- prev ~= nil and nxt == nil
        return i - 1, 0
      end
    end
  end
  return nil, nil
end

-- ─────────────────────────────────────────────────────────────────────
-- §4 Top-level detection
-- ─────────────────────────────────────────────────────────────────────

-- The EmojiZwjIntegrity detection function. Returns a verdict table mirroring
-- the Lean `Verdict`: `input`, `classify` (`{ kind, sub, positions, decoded }`),
-- `zwj_positions`, `chain_length`, `is_registered_rgi`, `skin_tone_count`.
function M.detect(input)
  local zwjs = zwj_positions(input)
  local st_count = skin_tone_count(input)
  local is_rgi = M.is_registered_zwj_sequence(input)
  local chain_len
  if #zwjs == 0 then
    chain_len = 0
  else
    chain_len = #input
  end

  local input_copy = {}
  if #input > 0 then
    input_copy = { unpack(input) }
  end

  if #zwjs == 0 and st_count <= 1 then
    return {
      input = input_copy,
      classify = { kind = "clear", sub = nil, positions = {}, decoded = {} },
      zwj_positions = {},
      chain_length = 0,
      is_registered_rgi = is_rgi,
      skin_tone_count = st_count,
    }
  end

  local classification
  if is_rgi then
    -- Phase 3: a registered RGI sequence is always clear.
    classification = { kind = "clear", sub = nil, positions = {}, decoded = {} }
  else
    -- Phase 4.1: ZWJ-ZWJ adjacency.
    local dzwj = double_zwj_positions(input)
    if #dzwj > 0 then
      classification = {
        kind = "hazard",
        sub = { tag = "DoubleZWJ", positions = dzwj },
        positions = dzwj,
        decoded = {},
      }
    else
      -- Phase 4.2: ZWJ adjacent to a non-emoji codepoint.
      local zwj_pos, offend_cp = first_non_emoji_injection(input)
      if zwj_pos ~= nil then
        classification = {
          kind = "hazard",
          sub = { tag = "NonEmojiInjection", zwj_pos = zwj_pos, non_emoji_cp = offend_cp },
          positions = { zwj_pos },
          decoded = {},
        }
      elseif #input > M.MAX_RGI_LENGTH then
        -- Phase 4.3: length cap.
        classification = {
          kind = "hazard",
          sub = { tag = "OverLength", length = #input, max_length = M.MAX_RGI_LENGTH },
          positions = {},
          decoded = {},
        }
      elseif st_count >= 5 then
        -- Phase 4.4: skin-tone overflow.
        classification = {
          kind = "hazard",
          sub = { tag = "SkinToneOverflow", count = st_count },
          positions = {},
          decoded = {},
        }
      elseif #zwjs > 0 then
        -- Phase 4.5: catch-all for unregistered ZWJ sequences.
        classification = {
          kind = "hazard",
          sub = { tag = "UnregisteredSequence", chain_len = #input },
          positions = zwjs,
          decoded = {},
        }
      else
        classification = { kind = "clear", sub = nil, positions = {}, decoded = {} }
      end
    end
  end

  return {
    input = input_copy,
    classify = classification,
    zwj_positions = zwjs,
    chain_length = chain_len,
    is_registered_rgi = is_rgi,
    skin_tone_count = st_count,
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
