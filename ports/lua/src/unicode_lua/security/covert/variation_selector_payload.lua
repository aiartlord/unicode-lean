-- Detection of GlassWorm-class invisible payloads encoded in Unicode variation
-- selectors (U+FE00..U+FE0F ∪ U+E0100..U+E01EF).  Exempts (base, VS) pairs that
-- appear in StandardizedVariants.txt or emoji-variation-sequences.txt.
-- Positions are 0-based codepoint offsets.

local bit = require("bit")
local datapath = require("unicode_lua.datapath")
local calculus = require("unicode_lua.security.calculus")
local ai_watermark = require("unicode_lua.security.crypto.ai_watermark_detectability")
local ClassificationKind = calculus.ClassificationKind

local M = {}

local function iter_lines(text)
  return (text .. "\n"):gmatch("([^\n]*)\n")
end

local function trim(s)
  return (s:gsub("^%s*(.-)%s*$", "%1"))
end

local function parse_hex_u32(s)
  return tonumber(trim(s), 16)
end

local function pair_key(base, vs)
  return base * 0x110000 + vs
end

local _legal_pairs = nil

local function parse_legal_pairs()
  local out = {}
  for _, name in ipairs({ "StandardizedVariants.txt", "emoji-variation-sequences.txt" }) do
    local text = datapath.read(name)
    for raw_line in iter_lines(text) do
      local hash = raw_line:find("#", 1, true)
      local body = raw_line
      if hash ~= nil then
        body = raw_line:sub(1, hash - 1)
      end
      local stripped = trim(body)
      if stripped ~= "" then
        local semi = stripped:find(";", 1, true)
        local pair_part = stripped
        if semi ~= nil then
          pair_part = stripped:sub(1, semi - 1)
        end
        local tokens = {}
        for tok in pair_part:gmatch("%S+") do
          tokens[#tokens + 1] = tok
        end
        if #tokens >= 2 then
          local base = parse_hex_u32(tokens[1])
          local vs = parse_hex_u32(tokens[2])
          if base ~= nil and vs ~= nil then
            out[pair_key(base, vs)] = true
          end
        end
      end
    end
  end
  return out
end

local function legal_pairs()
  if _legal_pairs == nil then
    _legal_pairs = parse_legal_pairs()
  end
  return _legal_pairs
end

function M.is_registered_variation_pair(base, vs)
  return legal_pairs()[pair_key(base, vs)] == true
end

function M.is_variation_selector(cp)
  return (cp >= 0xFE00 and cp <= 0xFE0F)
    or (cp >= 0xE0100 and cp <= 0xE01EF)
    or (cp >= 0x180B and cp <= 0x180D)
end

-- Decode a single VS codepoint to its nibble value in [0, 255]; nil for FVS.
function M.vs_to_nibble(cp)
  if cp >= 0xFE00 and cp <= 0xFE0F then
    return cp - 0xFE00
  elseif cp >= 0xE0100 and cp <= 0xE01EF then
    return cp - 0xE0100 + 16
  else
    return nil
  end
end

-- `positions` is a 0-based list.
local function decode_vs_run(input, positions)
  local out = {}
  local high = nil
  for _, p in ipairs(positions) do
    local n = M.vs_to_nibble(input[p + 1])
    if n ~= nil then
      if high == nil then
        high = n
      else
        out[#out + 1] = bit.bor(bit.lshift(high, 4), n)
        high = nil
      end
    end
  end
  return out
end

local function all_same_vs(input, positions)
  if #positions == 0 then
    return true
  end
  local cp0 = input[positions[1] + 1]
  for _, p in ipairs(positions) do
    if input[p + 1] ~= cp0 then
      return false
    end
  end
  return true
end

local function lossy_ascii(bytes)
  local out = {}
  for _, b in ipairs(bytes) do
    if (b >= 0x20 and b <= 0x7E) or b == 0x09 or b == 0x0A or b == 0x0D then
      out[#out + 1] = string.char(b)
    else
      out[#out + 1] = "?"
    end
  end
  return table.concat(out)
end

-- A selector on `base` is a registered use when the pair is registered
-- (StandardizedVariants plus the emoji variation sequences) or when it is
-- VS15/VS16 on an Emoji-property base. Mirrors the Lean isRegisteredUse.
function M.is_registered_variation_use(base, vs)
  if M.is_registered_variation_pair(base, vs) then
    return true
  end
  return (vs == 0xFE0E or vs == 0xFE0F) and ai_watermark.is_emoji(base)
end

-- Returns { kind, sub, vs_positions (0-based), suspicious_positions (0-based),
-- recovered_bytes }. A selector is suspicious unless it is a registered use of
-- its base; an input whose selectors are all registered is clear. Otherwise
-- the verdict ranks EmbeddedAfterRegistered (a registered use precedes the
-- first suspicious selector), RepeatedBase (at least four suspicious
-- selectors, all the same codepoint), DirectPayload (the nibble pairs over the
-- suspicious selectors recover at least one byte), else IllegalTarget. The
-- finding localises the suspicious selectors. Mirrors the Lean detect.
function M.detect(input)
  local vs_positions = {}
  local suspicious = {}
  local first_registered = nil
  for i = 1, #input do
    if M.is_variation_selector(input[i]) then
      vs_positions[#vs_positions + 1] = i - 1
      if i > 1 and M.is_registered_variation_use(input[i - 1], input[i]) then
        if first_registered == nil then
          first_registered = i - 1
        end
      else
        suspicious[#suspicious + 1] = i - 1
      end
    end
  end

  local v = {
    kind = ClassificationKind.Clear,
    sub = nil,
    vs_positions = vs_positions,
    suspicious_positions = suspicious,
    recovered_bytes = {},
  }

  if #suspicious == 0 then
    return v
  end

  v.recovered_bytes = decode_vs_run(input, suspicious)
  v.kind = ClassificationKind.Hazard

  local p = suspicious[1]
  local base
  if p == 0 then
    base = 0
  else
    base = input[p]
  end
  if first_registered ~= nil and first_registered < p then
    v.sub = { tag = "EmbeddedAfterRegistered", registered_pos = first_registered, suspicious_pos = p }
  elseif #suspicious >= 4 and all_same_vs(input, suspicious) then
    v.sub = { tag = "RepeatedBase", base_cp = base, vs_count = #suspicious }
  elseif #v.recovered_bytes > 0 then
    v.sub = { tag = "DirectPayload", decoded = lossy_ascii(v.recovered_bytes) }
  else
    v.sub = { tag = "IllegalTarget", target_cp = base, vs_cp = input[p + 1] }
  end
  return v
end

return M
