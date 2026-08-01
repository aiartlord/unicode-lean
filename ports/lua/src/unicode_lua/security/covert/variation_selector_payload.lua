-- Detection of GlassWorm-class invisible payloads encoded in Unicode variation
-- selectors (U+FE00..U+FE0F ∪ U+E0100..U+E01EF).  Exempts (base, VS) pairs that
-- appear in StandardizedVariants.txt or emoji-variation-sequences.txt.
-- Positions are 0-based codepoint offsets.

local bit = require("bit")
local datapath = require("unicode_lua.datapath")
local calculus = require("unicode_lua.security.calculus")
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

-- Returns { kind, sub, vs_positions (0-based), recovered_bytes }.
function M.detect(input)
  local vs_positions = {}
  for i = 1, #input do
    if M.is_variation_selector(input[i]) then
      vs_positions[#vs_positions + 1] = i - 1
    end
  end

  local v = { kind = ClassificationKind.Clear, sub = nil, vs_positions = vs_positions, recovered_bytes = {} }

  if #vs_positions == 0 then
    return v
  end

  v.recovered_bytes = decode_vs_run(input, vs_positions)

  -- Single-VS registered-pair exemption.
  if #vs_positions == 1 then
    local p = vs_positions[1]
    if p > 0 then
      local base = input[p - 1 + 1]
      local vs = input[p + 1]
      if M.is_registered_variation_pair(base, vs) then
        return v
      end
    end
  end

  v.kind = ClassificationKind.Hazard

  if #vs_positions >= 4 and all_same_vs(input, vs_positions) then
    local p0 = vs_positions[1]
    local base
    if p0 == 0 then
      base = 0
    else
      base = input[p0 - 1 + 1]
    end
    v.sub = { tag = "RepeatedBase", base_cp = base, vs_count = #vs_positions }
  elseif #v.recovered_bytes > 0 then
    v.sub = { tag = "DirectPayload", decoded = lossy_ascii(v.recovered_bytes) }
  else
    local p = vs_positions[1]
    local target
    if p == 0 then
      target = 0
    else
      target = input[p - 1 + 1]
    end
    v.sub = { tag = "IllegalTarget", target_cp = target, vs_cp = input[p + 1] }
  end
  return v
end

return M
