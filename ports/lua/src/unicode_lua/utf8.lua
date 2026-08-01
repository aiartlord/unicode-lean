-- Strict UTF-8 codec — validator and decoder.
--
-- The accepted byte set is exactly the strict RFC 3629 acceptance language: it
-- rejects overlong encodings, surrogate codepoints (U+D800..U+DFFF), codepoints
-- beyond U+10FFFF, truncated multi-byte sequences, invalid start bytes, and
-- invalid continuation bytes.  Byte inputs are 1-indexed tables of integers in
-- [0, 255]; reported offsets are 0-based, matching the shared decode fixtures.
--
-- Offset convention for `first_invalid_utf8_offset`: the returned offset is the
-- index of the byte on which the state machine transitions to reject.  For
-- `OverlongEncoding` the offset is the start byte of the sequence.

local bit = require("bit")
local strict = require("unicode_lua.strict")

local Utf8RejectKind = strict.Utf8RejectKind

local M = {}

-- Decoder state is a table:
--   { start = true }
--   { start = false, remaining = <int>, accum = <int>, min_cp = <int> }
-- A step returns one of:
--   "continue", state
--   "emit", cp, state
--   "reject", reject_kind

local function state_start()
  return { start = true }
end

-- Process one byte given the current state.
function M.utf8_decode_step(state, byte)
  local n = byte
  if state.start then
    if n < 0x80 then
      return "emit", n, state_start()
    elseif n < 0xC2 then
      return "reject", Utf8RejectKind.InvalidStartByte
    elseif n < 0xE0 then
      return "continue", { start = false, remaining = 1, accum = bit.band(n, 0x1F), min_cp = 0x80 }
    elseif n < 0xF0 then
      return "continue", { start = false, remaining = 2, accum = bit.band(n, 0x0F), min_cp = 0x800 }
    elseif n < 0xF5 then
      return "continue", { start = false, remaining = 3, accum = bit.band(n, 0x07), min_cp = 0x10000 }
    else
      return "reject", Utf8RejectKind.InvalidStartByte
    end
  else
    if n < 0x80 or n >= 0xC0 then
      return "reject", Utf8RejectKind.InvalidContinuationByte
    end
    local next_accum = bit.bor(bit.lshift(state.accum, 6), bit.band(n, 0x3F))
    if state.remaining == 1 then
      if next_accum < state.min_cp then
        return "reject", Utf8RejectKind.OverlongEncoding
      elseif next_accum >= 0xD800 and next_accum <= 0xDFFF then
        return "reject", Utf8RejectKind.SurrogateCodepoint
      elseif next_accum > 0x10FFFF then
        return "reject", Utf8RejectKind.CodepointBeyondMax
      else
        return "emit", next_accum, state_start()
      end
    else
      return "continue", { start = false, remaining = state.remaining - 1, accum = next_accum, min_cp = state.min_cp }
    end
  end
end

-- The first byte offset (0-based) at which the strict UTF-8 state machine
-- rejects, plus the reject kind; returns nil when the input is valid UTF-8.
-- `bytes` is a 1-indexed table of integers.
function M.first_invalid_utf8_offset(bytes)
  local state = state_start()
  local seq_start = 0
  local len = #bytes
  for idx = 1, len do
    local i = idx - 1
    local b = bytes[idx]
    if state.start then
      seq_start = i
    end
    local result, a, _c = M.utf8_decode_step(state, b)
    if result == "continue" then
      state = a
    elseif result == "emit" then
      state = _c
    else -- "reject"
      local kind = a
      if kind == Utf8RejectKind.OverlongEncoding then
        return seq_start, kind
      end
      return i, kind
    end
  end
  if not state.start then
    return len, Utf8RejectKind.TruncatedSequence
  end
  return nil
end

-- Whole-input validity predicate.
function M.is_valid_utf8(bytes)
  return M.first_invalid_utf8_offset(bytes) == nil
end

-- Decode a UTF-8 byte table to a codepoint table (1-indexed).  On malformed
-- input the walker yields the longest valid prefix and stops.
function M.decode_to_codepoints(bytes)
  local out = {}
  local state = state_start()
  for idx = 1, #bytes do
    local b = bytes[idx]
    local result, a, c = M.utf8_decode_step(state, b)
    if result == "continue" then
      state = a
    elseif result == "emit" then
      out[#out + 1] = a
      state = c
    else -- "reject"
      return out
    end
  end
  return out
end

-- Encode a single codepoint as a 1-4 byte UTF-8 sequence (1-indexed table).
function M.encode_codepoint(cp)
  if cp < 0x80 then
    return { cp }
  elseif cp < 0x800 then
    return {
      bit.bor(0xC0, bit.rshift(cp, 6)),
      bit.bor(0x80, bit.band(cp, 0x3F)),
    }
  elseif cp < 0x10000 then
    return {
      bit.bor(0xE0, bit.rshift(cp, 12)),
      bit.bor(0x80, bit.band(bit.rshift(cp, 6), 0x3F)),
      bit.bor(0x80, bit.band(cp, 0x3F)),
    }
  else
    return {
      bit.bor(0xF0, bit.rshift(cp, 18)),
      bit.bor(0x80, bit.band(bit.rshift(cp, 12), 0x3F)),
      bit.bor(0x80, bit.band(bit.rshift(cp, 6), 0x3F)),
      bit.bor(0x80, bit.band(cp, 0x3F)),
    }
  end
end

-- Concatenate the UTF-8 encodings of a codepoint table.
function M.encode_codepoints(cps)
  local out = {}
  for idx = 1, #cps do
    local enc = M.encode_codepoint(cps[idx])
    for j = 1, #enc do
      out[#out + 1] = enc[j]
    end
  end
  return out
end

return M
