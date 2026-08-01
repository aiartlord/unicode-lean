-- Surrogate-reassembly / malformed-byte-stream detection.  The input codepoint
-- list is treated as a byte stream (one octet per entry); the family only
-- applies when every entry is a byte (< 0x100).  The verdict projects the first
-- UTF-8 violation found by the shared strict decoder onto a covert-layer
-- sub-threat.  Positions are 0-based byte offsets.

local strict = require("unicode_lua.strict")
local utf8 = require("unicode_lua.utf8")

local Utf8RejectKind = strict.Utf8RejectKind

local M = {}

-- True iff every entry fits in one octet — the `looksLikeByteStream` gate.
function M.looks_like_byte_stream(input)
  for _, cp in ipairs(input) do
    if cp >= 0x100 then
      return false
    end
  end
  return true
end

local function sub_threat_of_reject_kind(kind)
  if kind == Utf8RejectKind.OverlongEncoding then return "Overlong" end
  if kind == Utf8RejectKind.SurrogateCodepoint then return "Cesu8" end
  if kind == Utf8RejectKind.TruncatedSequence then return "Truncated" end
  if kind == Utf8RejectKind.InvalidStartByte then return "InvalidStartByte" end
  if kind == Utf8RejectKind.InvalidContinuationByte then return "InvalidContinuation" end
  if kind == Utf8RejectKind.CodepointBeyondMax then return "CodepointBeyondMax" end
  error("surrogate_reassembly: unknown Utf8RejectKind " .. tostring(kind))
end

-- Returns { sub (string or nil), positions (0-based) }.
function M.detect(input)
  local bytes = {}
  for i = 1, #input do
    local cp = input[i]
    if cp > 0xFF then
      bytes[i] = 0xFF
    else
      bytes[i] = cp
    end
  end
  local offset, kind = utf8.first_invalid_utf8_offset(bytes)
  if offset == nil then
    return { sub = nil, positions = {} }
  end
  return { sub = sub_threat_of_reject_kind(kind), positions = { offset } }
end

return M
