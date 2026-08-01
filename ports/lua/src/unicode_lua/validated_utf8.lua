-- Refinement type for bytes validated as strict RFC 3629 UTF-8.
--
-- The validity claim is pinned at the module boundary: the only way to build a
-- validated value is via M.validate, which routes through the strict decoder
-- state machine. A consumer that wants the raw bytes calls M.unwrap, which
-- reads as "I am consuming the RFC 3629 claim here". Byte sequences are
-- 1-indexed tables of integers in this port.

local utf8mod = require("unicode_lua.utf8")

local M = {}

-- Validate data and, on success, return a value { bytes = data } carrying the
-- RFC 3629 validity claim. Returns nil when the bytes fail the strict machine.
function M.validate(data)
  if not utf8mod.is_valid_utf8(data) then
    return nil
  end
  return { bytes = data }
end

-- Borrow the validated bytes.
function M.as_bytes(validated)
  return validated.bytes
end

-- Consume the validity claim, returning the underlying bytes.
function M.unwrap(validated)
  return validated.bytes
end

return M
