-- Opaque text predicate — structurally valid UTF-8, size-bounded.
--
-- No character-class or codepoint filtering beyond UTF-8 validity. Intended
-- for callers who apply their own text hardening downstream; hardened
-- identifier and printable profiles layer on top of this predicate. Byte
-- sequences are 1-indexed tables of integers in this port.

local utf8mod = require("unicode_lua.utf8")

local M = {}

-- Opaque-blob predicate: structurally valid UTF-8. Named so the "blob" framing
-- (no character-class hardening) is explicit at the call site.
function M.is_utf8_blob(data)
  return utf8mod.is_valid_utf8(data)
end

-- Build a blob under the size bound max_bytes. Returns nil when either the
-- bound or UTF-8 validity is violated; otherwise a table { value, max_bytes }.
function M.of(data, max_bytes)
  if #data > max_bytes then
    return nil
  end
  if not M.is_utf8_blob(data) then
    return nil
  end
  return { value = data, max_bytes = max_bytes }
end

return M
