-- IdentifierTokens — identifier-shaped tokens of a running-text field.
--
-- Direct port of `Unicode/Security/Identity/IdentifierTokens.lean`. A source
-- line, a chat message or a display name is not one identifier, but the
-- identifier-shaped words inside it are the surface a homoglyph attack targets
-- (`scоpe` with a Cyrillic о in `let scоpe = 1;`). A token is a maximal run of
-- `XID_Continue` codepoints; everything else (space, punctuation, operators,
-- format controls) separates tokens. Each token carries its 0-based start
-- position so a finding made on the token can be reported in input coordinates.
--
-- `XID_Continue` is the port's own `ucd.is_xid_continue` over the bundled
-- DerivedCoreProperties.txt.

local ucd = require("unicode_lua.security.identity.ucd")

local M = {}

-- The maximal `XID_Continue` runs of the input, in input order, as
-- `{ start = <0-based>, cps = { ... } }` records.
function M.tokens(input)
  local out = {}
  local start = 0
  local current = nil
  for i = 1, #input do
    local cp = input[i]
    if ucd.is_xid_continue(cp) then
      if current == nil then
        current = {}
        start = i - 1
      end
      current[#current + 1] = cp
    elseif current ~= nil then
      out[#out + 1] = { start = start, cps = current }
      current = nil
    end
  end
  if current ~= nil then
    out[#out + 1] = { start = start, cps = current }
  end
  return out
end

-- Move token-local positions back into input coordinates.
function M.shift_positions(start, positions)
  local out = {}
  for _, pos in ipairs(positions) do
    out[#out + 1] = pos + start
  end
  return out
end

return M
