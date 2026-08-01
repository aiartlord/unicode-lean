local ucd = require("unicode_lua.security.identity.ucd")

local M = {}

local function first_divergence(a, b)
  local common = math.min(#a, #b)
  for i = 1, common do
    if a[i] ~= b[i] then
      return i - 1
    end
  end
  if #a ~= #b then
    return common
  end
  return nil
end

function M.detect(input)
  local nfc = ucd.to_nfc(input)
  local pos = first_divergence(input, nfc)
  if pos ~= nil then
    return { sub = "NonNfcForm", positions = { pos } }
  end
  local nfkc = ucd.to_nfkc(input)
  pos = first_divergence(input, nfkc)
  if pos ~= nil then
    return { sub = "NonNfkcCompatForm", positions = { pos } }
  end
  return { sub = nil, positions = {} }
end

return M
