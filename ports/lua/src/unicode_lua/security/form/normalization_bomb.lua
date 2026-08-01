local ucd = require("unicode_lua.security.identity.ucd")

local M = {}

local MAX_NFKD_PER_CP = 8
local NFD_RATIO_PCT = 300
local NFKD_RATIO_PCT = 400

local function first_blowup_cp(input)
  for i = 1, #input do
    if #ucd.to_nfkd({ input[i] }) > MAX_NFKD_PER_CP then
      return i - 1
    end
  end
  return nil
end

local function nfd_ratio_pct(input)
  if #input == 0 then
    return 0
  end
  return math.floor(#ucd.to_nfd(input) * 100 / #input)
end

local function nfkd_ratio_pct(input)
  if #input == 0 then
    return 0
  end
  return math.floor(#ucd.to_nfkd(input) * 100 / #input)
end

function M.detect(input)
  local pos = first_blowup_cp(input)
  if pos ~= nil then
    return { sub = "SingleCpBlowup", positions = { pos } }
  end
  if nfkd_ratio_pct(input) > NFKD_RATIO_PCT then
    return { sub = "NfkdHighExpansion", positions = {} }
  end
  if nfd_ratio_pct(input) > NFD_RATIO_PCT then
    return { sub = "NfdHighExpansion", positions = {} }
  end
  return { sub = nil, positions = {} }
end

return M
