local casing = require("unicode_lua.security.casing")

local M = {}

local function suffix_from(input, start_idx)
  local out = {}
  for i = start_idx, #input do
    out[#out + 1] = input[i]
  end
  return out
end

local function arrays_equal(a, b)
  if #a ~= #b then
    return false
  end
  for i = 1, #a do
    if a[i] ~= b[i] then
      return false
    end
  end
  return true
end

local function first_locale_divergence(locale, input)
  local rev_prefix = {}
  for i = 1, #input do
    local cp = input[i]
    local suffix = suffix_from(input, i + 1)
    local default_lower = casing.lower_codepoint(casing.Locale.DEFAULT, rev_prefix, suffix, cp)
    local locale_lower = casing.lower_codepoint(locale, rev_prefix, suffix, cp)
    if not arrays_equal(default_lower, locale_lower) then
      return i - 1
    end
    table.insert(rev_prefix, 1, cp)
  end
  return nil
end

function M.detect(input)
  local turkish = first_locale_divergence(casing.Locale.TURKISH, input)
  if turkish ~= nil then
    return { sub = "TurkishCaseDivergence", positions = { turkish } }
  end
  local lithuanian = first_locale_divergence(casing.Locale.LITHUANIAN, input)
  if lithuanian ~= nil then
    return { sub = "LithuanianCaseDivergence", positions = { lithuanian } }
  end
  return { sub = nil, positions = {} }
end

return M
