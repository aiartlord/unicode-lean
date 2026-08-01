local datapath = require("unicode_lua.datapath")
local casing = require("unicode_lua.security.casing")
local ucd = require("unicode_lua.security.identity.ucd")

local M = {}

M.WORDLIST_FILES = {
  { "english", "english.txt" },
  { "japanese", "japanese.txt" },
  { "korean", "korean.txt" },
  { "spanish", "spanish.txt" },
  { "chinese_simplified", "chinese_simplified.txt" },
  { "chinese_traditional", "chinese_traditional.txt" },
  { "french", "french.txt" },
  { "italian", "italian.txt" },
  { "czech", "czech.txt" },
  { "portuguese", "portuguese.txt" },
}

local _wordlists = nil

local function key(cps)
  return table.concat(cps, ",")
end

local function wordlist_set(raw)
  local set = {}
  for line in (raw .. "\n"):gmatch("([^\n]*)\n") do
    if line ~= "" then
      local cps = {}
      for _, cp in utf8.codes(line) do
        cps[#cps + 1] = cp
      end
      set[key(cps)] = true
    end
  end
  return set
end

local function wordlists()
  if _wordlists == nil then
    _wordlists = {}
    for _, entry in ipairs(M.WORDLIST_FILES) do
      _wordlists[#_wordlists + 1] = {
        name = entry[1],
        set = wordlist_set(datapath.read("bip39/" .. entry[2])),
      }
    end
  end
  return _wordlists
end

local function split_words(canonical)
  local words = {}
  local current = {}
  for _, cp in ipairs(canonical) do
    if cp == 0x20 then
      if #current > 0 then
        words[#words + 1] = current
        current = {}
      end
    else
      current[#current + 1] = cp
    end
  end
  if #current > 0 then
    words[#words + 1] = current
  end
  return words
end

local function wordlists_containing(word)
  local out = {}
  local k = key(word)
  for _, wl in ipairs(wordlists()) do
    if wl.set[k] then
      out[#out + 1] = wl.name
    end
  end
  return out
end

local function unique_language(words)
  for _, wl in ipairs(wordlists()) do
    local ok = true
    for _, word in ipairs(words) do
      if not wl.set[key(word)] then
        ok = false
        break
      end
    end
    if ok then
      return wl.name
    end
  end
  return nil
end

local function bip39_whitespace(cp)
  return cp == 0x20 or cp == 0x3000
end

local function collapse_whitespace_to_single(cps)
  local out = {}
  local in_ws = false
  for _, cp in ipairs(cps) do
    if bip39_whitespace(cp) then
      if not in_ws then
        out[#out + 1] = 0x20
      end
      in_ws = true
    else
      out[#out + 1] = cp
      in_ws = false
    end
  end
  return out
end

local function trim_leading_trailing(cps)
  local start_idx = nil
  for i = 1, #cps do
    if cps[i] ~= 0x20 then
      start_idx = i
      break
    end
  end
  if start_idx == nil then
    return {}
  end
  local end_idx = start_idx
  for i = #cps, start_idx, -1 do
    if cps[i] ~= 0x20 then
      end_idx = i
      break
    end
  end
  local out = {}
  for i = start_idx, end_idx do
    out[#out + 1] = cps[i]
  end
  return out
end

function M.bip39_canonical(cps)
  local nfkd = ucd.to_nfkd(cps)
  local lowered = casing.to_lower(casing.Locale.DEFAULT, nfkd)
  return trim_leading_trailing(collapse_whitespace_to_single(lowered))
end

local function count_trailing_whitespace(cps)
  local count = 0
  for i = #cps, 1, -1 do
    if not bip39_whitespace(cps[i]) then
      break
    end
    count = count + 1
  end
  return count
end

local function first_uppercase_pos(cps)
  for i = 1, #cps do
    if cps[i] >= 0x41 and cps[i] <= 0x5A then
      return i - 1
    end
  end
  return nil
end

local function first_whitespace_run_pos(cps)
  for i = 1, #cps do
    if bip39_whitespace(cps[i]) then
      if i == 1 then
        return 0
      end
      if i < #cps and bip39_whitespace(cps[i + 1]) then
        return i - 1
      end
    end
  end
  return nil
end

local function first_array_divergence(a, b)
  local n = math.min(#a, #b)
  for i = 1, n do
    if a[i] ~= b[i] then
      return i - 1
    end
  end
  if #a ~= #b then
    return n
  end
  return nil
end

local function arrays_equal(a, b)
  return first_array_divergence(a, b) == nil
end

function M.detect(input)
  local canonical = M.bip39_canonical(input)
  local words = split_words(canonical)
  local word_count = #words
  local trailing_count = count_trailing_whitespace(input)
  local uppercase_pos = first_uppercase_pos(input)
  local whitespace_pos = first_whitespace_run_pos(input)
  local nfkd = ucd.to_nfkd(input)
  local non_nfkd_pos = arrays_equal(input, nfkd) and nil or first_array_divergence(input, nfkd)
  local first_unknown_idx = nil
  for i, word in ipairs(words) do
    if #wordlists_containing(word) == 0 then
      first_unknown_idx = i - 1
      break
    end
  end

  if trailing_count > 0 then
    return { sub = "TrailingWhitespace", positions = { #input - trailing_count }, language = nil, canonical = canonical, word_count = word_count }
  elseif uppercase_pos ~= nil then
    return { sub = "MixedCase", positions = { uppercase_pos }, language = nil, canonical = canonical, word_count = word_count }
  elseif whitespace_pos ~= nil then
    return { sub = "WhitespaceAnomaly", positions = { whitespace_pos }, language = nil, canonical = canonical, word_count = word_count }
  elseif non_nfkd_pos ~= nil then
    return { sub = "NonNFKD", positions = { non_nfkd_pos }, language = nil, canonical = canonical, word_count = word_count }
  elseif first_unknown_idx ~= nil then
    return { sub = "WordlistMismatch", positions = { first_unknown_idx }, language = nil, canonical = canonical, word_count = word_count }
  end

  local lang = unique_language(words)
  if lang == nil then
    return { sub = "LanguageAmbiguous", positions = {}, language = nil, canonical = canonical, word_count = word_count }
  end
  return { sub = nil, positions = {}, language = lang, canonical = canonical, word_count = word_count }
end

return M
