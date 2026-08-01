local h = require("test_helper")
local locale = require("unicode_lua.security.form.locale_case_inversion")
local nfc = require("unicode_lua.security.form.nfc_idempotence_witness")
local bomb = require("unicode_lua.security.form.normalization_bomb")
local bip39 = require("unicode_lua.security.crypto.bip39_canonical")

local function assert_nil(v, label)
  if v ~= nil then
    error(label .. " expected nil")
  end
end

assert_nil(locale.detect({}).sub, "locale empty")
assert_nil(locale.detect({ 0x48, 0x65, 0x6C, 0x6C, 0x6F }).sub, "locale ascii")
h.assert_equal(locale.detect({ 0x0049 }).sub, "TurkishCaseDivergence", "locale I")
h.assert_equal(locale.detect({ 0x0049 }).positions, { 0 }, "locale I pos")
h.assert_equal(locale.detect({ 0x0130 }).sub, "TurkishCaseDivergence", "locale dotted I")
h.assert_equal(locale.detect({ 0x0049, 0x0300 }).sub, "TurkishCaseDivergence", "locale priority")
h.assert_equal(locale.detect({ 0x004A, 0x0300 }).sub, "LithuanianCaseDivergence", "locale lt")

assert_nil(nfc.detect({}).sub, "nfc empty")
assert_nil(nfc.detect({ 0x48, 0x65, 0x6C, 0x6C, 0x6F }).sub, "nfc ascii")
assert_nil(nfc.detect({ 0x00E9 }).sub, "nfc composed")
h.assert_equal(nfc.detect({ 0x0065, 0x0301 }).sub, "NonNfcForm", "nfc decomposed")
h.assert_equal(nfc.detect({ 0x0065, 0x0301 }).positions, { 0 }, "nfc pos")
h.assert_equal(nfc.detect({ 0xFB01 }).sub, "NonNfkcCompatForm", "nfkc ligature")

assert_nil(bomb.detect({}).sub, "bomb empty")
assert_nil(bomb.detect({ 0x48, 0x65, 0x6C, 0x6C, 0x6F }).sub, "bomb ascii")
assert_nil(bomb.detect({ 0xD55C }).sub, "bomb korean")
assert_nil(bomb.detect({ 0x2460 }).sub, "bomb circled")
h.assert_equal(bomb.detect({ 0xFDFA }).sub, "SingleCpBlowup", "bomb blowup")
h.assert_equal(bomb.detect({ 0xFDFA }).positions, { 0 }, "bomb blowup pos")
h.assert_equal(bomb.detect({ 0xFDFB }).sub, "NfkdHighExpansion", "bomb nfkd")
h.assert_equal(bomb.detect({ 0x1F82 }).sub, "NfdHighExpansion", "bomb nfd")

local abandon = { 0x61, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E }
local about = { 0x61, 0x62, 0x6F, 0x75, 0x74 }
h.assert_equal(bip39.bip39_canonical({ 0x61, 0x20, 0x20, 0x62 }), { 0x61, 0x20, 0x62 }, "bip39 collapse")
h.assert_equal(bip39.bip39_canonical({ 0x41 }), { 0x61 }, "bip39 lower")
h.assert_equal(bip39.detect({ table.unpack(abandon), 0x20 }).sub, "TrailingWhitespace", "bip39 trailing")
h.assert_equal(bip39.detect({ 0x41, 0x62, 0x61, 0x6E, 0x64, 0x6F, 0x6E }).sub, "MixedCase", "bip39 case")
local double_ws = { table.unpack(abandon) }
double_ws[#double_ws + 1] = 0x20
double_ws[#double_ws + 1] = 0x20
for _, cp in ipairs(about) do double_ws[#double_ws + 1] = cp end
h.assert_equal(bip39.detect(double_ws).sub, "WhitespaceAnomaly", "bip39 ws")
h.assert_equal(bip39.detect({ 0xFB00 }).sub, "NonNFKD", "bip39 nfkd")
h.assert_equal(bip39.detect({ 0x71, 0x7A, 0x71, 0x7A }).sub, "WordlistMismatch", "bip39 word")
local mnemonic = {}
for _ = 1, 11 do
  for _, cp in ipairs(abandon) do mnemonic[#mnemonic + 1] = cp end
  mnemonic[#mnemonic + 1] = 0x20
end
for _, cp in ipairs(about) do mnemonic[#mnemonic + 1] = cp end
local verdict = bip39.detect(mnemonic)
assert_nil(verdict.sub, "bip39 clear")
h.assert_equal(verdict.language, "english", "bip39 lang")
h.assert_equal(verdict.word_count, 12, "bip39 count")
