local h = require("test_helper")
local policy = require("unicode_lua.security.policy")
local calculus = require("unicode_lua.security.calculus")
local ezwj = require("unicode_lua.security.identity.emoji_zwj_integrity")

local Family = calculus.Family

local function tag(input)
  return ezwj.classification_tag(ezwj.detect(input))
end

-- ── Shared context-free fixture ─────────────────────────────────────────
-- Run every case through the detector and map the classification to the
-- family reason code, exactly as the policy layer would.

local fixture = h.json_file("testdata/fixtures/security/detectors/emoji_zwj_integrity.json")
local fixture_cases = 0
for _, case in ipairs(fixture.cases) do
  fixture_cases = fixture_cases + 1
  local verdict = ezwj.detect(case.input)
  local t = ezwj.classification_tag(verdict)
  local codes = {}
  if t ~= nil then
    codes[#codes + 1] = policy.reason_code(Family.EmojiZwjIntegrity, t)
  end
  for _, required in ipairs(case.required_findings) do
    h.assert_includes(codes, required, "fixture/" .. case.name)
  end
  if #case.required_findings == 0 and t ~= nil then
    error("fixture/" .. case.name .. " unexpected finding " .. t)
  end
end

-- ── data-layer sanity ───────────────────────────────────────────────────

h.assert_equal(ezwj.is_emoji_modifier(0x1F3FB), true, "is_emoji_modifier lo")
h.assert_equal(ezwj.is_emoji_modifier(0x1F3FF), true, "is_emoji_modifier hi")
h.assert_equal(ezwj.is_emoji_modifier(0x1F3FA), false, "is_emoji_modifier below")
h.assert_equal(ezwj.is_emoji_modifier(0x1F600), false, "is_emoji_modifier grinning")

-- U+2764 HEAVY BLACK HEART appears in couple-with-heart RGI sequences.
h.assert_equal(ezwj.is_emoji_target(0x2764), true, "alphabet admits heart")
-- U+1F468 MAN appears in family/couple RGI sequences.
h.assert_equal(ezwj.is_emoji_target(0x1F468), true, "alphabet admits man")
-- U+1F600 GRINNING FACE appears in no registered RGI ZWJ sequence.
h.assert_equal(ezwj.is_emoji_target(0x1F600), false, "alphabet rejects grinning")
-- The joiner itself is excluded from the alphabet.
h.assert_equal(ezwj.is_emoji_target(ezwj.ZWJ), false, "alphabet excludes joiner")

-- MAN + ZWJ + LAPTOP (man technologist) is a registered RGI sequence.
h.assert_equal(ezwj.is_registered_zwj_sequence({ 0x1F468, 0x200D, 0x1F4BB }), true, "man technologist registered")
-- MAN + ZWJ + WOMAN is not a registered RGI sequence.
h.assert_equal(ezwj.is_registered_zwj_sequence({ 0x1F468, 0x200D, 0x1F469 }), false, "man woman unregistered")

-- ── §5 detect spot checks (one per Rust theorem) ─────────────────────────

-- detect_empty_clear
local vempty = ezwj.detect({})
h.assert_equal(ezwj.is_clear(vempty), true, "empty is clear")
h.assert_equal(ezwj.classification_tag(vempty), nil, "empty tag nil")
h.assert_equal(vempty.zwj_positions, {}, "empty zwj_positions")
h.assert_equal(vempty.chain_length, 0, "empty chain_length")
h.assert_equal(vempty.skin_tone_count, 0, "empty skin_tone_count")

-- detect_ascii_clear
h.assert_equal(tag({ 0x48, 0x65, 0x6C, 0x6C, 0x6F }), nil, "ascii clear")

-- detect_plain_emoji_clear
h.assert_equal(tag({ 0x1F600 }), nil, "plain emoji clear")

-- detect_one_skintone_clear — a base plus a single skin-tone (count = 1).
local vone = ezwj.detect({ 0x1F44B, 0x1F3FB })
h.assert_equal(ezwj.is_clear(vone), true, "one skintone clear")
h.assert_equal(vone.skin_tone_count, 1, "one skintone count")

-- detect_family_rgi_clear — man + woman + girl + boy via ZWJs (registered).
local vfam = ezwj.detect({ 0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467, 0x200D, 0x1F466 })
h.assert_equal(ezwj.is_clear(vfam), true, "family rgi clear")
h.assert_equal(vfam.is_registered_rgi, true, "family rgi registered")

-- detect_double_zwj — ZWJ + ZWJ adjacency.
local vdz = ezwj.detect({ 0x1F600, 0x200D, 0x200D, 0x1F600 })
h.assert_equal(ezwj.classification_tag(vdz), "DoubleZWJ", "double zwj tag")
h.assert_equal(vdz.classify.positions, { 1 }, "double zwj positions")

-- detect_non_emoji_injection — ZWJ joining ASCII 'a'.
h.assert_equal(tag({ 0x1F600, 0x200D, 0x0061 }), "NonEmojiInjection", "non-emoji injection tag")

-- detect_skin_tone_overflow — five skin-tone modifiers.
local vst = ezwj.detect({ 0x1F44B, 0x1F3FB, 0x1F3FC, 0x1F3FD, 0x1F3FE, 0x1F3FF })
h.assert_equal(ezwj.classification_tag(vst), "SkinToneOverflow", "skin tone overflow tag")
h.assert_equal(vst.skin_tone_count, 5, "skin tone overflow count")

-- detect_man_laptop_registered_clear — man technologist (registered).
h.assert_equal(tag({ 0x1F468, 0x200D, 0x1F4BB }), nil, "man laptop registered clear")

-- detect_unregistered — man + ZWJ + woman: both flanks in the RGI alphabet but
-- the joined sequence is not registered.
h.assert_equal(tag({ 0x1F468, 0x200D, 0x1F469 }), "UnregisteredSequence", "unregistered tag")

-- detect_grinning_laptop_non_emoji_injection — grinning face is not a valid
-- ZWJ-join target, so this surfaces as NonEmojiInjection.
h.assert_equal(tag({ 0x1F600, 0x200D, 0x1F4BB }), "NonEmojiInjection", "grinning laptop injection")

-- ── structural checks (follow from the priority ladder) ──────────────────

-- A long chain of valid ZWJ-joined targets that is not registered and hits no
-- earlier sub-threat surfaces as OverLength once it exceeds the cap.
-- 9 men joined by 8 ZWJs = 17 codepoints (> MAX_RGI_LENGTH).
local over = {}
for i = 0, 8 do
  if i > 0 then
    over[#over + 1] = 0x200D
  end
  over[#over + 1] = 0x1F468
end
h.assert_equal(#over, 17, "over-length input length")
local vover = ezwj.detect(over)
h.assert_equal(ezwj.classification_tag(vover), "OverLength", "over-length tag")
h.assert_equal(vover.classify.sub.length, 17, "over-length length field")
h.assert_equal(vover.classify.sub.max_length, ezwj.MAX_RGI_LENGTH, "over-length max_length field")
h.assert_equal(vover.classify.positions, {}, "over-length no positions")

-- A ZWJ at the trailing edge of input is an injection-class hazard.
local vtrail = ezwj.detect({ 0x1F468, 0x200D })
h.assert_equal(ezwj.classification_tag(vtrail), "NonEmojiInjection", "trailing zwj injection tag")
h.assert_equal(vtrail.classify.positions, { 1 }, "trailing zwj injection positions")
h.assert_equal(vtrail.classify.sub.non_emoji_cp, 0, "trailing zwj edge cp is 0")

-- Double-ZWJ wins over the unregistered catch-all (priority order).
-- man ZWJ ZWJ boy — adjacent ZWJs present.
h.assert_equal(tag({ 0x1F468, 0x200D, 0x200D, 0x1F466 }), "DoubleZWJ", "double zwj beats unregistered")

print("emoji_zwj_integrity: fixture cases = " .. fixture_cases)
