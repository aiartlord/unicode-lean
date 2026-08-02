local h = require("test_helper")
local policy = require("unicode_lua.security.policy")
local calculus = require("unicode_lua.security.calculus")
local stvf = require("unicode_lua.security.identity.skin_tone_variation_forgery")

local Family = calculus.Family

local function tag(input)
  return stvf.classification_tag(stvf.detect(input))
end

-- ── Shared context-free fixture ─────────────────────────────────────────
-- Drive every case through the detector and map the classification to the
-- family reason code, exactly as the policy layer would.

local fixture = h.json_file("testdata/fixtures/security/detectors/skin_tone_variation_forgery.json")
local fixture_cases = 0
for _, case in ipairs(fixture.cases) do
  fixture_cases = fixture_cases + 1
  local verdict = stvf.detect(case.input)
  local t = stvf.classification_tag(verdict)
  local codes = {}
  if t ~= nil then
    codes[#codes + 1] = policy.reason_code(Family.SkinToneVariationForgery, t)
  end
  for _, required in ipairs(case.required_findings) do
    h.assert_includes(codes, required, "fixture/" .. case.name)
  end
  if #case.required_findings == 0 and t ~= nil then
    error("fixture/" .. case.name .. " unexpected finding " .. t)
  end
end

-- ── §6 detect spot checks (one per Rust theorem) ─────────────────────────

-- detect_empty_clear
local vempty = stvf.detect({})
h.assert_equal(stvf.is_clear(vempty), true, "empty is clear")
h.assert_equal(stvf.classification_tag(vempty), nil, "empty tag nil")

-- detect_ascii_clear — "He"
h.assert_equal(stvf.is_clear(stvf.detect({ 0x48, 0x65 })), true, "ascii clear")

-- detect_plain_emoji_clear — grinning face
h.assert_equal(stvf.is_clear(stvf.detect({ 0x1F600 })), true, "plain emoji clear")

-- detect_wave_skin_tone_clear — waving hand (a modifier base) + one skin tone
local vwave = stvf.detect({ 0x1F44B, 0x1F3FB })
h.assert_equal(stvf.is_clear(vwave), true, "wave+single-tone clear")
h.assert_equal(vwave.skin_tone_count, 1, "wave skin_tone_count")

-- detect_stacked_skin_tones — waving hand + two skin tones
local vstack = stvf.detect({ 0x1F44B, 0x1F3FB, 0x1F3FC })
h.assert_equal(tag({ 0x1F44B, 0x1F3FB, 0x1F3FC }), "StackedSkinTones", "stacked tag")
h.assert_equal(vstack.classify.positions[1], 1, "stacked positions[1]")
h.assert_equal(vstack.classify.positions[2], 2, "stacked positions[2]")

-- detect_invalid_target_ascii — skin tone on ASCII 'A'
local vinva = stvf.detect({ 0x0041, 0x1F3FB })
h.assert_equal(stvf.classification_tag(vinva), "InvalidSkinToneTarget", "invalid-ascii tag")
h.assert_equal(vinva.classify.positions[1], 1, "invalid-ascii positions[1]")

-- detect_invalid_target_smiley — skin tone on grinning face (not a modifier base)
h.assert_equal(tag({ 0x1F600, 0x1F3FB }), "InvalidSkinToneTarget", "invalid-smiley tag")

-- detect_forced_text_style — VS15 on grinning face (Emoji_Presentation)
local vforced = stvf.detect({ 0x1F600, 0xFE0E })
h.assert_equal(stvf.classification_tag(vforced), "ForcedTextStyle", "forced-text-style tag")
h.assert_equal(vforced.variation_selector15_count, 1, "vs15 count")

-- Reused-predicate sanity: skin-tone predicate, modifier-base, presentation.
h.assert_equal(stvf.is_skin_tone(0x1F3FB), true, "1F3FB is skin tone")
h.assert_equal(stvf.is_skin_tone_base(0x1F44B), true, "1F44B is modifier base")
h.assert_equal(stvf.is_emoji_presentation(0x1F600), true, "1F600 is emoji presentation")
h.assert_equal(stvf.is_skin_tone_base(0x1F600), false, "1F600 not a modifier base")

-- Reason code composition.
h.assert_equal(
  policy.reason_code(Family.SkinToneVariationForgery, "StackedSkinTones"),
  "unicode.security.I.skin-tone-variation-forgery.StackedSkinTones",
  "reason code")

print("skin_tone_variation_forgery: fixture cases = " .. fixture_cases)
