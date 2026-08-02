local h = require("test_helper")
local policy = require("unicode_lua.security.policy")
local calculus = require("unicode_lua.security.calculus")
local ifd = require("unicode_lua.security.boundary.identifier_form_drift")

local Family = calculus.Family

local function tag(input)
  return ifd.classification_tag(ifd.detect(input))
end

-- ── Shared context-free fixture ─────────────────────────────────────────
-- Run every case through the detector and map the classification to the family
-- reason code, exactly as the policy layer would.

local fixture = h.json_file("testdata/fixtures/security/detectors/identifier_form_drift.json")
local fixture_cases = 0
for _, case in ipairs(fixture.cases) do
  fixture_cases = fixture_cases + 1
  local verdict = ifd.detect(case.input)
  local t = ifd.classification_tag(verdict)
  local codes = {}
  if t ~= nil then
    codes[#codes + 1] = policy.reason_code(Family.IdentifierFormDrift, t)
  end
  for _, required in ipairs(case.required_findings) do
    h.assert_includes(codes, required, "fixture/" .. case.name)
  end
  if #case.required_findings == 0 and t ~= nil then
    error("fixture/" .. case.name .. " unexpected finding " .. t)
  end
end

-- ── §4 detect spot checks (one per Rust theorem) ─────────────────────────

-- detect_empty_clear
local vempty = ifd.detect({})
h.assert_equal(ifd.is_clear(vempty), true, "empty is clear")
h.assert_equal(ifd.classification_tag(vempty), nil, "empty tag nil")

-- detect_ascii_clear — "Hello"; every ASCII letter is Allowed, identity NFKD.
local vascii = ifd.detect({ 0x48, 0x65, 0x6C, 0x6C, 0x6F })
h.assert_equal(ifd.is_clear(vascii), true, "ascii hello clear")
h.assert_equal(vascii.shift_count, 0, "ascii hello shift_count 0")

-- detect_greek_alpha_clear — U+03B1 is Allowed with identity NFKD.
h.assert_equal(ifd.is_clear(ifd.detect({ 0x03B1 })), true, "greek alpha clear")

-- detect_math_italic_a_shift — U+1D44E Restricted, NFKD head U+0061 Allowed.
local vmath = ifd.detect({ 0x1D44E })
h.assert_equal(ifd.classification_tag(vmath), "IdentifierStatusShift", "math italic a shift")
h.assert_equal(vmath.classify.positions, { 0 }, "math italic a positions")
h.assert_equal(vmath.shift_count, 1, "math italic a shift_count")

-- detect_fullwidth_A_shift — U+FF21 Restricted, NFKD head U+0041 Allowed.
h.assert_equal(tag({ 0xFF21 }), "IdentifierStatusShift", "fullwidth A shift")

-- detect_circled_A_shift — U+24B6 CIRCLED LATIN CAPITAL LETTER A → Allowed (A).
h.assert_equal(tag({ 0x24B6 }), "IdentifierStatusShift", "circled A shift")

-- detect_fi_ligature_shift — U+FB01 'ﬁ' ligature → Allowed (f).
h.assert_equal(tag({ 0xFB01 }), "IdentifierStatusShift", "fi ligature shift")

-- detect_roman_iv_shift — U+2163 ROMAN NUMERAL FOUR → Allowed (I).
h.assert_equal(tag({ 0x2163 }), "IdentifierStatusShift", "roman iv shift")

-- detect_reports_first_shift_position — "ab" + U+1D44E: position 2 shifts.
local vmid = ifd.detect({ 0x61, 0x62, 0x1D44E })
h.assert_equal(vmid.classify.positions, { 2 }, "first shift position [2]")
h.assert_equal(vmid.shift_count, 1, "mid-string shift_count 1")

-- reason_code_is_stable — the composed reason code for the sole sub-threat.
h.assert_equal(
  policy.reason_code(Family.IdentifierFormDrift, "IdentifierStatusShift"),
  "unicode.security.X.identifier-form-drift.IdentifierStatusShift",
  "reason code stable"
)

print("identifier_form_drift: fixture cases = " .. fixture_cases)
