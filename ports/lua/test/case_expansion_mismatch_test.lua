local h = require("test_helper")
local policy = require("unicode_lua.security.policy")
local calculus = require("unicode_lua.security.calculus")
local cem = require("unicode_lua.security.form.case_expansion_mismatch")

local Family = calculus.Family

local function tag(input)
  return cem.classification_tag(cem.detect(input))
end

-- ── Shared context-free fixture ─────────────────────────────────────────
-- Run every case through the detector and map the classification to the family
-- reason code, exactly as the policy layer would.

local fixture = h.json_file("testdata/fixtures/security/detectors/case_expansion_mismatch.json")
local fixture_cases = 0
for _, case in ipairs(fixture.cases) do
  fixture_cases = fixture_cases + 1
  local verdict = cem.detect(case.input)
  local t = cem.classification_tag(verdict)
  local codes = {}
  if t ~= nil then
    codes[#codes + 1] = policy.reason_code(Family.CaseExpansionMismatch, t)
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
local vempty = cem.detect({})
h.assert_equal(cem.is_clear(vempty), true, "empty is clear")
h.assert_equal(cem.classification_tag(vempty), nil, "empty tag nil")

-- detect_ascii_clear — "Hello"; every ASCII cp case-maps to a single cp.
local vascii = cem.detect({ 0x48, 0x65, 0x6C, 0x6C, 0x6F })
h.assert_equal(cem.is_clear(vascii), true, "ascii clear")
h.assert_equal(vascii.max_expansion_len, 1, "ascii max_expansion_len")

-- detect_sharp_s_upper — ß (U+00DF) toUpper → "SS".
local vsharp = cem.detect({ 0x00DF })
h.assert_equal(cem.classification_tag(vsharp), "UpperExpansion", "sharp s tag")
h.assert_equal(cem.positions(vsharp), { 0 }, "sharp s positions")
h.assert_equal(vsharp.upper_expansion_count, 1, "sharp s upper count")
h.assert_equal(vsharp.max_expansion_len, 2, "sharp s max_expansion_len")

-- detect_fi_ligature_upper — ﬁ (U+FB01) toUpper → "FI".
h.assert_equal(tag({ 0xFB01 }), "UpperExpansion", "fi ligature tag")

-- detect_dotted_I_lower — İ (U+0130) toLower under default → "i + 0307";
-- no upper expansion, so the detector falls through to the lower scan.
local vdot = cem.detect({ 0x0130 })
h.assert_equal(cem.classification_tag(vdot), "LowerExpansion", "dotted I tag")
h.assert_equal(vdot.lower_expansion_count, 1, "dotted I lower count")

-- ﬃ (U+FB03) toUpper → "FFI" (length 3) — the expansion length is reported.
local vffi = cem.detect({ 0xFB03 })
h.assert_equal(cem.classification_tag(vffi), "UpperExpansion", "ffi ligature tag")
h.assert_equal(vffi.max_expansion_len, 3, "ffi ligature max_expansion_len")

-- A leading ASCII then ß: the upper expansion is reported at 0-based position 1.
local vmid = cem.detect({ 0x61, 0x00DF })
h.assert_equal(cem.positions(vmid), { 1 }, "mid-string positions")

-- ── reason code stability ────────────────────────────────────────────────

h.assert_equal(
  policy.reason_code(Family.CaseExpansionMismatch, "UpperExpansion"),
  "unicode.security.F.case-expansion-mismatch.UpperExpansion",
  "upper reason code"
)
h.assert_equal(
  policy.reason_code(Family.CaseExpansionMismatch, "LowerExpansion"),
  "unicode.security.F.case-expansion-mismatch.LowerExpansion",
  "lower reason code"
)

print("case_expansion_mismatch: fixture cases = " .. fixture_cases)
