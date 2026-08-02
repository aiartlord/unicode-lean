local h = require("test_helper")
local policy = require("unicode_lua.security.policy")
local calculus = require("unicode_lua.security.calculus")
local afd = require("unicode_lua.security.boundary.admissibility_form_drift")

local Family = calculus.Family

local function tag(input)
  return afd.classification_tag(afd.detect(input))
end

-- ── Shared context-free fixture ─────────────────────────────────────────
-- Run every case through the detector and map the classification to the family
-- reason code, exactly as the policy layer would.

local fixture = h.json_file("testdata/fixtures/security/detectors/admissibility_form_drift.json")
local fixture_cases = 0
for _, case in ipairs(fixture.cases) do
  fixture_cases = fixture_cases + 1
  local verdict = afd.detect(case.input)
  local t = afd.classification_tag(verdict)
  local codes = {}
  if t ~= nil then
    codes[#codes + 1] = policy.reason_code(Family.AdmissibilityFormDrift, t)
  end
  for _, required in ipairs(case.required_findings) do
    h.assert_includes(codes, required, "fixture/" .. case.name)
  end
  if #case.required_findings == 0 and t ~= nil then
    error("fixture/" .. case.name .. " unexpected finding " .. t)
  end
end

-- ── §2 detect spot checks (one per Rust theorem) ─────────────────────────

-- detect_empty_clear — both admissibility calls return false, so they agree.
local vempty = afd.detect({})
h.assert_equal(afd.is_clear(vempty), true, "empty is clear")
h.assert_equal(afd.classification_tag(vempty), nil, "empty tag nil")

-- detect_ascii_clear — "admin"; admissible on both sides (NFKC is identity).
local vascii = afd.detect({ 0x61, 0x64, 0x6D, 0x69, 0x6E })
h.assert_equal(afd.is_clear(vascii), true, "admin clear")
h.assert_equal(vascii.input_admissible, true, "admin input admissible")
h.assert_equal(vascii.nfkc_admissible, true, "admin nfkc admissible")

-- detect_fi_ligature_drift — U+FB01 'ﬁ' is Restricted (inadmissible), but NFKC
-- decomposes it to "fi" (admissible). Drift fires.
local vfi = afd.detect({ 0xFB01 })
h.assert_equal(afd.classification_tag(vfi), "AdmissibilityFormDrift", "fi ligature drift")
h.assert_equal(vfi.input_admissible, false, "fi input inadmissible")
h.assert_equal(vfi.nfkc_admissible, true, "fi nfkc admissible")

-- detect_jamo_sequence_drift — decomposed Hangul jamos [U+1112, U+1161, U+11AB]
-- are inadmissible, but NFKC composes them to U+D55C 한 (admissible).
h.assert_equal(tag({ 0x1112, 0x1161, 0x11AB }), "AdmissibilityFormDrift", "jamo sequence drift")

-- reason_code_is_stable — the composed reason code for the sole sub-threat.
h.assert_equal(
  policy.reason_code(Family.AdmissibilityFormDrift, "AdmissibilityFormDrift"),
  "unicode.security.X.admissibility-form-drift.AdmissibilityFormDrift",
  "reason code stable"
)

print("admissibility_form_drift: fixture cases = " .. fixture_cases)
