local h = require("test_helper")
local policy = require("unicode_lua.security.policy")
local calculus = require("unicode_lua.security.calculus")
local sdd = require("unicode_lua.security.display.source_display_divergence")

local Family = calculus.Family

local function tag(input)
  return sdd.classification_tag(sdd.detect(input))
end

-- ── Shared context-free fixture ─────────────────────────────────────────
-- Run every case through the detector and map the classification to the family
-- reason code, exactly as the policy layer would.

local fixture = h.json_file("testdata/fixtures/security/detectors/source_display_divergence.json")
local fixture_cases = 0
for _, case in ipairs(fixture.cases) do
  fixture_cases = fixture_cases + 1
  local t = tag(case.input)
  local codes = {}
  if t ~= nil then
    codes[#codes + 1] = policy.reason_code(Family.SourceDisplayDivergence, t)
  end
  for _, required in ipairs(case.required_findings) do
    h.assert_includes(codes, required, "fixture/" .. case.name)
  end
  if #case.required_findings == 0 and t ~= nil then
    error("fixture/" .. case.name .. " unexpected finding " .. t)
  end
end

-- ── §2 detect spot checks (one per Rust theorem) ─────────────────────────

-- clear_cases — no constituent fires.
h.assert_equal(tag({}), nil, "empty clear")
-- "Hello world"
h.assert_equal(tag({ 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64 }), nil, "hello world clear")
-- "let x = 1;"
h.assert_equal(tag({ 0x6C, 0x65, 0x74, 0x20, 0x78, 0x20, 0x3D, 0x20, 0x31, 0x3B }), nil, "let x = 1; clear")

-- single_fire_passthrough — exactly one constituent fires, its tag passes through.
-- tag-encoded "AB"
h.assert_equal(tag({ 0xE0041, 0xE0042 }), "TagBlock", "tag block passthrough")
-- A + VS16
h.assert_equal(tag({ 0x0041, 0xFE0F }), "VariationSelector", "variation selector passthrough")
-- H + ZWSP + i
h.assert_equal(tag({ 0x0048, 0x200B, 0x69 }), "ZeroWidth", "zero width passthrough")
-- RLO + A
h.assert_equal(tag({ 0x202E, 0x41 }), "BidiControl", "bidi control passthrough")
-- "Neth<Cyrillic е>um"
h.assert_equal(tag({ 0x4E, 0x65, 0x74, 0x68, 0x65, 0x72, 0x0435, 0x75, 0x6D }), "IdentifierHomoglyph", "identifier homoglyph passthrough")

-- two_or_more_is_compound — two constituents fire → Compound.
-- A + VS16 + ZWSP
h.assert_equal(tag({ 0x0041, 0xFE0F, 0x200B }), "Compound", "vs + zero width compound")
-- tag "AB" + ZWSP
h.assert_equal(tag({ 0xE0041, 0xE0042, 0x200B }), "Compound", "tag block + zero width compound")

-- is_clear accessor agrees with a nil tag.
h.assert_equal(sdd.is_clear(sdd.detect({})), true, "empty is clear")
h.assert_equal(sdd.is_clear(sdd.detect({ 0xE0041, 0xE0042 })), false, "tag block not clear")

-- reason_code_is_stable — the composed reason code for a passthrough and Compound.
h.assert_equal(
  policy.reason_code(Family.SourceDisplayDivergence, "TagBlock"),
  "unicode.security.D.source-display-divergence.TagBlock",
  "reason code tag block stable"
)
h.assert_equal(
  policy.reason_code(Family.SourceDisplayDivergence, "Compound"),
  "unicode.security.D.source-display-divergence.Compound",
  "reason code compound stable"
)

print("source_display_divergence: fixture cases = " .. fixture_cases)
