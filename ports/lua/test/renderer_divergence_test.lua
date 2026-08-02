local h = require("test_helper")
local policy = require("unicode_lua.security.policy")
local calculus = require("unicode_lua.security.calculus")
local rd = require("unicode_lua.security.display.renderer_divergence")

local Family = calculus.Family

local function tag(input)
  return rd.classification_tag(rd.detect(input))
end

-- ── Shared context-free fixture ─────────────────────────────────────────
-- Run every case through the detector and map the classification to the
-- family reason code, exactly as the policy layer would.

local fixture = h.json_file("testdata/fixtures/security/detectors/renderer_divergence.json")
local fixture_cases = 0
for _, case in ipairs(fixture.cases) do
  fixture_cases = fixture_cases + 1
  local verdict = rd.detect(case.input)
  local t = rd.classification_tag(verdict)
  local codes = {}
  if t ~= nil then
    codes[#codes + 1] = policy.reason_code(Family.RendererDivergence, t)
  end
  for _, required in ipairs(case.required_findings) do
    h.assert_includes(codes, required, "fixture/" .. case.name)
  end
  if #case.required_findings == 0 and t ~= nil then
    error("fixture/" .. case.name .. " unexpected finding " .. t)
  end
end

-- ── data-layer sanity (reused predicates) ────────────────────────────────

h.assert_equal(rd.is_variation_selector(0xFE0F), true, "vs FE0F")
h.assert_equal(rd.is_variation_selector(0xE0100), true, "vs E0100")
h.assert_equal(rd.is_variation_selector(0x0041), false, "vs reject A")
h.assert_equal(rd.is_grapheme_extend(0x0301), true, "extend combining acute")
h.assert_equal(rd.is_grapheme_extend(0x0061), false, "extend reject a")
h.assert_equal(rd.is_fullwidth_halfwidth(0xFF21), true, "fullwidth A")
h.assert_equal(rd.is_fullwidth_halfwidth(0xFF00), false, "fullwidth below block")
h.assert_equal(rd.is_zwj(0x200D), true, "zwj")

-- ── §5 detect spot checks (one per Rust theorem) ─────────────────────────

-- detect_empty_clear
local vempty = rd.detect({})
h.assert_equal(rd.is_clear(vempty), true, "empty is clear")
h.assert_equal(rd.classification_tag(vempty), nil, "empty tag nil")

-- detect_ascii_clear
h.assert_equal(tag({ 0x48, 0x65, 0x6C, 0x6C, 0x6F }), nil, "ascii clear")

-- detect_han_clear
h.assert_equal(tag({ 0x4E2D, 0x6587 }), nil, "han clear")

-- detect_vs_variance — a single VS (FE0F) after an emoji.
h.assert_equal(tag({ 0x1F600, 0xFE0F }), "VariationSelectorVariance", "vs variance")

-- detect_rgi_family_clear — a registered RGI family ZWJ sequence.
local vfam = rd.detect({ 0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467, 0x200D, 0x1F466 })
h.assert_equal(rd.is_clear(vfam), true, "rgi family clear")
h.assert_equal(vfam.has_zwj, true, "rgi family has_zwj")

-- detect_unregistered_zwj_variance — man + ZWJ + woman, not in RGI.
h.assert_equal(tag({ 0x1F468, 0x200D, 0x1F469 }), "UnregisteredZwjVariance", "unregistered zwj variance")

-- detect_zalgo_variance — a 4-deep combining stack.
local vzalgo = rd.detect({ 0x0061, 0x0301, 0x0302, 0x0303, 0x0304 })
h.assert_equal(rd.classification_tag(vzalgo), "CombiningStackOverflow", "zalgo tag")
h.assert_equal(vzalgo.classify.positions, { 0 }, "zalgo positions")
h.assert_equal(vzalgo.combining_count, 4, "zalgo combining_count")

-- detect_fullwidth_variance — fullwidth 'A'.
h.assert_equal(tag({ 0xFF21 }), "FullwidthVariance", "fullwidth variance")

-- detect_mixed_direction — Latin + Hebrew in one input.
local vmixed = rd.detect({ 0x41, 0x42, 0x05D0, 0x05D1 })
h.assert_equal(rd.classification_tag(vmixed), "MixedDirectionVariance", "mixed direction tag")
h.assert_equal(vmixed.strong_ltr_count > 0 and vmixed.strong_rtl_count > 0, true, "mixed direction counts")

-- ── priority-ladder structural checks ────────────────────────────────────

-- A combining stack outranks a variation selector present later.
local vbeats = rd.detect({ 0x0061, 0x0301, 0x0302, 0x0303, 0x0304, 0xFE0F })
h.assert_equal(rd.classification_tag(vbeats), "CombiningStackOverflow", "combining stack beats vs")

-- Exactly three combining marks is below the stack threshold — no overflow.
local vthree = rd.detect({ 0x0061, 0x0301, 0x0302, 0x0303 })
h.assert_equal(rd.classification_tag(vthree) ~= "CombiningStackOverflow", true, "three marks below threshold")

print("renderer_divergence: fixture cases = " .. fixture_cases)
