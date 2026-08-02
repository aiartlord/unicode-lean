local h = require("test_helper")
local policy = require("unicode_lua.security.policy")
local calculus = require("unicode_lua.security.calculus")
local awd = require("unicode_lua.security.crypto.ai_watermark_detectability")

local Family = calculus.Family
local CueClass = awd.CueClass

local function tag(input)
  return awd.classification_tag(awd.detect(input))
end

-- ── Shared context-free fixture ─────────────────────────────────────────
-- Run every case through the detector and map the classification to the
-- family reason code, exactly as the policy layer would.

local fixture = h.json_file("testdata/fixtures/security/detectors/ai_watermark_detectability.json")
local fixture_cases = 0
for _, case in ipairs(fixture.cases) do
  fixture_cases = fixture_cases + 1
  local verdict = awd.detect(case.input)
  local t = awd.classification_tag(verdict)
  local codes = {}
  if t ~= nil then
    codes[#codes + 1] = policy.reason_code(Family.AiWatermarkDetectability, t)
  end
  for _, required in ipairs(case.required_findings) do
    h.assert_includes(codes, required, "fixture/" .. case.name)
  end
  if #case.required_findings == 0 and t ~= nil then
    error("fixture/" .. case.name .. " unexpected finding " .. t)
  end
end

-- ── §4 detect spot checks ───────────────────────────────────────────────

h.assert_equal(tag({}), nil, "detect empty clear")
h.assert_equal(tag({ 0x61, 0x62, 0x63 }), nil, "detect ascii clear")
h.assert_equal(tag({ 0x4E2D, 0x6587 }), nil, "detect han clear")

local vn = awd.detect({ 0x61, 0x202F, 0x62 })
h.assert_equal(awd.classification_tag(vn), "NnbspBoundary", "detect nnbsp tag")
h.assert_equal(vn.classify.positions, { 1 }, "detect nnbsp positions")
h.assert_equal(vn.marker_count, 1, "detect nnbsp marker_count")

local vvs = awd.detect({ 0x61, 0xFE0F, 0x62 })
h.assert_equal(awd.classification_tag(vvs), "VariationSelectorCarrier", "detect vs tag")
h.assert_equal(vvs.marker_count, 1, "detect vs marker_count")

h.assert_equal(tag({ 0x1F600, 0xFE0F }), nil, "detect vs after emoji clear")

local vzwj = awd.detect({ 0x61, 0x200D, 0x62 })
h.assert_equal(awd.classification_tag(vzwj), "ZwjNonEmoji", "detect zwj tag")
h.assert_equal(vzwj.marker_count, 1, "detect zwj marker_count")

h.assert_equal(tag({ 0x1F469, 0x200D, 0x1F52C }), nil, "detect zwj emoji sequence clear")

local vsh = awd.detect({ 0x61, 0x00AD, 0x62 })
h.assert_equal(awd.classification_tag(vsh), "DefaultIgnorableCarrier", "detect soft hyphen tag")
h.assert_equal(vsh.marker_count, 1, "detect soft hyphen marker_count")

local vzwsp = awd.detect({ 0x61, 0x200B, 0x62 })
h.assert_equal(awd.classification_tag(vzwsp), "DefaultIgnorableCarrier", "detect zwsp tag")
h.assert_equal(vzwsp.marker_count, 1, "detect zwsp marker_count")

local vagg = awd.detect({ 0x61, 0x202F, 0x62, 0x202F, 0x63 })
h.assert_equal(awd.classification_tag(vagg), "NnbspBoundary", "detect multiple nnbsp tag")
h.assert_equal(vagg.marker_count, 2, "detect multiple nnbsp marker_count")
h.assert_equal(vagg.classify.positions, { 1, 3 }, "detect multiple nnbsp positions")

-- ── §7 refinement-probe spot checks ─────────────────────────────────────

local vadv = awd.detect({ 0x61, 0x202F, 0x62, 0x202F, 0x63, 0x202F, 0x64 })
h.assert_equal(awd.classification_tag(vadv), "Adversarial", "detect adversarial tag")
h.assert_equal(vadv.marker_count, 3, "detect adversarial marker_count")

h.assert_equal(tag({ 0x61, 0x202F, 0x62, 0x202F, 0x63 }), "NnbspBoundary", "nnbsp two below adversarial")

local vmod = awd.detect({ 0x61, 0x200B, 0x62, 0x200B, 0x63, 0x200B, 0x64 })
h.assert_equal(awd.classification_tag(vmod), "Gpt5ZwspModulo", "detect gpt5 zwsp modulo tag")
h.assert_equal(vmod.marker_count, 3, "detect gpt5 zwsp modulo marker_count")

h.assert_equal(tag({ 0x61, 0x200B, 0x62, 0x200B, 0x63 }), "DefaultIgnorableCarrier", "zwsp two below modulo")

local vsq = awd.detect({ 0x201C, 0x61, 0x62, 0x63, 0x201D })
h.assert_equal(awd.classification_tag(vsq), "SmartQuoteAlternation", "detect smart quote tag")
h.assert_equal(vsq.marker_count, 2, "detect smart quote marker_count")

h.assert_equal(tag({ 0x201C, 0x61, 0x22, 0x201D }), nil, "smart quote with straight clear")

local vem = awd.detect({ 0x61, 0x62, 0x20, 0x2014, 0x20, 0x63, 0x64, 0x20, 0x2014, 0x20, 0x65, 0x66 })
h.assert_equal(awd.classification_tag(vem), "EmDashPattern", "detect em dash tag")
h.assert_equal(vem.marker_count, 2, "detect em dash marker_count")

h.assert_equal(tag({ 0x61, 0x62, 0x2D, 0x63, 0x64, 0x20, 0x2014, 0x20, 0x65, 0x66 }), nil, "em dash with hyphen clear")

local vdelve = awd.detect({ 0x64, 0x65, 0x6C, 0x76, 0x65 })
h.assert_equal(awd.classification_tag(vdelve), "StatisticalTokenChoice", "detect delve tag")
h.assert_equal(vdelve.marker_count, 1, "detect delve marker_count")

local vmore = awd.detect({ 0x3B, 0x20, 0x6D, 0x6F, 0x72, 0x65, 0x6F, 0x76, 0x65, 0x72, 0x2C, 0x20 })
h.assert_equal(awd.classification_tag(vmore), "StatisticalTokenChoice", "detect moreover tag")
h.assert_equal(vmore.classify.positions, { 2 }, "detect moreover positions")

-- ── §7 unknown priority ─────────────────────────────────────────────────

local vu1 = awd.detect({ 0x61, 0x202F, 0x00AD, 0x62 })
h.assert_equal(awd.classification_tag(vu1), "Unknown", "unknown nnbsp+di tag")
h.assert_equal(vu1.marker_count, 2, "unknown nnbsp+di marker_count")

local vu2 = awd.detect({ 0x61, 0xFE0F, 0x200D, 0x62 })
h.assert_equal(awd.classification_tag(vu2), "Unknown", "unknown vs+zwj tag")
h.assert_equal(vu2.marker_count, 2, "unknown vs+zwj marker_count")

local vu3 = awd.detect({ 0x61, 0x202F, 0x200D, 0x62 })
h.assert_equal(awd.classification_tag(vu3), "Unknown", "unknown nnbsp+zwj tag")
h.assert_equal(vu3.marker_count, 2, "unknown nnbsp+zwj marker_count")

h.assert_equal(tag({ 0x61, 0x202F, 0x62 }), "NnbspBoundary", "single category skips unknown")
h.assert_equal(tag({ 0x61, 0x202F, 0x62, 0x202F, 0x63, 0x202F, 0x64 }), "Adversarial", "priority adversarial over nnbsp")
h.assert_equal(tag({ 0x61, 0x200B, 0x62, 0x200B, 0x63, 0x200B, 0x64 }), "Gpt5ZwspModulo", "priority zwsp modulo over di")

-- ── §8 tolerance-parameterised probes (Context vectors) ──────────────────

-- ZWSPs at 1, 3, 6 (gaps 2, 3). Bare detect (tolerance 0) does not fire
-- gpt5ZwspModulo; falls through to defaultIgnorableCarrier.
local jitter = { 0x61, 0x200B, 0x62, 0x200B, 0x63, 0x64, 0x200B, 0x65 }
h.assert_equal(tag(jitter), "DefaultIgnorableCarrier", "zwsp jittered strict clear")

local vjt = awd.detect_with_context({ zwsp_modulo_tolerance = 1 }, jitter)
h.assert_equal(awd.classification_tag(vjt), "Gpt5ZwspModulo", "zwsp jittered tolerant fires")

local dd = awd.detect({ 0x61, 0x202F, 0x62 })
local cc = awd.detect_with_context({}, { 0x61, 0x202F, 0x62 })
h.assert_equal(awd.classification_tag(cc), awd.classification_tag(dd), "default matches detect")

-- ── §7 cue-class coverage ───────────────────────────────────────────────

local sub_threats = {
  { tag = "NnbspBoundary" },
  { tag = "VariationSelectorCarrier" },
  { tag = "ZwjNonEmoji" },
  { tag = "DefaultIgnorableCarrier" },
  { tag = "Gpt5ZwspModulo" },
  { tag = "EmDashPattern" },
  { tag = "SmartQuoteAlternation" },
  { tag = "StatisticalTokenChoice" },
  { tag = "Adversarial" },
}
for _, cls in ipairs({ CueClass.GreenListBias, CueClass.PseudorandomSeq, CueClass.SemanticDrift }) do
  local probed = false
  for _, st in ipairs(sub_threats) do
    if awd.cue_class(st) == cls then
      probed = true
      break
    end
  end
  if not probed then
    error("cue class " .. cls .. " is not probed by any sub-threat")
  end
end

h.assert_equal(awd.cue_class({ tag = "Unknown" }), nil, "unknown has no cue class")

print("ai_watermark_detectability: fixture cases = " .. fixture_cases)
