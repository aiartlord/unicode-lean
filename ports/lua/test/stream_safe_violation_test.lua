local h = require("test_helper")
local calculus = require("unicode_lua.security.calculus")
local policy = require("unicode_lua.security.policy")
local ss = require("unicode_lua.security.form.stream_safe_violation")

local Family = calculus.Family

-- Map a detect verdict to the reason codes it would contribute, using the same
-- family/layer wiring the policy engine applies (F2 ⇒
-- unicode.security.F.stream-safe-violation.<sub>).
local function codes_of(verdict)
  local out = {}
  if not ss.classification_is_clear(verdict.classify) then
    out[#out + 1] = policy.reason_code(Family.StreamSafeViolation, ss.classification_tag(verdict.classify))
  end
  return out
end

-- ── The reason-code wiring is exactly the fixture's required finding ──────────
h.assert_equal(
  policy.reason_code(Family.StreamSafeViolation, "StreamSafeOverrun"),
  "unicode.security.F.stream-safe-violation.StreamSafeOverrun",
  "reason-code wiring"
)

-- ── Shared fixture through detect ─────────────────────────────────────────────
local ROOT = "testdata"
local fixture = h.json_file(ROOT .. "/fixtures/security/detectors/stream_safe_violation.json")
h.assert_equal(fixture.family, "stream-safe-violation", "fixture family")

for _, case in ipairs(fixture.cases) do
  local verdict = ss.detect(case.input)
  local codes = codes_of(verdict)
  for _, required in ipairs(case.required_findings) do
    h.assert_includes(codes, required, "fixture/" .. case.name)
  end
  if #case.required_findings == 0 then
    for _, code in ipairs(codes) do
      if code:find("%." .. fixture.family .. "%.", 1) ~= nil then
        error("fixture/" .. case.name .. " unexpected family " .. fixture.family)
      end
    end
  end
end

-- ── 30 / 31 boundary (strict `>` at STREAM_SAFE_LIMIT = 30) ───────────────────
local ACUTE = 0x0301 -- COMBINING ACUTE ACCENT, CCC = 230 (a non-starter)

local function a_plus_marks(n)
  local v = { 0x61 }
  for _ = 1, n do
    v[#v + 1] = ACUTE
  end
  return v
end

h.assert_equal(ss.STREAM_SAFE_LIMIT, 30, "stream-safe limit")

-- Exactly 30 marks after a starter is the boundary case — stays clear under `>`.
local thirty = ss.detect(a_plus_marks(30))
if not ss.classification_is_clear(thirty.classify) then
  error("30-mark boundary should be clear")
end
h.assert_equal(ss.classification_tag(thirty.classify), nil, "30-mark tag nil")
h.assert_equal(thirty.max_run_len, 30, "30-mark max_run_len")
h.assert_equal(thirty.overrun_count, 0, "30-mark overrun_count")
h.assert_equal(thirty.total_non_starters, 30, "30-mark total_non_starters")

-- 31 marks after a starter fires StreamSafeOverrun with base_pos 1, run_len 31.
local thirtyone = ss.detect(a_plus_marks(31))
if ss.classification_is_clear(thirtyone.classify) then
  error("31-mark boundary should be a hazard")
end
h.assert_equal(ss.classification_tag(thirtyone.classify), "StreamSafeOverrun", "31-mark tag")
h.assert_equal(ss.classification_positions(thirtyone.classify), { 1 }, "31-mark positions")
h.assert_equal(thirtyone.classify.sub.base_pos, 1, "31-mark base_pos")
h.assert_equal(thirtyone.classify.sub.run_len, 31, "31-mark run_len")
h.assert_equal(thirtyone.max_run_len, 31, "31-mark max_run_len")
h.assert_equal(thirtyone.overrun_count, 1, "31-mark overrun_count")
h.assert_equal(thirtyone.total_non_starters, 31, "31-mark total_non_starters")

-- ── Run-inventory structure (mirrors the reference's collectRunsGo tests) ─────

-- A bare non-starter run opening at index 0 records its start as 0.
local bare = {}
for _ = 1, 31 do
  bare[#bare + 1] = ACUTE
end
local bare_v = ss.detect(bare)
h.assert_equal(ss.classification_tag(bare_v.classify), "StreamSafeOverrun", "bare tag")
h.assert_equal(ss.classification_positions(bare_v.classify), { 0 }, "bare positions")
h.assert_equal(bare_v.max_run_len, 31, "bare max_run_len")
h.assert_equal(bare_v.total_non_starters, 31, "bare total_non_starters")

-- Two separate runs, each under the limit, stay clear but sum into the totals.
local two = a_plus_marks(30)
two[#two + 1] = 0x62
for _ = 1, 30 do
  two[#two + 1] = ACUTE
end
local two_v = ss.detect(two)
if not ss.classification_is_clear(two_v.classify) then
  error("two short runs should be clear")
end
h.assert_equal(two_v.max_run_len, 30, "two-run max_run_len")
h.assert_equal(two_v.overrun_count, 0, "two-run overrun_count")
h.assert_equal(two_v.total_non_starters, 60, "two-run total_non_starters")

-- The first overrun wins: a short run preceding a long run does not shadow it,
-- and the reported base_pos is the long run's start. "a" + 5 + "b" + 31 marks.
local first = a_plus_marks(5)
first[#first + 1] = 0x62
for _ = 1, 31 do
  first[#first + 1] = ACUTE
end
local first_v = ss.detect(first)
h.assert_equal(ss.classification_tag(first_v.classify), "StreamSafeOverrun", "first-overrun tag")
h.assert_equal(ss.classification_positions(first_v.classify), { 7 }, "first-overrun positions")
h.assert_equal(first_v.max_run_len, 31, "first-overrun max_run_len")
h.assert_equal(first_v.overrun_count, 1, "first-overrun overrun_count")
h.assert_equal(first_v.total_non_starters, 36, "first-overrun total_non_starters")
