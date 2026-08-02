local h = require("test_helper")
local policy = require("unicode_lua.security.policy")
local calculus = require("unicode_lua.security.calculus")
local fd = require("unicode_lua.security.display.filename_disguise")

local Family = calculus.Family

local function tag(input)
  return fd.classification_tag(fd.detect(input))
end

-- ── Shared context-free fixture ─────────────────────────────────────────
-- Run every case through the detector and map the classification to the family
-- reason code, exactly as the policy layer would.

local fixture = h.json_file("testdata/fixtures/security/detectors/filename_disguise.json")
local fixture_cases = 0
for _, case in ipairs(fixture.cases) do
  fixture_cases = fixture_cases + 1
  local verdict = fd.detect(case.input)
  local t = fd.classification_tag(verdict)
  local codes = {}
  if t ~= nil then
    codes[#codes + 1] = policy.reason_code(Family.FilenameDisguise, t)
  end
  for _, required in ipairs(case.required_findings) do
    h.assert_includes(codes, required, "fixture/" .. case.name)
  end
  if #case.required_findings == 0 and t ~= nil then
    error("fixture/" .. case.name .. " unexpected finding " .. t)
  end
end

-- ── data-layer sanity (reused predicates) ────────────────────────────────

h.assert_equal(fd.is_ascii_dot(0x2E), true, "ascii dot")
h.assert_equal(fd.is_ascii_dot(0x41), false, "ascii dot reject A")
h.assert_equal(fd.is_fullwidth_halfwidth(0xFF25), true, "fullwidth E")
h.assert_equal(fd.is_fullwidth_halfwidth(0xFF00), false, "fullwidth below block")
h.assert_equal(fd.is_bidi_format_control(0x202E), true, "rlo is bidi control")
h.assert_equal(fd.is_bidi_format_control(0x0041), false, "A not bidi control")
h.assert_equal(fd.is_grapheme_extend(0x0301), true, "extend combining acute")
h.assert_equal(fd.is_grapheme_extend(0x0061), false, "extend reject a")

-- ── §4 detect spot checks (one per Rust theorem) ─────────────────────────

-- detect_empty_clear
local vempty = fd.detect({})
h.assert_equal(fd.is_clear(vempty), true, "empty is clear")
h.assert_equal(fd.classification_tag(vempty), nil, "empty tag nil")

-- detect_plain_txt_clear — "document.txt", last dot at 0-based 8.
local vplain = fd.detect({ 0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74, 0x2E, 0x74, 0x78, 0x74 })
h.assert_equal(fd.is_clear(vplain), true, "plain txt clear")
h.assert_equal(vplain.last_dot_pos, 8, "plain txt last_dot_pos")

-- detect_no_extension_clear — "foo", no dot.
local vnoext = fd.detect({ 0x66, 0x6F, 0x6F })
h.assert_equal(fd.is_clear(vnoext), true, "no extension clear")
h.assert_equal(vnoext.last_dot_pos, nil, "no extension last_dot_pos nil")

-- detect_tar_gz_clear — "archive.tar.gz" (2 dots, below the multi-ext bound).
h.assert_equal(fd.is_clear(fd.detect({ 0x61, 0x72, 0x63, 0x68, 0x69, 0x76, 0x65, 0x2E, 0x74, 0x61, 0x72, 0x2E, 0x67, 0x7A })), true, "tar.gz clear")

-- detect_rlo_flip — "document<RLO>txt.exe", RLO at 0-based 8.
local vrlo = fd.detect({ 0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74, 0x202E, 0x74, 0x78, 0x74, 0x2E, 0x65, 0x78, 0x65 })
h.assert_equal(fd.classification_tag(vrlo), "RloFlip", "rlo flip tag")
h.assert_equal(vrlo.classify.positions, { 8 }, "rlo flip positions")

-- detect_fullwidth_exe — "file.ＥＸＥ".
h.assert_equal(tag({ 0x66, 0x69, 0x6C, 0x65, 0x2E, 0xFF25, 0xFF38, 0xFF25 }), "WidthClassExt", "fullwidth ext")

-- detect_combining_in_ext — "file.e<combining acute>xe".
h.assert_equal(tag({ 0x66, 0x69, 0x6C, 0x65, 0x2E, 0x65, 0x0301, 0x78, 0x65 }), "CombiningInExt", "combining in ext")

-- detect_triple_extension — "setup.tar.gz.sig" (3 dots).
h.assert_equal(tag({ 0x73, 0x65, 0x74, 0x75, 0x70, 0x2E, 0x74, 0x61, 0x72, 0x2E, 0x67, 0x7A, 0x2E, 0x73, 0x69, 0x67 }), "MultipleExtensions", "triple extension")

-- detect_hebrew_clear — native Hebrew name, no bidi controls.
h.assert_equal(fd.is_clear(fd.detect({ 0x05D0, 0x05D1, 0x05D2, 0x2E, 0x74, 0x78, 0x74 })), true, "hebrew clear")

-- detect_isolate_flip — RLI/PDI isolate variant, also RloFlip.
h.assert_equal(tag({ 0x64, 0x6F, 0x63, 0x2067, 0x74, 0x78, 0x74, 0x2E, 0x65, 0x78, 0x65, 0x2069 }), "RloFlip", "isolate flip")

-- ── priority-ladder structural check ─────────────────────────────────────

-- A bidi control outranks a fullwidth extension.
h.assert_equal(tag({ 0x202E, 0x66, 0x2E, 0xFF25 }), "RloFlip", "bidi beats fullwidth")

print("filename_disguise: fixture cases = " .. fixture_cases)
