local h = require("test_helper")
local policy = require("unicode_lua.security.policy")
local calculus = require("unicode_lua.security.calculus")
local his = require("unicode_lua.security.crypto.hash_input_stability")

local Family = calculus.Family
local RfcRule = his.RfcRule

local function tag(input)
  return his.classification_tag(his.detect(input))
end

local function ctx_tag(ctx, input)
  return his.classification_tag(his.detect_with_context(ctx, input))
end

-- ── Shared context-free fixture ─────────────────────────────────────────
-- Run every case through the detector and map the classification to the
-- family reason code, exactly as the policy layer would.

local fixture = h.json_file("testdata/fixtures/security/detectors/hash_input_stability.json")
local fixture_cases = 0
for _, case in ipairs(fixture.cases) do
  fixture_cases = fixture_cases + 1
  local verdict = his.detect(case.input)
  local t = his.classification_tag(verdict)
  local codes = {}
  if t ~= nil then
    codes[#codes + 1] = policy.reason_code(Family.HashInputStability, t)
  end
  for _, required in ipairs(case.required_findings) do
    h.assert_includes(codes, required, "fixture/" .. case.name)
  end
  if #case.required_findings == 0 and t ~= nil then
    error("fixture/" .. case.name .. " unexpected finding " .. t)
  end
end

-- ── §4 hash_stable spot checks ──────────────────────────────────────────

h.assert_equal(his.hash_stable({}), {}, "stable empty")
h.assert_equal(his.hash_stable({ 0x61, 0x62, 0x63 }), { 0x61, 0x62, 0x63 }, "stable ascii")
h.assert_equal(
  his.hash_stable(his.hash_stable({ 0x61, 0x62, 0x63 })),
  his.hash_stable({ 0x61, 0x62, 0x63 }),
  "stable idempotent"
)
h.assert_equal(his.hash_stable({ 0x61, 0x20 }), { 0x61 }, "stable strips space")
h.assert_equal(his.hash_stable({ 0x61, 0x09 }), { 0x61 }, "stable strips tab")
h.assert_equal(his.hash_stable({ 0x61, 0x0A }), { 0x61 }, "stable strips lf")
h.assert_equal(his.hash_stable({ 0x61, 0x0D, 0x0A }), { 0x61 }, "stable strips crlf")
h.assert_equal(his.hash_stable({ 0x61, 0x20, 0x62 }), { 0x61, 0x20, 0x62 }, "stable internal space")
h.assert_equal(his.hash_stable({ 0x0065, 0x0301 }), { 0x00E9 }, "stable composes nfc")
h.assert_equal(his.hash_stable({ 0x61, 0x00A0 }), { 0x61, 0x00A0 }, "stable preserves nbsp")

-- ── §8 detect spot checks ───────────────────────────────────────────────

h.assert_equal(tag({}), nil, "detect empty clear")
h.assert_equal(tag({ 0x61, 0x62, 0x63 }), nil, "detect ascii clear")

local v = his.detect({ 0x61, 0x20 })
h.assert_equal(his.classification_tag(v), "TrailingWhitespace", "detect trailing space")
h.assert_equal(v.stable_size, 1, "detect trailing space stable_size")
h.assert_equal(v.classify.positions, { 1 }, "detect trailing space positions")

local vcrlf = his.detect({ 0x61, 0x0D, 0x0A })
h.assert_equal(his.classification_tag(vcrlf), "TrailingWhitespace", "detect trailing crlf")
h.assert_equal(vcrlf.stable_size, 1, "detect trailing crlf stable_size")

local vd = his.detect({ 0x0065, 0x0301 })
h.assert_equal(his.classification_tag(vd), "NormalizationDrift", "detect decomposed")
h.assert_equal(vd.classify.positions, { 0 }, "detect decomposed positions")

h.assert_equal(tag({ 0x00E9 }), nil, "detect precomposed clear")
h.assert_equal(tag({ 0x0065, 0x0301, 0x20 }), "TrailingWhitespace", "detect priority trailing over nfc")
h.assert_equal(tag({ 0x61, 0x20, 0x62 }), nil, "detect internal space clear")

-- ── §9 context-bearing probe vectors (transcribed verbatim from the Rust
--    test module's Context-vector comment block) ──────────────────────────

-- detect_with_context({}, input) equals detect(input).
local d = his.detect({ 0x61, 0x62, 0x63 })
local c = his.detect_with_context({}, { 0x61, 0x62, 0x63 })
h.assert_equal(his.classification_tag(c), his.classification_tag(d), "default matches detect tag")
h.assert_equal(c.stable_size, d.stable_size, "default matches detect stable_size")

-- declared_encoding = Some("utf-16"), [0x61,0x62,0x63] → EncodingMismatch, [0]
local venc = his.detect_with_context({ declared_encoding = "utf-16" }, { 0x61, 0x62, 0x63 })
h.assert_equal(his.classification_tag(venc), "EncodingMismatch", "enc utf-16 tag")
h.assert_equal(venc.classify.positions, { 0 }, "enc utf-16 pos")

-- declared_encoding = Some("utf-8"), [0x61,0xD800,0x62] → EncodingMismatch, [1] (invalid surrogate)
local vsur = his.detect_with_context({ declared_encoding = "utf-8" }, { 0x61, 0xD800, 0x62 })
h.assert_equal(his.classification_tag(vsur), "EncodingMismatch", "enc surrogate tag")
h.assert_equal(vsur.classify.positions, { 1 }, "enc surrogate pos")

-- declared_encoding = Some("utf-8"), [0x61,0x110000,0x62] → EncodingMismatch, [1] (out of range)
local voor = his.detect_with_context({ declared_encoding = "utf-8" }, { 0x61, 0x110000, 0x62 })
h.assert_equal(his.classification_tag(voor), "EncodingMismatch", "enc oor tag")
h.assert_equal(voor.classify.positions, { 1 }, "enc oor pos")

-- declared_encoding = Some("UTF-8"|"utf-8"|"UTF8"), [0x61,0x62,0x63] → clear
for _, label in ipairs({ "UTF-8", "utf-8", "UTF8", "utf8" }) do
  h.assert_equal(ctx_tag({ declared_encoding = label }, { 0x61, 0x62, 0x63 }), nil, "enc utf8 label clear " .. label)
end

-- rfc_rule = Pgp4880TrailingWhitespace, [0x61,0x20] → SignedMessageRule, [1]
local vp4880 = his.detect_with_context({ rfc_rule = RfcRule.Pgp4880TrailingWhitespace }, { 0x61, 0x20 })
h.assert_equal(his.classification_tag(vp4880), "SignedMessageRule", "pgp4880 tag")
h.assert_equal(vp4880.classify.positions, { 1 }, "pgp4880 pos")

-- rfc_rule = Pgp9580LineEnding, [0x61,0x0A,0x62] → SignedMessageRule, [1] (bare LF)
local vp9580 = his.detect_with_context({ rfc_rule = RfcRule.Pgp9580LineEnding }, { 0x61, 0x0A, 0x62 })
h.assert_equal(his.classification_tag(vp9580), "SignedMessageRule", "pgp9580 bare lf tag")
h.assert_equal(vp9580.classify.positions, { 1 }, "pgp9580 bare lf pos")

-- rfc_rule = Pgp9580LineEnding, [0x61,0x62,0x63,0x0D,0x0A,0x64,0x65,0x66] → clear (CRLF)
h.assert_equal(
  ctx_tag({ rfc_rule = RfcRule.Pgp9580LineEnding }, { 0x61, 0x62, 0x63, 0x0D, 0x0A, 0x64, 0x65, 0x66 }),
  nil,
  "pgp9580 crlf clear"
)

-- rfc_rule = Rfc8785NfcRequirement, [0x0065,0x0301] → SignedMessageRule, [0]
local v8785 = his.detect_with_context({ rfc_rule = RfcRule.Rfc8785NfcRequirement }, { 0x0065, 0x0301 })
h.assert_equal(his.classification_tag(v8785), "SignedMessageRule", "rfc8785 tag")
h.assert_equal(v8785.classify.positions, { 0 }, "rfc8785 pos")

-- rfc_rule = Rfc8259ControlChar, [0x61,0x01,0x62] → SignedMessageRule, [1]
local v8259 = his.detect_with_context({ rfc_rule = RfcRule.Rfc8259ControlChar }, { 0x61, 0x01, 0x62 })
h.assert_equal(his.classification_tag(v8259), "SignedMessageRule", "rfc8259 tag")
h.assert_equal(v8259.classify.positions, { 1 }, "rfc8259 pos")

-- rfc_rule = Rfc7515JwsBase64Url, [0x41,0x2B,0x42] → SignedMessageRule, [1] ('+')
local v7515 = his.detect_with_context({ rfc_rule = RfcRule.Rfc7515JwsBase64Url }, { 0x41, 0x2B, 0x42 })
h.assert_equal(his.classification_tag(v7515), "SignedMessageRule", "rfc7515 tag")
h.assert_equal(v7515.classify.positions, { 1 }, "rfc7515 pos")

-- rfc_rule = Rfc7515JwsBase64Url, [0x41,0x61,0x30,0x2D,0x5F,0x7A,0x5A,0x39] → clear
h.assert_equal(
  ctx_tag({ rfc_rule = RfcRule.Rfc7515JwsBase64Url }, { 0x41, 0x61, 0x30, 0x2D, 0x5F, 0x7A, 0x5A, 0x39 }),
  nil,
  "rfc7515 clean clear"
)

-- rfc_rule = Rfc6376DkimRelaxed, [0x61,0x20,0x20,0x62] → SignedMessageRule, [2]
local v6376 = his.detect_with_context({ rfc_rule = RfcRule.Rfc6376DkimRelaxed }, { 0x61, 0x20, 0x20, 0x62 })
h.assert_equal(his.classification_tag(v6376), "SignedMessageRule", "rfc6376 tag")
h.assert_equal(v6376.classify.positions, { 2 }, "rfc6376 pos")

-- rfc_rule = Rfc6376DkimRelaxed, [0x61,0x20,0x62] → clear (single space)
h.assert_equal(ctx_tag({ rfc_rule = RfcRule.Rfc6376DkimRelaxed }, { 0x61, 0x20, 0x62 }), nil, "rfc6376 single clear")

-- rfc_rule = Rfc5751SmimeLineEnding, [0x61,0x0A,0x62] → SignedMessageRule, [1] (bare LF)
local v5751 = his.detect_with_context({ rfc_rule = RfcRule.Rfc5751SmimeLineEnding }, { 0x61, 0x0A, 0x62 })
h.assert_equal(his.classification_tag(v5751), "SignedMessageRule", "rfc5751 tag")
h.assert_equal(v5751.classify.positions, { 1 }, "rfc5751 pos")

-- as_written = Some([0x61,0x62,0x63]), input [0x61,0x62,0x64] → AuditLogReinterpretation, [2]
local vaudit = his.detect_with_context({ as_written = { 0x61, 0x62, 0x63 } }, { 0x61, 0x62, 0x64 })
h.assert_equal(his.classification_tag(vaudit), "AuditLogReinterpretation", "audit tag")
h.assert_equal(vaudit.classify.positions, { 2 }, "audit pos")

-- as_written = Some([0x61,0x62,0x63]), input [0x61,0x62,0x63] → clear
h.assert_equal(ctx_tag({ as_written = { 0x61, 0x62, 0x63 } }, { 0x61, 0x62, 0x63 }), nil, "audit identical clear")

-- server_bytes = Some([0x61,0x62,0x64]), input [0x61,0x62,0x63] → WebhookSignatureDrift, [2]
local vhook = his.detect_with_context({ server_bytes = { 0x61, 0x62, 0x64 } }, { 0x61, 0x62, 0x63 })
h.assert_equal(his.classification_tag(vhook), "WebhookSignatureDrift", "webhook tag")
h.assert_equal(vhook.classify.positions, { 2 }, "webhook pos")

-- server_bytes = Some([0x61,0x62,0x63]), input [0x61,0x62,0x63] → clear
h.assert_equal(ctx_tag({ server_bytes = { 0x61, 0x62, 0x63 } }, { 0x61, 0x62, 0x63 }), nil, "webhook match clear")

-- declared_encoding = Some("utf-16") + rfc_rule = Pgp9580LineEnding,
--   [0x0065,0x0301,0x0A] → EncodingMismatch (priority over rfc)
h.assert_equal(
  ctx_tag({ declared_encoding = "utf-16", rfc_rule = RfcRule.Pgp9580LineEnding }, { 0x0065, 0x0301, 0x0A }),
  "EncodingMismatch",
  "priority encoding over rfc"
)

-- server_bytes = Some([0x61,0x62,0x65]) + as_written = Some([0x61,0x62,0x66]),
--   input [0x61,0x62,0x63] → WebhookSignatureDrift (priority over audit)
h.assert_equal(
  ctx_tag({ server_bytes = { 0x61, 0x62, 0x65 }, as_written = { 0x61, 0x62, 0x66 } }, { 0x61, 0x62, 0x63 }),
  "WebhookSignatureDrift",
  "priority webhook over audit"
)

-- rfc_rule = Pgp4880TrailingWhitespace, [0x61,0x20] → SignedMessageRule (priority over trailing)
h.assert_equal(
  ctx_tag({ rfc_rule = RfcRule.Pgp4880TrailingWhitespace }, { 0x61, 0x20 }),
  "SignedMessageRule",
  "priority rfc over trailing"
)

-- ── RfcRule tag round-trip ──────────────────────────────────────────────
for _, rule in ipairs({
  RfcRule.Pgp4880TrailingWhitespace,
  RfcRule.Pgp9580LineEnding,
  RfcRule.Rfc8785NfcRequirement,
  RfcRule.Rfc8259ControlChar,
  RfcRule.Rfc7515JwsBase64Url,
  RfcRule.Rfc6376DkimRelaxed,
  RfcRule.Rfc5751SmimeLineEnding,
}) do
  h.assert_equal(his.rfc_rule_from_tag(his.rfc_rule_tag(rule)), rule, "rfc rule roundtrip " .. rule)
end
h.assert_equal(his.rfc_rule_from_tag("nope"), nil, "rfc rule from_tag unknown")

print("hash_input_stability: fixture cases = " .. fixture_cases)
