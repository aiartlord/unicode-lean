local h = require("test_helper")
local policy = require("unicode_lua.security.policy")

local ROOT = "testdata"

local function scan_case(case)
  return policy.scan(case.profile, case.mode, case.input)
end

local function scan_encoded_case(case)
  local scanners = {
    ["utf-8"] = policy.scan_utf8,
    ["utf-16be"] = policy.scan_utf16be,
    ["utf-16le"] = policy.scan_utf16le,
    ["utf-32be"] = policy.scan_utf32be,
    ["utf-32le"] = policy.scan_utf32le,
  }
  return scanners[case.encoding](case.profile, case.mode, case.input_bytes)
end

local function assert_required(case, verdict)
  local codes = h.codes(verdict)
  for _, required in ipairs(case.required_findings) do
    h.assert_includes(codes, required, case.name)
  end
  local by_code = {}
  for _, finding in ipairs(verdict.findings) do
    by_code[finding.code] = finding.positions
  end
  for _, expected in ipairs(case.required_positions or {}) do
    h.assert_equal(by_code[expected.code], expected.positions, case.name)
  end
end

local payload = h.json_file(ROOT .. "/fixtures/security/policy_contract.json")
for _, case in ipairs(payload.cases) do
  local verdict = scan_case(case)
  h.assert_equal(verdict.action, case.action, case.name)
  assert_required(case, verdict)
end

payload = h.json_file(ROOT .. "/fixtures/security/verdict_contract.json")
for _, case in ipairs(payload.cases) do
  local verdict = scan_case(case)
  h.assert_equal(policy.verdict_to_wire(verdict), case.verdict, case.name)
end

payload = h.json_file(ROOT .. "/fixtures/security/decode_contract.json")
for _, case in ipairs(payload.cases) do
  local verdict = policy.scan_utf8(case.profile, case.mode, case.input_bytes)
  h.assert_equal(verdict.action, case.action, case.name)
  h.assert_equal(verdict.input, case.input, case.name)
  assert_required(case, verdict)
end

payload = h.json_file(ROOT .. "/fixtures/security/decode_multiencoding_contract.json")
for _, case in ipairs(payload.cases) do
  local verdict = scan_encoded_case(case)
  h.assert_equal(verdict.action, case.action, case.name)
  h.assert_equal(verdict.input, case.input, case.name)
  assert_required(case, verdict)
end
