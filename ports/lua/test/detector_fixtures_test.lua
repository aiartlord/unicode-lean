local h = require("test_helper")
local policy = require("unicode_lua.security.policy")

local ROOT = "testdata"
local fixtures = {
  "tag_block_payload.json",
  "variation_selector_payload.json",
  "zero_width_payload.json",
  "surrogate_reassembly.json",
  "bidi_control_balance.json",
  "noncharacter_control.json",
  "homoglyph_confusable.json",
  "mixed_script_admissibility.json",
  "rtl_injection.json",
  "covert_display_compound.json",
  "confusable_bidi_compound.json",
}

for _, name in ipairs(fixtures) do
  local fixture = h.json_file(ROOT .. "/fixtures/security/detectors/" .. name)
  for _, case in ipairs(fixture.cases) do
    local verdict = policy.scan(policy.Profile.GatewayHeader, policy.Mode.Observe, case.input)
    local codes = h.codes(verdict)
    for _, required in ipairs(case.required_findings) do
      h.assert_includes(codes, required, name .. "/" .. case.name)
    end
    if #case.required_findings == 0 then
      for _, code in ipairs(codes) do
        if code:find("%." .. fixture.family .. "%.", 1) ~= nil then
          error(name .. "/" .. case.name .. " unexpected family " .. fixture.family)
        end
      end
    end
  end
end
