# frozen_string_literal: true

require_relative "test_helper"

class SecurityPolicyTest < Minitest::Test
  include RubyPortTestHelpers

  Policy = UnicodeRuby::Security::Policy
  Family = UnicodeRuby::Security::Calculus::Family

  def test_policy_reason_codes_are_stable
    assert_equal(
      "unicode.security.C.tag-block-payload.DirectAscii",
      Policy.reason_code(Family::TAG_BLOCK_PAYLOAD, "DirectAscii")
    )
    assert_equal(
      "unicode.security.C.bidi-control-balance.hazard",
      Policy.reason_code(Family::BIDI_CONTROL_BALANCE)
    )
    assert_equal(
      "unicode.security.I.homoglyph-confusable.TargetMatch",
      Policy.reason_code(Family::HOMOGLYPH_CONFUSABLE, "TargetMatch")
    )
    assert_equal(
      "unicode.security.I.mixed-script-admissibility.CrossScriptMix",
      Policy.reason_code(Family::MIXED_SCRIPT_ADMISSIBILITY, "CrossScriptMix")
    )
    assert_equal(
      "unicode.security.C.noncharacter-control.Noncharacter",
      Policy.reason_code(Family::NONCHARACTER_CONTROL, "Noncharacter")
    )
    assert_equal(
      "unicode.security.C.malformed-utf8.InvalidStartByte",
      Policy.reason_code(Family::MALFORMED_UTF8, "InvalidStartByte")
    )
  end

  def test_policy_contract_fixture_cases
    payload = fixture_json("policy_contract.json")
    assert_equal "unicode-security-policy-v0", payload.fetch("contract")

    payload.fetch("cases").each do |case_data|
      verdict = Policy.scan(profile(case_data.fetch("profile")), mode(case_data.fetch("mode")), case_data.fetch("input"))
      assert_equal case_data.fetch("action"), verdict.action, case_data.fetch("name")
      codes = verdict.findings.map(&:code)
      case_data.fetch("required_findings").each do |required|
        assert_includes codes, required, case_data.fetch("name")
      end
    end
  end

  def test_verdict_contract_fixture_cases
    payload = fixture_json("verdict_contract.json")
    assert_equal "unicode-security-verdict-v0", payload.fetch("contract")

    payload.fetch("cases").each do |case_data|
      verdict = Policy.scan(profile(case_data.fetch("profile")), mode(case_data.fetch("mode")), case_data.fetch("input"))
      assert_equal case_data.fetch("verdict"), Policy.verdict_to_wire(verdict), case_data.fetch("name")
      assert_equal JSON.generate(case_data.fetch("verdict")), Policy.verdict_to_json(verdict), case_data.fetch("name")
    end
  end

  def test_decode_contract_fixture_cases
    payload = fixture_json("decode_contract.json")
    assert_equal "unicode-security-decode-v0", payload.fetch("contract")

    payload.fetch("cases").each do |case_data|
      verdict = Policy.scan_utf8(
        profile(case_data.fetch("profile")),
        mode(case_data.fetch("mode")),
        case_data.fetch("input_bytes")
      )
      assert_equal case_data.fetch("action"), verdict.action, case_data.fetch("name")
      assert_equal case_data.fetch("input"), verdict.input, case_data.fetch("name")
      assert_required_findings_and_positions(case_data, verdict)
    end
  end

  def test_multiencoding_decode_contract_fixture_cases
    payload = fixture_json("decode_multiencoding_contract.json")
    assert_equal "unicode-security-multiencoding-decode-v0", payload.fetch("contract")

    payload.fetch("cases").each do |case_data|
      verdict = scan_encoded_case(case_data)
      assert_equal case_data.fetch("action"), verdict.action, case_data.fetch("name")
      assert_equal case_data.fetch("input"), verdict.input, case_data.fetch("name")
      assert_required_findings_and_positions(case_data, verdict)
    end
  end

  private

  def assert_required_findings_and_positions(case_data, verdict)
    codes = verdict.findings.map(&:code)
    case_data.fetch("required_findings").each do |required|
      assert_includes codes, required, case_data.fetch("name")
    end

    positions_by_code = verdict.findings.to_h { |finding| [finding.code, finding.positions] }
    case_data.fetch("required_positions").each do |expected|
      assert_equal expected.fetch("positions"), positions_by_code.fetch(expected.fetch("code")), case_data.fetch("name")
    end
  end
end
