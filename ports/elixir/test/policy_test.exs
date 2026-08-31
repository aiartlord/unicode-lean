defmodule UnicodeSecurity.PolicyTest do
  use ExUnit.Case, async: false
  alias UnicodeSecurity.Policy
  import UnicodeSecurity.TestHelpers

  test "reason codes are stable" do
    assert Policy.reason_code(:tag_block_payload, "DirectAscii") ==
             "unicode.security.C.tag-block-payload.DirectAscii"

    assert Policy.reason_code(:bidi_control_balance) ==
             "unicode.security.C.bidi-control-balance.hazard"

    assert Policy.reason_code(:homoglyph_confusable, "TargetMatch") ==
             "unicode.security.I.homoglyph-confusable.TargetMatch"

    assert Policy.reason_code(:mixed_script_admissibility, "CrossScriptMix") ==
             "unicode.security.I.mixed-script-admissibility.CrossScriptMix"

    assert Policy.reason_code(:noncharacter_control, "Noncharacter") ==
             "unicode.security.C.noncharacter-control.Noncharacter"

    assert Policy.reason_code(:malformed_utf8, "InvalidStartByte") ==
             "unicode.security.C.malformed-utf8.InvalidStartByte"
  end

  test "policy contract fixture" do
    payload = fixture_json("policy_contract.json")
    assert payload["contract"] == "unicode-security-policy-v0"

    Enum.each(payload["cases"], fn case_data ->
      verdict = Policy.scan(case_data["profile"], case_data["mode"], case_data["input"])
      assert verdict.action == case_data["action"], case_data["name"]
      codes = codes(verdict)

      Enum.each(case_data["required_findings"], fn required ->
        assert required in codes, case_data["name"]
      end)
    end)
  end

  test "verdict contract fixture" do
    payload = fixture_json("verdict_contract.json")
    assert payload["contract"] == "unicode-security-verdict-v0"

    Enum.each(payload["cases"], fn case_data ->
      verdict = Policy.scan(case_data["profile"], case_data["mode"], case_data["input"])
      assert Policy.verdict_to_wire(verdict) == case_data["verdict"], case_data["name"]

      assert Policy.verdict_to_json(verdict) == JSON.encode!(case_data["verdict"]),
             case_data["name"]
    end)
  end

  # Agreement with the reference over a generated input stream. The corpus shares
  # the verdict contract's schema, so it runs through the same comparison, but
  # its cases come from the Rust reference over a deterministic stream rather
  # than being hand-written: agreement here is evidence that this port decides as
  # the reference does on inputs nobody chose, across every profile.
  test "differential corpus" do
    payload = fixture_json("differential_corpus.json")
    assert payload["contract"] == "unicode-security-verdict-v0"

    Enum.each(payload["cases"], fn case_data ->
      verdict = Policy.scan(case_data["profile"], case_data["mode"], case_data["input"])
      assert Policy.verdict_to_wire(verdict) == case_data["verdict"], case_data["name"]

      assert Policy.verdict_to_json(verdict) == JSON.encode!(case_data["verdict"]),
             case_data["name"]
    end)
  end

  test "utf-8 decode contract fixture" do
    payload = fixture_json("decode_contract.json")
    assert payload["contract"] == "unicode-security-decode-v0"

    Enum.each(payload["cases"], fn case_data ->
      verdict =
        Policy.scan_utf8(case_data["profile"], case_data["mode"], case_data["input_bytes"])

      assert verdict.action == case_data["action"], case_data["name"]
      assert verdict.input == case_data["input"], case_data["name"]
      assert_required_findings_and_positions(case_data, verdict)
    end)
  end

  test "multi-encoding decode contract fixture" do
    payload = fixture_json("decode_multiencoding_contract.json")
    assert payload["contract"] == "unicode-security-multiencoding-decode-v0"

    Enum.each(payload["cases"], fn case_data ->
      verdict = scan_encoded_case(case_data)
      assert verdict.action == case_data["action"], case_data["name"]
      assert verdict.input == case_data["input"], case_data["name"]
      assert_required_findings_and_positions(case_data, verdict)
    end)
  end
end
