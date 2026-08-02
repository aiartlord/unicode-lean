defmodule UnicodeSecurity.HashInputStabilityTest do
  use ExUnit.Case, async: false
  alias UnicodeSecurity.Crypto.HashInputStability
  alias UnicodeSecurity.Crypto.HashInputStability.Context
  alias UnicodeSecurity.Policy
  import UnicodeSecurity.TestHelpers

  # Detector tag for a bare-input detect.
  defp tag(input), do: HashInputStability.detect(input) |> Map.fetch!(:classify) |> HashInputStability.classification_tag()

  # Detector tag under a context.
  defp ctx_tag(ctx, input),
    do: HashInputStability.detect_with_context(ctx, input) |> Map.fetch!(:classify) |> HashInputStability.classification_tag()

  # ── §4 hash_stable spot checks ────────────────────────────────────────

  test "hash_stable spot checks" do
    assert HashInputStability.hash_stable([]) == []
    assert HashInputStability.hash_stable([0x61, 0x62, 0x63]) == [0x61, 0x62, 0x63]

    assert HashInputStability.hash_stable(HashInputStability.hash_stable([0x61, 0x62, 0x63])) ==
             HashInputStability.hash_stable([0x61, 0x62, 0x63])

    assert HashInputStability.hash_stable([0x61, 0x20]) == [0x61]
    assert HashInputStability.hash_stable([0x61, 0x09]) == [0x61]
    assert HashInputStability.hash_stable([0x61, 0x0A]) == [0x61]
    assert HashInputStability.hash_stable([0x61, 0x0D, 0x0A]) == [0x61]
    assert HashInputStability.hash_stable([0x61, 0x20, 0x62]) == [0x61, 0x20, 0x62]
    assert HashInputStability.hash_stable([0x0065, 0x0301]) == [0x00E9]
    assert HashInputStability.hash_stable([0x61, 0x00A0]) == [0x61, 0x00A0]
  end

  # ── §8 detect spot checks (bare input) ────────────────────────────────

  test "detect spot checks" do
    assert tag([]) == nil
    assert tag([0x61, 0x62, 0x63]) == nil

    v = HashInputStability.detect([0x61, 0x20])
    assert HashInputStability.classification_tag(v.classify) == "TrailingWhitespace"
    assert v.stable_size == 1
    assert HashInputStability.classification_positions(v.classify) == [1]

    crlf = HashInputStability.detect([0x61, 0x0D, 0x0A])
    assert HashInputStability.classification_tag(crlf.classify) == "TrailingWhitespace"
    assert crlf.stable_size == 1

    drift = HashInputStability.detect([0x0065, 0x0301])
    assert HashInputStability.classification_tag(drift.classify) == "NormalizationDrift"
    assert HashInputStability.classification_positions(drift.classify) == [0]

    assert tag([0x00E9]) == nil
    # Decomposed "é " — TrailingWhitespace wins over NormalizationDrift.
    assert tag([0x0065, 0x0301, 0x20]) == "TrailingWhitespace"
    assert tag([0x61, 0x20, 0x62]) == nil
  end

  # ── Shared context-free fixture through detect ────────────────────────

  test "shared detector fixture" do
    fixture = fixture_json(Path.join("detectors", "hash_input_stability.json"))

    Enum.each(fixture["cases"], fn case_data ->
      input = case_data["input"]
      classify = HashInputStability.detect(input).classify

      # Detector verdict wired through the policy reason-code machinery.
      code =
        case HashInputStability.classification_tag(classify) do
          nil -> nil
          hazard_tag -> Policy.reason_code(:hash_input_stability, hazard_tag)
        end

      required = case_data["required_findings"]

      Enum.each(required, fn expected ->
        assert code == expected, "#{case_data["name"]}: expected #{expected}, got #{inspect(code)}"
      end)

      if required == [] do
        assert code == nil, "#{case_data["name"]}: expected clear, got #{inspect(code)}"
      end

      # The same input routed through Policy.scan_hash_input must surface the
      # required reason codes and nothing hash-input-stability when clear.
      verdict = Policy.scan_hash_input("opaque-secret", "observe", input)
      codes = codes(verdict)

      Enum.each(required, fn expected -> assert expected in codes, case_data["name"] end)

      if required == [] do
        needle = "." <> fixture["family"] <> "."
        Enum.each(codes, fn c -> refute String.contains?(c, needle), case_data["name"] end)
      end
    end)
  end

  # ── §9 context-bearing probe vectors ──────────────────────────────────
  # Transcribed verbatim from the rust `#[test]` module's Context-vector
  # comment block in
  # `ports/rust/src/security/crypto/hash_input_stability.rs`.

  test "detect_with_context default matches detect" do
    d = HashInputStability.detect([0x61, 0x62, 0x63])
    c = HashInputStability.detect_with_context(%Context{}, [0x61, 0x62, 0x63])
    assert c.classify == d.classify
    assert c.stable_size == d.stable_size
  end

  test "encodingMismatch — utf-16 label" do
    ctx = %Context{declared_encoding: "utf-16"}
    v = HashInputStability.detect_with_context(ctx, [0x61, 0x62, 0x63])
    assert HashInputStability.classification_tag(v.classify) == "EncodingMismatch"
    assert HashInputStability.classification_positions(v.classify) == [0]
  end

  test "encodingMismatch — invalid surrogate under utf-8" do
    ctx = %Context{declared_encoding: "utf-8"}
    v = HashInputStability.detect_with_context(ctx, [0x61, 0xD800, 0x62])
    assert HashInputStability.classification_tag(v.classify) == "EncodingMismatch"
    assert HashInputStability.classification_positions(v.classify) == [1]
  end

  test "encodingMismatch — out of range under utf-8" do
    ctx = %Context{declared_encoding: "utf-8"}
    v = HashInputStability.detect_with_context(ctx, [0x61, 0x110000, 0x62])
    assert HashInputStability.classification_tag(v.classify) == "EncodingMismatch"
    assert HashInputStability.classification_positions(v.classify) == [1]
  end

  test "encodingMismatch — utf-8 labels case-insensitive clear" do
    Enum.each(["UTF-8", "utf-8", "UTF8", "utf8"], fn label ->
      ctx = %Context{declared_encoding: label}
      assert ctx_tag(ctx, [0x61, 0x62, 0x63]) == nil, "label #{label} should be UTF-8"
    end)
  end

  test "signedMessageRule — pgp4880 trailing whitespace" do
    ctx = %Context{rfc_rule: :pgp4880_trailing_whitespace}
    v = HashInputStability.detect_with_context(ctx, [0x61, 0x20])
    assert HashInputStability.classification_tag(v.classify) == "SignedMessageRule"
    assert HashInputStability.classification_positions(v.classify) == [1]
  end

  test "signedMessageRule — pgp9580 bare LF" do
    ctx = %Context{rfc_rule: :pgp9580_line_ending}
    v = HashInputStability.detect_with_context(ctx, [0x61, 0x0A, 0x62])
    assert HashInputStability.classification_tag(v.classify) == "SignedMessageRule"
    assert HashInputStability.classification_positions(v.classify) == [1]
  end

  test "signedMessageRule — pgp9580 CRLF clear" do
    ctx = %Context{rfc_rule: :pgp9580_line_ending}
    assert ctx_tag(ctx, [0x61, 0x62, 0x63, 0x0D, 0x0A, 0x64, 0x65, 0x66]) == nil
  end

  test "signedMessageRule — rfc8785 decomposed" do
    ctx = %Context{rfc_rule: :rfc8785_nfc_requirement}
    v = HashInputStability.detect_with_context(ctx, [0x0065, 0x0301])
    assert HashInputStability.classification_tag(v.classify) == "SignedMessageRule"
    assert HashInputStability.classification_positions(v.classify) == [0]
  end

  test "signedMessageRule — rfc8259 control char" do
    ctx = %Context{rfc_rule: :rfc8259_control_char}
    v = HashInputStability.detect_with_context(ctx, [0x61, 0x01, 0x62])
    assert HashInputStability.classification_tag(v.classify) == "SignedMessageRule"
    assert HashInputStability.classification_positions(v.classify) == [1]
  end

  test "signedMessageRule — rfc7515 plus char" do
    ctx = %Context{rfc_rule: :rfc7515_jws_base64_url}
    v = HashInputStability.detect_with_context(ctx, [0x41, 0x2B, 0x42])
    assert HashInputStability.classification_tag(v.classify) == "SignedMessageRule"
    assert HashInputStability.classification_positions(v.classify) == [1]
  end

  test "signedMessageRule — rfc7515 clean clear" do
    ctx = %Context{rfc_rule: :rfc7515_jws_base64_url}
    assert ctx_tag(ctx, [0x41, 0x61, 0x30, 0x2D, 0x5F, 0x7A, 0x5A, 0x39]) == nil
  end

  test "signedMessageRule — rfc6376 double space" do
    ctx = %Context{rfc_rule: :rfc6376_dkim_relaxed}
    v = HashInputStability.detect_with_context(ctx, [0x61, 0x20, 0x20, 0x62])
    assert HashInputStability.classification_tag(v.classify) == "SignedMessageRule"
    assert HashInputStability.classification_positions(v.classify) == [2]
  end

  test "signedMessageRule — rfc6376 single space clear" do
    ctx = %Context{rfc_rule: :rfc6376_dkim_relaxed}
    assert ctx_tag(ctx, [0x61, 0x20, 0x62]) == nil
  end

  test "signedMessageRule — rfc5751 bare LF" do
    ctx = %Context{rfc_rule: :rfc5751_smime_line_ending}
    v = HashInputStability.detect_with_context(ctx, [0x61, 0x0A, 0x62])
    assert HashInputStability.classification_tag(v.classify) == "SignedMessageRule"
    assert HashInputStability.classification_positions(v.classify) == [1]
  end

  test "auditLogReinterpretation — divergence" do
    ctx = %Context{as_written: [0x61, 0x62, 0x63]}
    v = HashInputStability.detect_with_context(ctx, [0x61, 0x62, 0x64])
    assert HashInputStability.classification_tag(v.classify) == "AuditLogReinterpretation"
    assert HashInputStability.classification_positions(v.classify) == [2]
  end

  test "auditLogReinterpretation — identical clear" do
    ctx = %Context{as_written: [0x61, 0x62, 0x63]}
    assert ctx_tag(ctx, [0x61, 0x62, 0x63]) == nil
  end

  test "webhookSignatureDrift — divergence" do
    ctx = %Context{server_bytes: [0x61, 0x62, 0x64]}
    v = HashInputStability.detect_with_context(ctx, [0x61, 0x62, 0x63])
    assert HashInputStability.classification_tag(v.classify) == "WebhookSignatureDrift"
    assert HashInputStability.classification_positions(v.classify) == [2]
  end

  test "webhookSignatureDrift — match clear" do
    ctx = %Context{server_bytes: [0x61, 0x62, 0x63]}
    assert ctx_tag(ctx, [0x61, 0x62, 0x63]) == nil
  end

  test "priority — encoding over rfc" do
    ctx = %Context{declared_encoding: "utf-16", rfc_rule: :pgp9580_line_ending}
    assert ctx_tag(ctx, [0x0065, 0x0301, 0x0A]) == "EncodingMismatch"
  end

  test "priority — webhook over audit" do
    ctx = %Context{server_bytes: [0x61, 0x62, 0x65], as_written: [0x61, 0x62, 0x66]}
    assert ctx_tag(ctx, [0x61, 0x62, 0x63]) == "WebhookSignatureDrift"
  end

  test "priority — rfc over trailing" do
    ctx = %Context{rfc_rule: :pgp4880_trailing_whitespace}
    assert ctx_tag(ctx, [0x61, 0x20]) == "SignedMessageRule"
  end

  # ── RfcRule fixture-tag round-trip ────────────────────────────────────

  test "rfc rule tag roundtrip" do
    rules = [
      :pgp4880_trailing_whitespace,
      :pgp9580_line_ending,
      :rfc8785_nfc_requirement,
      :rfc8259_control_char,
      :rfc7515_jws_base64_url,
      :rfc6376_dkim_relaxed,
      :rfc5751_smime_line_ending
    ]

    Enum.each(rules, fn rule ->
      assert HashInputStability.from_tag(HashInputStability.tag(rule)) == rule
    end)

    assert HashInputStability.from_tag("nope") == nil
  end
end
