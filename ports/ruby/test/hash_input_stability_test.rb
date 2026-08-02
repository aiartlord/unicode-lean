# frozen_string_literal: true

require_relative "test_helper"

class HashInputStabilityTest < Minitest::Test
  include RubyPortTestHelpers

  Hash2 = UnicodeRuby::Security::Crypto::HashInputStability
  RfcRule = Hash2::RfcRule
  Policy = UnicodeRuby::Security::Policy
  Family = UnicodeRuby::Security::Calculus::Family

  # ── (a) shared context-free detector fixture ─────────────────────────────
  #
  # The shared fixture carries no Context, so it exercises only the two
  # bare-input probes.  Each hazard tag maps to its stable reason code via the
  # same Policy wiring bip39 uses.

  def code_for(input)
    tag = Hash2.detect(input).classify.tag
    tag.nil? ? [] : [Policy.reason_code(Family::HASH_INPUT_STABILITY, tag)]
  end

  def test_shared_fixture_cases
    fixture = fixture_json("detectors", "hash_input_stability.json")
    assert_equal 1, fixture.fetch("schema")
    assert_equal "hash-input-stability", fixture.fetch("family")

    fixture.fetch("cases").each do |case_data|
      name = case_data.fetch("name")
      codes = code_for(case_data.fetch("input"))
      case_data.fetch("required_findings").each do |required|
        assert_includes codes, required, name
      end
      next unless case_data.fetch("required_findings").empty?

      assert codes.none? { |code| code.include?(".hash-input-stability.") },
             "#{name}: unexpected hash-input finding in #{codes.inspect}"
    end
  end

  # ── §4 hash_stable spot checks ───────────────────────────────────────────

  def test_hash_stable_spot_checks
    assert_equal [], Hash2.hash_stable([])
    assert_equal [0x61, 0x62, 0x63], Hash2.hash_stable([0x61, 0x62, 0x63])
    assert_equal Hash2.hash_stable([0x61, 0x62, 0x63]),
                 Hash2.hash_stable(Hash2.hash_stable([0x61, 0x62, 0x63]))
    assert_equal [0x61], Hash2.hash_stable([0x61, 0x20])
    assert_equal [0x61], Hash2.hash_stable([0x61, 0x09])
    assert_equal [0x61], Hash2.hash_stable([0x61, 0x0A])
    assert_equal [0x61], Hash2.hash_stable([0x61, 0x0D, 0x0A])
    assert_equal [0x61, 0x20, 0x62], Hash2.hash_stable([0x61, 0x20, 0x62])
    assert_equal [0x00E9], Hash2.hash_stable([0x0065, 0x0301])
    assert_equal [0x61, 0x00A0], Hash2.hash_stable([0x61, 0x00A0])
  end

  # ── §8 bare-input detect spot checks ─────────────────────────────────────

  def test_detect_bare_input
    assert_nil Hash2.detect([]).classify.tag
    assert_nil Hash2.detect([0x61, 0x62, 0x63]).classify.tag

    v = Hash2.detect([0x61, 0x20])
    assert_equal "TrailingWhitespace", v.classify.tag
    assert_equal 1, v.stable_size
    assert_equal [1], v.classify.positions

    crlf = Hash2.detect([0x61, 0x0D, 0x0A])
    assert_equal "TrailingWhitespace", crlf.classify.tag
    assert_equal 1, crlf.stable_size

    drift = Hash2.detect([0x0065, 0x0301])
    assert_equal "NormalizationDrift", drift.classify.tag
    assert_equal [0], drift.classify.positions

    assert_nil Hash2.detect([0x00E9]).classify.tag
    # Priority: TrailingWhitespace wins over NormalizationDrift.
    assert_equal "TrailingWhitespace", Hash2.detect([0x0065, 0x0301, 0x20]).classify.tag
    assert_nil Hash2.detect([0x61, 0x20, 0x62]).classify.tag
  end

  # ── §9 context-bearing probe vectors ─────────────────────────────────────
  #
  # Transcribed verbatim from the Rust reference's Context-vector comment
  # block (ports/rust/src/security/crypto/hash_input_stability.rs lines
  # 588-610), which the shared detector-fixture schema cannot express.

  def ctx(declared_encoding: nil, rfc_rule: nil, as_written: nil, server_bytes: nil)
    Hash2::Context.new(declared_encoding, rfc_rule, as_written, server_bytes)
  end

  def ctx_verdict(context, input)
    Hash2.detect_with_context(context, input)
  end

  def ctx_tag(context, input)
    ctx_verdict(context, input).classify.tag
  end

  def test_context_default_matches_detect
    d = Hash2.detect([0x61, 0x62, 0x63])
    c = Hash2.detect_with_context(Hash2::Context.new, [0x61, 0x62, 0x63])
    assert_nil d.classify.tag
    assert_nil c.classify.tag
    assert_equal d.classify.positions, c.classify.positions
    assert_equal d.stable_size, c.stable_size
  end

  # declared_encoding = Some("utf-16"), [0x61,0x62,0x63] → EncodingMismatch, [0]
  def test_ctx_encoding_mismatch_utf16
    v = ctx_verdict(ctx(declared_encoding: "utf-16"), [0x61, 0x62, 0x63])
    assert_equal "EncodingMismatch", v.classify.tag
    assert_equal [0], v.classify.positions
  end

  # declared_encoding = Some("utf-8"), [0x61,0xD800,0x62] → EncodingMismatch, [1]
  def test_ctx_encoding_invalid_surrogate
    v = ctx_verdict(ctx(declared_encoding: "utf-8"), [0x61, 0xD800, 0x62])
    assert_equal "EncodingMismatch", v.classify.tag
    assert_equal [1], v.classify.positions
  end

  # declared_encoding = Some("utf-8"), [0x61,0x110000,0x62] → EncodingMismatch, [1]
  def test_ctx_encoding_invalid_out_of_range
    v = ctx_verdict(ctx(declared_encoding: "utf-8"), [0x61, 0x110000, 0x62])
    assert_equal "EncodingMismatch", v.classify.tag
    assert_equal [1], v.classify.positions
  end

  # declared_encoding = Some("UTF-8"|"utf-8"|"UTF8"|"utf8"), [0x61,0x62,0x63] → clear
  def test_ctx_encoding_utf8_label_case_insensitive
    ["UTF-8", "utf-8", "UTF8", "utf8"].each do |label|
      assert_nil ctx_tag(ctx(declared_encoding: label), [0x61, 0x62, 0x63]),
                 "label #{label} should be recognised as UTF-8"
    end
  end

  # rfc_rule = Pgp4880TrailingWhitespace, [0x61,0x20] → SignedMessageRule, [1]
  def test_ctx_pgp4880
    v = ctx_verdict(ctx(rfc_rule: RfcRule::PGP4880_TRAILING_WHITESPACE), [0x61, 0x20])
    assert_equal "SignedMessageRule", v.classify.tag
    assert_equal [1], v.classify.positions
  end

  # rfc_rule = Pgp9580LineEnding, [0x61,0x0A,0x62] → SignedMessageRule, [1]  (bare LF)
  def test_ctx_pgp9580_bare_lf
    v = ctx_verdict(ctx(rfc_rule: RfcRule::PGP9580_LINE_ENDING), [0x61, 0x0A, 0x62])
    assert_equal "SignedMessageRule", v.classify.tag
    assert_equal [1], v.classify.positions
  end

  # rfc_rule = Pgp9580LineEnding, [0x61,0x62,0x63,0x0D,0x0A,0x64,0x65,0x66] → clear (CRLF)
  def test_ctx_pgp9580_crlf_clear
    assert_nil ctx_tag(ctx(rfc_rule: RfcRule::PGP9580_LINE_ENDING),
                       [0x61, 0x62, 0x63, 0x0D, 0x0A, 0x64, 0x65, 0x66])
  end

  # rfc_rule = Rfc8785NfcRequirement, [0x0065,0x0301] → SignedMessageRule, [0]
  def test_ctx_rfc8785_decomposed
    v = ctx_verdict(ctx(rfc_rule: RfcRule::RFC8785_NFC_REQUIREMENT), [0x0065, 0x0301])
    assert_equal "SignedMessageRule", v.classify.tag
    assert_equal [0], v.classify.positions
  end

  # rfc_rule = Rfc8259ControlChar, [0x61,0x01,0x62] → SignedMessageRule, [1]
  def test_ctx_rfc8259_control
    v = ctx_verdict(ctx(rfc_rule: RfcRule::RFC8259_CONTROL_CHAR), [0x61, 0x01, 0x62])
    assert_equal "SignedMessageRule", v.classify.tag
    assert_equal [1], v.classify.positions
  end

  # rfc_rule = Rfc7515JwsBase64Url, [0x41,0x2B,0x42] → SignedMessageRule, [1]  ('+')
  def test_ctx_rfc7515_plus_char
    v = ctx_verdict(ctx(rfc_rule: RfcRule::RFC7515_JWS_BASE64_URL), [0x41, 0x2B, 0x42])
    assert_equal "SignedMessageRule", v.classify.tag
    assert_equal [1], v.classify.positions
  end

  # rfc_rule = Rfc7515JwsBase64Url, [0x41,0x61,0x30,0x2D,0x5F,0x7A,0x5A,0x39] → clear
  def test_ctx_rfc7515_clean_clear
    assert_nil ctx_tag(ctx(rfc_rule: RfcRule::RFC7515_JWS_BASE64_URL),
                       [0x41, 0x61, 0x30, 0x2D, 0x5F, 0x7A, 0x5A, 0x39])
  end

  # rfc_rule = Rfc6376DkimRelaxed, [0x61,0x20,0x20,0x62] → SignedMessageRule, [2]
  def test_ctx_rfc6376_double_space
    v = ctx_verdict(ctx(rfc_rule: RfcRule::RFC6376_DKIM_RELAXED), [0x61, 0x20, 0x20, 0x62])
    assert_equal "SignedMessageRule", v.classify.tag
    assert_equal [2], v.classify.positions
  end

  # rfc_rule = Rfc6376DkimRelaxed, [0x61,0x20,0x62] → clear (single space)
  def test_ctx_rfc6376_single_space_clear
    assert_nil ctx_tag(ctx(rfc_rule: RfcRule::RFC6376_DKIM_RELAXED), [0x61, 0x20, 0x62])
  end

  # rfc_rule = Rfc5751SmimeLineEnding, [0x61,0x0A,0x62] → SignedMessageRule, [1]  (bare LF)
  def test_ctx_rfc5751_bare_lf
    v = ctx_verdict(ctx(rfc_rule: RfcRule::RFC5751_SMIME_LINE_ENDING), [0x61, 0x0A, 0x62])
    assert_equal "SignedMessageRule", v.classify.tag
    assert_equal [1], v.classify.positions
  end

  # as_written = Some([0x61,0x62,0x63]), input [0x61,0x62,0x64] → AuditLogReinterpretation, [2]
  def test_ctx_audit_log_divergence
    v = ctx_verdict(ctx(as_written: [0x61, 0x62, 0x63]), [0x61, 0x62, 0x64])
    assert_equal "AuditLogReinterpretation", v.classify.tag
    assert_equal [2], v.classify.positions
  end

  # as_written = Some([0x61,0x62,0x63]), input [0x61,0x62,0x63] → clear
  def test_ctx_audit_log_identical_clear
    assert_nil ctx_tag(ctx(as_written: [0x61, 0x62, 0x63]), [0x61, 0x62, 0x63])
  end

  # server_bytes = Some([0x61,0x62,0x64]), input [0x61,0x62,0x63] → WebhookSignatureDrift, [2]
  def test_ctx_webhook_signature_drift
    v = ctx_verdict(ctx(server_bytes: [0x61, 0x62, 0x64]), [0x61, 0x62, 0x63])
    assert_equal "WebhookSignatureDrift", v.classify.tag
    assert_equal [2], v.classify.positions
  end

  # server_bytes = Some([0x61,0x62,0x63]), input [0x61,0x62,0x63] → clear
  def test_ctx_webhook_signature_match_clear
    assert_nil ctx_tag(ctx(server_bytes: [0x61, 0x62, 0x63]), [0x61, 0x62, 0x63])
  end

  # declared_encoding = Some("utf-16") + rfc_rule = Pgp9580LineEnding,
  #   [0x0065,0x0301,0x0A] → EncodingMismatch  (priority over rfc)
  def test_ctx_priority_encoding_over_rfc
    context = ctx(declared_encoding: "utf-16", rfc_rule: RfcRule::PGP9580_LINE_ENDING)
    assert_equal "EncodingMismatch", ctx_tag(context, [0x0065, 0x0301, 0x0A])
  end

  # server_bytes = Some([0x61,0x62,0x65]) + as_written = Some([0x61,0x62,0x66]),
  #   input [0x61,0x62,0x63] → WebhookSignatureDrift  (priority over audit)
  def test_ctx_priority_webhook_over_audit
    context = ctx(server_bytes: [0x61, 0x62, 0x65], as_written: [0x61, 0x62, 0x66])
    assert_equal "WebhookSignatureDrift", ctx_tag(context, [0x61, 0x62, 0x63])
  end

  # rfc_rule = Pgp4880TrailingWhitespace, [0x61,0x20] → SignedMessageRule  (priority over trailing)
  def test_ctx_priority_rfc_over_trailing
    context = ctx(rfc_rule: RfcRule::PGP4880_TRAILING_WHITESPACE)
    assert_equal "SignedMessageRule", ctx_tag(context, [0x61, 0x20])
  end

  # ── RfcRule fixture-tag round-trip ───────────────────────────────────────

  def test_rfc_rule_tag_roundtrip
    RfcRule::ALL.each do |rule|
      assert_equal rule, RfcRule.from_tag(RfcRule.tag(rule))
    end
    assert_nil RfcRule.from_tag("nope")
  end
end
