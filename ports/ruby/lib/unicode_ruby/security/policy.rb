# frozen_string_literal: true

require "json"

require_relative "calculus"
require_relative "../noncharacters"
require_relative "../strict"
require_relative "../utf8"
require_relative "covert/tag_block_payload"
require_relative "covert/variation_selector_payload"
require_relative "covert/zero_width_payload"
require_relative "covert/bidi_control_balance"
require_relative "covert/surrogate_reassembly"
require_relative "identity/homoglyph_confusable"
require_relative "boundary/confusable_bidi_compound"
require_relative "boundary/covert_display_compound"
require_relative "display/rtl_injection"
require_relative "identity/emoji_zwj_integrity"
require_relative "identity/skin_tone_variation_forgery"
require_relative "display/filename_disguise"
require_relative "display/renderer_divergence"
require_relative "display/source_display_divergence"
require_relative "form/case_expansion_mismatch"
require_relative "form/locale_case_inversion"
require_relative "form/nfc_idempotence_witness"
require_relative "form/normalization_bomb"
require_relative "form/stream_safe_violation"
require_relative "form/width_class_confusion"
require_relative "boundary/admissibility_form_drift"
require_relative "boundary/identifier_form_drift"

module UnicodeRuby
  module Security
    # Product-facing security policy contract: named profiles, runtime modes,
    # stable reason codes, and a `scan` verdict over decoded codepoints.
    module Policy
      Family = Calculus::Family
      Severity = Calculus::Severity
      ClassificationKind = Calculus::ClassificationKind

      # Runtime action recommended for the current payload.
      module Action
        ALLOW = "allow"
        REJECT = "reject"
        QUARANTINE = "quarantine"
        REWRITE = "rewrite"
        OBSERVE = "observe"
      end

      # Operator-selected runtime mode.
      module Mode
        OBSERVE = "observe"
        WARN = "warn"
        ENFORCE = "enforce"
        STRICT = "strict"
      end

      # Product context profile.
      module Profile
        GATEWAY_HEADER = "gateway-header"
        DOMAIN_NAME = "domain-name"
        DNS_LABEL = "dns-label"
        URL = "url"
        USERNAME = "username"
        DISPLAY_NAME = "display-name"
        CHAT_MESSAGE = "chat-message"
        SOURCE_CODE = "source-code"
        OPAQUE_SECRET = "opaque-secret"
        BINARY_BLOB = "binary-blob"
      end

      # Policy strictness level.
      module PolicyLevel
        RESTRICTIVE = :restrictive
        MODERATE = :moderate
        MINIMAL = :minimal
      end

      # Optional crypto-shaped policy context.
      module CryptoContext
        NON_CRYPTO = :non_crypto
        BIP39_MNEMONIC = :bip39_mnemonic
        HASH_INPUT = :hash_input
        AI_ATTRIBUTION = :ai_attribution
      end

      ProfilePolicy = Struct.new(:level, :crypto_context, :quarantine)
      Finding = Struct.new(:code, :family, :severity, :positions, :sub_threat, :detail)
      Verdict = Struct.new(:input, :profile, :mode, :action, :findings, :normalized)

      RESTRICTIVE_REJECTION_SET = [
        Family::MALFORMED_UTF8, Family::MALFORMED_UTF16, Family::MALFORMED_UTF32,
        Family::TAG_BLOCK_PAYLOAD, Family::VARIATION_SELECTOR_PAYLOAD,
        Family::ZERO_WIDTH_PAYLOAD, Family::SURROGATE_REASSEMBLY,
        Family::BIDI_CONTROL_BALANCE, Family::NONCHARACTER_CONTROL,
        Family::HOMOGLYPH_CONFUSABLE, Family::MIXED_SCRIPT_ADMISSIBILITY,
        Family::EMOJI_ZWJ_INTEGRITY, Family::SKIN_TONE_VARIATION_FORGERY,
        Family::SOURCE_DISPLAY_DIVERGENCE, Family::FILENAME_DISGUISE,
        Family::RTL_INJECTION, Family::RENDERER_DIVERGENCE,
        Family::NORMALIZATION_BOMB, Family::STREAM_SAFE_VIOLATION,
        Family::LOCALE_CASE_INVERSION, Family::CASE_EXPANSION_MISMATCH,
        Family::WIDTH_CLASS_CONFUSION, Family::NFC_IDEMPOTENCE_WITNESS,
        Family::IDENTIFIER_FORM_DRIFT, Family::COVERT_DISPLAY_COMPOUND,
        Family::CONFUSABLE_BIDI_COMPOUND, Family::ADMISSIBILITY_FORM_DRIFT
      ].freeze

      MODERATE_REJECTION_SET = [
        Family::MALFORMED_UTF8, Family::MALFORMED_UTF16, Family::MALFORMED_UTF32,
        Family::TAG_BLOCK_PAYLOAD, Family::VARIATION_SELECTOR_PAYLOAD,
        Family::ZERO_WIDTH_PAYLOAD, Family::SURROGATE_REASSEMBLY,
        Family::BIDI_CONTROL_BALANCE, Family::NONCHARACTER_CONTROL,
        Family::HOMOGLYPH_CONFUSABLE, Family::MIXED_SCRIPT_ADMISSIBILITY,
        Family::SKIN_TONE_VARIATION_FORGERY, Family::SOURCE_DISPLAY_DIVERGENCE,
        Family::FILENAME_DISGUISE, Family::STREAM_SAFE_VIOLATION,
        Family::LOCALE_CASE_INVERSION, Family::CASE_EXPANSION_MISMATCH,
        Family::WIDTH_CLASS_CONFUSION, Family::NFC_IDEMPOTENCE_WITNESS,
        Family::IDENTIFIER_FORM_DRIFT, Family::COVERT_DISPLAY_COMPOUND,
        Family::CONFUSABLE_BIDI_COMPOUND, Family::ADMISSIBILITY_FORM_DRIFT
      ].freeze

      MINIMAL_REJECTION_SET = [
        Family::MALFORMED_UTF8, Family::MALFORMED_UTF16, Family::MALFORMED_UTF32,
        Family::SURROGATE_REASSEMBLY, Family::BIDI_CONTROL_BALANCE,
        Family::NONCHARACTER_CONTROL, Family::STREAM_SAFE_VIOLATION
      ].freeze

      FAMILY_SLUGS = {
        Family::MALFORMED_UTF8 => "malformed-utf8",
        Family::MALFORMED_UTF16 => "malformed-utf16",
        Family::MALFORMED_UTF32 => "malformed-utf32",
        Family::TAG_BLOCK_PAYLOAD => "tag-block-payload",
        Family::VARIATION_SELECTOR_PAYLOAD => "variation-selector-payload",
        Family::ZERO_WIDTH_PAYLOAD => "zero-width-payload",
        Family::SURROGATE_REASSEMBLY => "surrogate-reassembly",
        Family::BIDI_CONTROL_BALANCE => "bidi-control-balance",
        Family::NONCHARACTER_CONTROL => "noncharacter-control",
        Family::HOMOGLYPH_CONFUSABLE => "homoglyph-confusable",
        Family::MIXED_SCRIPT_ADMISSIBILITY => "mixed-script-admissibility",
        Family::EMOJI_ZWJ_INTEGRITY => "emoji-zwj-integrity",
        Family::SKIN_TONE_VARIATION_FORGERY => "skin-tone-variation-forgery",
        Family::SOURCE_DISPLAY_DIVERGENCE => "source-display-divergence",
        Family::FILENAME_DISGUISE => "filename-disguise",
        Family::RTL_INJECTION => "rtl-injection",
        Family::RENDERER_DIVERGENCE => "renderer-divergence",
        Family::NORMALIZATION_BOMB => "normalization-bomb",
        Family::STREAM_SAFE_VIOLATION => "stream-safe-violation",
        Family::LOCALE_CASE_INVERSION => "locale-case-inversion",
        Family::CASE_EXPANSION_MISMATCH => "case-expansion-mismatch",
        Family::WIDTH_CLASS_CONFUSION => "width-class-confusion",
        Family::NFC_IDEMPOTENCE_WITNESS => "nfc-idempotence-witness",
        Family::IDENTIFIER_FORM_DRIFT => "identifier-form-drift",
        Family::COVERT_DISPLAY_COMPOUND => "covert-display-compound",
        Family::CONFUSABLE_BIDI_COMPOUND => "confusable-bidi-compound",
        Family::ADMISSIBILITY_FORM_DRIFT => "admissibility-form-drift",
        Family::BIP39_CANONICAL => "bip39-canonical",
        Family::HASH_INPUT_STABILITY => "hash-input-stability",
        Family::AI_WATERMARK_DETECTABILITY => "ai-watermark-detectability"
      }.freeze

      LAYER_C = [
        Family::MALFORMED_UTF8, Family::MALFORMED_UTF16, Family::MALFORMED_UTF32,
        Family::TAG_BLOCK_PAYLOAD, Family::VARIATION_SELECTOR_PAYLOAD,
        Family::ZERO_WIDTH_PAYLOAD, Family::SURROGATE_REASSEMBLY,
        Family::BIDI_CONTROL_BALANCE, Family::NONCHARACTER_CONTROL
      ].freeze
      LAYER_I = [
        Family::HOMOGLYPH_CONFUSABLE, Family::MIXED_SCRIPT_ADMISSIBILITY,
        Family::EMOJI_ZWJ_INTEGRITY, Family::SKIN_TONE_VARIATION_FORGERY
      ].freeze
      LAYER_D = [
        Family::SOURCE_DISPLAY_DIVERGENCE, Family::FILENAME_DISGUISE,
        Family::RTL_INJECTION, Family::RENDERER_DIVERGENCE
      ].freeze
      LAYER_F = [
        Family::NORMALIZATION_BOMB, Family::STREAM_SAFE_VIOLATION,
        Family::LOCALE_CASE_INVERSION, Family::CASE_EXPANSION_MISMATCH,
        Family::WIDTH_CLASS_CONFUSION, Family::NFC_IDEMPOTENCE_WITNESS
      ].freeze
      LAYER_X = [
        Family::IDENTIFIER_FORM_DRIFT, Family::COVERT_DISPLAY_COMPOUND,
        Family::CONFUSABLE_BIDI_COMPOUND, Family::ADMISSIBILITY_FORM_DRIFT
      ].freeze

      module_function

      def crypto_families(context)
        case context
        when CryptoContext::BIP39_MNEMONIC then [Family::BIP39_CANONICAL]
        when CryptoContext::HASH_INPUT then [Family::HASH_INPUT_STABILITY]
        when CryptoContext::AI_ATTRIBUTION then [Family::AI_WATERMARK_DETECTABILITY]
        when CryptoContext::NON_CRYPTO then []
        else
          raise "crypto_families: unknown context #{context.inspect}"
        end
      end

      def rejection_set(level)
        case level
        when PolicyLevel::RESTRICTIVE then RESTRICTIVE_REJECTION_SET
        when PolicyLevel::MODERATE then MODERATE_REJECTION_SET
        when PolicyLevel::MINIMAL then MINIMAL_REJECTION_SET
        else
          raise "rejection_set: unknown level #{level.inspect}"
        end
      end

      def policy_of_profile(profile)
        case profile
        when Profile::GATEWAY_HEADER, Profile::DOMAIN_NAME, Profile::DNS_LABEL, Profile::SOURCE_CODE
          ProfilePolicy.new(PolicyLevel::RESTRICTIVE, CryptoContext::NON_CRYPTO, false)
        when Profile::URL
          ProfilePolicy.new(PolicyLevel::MODERATE, CryptoContext::NON_CRYPTO, false)
        when Profile::USERNAME
          ProfilePolicy.new(PolicyLevel::MODERATE, CryptoContext::NON_CRYPTO, true)
        when Profile::DISPLAY_NAME, Profile::CHAT_MESSAGE
          ProfilePolicy.new(PolicyLevel::MINIMAL, CryptoContext::NON_CRYPTO, true)
        when Profile::OPAQUE_SECRET
          ProfilePolicy.new(PolicyLevel::MINIMAL, CryptoContext::HASH_INPUT, false)
        when Profile::BINARY_BLOB
          ProfilePolicy.new(PolicyLevel::MINIMAL, CryptoContext::NON_CRYPTO, false)
        else
          raise "policy_of_profile: unknown profile #{profile.inspect}"
        end
      end

      def family_layer_code(family)
        return "C" if LAYER_C.include?(family)
        return "I" if LAYER_I.include?(family)
        return "D" if LAYER_D.include?(family)
        return "F" if LAYER_F.include?(family)
        return "X" if LAYER_X.include?(family)

        "K"
      end

      def family_slug(family)
        slug = FAMILY_SLUGS[family]
        raise "family_slug: unknown family #{family.inspect}" if slug.nil?

        slug
      end

      def reason_base(family)
        "unicode.security.#{family_layer_code(family)}.#{family_slug(family)}"
      end

      def reason_code(family, sub_threat = nil)
        if sub_threat.nil?
          "#{reason_base(family)}.hazard"
        else
          "#{reason_base(family)}.#{sub_threat}"
        end
      end

      def utf8_reject_tag(kind)
        kind
      end

      def finding_to_wire(finding)
        {
          "code" => finding.code,
          "family" => family_slug(finding.family),
          "severity" => finding.severity,
          "positions" => finding.positions,
          "sub_threat" => finding.sub_threat,
          "detail" => finding.detail
        }
      end

      def verdict_to_wire(verdict)
        {
          "action" => verdict.action,
          "profile" => verdict.profile,
          "mode" => verdict.mode,
          "input" => verdict.input,
          "findings" => verdict.findings.map { |f| finding_to_wire(f) },
          "normalized" => verdict.normalized
        }
      end

      def verdict_to_json(verdict)
        JSON.generate(verdict_to_wire(verdict))
      end

      def malformed_decode_verdict(profile, mode, family, sub_threat, offset)
        findings = [
          Finding.new(
            reason_code(family, sub_threat), family, Severity::MODERATE,
            [offset], sub_threat, family_slug(family)
          )
        ]
        Verdict.new([], profile, mode, select_action(profile, mode, findings), findings, nil)
      end

      def family_blocks(profile, family)
        policy = policy_of_profile(profile)
        rejection_set(policy.level).include?(family) ||
          crypto_families(policy.crypto_context).include?(family)
      end

      def blocking_findings(profile, findings)
        findings.select { |f| family_blocks(profile, f.family) }
      end

      def select_action(profile, mode, findings)
        has_findings = !findings.empty?
        has_blocking = findings.any? { |f| family_blocks(profile, f.family) }
        case mode
        when Mode::OBSERVE, Mode::WARN
          has_findings ? Action::OBSERVE : Action::ALLOW
        when Mode::ENFORCE
          if !has_blocking
            Action::ALLOW
          elsif policy_of_profile(profile).quarantine
            Action::QUARANTINE
          else
            Action::REJECT
          end
        when Mode::STRICT
          has_findings ? Action::REJECT : Action::ALLOW
        else
          raise "select_action: unknown mode #{mode.inspect}"
        end
      end

      def default_policy_severity(kind)
        case kind
        when ClassificationKind::CLEAR then Severity::INFORMATIONAL
        when ClassificationKind::HAZARD then Severity::MODERATE
        when ClassificationKind::COMPOUND then Severity::HIGH
        when ClassificationKind::INFORMATIONAL then Severity::INFORMATIONAL
        else
          raise "default_policy_severity: unknown kind #{kind.inspect}"
        end
      end

      def push_finding(findings, family, kind, sub_threat, positions)
        return if kind == ClassificationKind::CLEAR

        findings << Finding.new(
          reason_code(family, sub_threat), family, default_policy_severity(kind),
          positions, sub_threat, family_slug(family)
        )
      end

      def push_positional_hazard(findings, family, sub_threat, positions)
        return if positions.empty?

        push_finding(findings, family, ClassificationKind::HAZARD, sub_threat, positions)
      end

      def positions_where(input)
        out = []
        input.each_index { |i| out << i if yield(input[i]) }
        out
      end

      def c0_control?(cp)
        (cp >= 0 && cp <= 0x1F && cp != 0x09 && cp != 0x0A && cp != 0x0D) || cp == 0x7F
      end

      def c1_control?(cp)
        cp >= 0x80 && cp <= 0x9F
      end

      # Scan a decoded codepoint sequence with the implemented native detectors.
      def scan(profile, mode, input)
        findings = []

        tag = Covert::TagBlockPayload.detect(input)
        push_finding(findings, Family::TAG_BLOCK_PAYLOAD, tag.kind, tag.sub, tag.tag_positions)

        vs = Covert::VariationSelectorPayload.detect(input)
        push_finding(findings, Family::VARIATION_SELECTOR_PAYLOAD, vs.kind, vs.sub, vs.vs_positions)

        zw = Covert::ZeroWidthPayload.detect(input)
        push_finding(findings, Family::ZERO_WIDTH_PAYLOAD, zw.kind, zw.sub, zw.zero_width_positions)

        # SurrogateReassembly only applies to byte-stream input (every
        # codepoint <= 0xFF); on codepoint-array input the family is skipped.
        if Covert::SurrogateReassembly.looks_like_byte_stream(input)
          sr = Covert::SurrogateReassembly.detect(input)
          unless sr.sub.nil?
            push_finding(findings, Family::SURROGATE_REASSEMBLY, ClassificationKind::HAZARD,
                         sr.sub, sr.positions)
          end
        end

        bidi = Covert::BidiControlBalance.detect(input)
        push_finding(findings, Family::BIDI_CONTROL_BALANCE, bidi.kind, bidi.sub, bidi.bidi_positions)

        push_positional_hazard(findings, Family::NONCHARACTER_CONTROL, "Noncharacter",
                               positions_where(input) { |cp| Noncharacters.noncharacter?(cp) })
        push_positional_hazard(findings, Family::NONCHARACTER_CONTROL, "C0Control",
                               positions_where(input) { |cp| c0_control?(cp) })
        push_positional_hazard(findings, Family::NONCHARACTER_CONTROL, "C1Control",
                               positions_where(input) { |cp| c1_control?(cp) })

        homoglyph = Identity::HomoglyphConfusable.detect(input)
        homoglyph_sub = homoglyph.sub
        if homoglyph_sub != "CrossScriptMix"
          positions =
            homoglyph.kind == ClassificationKind::CLEAR ? [] : (0...input.length).to_a
          push_finding(findings, Family::HOMOGLYPH_CONFUSABLE, homoglyph.kind,
                       homoglyph_sub, positions)
        end
        if Identity::HomoglyphConfusable.has_mixed_script_admissibility(input)
          push_finding(findings, Family::MIXED_SCRIPT_ADMISSIBILITY, ClassificationKind::HAZARD,
                       Identity::HomoglyphConfusable.mixed_script_subthreat(input),
                       (0...input.length).to_a)
        end

        rtl = Display::RtlInjection.detect(input)
        unless rtl.sub.nil?
          push_finding(findings, Family::RTL_INJECTION, ClassificationKind::HAZARD,
                       rtl.sub, rtl.positions)
        end

        confusable_bidi = Boundary::ConfusableBidiCompound.detect(input)
        unless confusable_bidi.sub.nil?
          push_finding(findings, Family::CONFUSABLE_BIDI_COMPOUND, ClassificationKind::HAZARD,
                       confusable_bidi.sub, confusable_bidi.positions)
        end

        covert_display = Boundary::CovertDisplayCompound.detect(input)
        unless covert_display.sub.nil?
          push_finding(findings, Family::COVERT_DISPLAY_COMPOUND, ClassificationKind::HAZARD,
                       covert_display.sub, covert_display.positions)
        end

        # The remaining families the Lean reference's runAll dispatches on
        # plain input. Detectors carrying a Classification report through it;
        # the rest return a bare sub-threat with its positions.
        emoji_zwj_integrity = Identity::EmojiZwjIntegrity.detect(input).classify
        unless emoji_zwj_integrity.clear?
          push_finding(findings, Family::EMOJI_ZWJ_INTEGRITY, ClassificationKind::HAZARD,
                       emoji_zwj_integrity.tag, emoji_zwj_integrity.positions)
        end

        skin_tone_variation_forgery = Identity::SkinToneVariationForgery.detect(input).classify
        unless skin_tone_variation_forgery.clear?
          push_finding(findings, Family::SKIN_TONE_VARIATION_FORGERY, ClassificationKind::HAZARD,
                       skin_tone_variation_forgery.tag, skin_tone_variation_forgery.positions)
        end

        filename_disguise = Display::FilenameDisguise.detect(input).classify
        unless filename_disguise.clear?
          push_finding(findings, Family::FILENAME_DISGUISE, ClassificationKind::HAZARD,
                       filename_disguise.tag, filename_disguise.positions)
        end

        renderer_divergence = Display::RendererDivergence.detect(input).classify
        unless renderer_divergence.clear?
          push_finding(findings, Family::RENDERER_DIVERGENCE, ClassificationKind::HAZARD,
                       renderer_divergence.tag, renderer_divergence.positions)
        end

        case_expansion_mismatch = Form::CaseExpansionMismatch.detect(input).classify
        unless case_expansion_mismatch.clear?
          push_finding(findings, Family::CASE_EXPANSION_MISMATCH, ClassificationKind::HAZARD,
                       case_expansion_mismatch.tag, case_expansion_mismatch.positions)
        end

        stream_safe_violation = Form::StreamSafeViolation.detect(input).classify
        unless stream_safe_violation.clear?
          push_finding(findings, Family::STREAM_SAFE_VIOLATION, ClassificationKind::HAZARD,
                       stream_safe_violation.tag, stream_safe_violation.positions)
        end

        admissibility_form_drift = Boundary::AdmissibilityFormDrift.detect(input).classify
        unless admissibility_form_drift.clear?
          push_finding(findings, Family::ADMISSIBILITY_FORM_DRIFT, ClassificationKind::HAZARD,
                       admissibility_form_drift.tag, admissibility_form_drift.positions)
        end

        identifier_form_drift = Boundary::IdentifierFormDrift.detect(input).classify
        unless identifier_form_drift.clear?
          push_finding(findings, Family::IDENTIFIER_FORM_DRIFT, ClassificationKind::HAZARD,
                       identifier_form_drift.tag, identifier_form_drift.positions)
        end

        normalization_bomb = Form::NormalizationBomb.detect(input)
        unless normalization_bomb.sub.nil?
          push_finding(findings, Family::NORMALIZATION_BOMB, ClassificationKind::HAZARD,
                       normalization_bomb.sub, normalization_bomb.positions)
        end

        locale_case_inversion = Form::LocaleCaseInversion.detect(input)
        unless locale_case_inversion.sub.nil?
          push_finding(findings, Family::LOCALE_CASE_INVERSION, ClassificationKind::HAZARD,
                       locale_case_inversion.sub, locale_case_inversion.positions)
        end

        nfc_idempotence_witness = Form::NfcIdempotenceWitness.detect(input)
        unless nfc_idempotence_witness.sub.nil?
          push_finding(findings, Family::NFC_IDEMPOTENCE_WITNESS, ClassificationKind::HAZARD,
                       nfc_idempotence_witness.sub, nfc_idempotence_witness.positions)
        end

        width_class_confusion = Form::WidthClassConfusion.detect(input)
        unless width_class_confusion.sub.nil?
          push_finding(findings, Family::WIDTH_CLASS_CONFUSION, ClassificationKind::HAZARD,
                       width_class_confusion.sub, width_class_confusion.positions)
        end

        # SourceDisplayDivergence judges the input as a unit, so the Lean spec
        # keeps positions on the per-family verdicts and this layer carries none.
        source_display = Display::SourceDisplayDivergence.detect(input)
        unless source_display.sub.nil?
          push_finding(findings, Family::SOURCE_DISPLAY_DIVERGENCE, ClassificationKind::HAZARD,
                       source_display.sub, [])
        end
        Verdict.new(input.dup, profile, mode, select_action(profile, mode, findings), findings, nil)
      end

      def scan_utf8(profile, mode, bytes)
        inv = Utf8.first_invalid_offset(bytes)
        unless inv.nil?
          offset, kind = inv
          return malformed_decode_verdict(profile, mode, Family::MALFORMED_UTF8,
                                          utf8_reject_tag(kind), offset)
        end
        scan(profile, mode, Utf8.decode_to_codepoints(bytes))
      end

      def read_u16(bytes, offset, endian)
        if endian == :big
          (bytes[offset] << 8) | bytes[offset + 1]
        else
          bytes[offset] | (bytes[offset + 1] << 8)
        end
      end

      def read_u32(bytes, offset, endian)
        if endian == :big
          (bytes[offset] << 24) | (bytes[offset + 1] << 16) |
            (bytes[offset + 2] << 8) | bytes[offset + 3]
        else
          bytes[offset] | (bytes[offset + 1] << 8) |
            (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)
        end
      end

      # Returns [cps, nil, nil] on success, [nil, sub_threat, offset] on error.
      def decode_utf16_stream(bytes, endian)
        input = []
        offset = 0
        while offset < bytes.length
          return [nil, "TruncatedCodeUnit", bytes.length] if offset + 2 > bytes.length

          unit = read_u16(bytes, offset, endian)
          unit_offset = offset
          offset += 2

          if unit >= 0xD800 && unit <= 0xDBFF
            return [nil, "TruncatedSurrogatePair", bytes.length] if offset + 2 > bytes.length

            low = read_u16(bytes, offset, endian)
            return [nil, "InvalidSurrogatePair", offset] unless low >= 0xDC00 && low <= 0xDFFF

            input << (0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00))
            offset += 2
          elsif unit >= 0xDC00 && unit <= 0xDFFF
            return [nil, "LoneSurrogate", unit_offset]
          else
            input << unit
          end
        end
        [input, nil, nil]
      end

      def decode_utf32_stream(bytes, endian)
        return [nil, "TruncatedCodeUnit", bytes.length] if (bytes.length % 4) != 0

        input = []
        offset = 0
        while offset < bytes.length
          cp = read_u32(bytes, offset, endian)
          return [nil, "SurrogateCodepoint", offset] if cp >= 0xD800 && cp <= 0xDFFF
          return [nil, "CodepointBeyondMax", offset] if cp > 0x10FFFF

          input << cp
          offset += 4
        end
        [input, nil, nil]
      end

      def scan_utf16(profile, mode, bytes, endian)
        input, sub_threat, offset = decode_utf16_stream(bytes, endian)
        if input.nil?
          malformed_decode_verdict(profile, mode, Family::MALFORMED_UTF16, sub_threat, offset)
        else
          scan(profile, mode, input)
        end
      end

      def scan_utf32(profile, mode, bytes, endian)
        input, sub_threat, offset = decode_utf32_stream(bytes, endian)
        if input.nil?
          malformed_decode_verdict(profile, mode, Family::MALFORMED_UTF32, sub_threat, offset)
        else
          scan(profile, mode, input)
        end
      end

      def scan_utf16be(profile, mode, bytes)
        scan_utf16(profile, mode, bytes, :big)
      end

      def scan_utf16le(profile, mode, bytes)
        scan_utf16(profile, mode, bytes, :little)
      end

      def scan_utf32be(profile, mode, bytes)
        scan_utf32(profile, mode, bytes, :big)
      end

      def scan_utf32le(profile, mode, bytes)
        scan_utf32(profile, mode, bytes, :little)
      end

      def scan_default(profile, input)
        scan(profile, Mode::ENFORCE, input)
      end

      def permits(profile, mode, input)
        action = scan(profile, mode, input).action
        action == Action::ALLOW || action == Action::OBSERVE || action == Action::REWRITE
      end
    end
  end
end
