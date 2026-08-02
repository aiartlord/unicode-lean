# frozen_string_literal: true

require_relative "../identity/ucd"

module UnicodeRuby
  module Security
    module Crypto
      # hash-input-stability: detection of inputs that are not in canonical
      # hash-input form.  Per UTS #39 §6.1 + RFC 4880 / 9580 + RFC 8785, an
      # input hashed by a signer must be byte-identical to the input hashed by
      # the verifier; if the two ends pick different canonical forms (NFC vs
      # NFD, trim policy, line-ending convention) the resulting hashes diverge
      # silently while both sides believe they signed the same content.
      #
      # Direct port of `Unicode/Security/Crypto/HashInputStability.lean` (and the
      # verified Rust reference).  The canonical (hash-stable) form is
      # `trim_trailing(to_nfc(input))`, where `trim_trailing` strips only ASCII
      # whitespace {U+0020, U+0009, U+000A, U+000D}; Unicode whitespace (U+00A0,
      # U+2000..U+200A, U+3000) is content and is not stripped.  NFC is the
      # port's `Ucd.to_nfc`, never a host normalizer.
      #
      # Six probes run in strict priority order (first hit wins):
      #
      #   1. encodingMismatch         (context: declared_encoding)
      #   2. webhookSignatureDrift    (context: server_bytes)
      #   3. auditLogReinterpretation (context: as_written)
      #   4. signedMessageRule        (context: rfc_rule)
      #   5. trailingWhitespace       (bare input)
      #   6. normalizationDrift       (bare input)
      #   7. clear
      #
      # Context-specific probes fire first because they carry more precise
      # threat information than the generic probes.  `detect` is the convenience
      # wrapper `detect_with_context(Context.new, input)` that leaves the four
      # context-bearing probes silent.
      module HashInputStability
        # RFC canonicalisation profiles the `signedMessageRule` probe checks
        # against.  Each variant's value is its stable fixture tag, so a rule
        # value is its own `tag` — `tag`/`from_tag` round-trip the selections.
        module RfcRule
          # RFC 4880 §5.2.4 — detached signatures normalise trailing whitespace.
          PGP4880_TRAILING_WHITESPACE = "pgp4880TrailingWhitespace"
          # RFC 9580 (current OpenPGP) — line-endings normalise to CRLF.
          PGP9580_LINE_ENDING = "pgp9580LineEnding"
          # RFC 8785 §3.2.5 — JSON Canonicalization Scheme requires NFC strings.
          RFC8785_NFC_REQUIREMENT = "rfc8785NfcRequirement"
          # RFC 8259 §7 — JSON strings must escape control characters.
          RFC8259_CONTROL_CHAR = "rfc8259ControlChar"
          # RFC 7515 §2 — JWS Base64URL encoding; only [A-Za-z0-9_-].
          RFC7515_JWS_BASE64_URL = "rfc7515JwsBase64Url"
          # RFC 6376 §3.4.4 — DKIM relaxed body canonicalization collapses runs.
          RFC6376_DKIM_RELAXED = "rfc6376DkimRelaxed"
          # RFC 5751 §3.1.1 — S/MIME canonical text; like PGP 9580.
          RFC5751_SMIME_LINE_ENDING = "rfc5751SmimeLineEnding"

          ALL = [
            PGP4880_TRAILING_WHITESPACE, PGP9580_LINE_ENDING,
            RFC8785_NFC_REQUIREMENT, RFC8259_CONTROL_CHAR,
            RFC7515_JWS_BASE64_URL, RFC6376_DKIM_RELAXED,
            RFC5751_SMIME_LINE_ENDING
          ].freeze

          module_function

          # Fixture-string identifier for a rule (the value is the tag).
          def tag(rule)
            case rule
            when PGP4880_TRAILING_WHITESPACE then PGP4880_TRAILING_WHITESPACE
            when PGP9580_LINE_ENDING then PGP9580_LINE_ENDING
            when RFC8785_NFC_REQUIREMENT then RFC8785_NFC_REQUIREMENT
            when RFC8259_CONTROL_CHAR then RFC8259_CONTROL_CHAR
            when RFC7515_JWS_BASE64_URL then RFC7515_JWS_BASE64_URL
            when RFC6376_DKIM_RELAXED then RFC6376_DKIM_RELAXED
            when RFC5751_SMIME_LINE_ENDING then RFC5751_SMIME_LINE_ENDING
            else
              raise "RfcRule.tag: unknown rule #{rule.inspect}"
            end
          end

          # Inverse of `tag`.  Returns nil for unrecognised strings.
          def from_tag(tag)
            case tag
            when PGP4880_TRAILING_WHITESPACE then PGP4880_TRAILING_WHITESPACE
            when PGP9580_LINE_ENDING then PGP9580_LINE_ENDING
            when RFC8785_NFC_REQUIREMENT then RFC8785_NFC_REQUIREMENT
            when RFC8259_CONTROL_CHAR then RFC8259_CONTROL_CHAR
            when RFC7515_JWS_BASE64_URL then RFC7515_JWS_BASE64_URL
            when RFC6376_DKIM_RELAXED then RFC6376_DKIM_RELAXED
            when RFC5751_SMIME_LINE_ENDING then RFC5751_SMIME_LINE_ENDING
            else nil
            end
          end
        end

        # A sub-threat the detector can fire.  `tag` is the human-facing
        # classification tag; `data` carries the variant-specific fields
        # (`first_divergent_pos`, `count`, `declared_enc`/`detected_enc`,
        # `rfc_rule`/`first_pos`).
        SubThreat = Struct.new(:tag, :data)

        # Top-level classification.  `sub` is nil when clear; `positions` is the
        # list of codepoint indices the sub-threat implicates (empty when clear).
        Classification = Struct.new(:sub, :positions) do
          def clear?
            sub.nil?
          end

          def tag
            sub.nil? ? nil : sub.tag
          end
        end

        # The structured output of `detect`.  `stable_size` is the codepoint
        # count of the hash-stable canonical form; downstream callers compare it
        # against `input.length` to size the byte-drift their hash sees.
        Verdict = Struct.new(:input, :classify, :stable_form, :stable_size)

        # Context enabling the four context-bearing probes.  Each field is nil
        # by default — the empty context is the identity case:
        # `detect_with_context(Context.new, input)` equals `detect(input)`.
        Context = Struct.new(:declared_encoding, :rfc_rule, :as_written, :server_bytes)

        module_function

        def normalization_drift(pos)
          SubThreat.new("NormalizationDrift", { first_divergent_pos: pos })
        end

        def trailing_whitespace(count)
          SubThreat.new("TrailingWhitespace", { count: count })
        end

        def encoding_mismatch(declared_enc, detected_enc)
          SubThreat.new("EncodingMismatch", { declared_enc: declared_enc, detected_enc: detected_enc })
        end

        def signed_message_rule(rfc_rule, first_pos)
          SubThreat.new("SignedMessageRule", { rfc_rule: rfc_rule, first_pos: first_pos })
        end

        def audit_log_reinterpretation(pos)
          SubThreat.new("AuditLogReinterpretation", { first_divergent_pos: pos })
        end

        def webhook_signature_drift(pos)
          SubThreat.new("WebhookSignatureDrift", { first_pos: pos })
        end

        def clear
          Classification.new(nil, [])
        end

        def hazard(sub, positions)
          Classification.new(sub, positions)
        end

        # ── Canonicalisation pipeline ──────────────────────────────────────

        # True iff `cp` is an ASCII whitespace codepoint that line-oriented
        # hash-input protocols treat as framing rather than content: U+0020
        # SPACE, U+0009 TAB, U+000A LF, U+000D CR.
        def ascii_whitespace?(cp)
          cp == 0x0020 || cp == 0x0009 || cp == 0x000A || cp == 0x000D
        end

        # Count of trailing ASCII whitespace codepoints in `input`.
        def count_trailing_whitespace(input)
          count = 0
          input.reverse_each do |cp|
            break unless ascii_whitespace?(cp)

            count += 1
          end
          count
        end

        # Strip trailing ASCII whitespace.
        def trim_trailing(input)
          keep = input.length - count_trailing_whitespace(input)
          input[0...keep]
        end

        # The hash-stable form of an input: NFC then trim, in spec order.
        def hash_stable(input)
          trim_trailing(Ucd.to_nfc(input))
        end

        # ── Priority position-finder ───────────────────────────────────────

        # First position at which `a` and `b` diverge, or the length of the
        # shared prefix when one strictly extends the other.  Nil when identical.
        def first_array_divergence(a, b)
          common = [a.length, b.length].min
          (0...common).each do |i|
            return i if a[i] != b[i]
          end
          return common if a.length != b.length

          nil
        end

        # ── Context-bearing probes ─────────────────────────────────────────

        # Lower-case an ASCII letter (U+0041..U+005A → U+0061..U+007A).
        def ascii_lower(cp)
          if cp >= 0x41 && cp <= 0x5A
            cp + 0x20
          else
            cp
          end
        end

        # True iff `label` (after ASCII case-fold) names UTF-8: accepts "utf-8",
        # "UTF-8", "UTF8", "utf8".  Non-ASCII characters pass through unchanged.
        def utf8_label?(label)
          normalised = label.each_char.map { |ch| ascii_lower(ch.ord).chr(Encoding::UTF_8) }.join
          normalised == "utf-8" || normalised == "utf8"
        end

        # True iff `cp` is a valid Unicode scalar value: in [0, 0x10FFFF] and
        # not a surrogate [0xD800, 0xDFFF].
        def valid_scalar?(cp)
          cp <= 0x10FFFF && !(cp >= 0xD800 && cp <= 0xDFFF)
        end

        # First position in `input` holding a codepoint that is not a valid
        # Unicode scalar, or nil if every codepoint is valid.
        def first_invalid_scalar(input)
          input.index { |cp| !valid_scalar?(cp) }
        end

        # Probe: encodingMismatch.  Validity is dispatched first — an invalid
        # scalar fires with detected_enc = "invalid" regardless of the declared
        # label; otherwise a non-UTF-8 label fires with detected_enc = "utf-8"
        # at position 0.  Returns [declared, detected, first_pos] when firing.
        def encoding_mismatch_probe(declared, input)
          pos = first_invalid_scalar(input)
          if pos.nil?
            if utf8_label?(declared)
              nil
            else
              [declared, "utf-8", 0]
            end
          else
            [declared, "invalid", pos]
          end
        end

        # Probe: signedMessageRule for pgp4880TrailingWhitespace.  Same
        # condition as trailingWhitespace; returns the first trailing-run pos.
        def pgp4880_violation(input)
          trailing = count_trailing_whitespace(input)
          trailing > 0 ? input.length - trailing : nil
        end

        # Probe: signedMessageRule for pgp9580LineEnding.  First bare LF
        # (U+000A not preceded by CR) or bare CR (U+000D not followed by LF).
        def pgp9580_violation(input)
          input.each_index do |i|
            cp = input[i]
            if cp == 0x000A
              preceded_by_cr = i > 0 && input[i - 1] == 0x000D
              return i unless preceded_by_cr
            elsif cp == 0x000D
              followed_by_lf = i + 1 < input.length && input[i + 1] == 0x000A
              return i unless followed_by_lf
            end
          end
          nil
        end

        # Probe: signedMessageRule for rfc8785NfcRequirement.  Same condition as
        # normalizationDrift; returns the first NFC divergence position.
        def rfc8785_violation(input)
          nfc = Ucd.to_nfc(input)
          input == nfc ? nil : first_array_divergence(input, nfc)
        end

        # Probe: signedMessageRule for rfc8259ControlChar.  First C0 control
        # (U+0000..U+001F).
        def rfc8259_violation(input)
          input.index { |cp| cp <= 0x1F }
        end

        # True iff `cp` is in the JWS Base64URL alphabet [A-Za-z0-9_-].
        def base64_url?(cp)
          (cp >= 0x41 && cp <= 0x5A) ||
            (cp >= 0x61 && cp <= 0x7A) ||
            (cp >= 0x30 && cp <= 0x39) ||
            cp == 0x2D ||
            cp == 0x5F
        end

        # Probe: signedMessageRule for rfc7515JwsBase64Url.  First codepoint
        # outside [A-Za-z0-9_-].
        def rfc7515_violation(input)
          input.index { |cp| !base64_url?(cp) }
        end

        # True iff `cp` is DKIM whitespace: U+0020 SPACE or U+0009 HTAB.
        def dkim_whitespace?(cp)
          cp == 0x20 || cp == 0x09
        end

        # Probe: signedMessageRule for rfc6376DkimRelaxed.  Position of the
        # second whitespace codepoint in the first internal run longer than one.
        def rfc6376_violation(input)
          input.each_index do |i|
            cp = input[i]
            return i if dkim_whitespace?(cp) && i > 0 && dkim_whitespace?(input[i - 1])
          end
          nil
        end

        # Probe: signedMessageRule for rfc5751SmimeLineEnding.  Reuses the PGP
        # 9580 bare-line-ending rule.
        def rfc5751_violation(input)
          pgp9580_violation(input)
        end

        # Dispatch the RFC-rule probe.  First violation position, or nil.
        def rfc_rule_violation(rule, input)
          case rule
          when RfcRule::PGP4880_TRAILING_WHITESPACE then pgp4880_violation(input)
          when RfcRule::PGP9580_LINE_ENDING then pgp9580_violation(input)
          when RfcRule::RFC8785_NFC_REQUIREMENT then rfc8785_violation(input)
          when RfcRule::RFC8259_CONTROL_CHAR then rfc8259_violation(input)
          when RfcRule::RFC7515_JWS_BASE64_URL then rfc7515_violation(input)
          when RfcRule::RFC6376_DKIM_RELAXED then rfc6376_violation(input)
          when RfcRule::RFC5751_SMIME_LINE_ENDING then rfc5751_violation(input)
          else
            raise "rfc_rule_violation: unknown rule #{rule.inspect}"
          end
        end

        # ── Top-level detection ────────────────────────────────────────────

        # The full detection function.  Runs all six probes in priority order,
        # with the context-bearing probes ahead of the generic ones.
        def detect_with_context(ctx, input)
          stable = hash_stable(input)

          # Probe 1: encodingMismatch.
          encoding_hit =
            if ctx.declared_encoding.nil?
              nil
            else
              encoding_mismatch_probe(ctx.declared_encoding, input)
            end

          # Probe 2: webhookSignatureDrift.
          webhook_hit =
            if ctx.server_bytes.nil?
              nil
            else
              first_array_divergence(input, ctx.server_bytes)
            end

          # Probe 3: auditLogReinterpretation.
          audit_hit =
            if ctx.as_written.nil?
              nil
            else
              first_array_divergence(ctx.as_written, input)
            end

          # Probe 4: signedMessageRule.
          rfc_hit =
            if ctx.rfc_rule.nil?
              nil
            else
              pos = rfc_rule_violation(ctx.rfc_rule, input)
              pos.nil? ? nil : [ctx.rfc_rule, pos]
            end

          # Probe 5: trailingWhitespace.
          trailing_count = count_trailing_whitespace(input)

          # Probe 6: normalizationDrift.
          nfc = Ucd.to_nfc(input)
          non_nfc_pos = input == nfc ? nil : first_array_divergence(input, nfc)

          classification = classify(
            encoding_hit, webhook_hit, audit_hit, rfc_hit,
            trailing_count, input.length, non_nfc_pos
          )

          Verdict.new(input.dup, classification, stable, stable.length)
        end

        # The priority resolver: first hit wins, in the spec's fixed order.
        def classify(encoding_hit, webhook_hit, audit_hit, rfc_hit,
                     trailing_count, input_len, non_nfc_pos)
          unless encoding_hit.nil?
            declared, detected, pos = encoding_hit
            return hazard(encoding_mismatch(declared, detected), [pos])
          end
          unless webhook_hit.nil?
            return hazard(webhook_signature_drift(webhook_hit), [webhook_hit])
          end
          unless audit_hit.nil?
            return hazard(audit_log_reinterpretation(audit_hit), [audit_hit])
          end
          unless rfc_hit.nil?
            rule, pos = rfc_hit
            return hazard(signed_message_rule(RfcRule.tag(rule), pos), [pos])
          end
          if trailing_count > 0
            p = input_len - trailing_count
            return hazard(trailing_whitespace(trailing_count), [p])
          end
          if non_nfc_pos.nil?
            clear
          else
            hazard(normalization_drift(non_nfc_pos), [non_nfc_pos])
          end
        end

        # Convenience wrapper over `detect_with_context` with the empty context
        # — equivalent to running only the two bare-input probes
        # (trailingWhitespace, normalizationDrift).
        def detect(input)
          detect_with_context(Context.new, input)
        end
      end
    end
  end
end
