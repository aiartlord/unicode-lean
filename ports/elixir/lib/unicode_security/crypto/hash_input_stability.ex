defmodule UnicodeSecurity.Crypto.HashInputStability do
  @moduledoc """
  hash-input-stability — detection of inputs that are not in canonical
  hash-input form. Per UTS #39 §6.1 + RFC 4880 / 9580 + RFC 8785, an input
  hashed by a signer must be byte-identical to the input hashed by the
  verifier; if the two ends pick different canonical forms (NFC vs NFD, trim
  policy, line-ending convention) the resulting hashes diverge silently while
  both sides believe they signed the same content.

  Direct port of `Unicode/Security/Crypto/HashInputStability.lean`. The
  canonical (hash-stable) form is `trim_trailing(to_nfc(input))`, where
  `trim_trailing` strips only ASCII whitespace {U+0020, U+0009, U+000A,
  U+000D}; Unicode whitespace (U+00A0, U+2000..U+200A, U+3000) is content and
  is not stripped. NFC is the port's `UnicodeSecurity.Ucd.to_nfc`, never a
  host normalizer.

  Six probes run in strict priority order (first hit wins):

    1. `encodingMismatch`         (context: `declared_encoding`)
    2. `webhookSignatureDrift`    (context: `server_bytes`)
    3. `auditLogReinterpretation` (context: `as_written`)
    4. `signedMessageRule`        (context: `rfc_rule`)
    5. `trailingWhitespace`       (bare input)
    6. `normalizationDrift`       (bare input)
    7. clear

  Context-specific probes fire first because they carry more precise threat
  information than the generic probes. `detect` is the convenience wrapper
  `detect_with_context(%Context{}, input)` that leaves the four context-bearing
  probes silent.
  """

  alias UnicodeSecurity.Ucd

  # ───────────────────────────────────────────────────────────────────
  # §1 Types
  # ───────────────────────────────────────────────────────────────────

  # RFC canonicalisation profiles that the `signedMessageRule` probe checks
  # against. Each atom names a specific canonicalisation rule from a published
  # RFC; callers pass one as `Context.rfc_rule` to opt the probe in.
  #
  #   :pgp4880_trailing_whitespace — RFC 4880 §5.2.4 detached-signature trailing
  #     whitespace normalisation.
  #   :pgp9580_line_ending — RFC 9580 (current OpenPGP) CRLF line-ending rule.
  #   :rfc8785_nfc_requirement — RFC 8785 §3.2.5 JSON Canonicalization NFC.
  #   :rfc8259_control_char — RFC 8259 §7 JSON control-character escaping.
  #   :rfc7515_jws_base64_url — RFC 7515 §2 JWS Base64URL alphabet.
  #   :rfc6376_dkim_relaxed — RFC 6376 §3.4.4 DKIM relaxed body whitespace.
  #   :rfc5751_smime_line_ending — RFC 5751 §3.1.1 S/MIME canonical text.

  @tag_by_rule %{
    pgp4880_trailing_whitespace: "pgp4880TrailingWhitespace",
    pgp9580_line_ending: "pgp9580LineEnding",
    rfc8785_nfc_requirement: "rfc8785NfcRequirement",
    rfc8259_control_char: "rfc8259ControlChar",
    rfc7515_jws_base64_url: "rfc7515JwsBase64Url",
    rfc6376_dkim_relaxed: "rfc6376DkimRelaxed",
    rfc5751_smime_line_ending: "rfc5751SmimeLineEnding"
  }

  @rule_by_tag Map.new(@tag_by_rule, fn {rule, tag} -> {tag, rule} end)

  @doc """
  Fixture-string identifier for an RFC rule — used by the conformance
  harness's attribution parser to round-trip rule selections.
  """
  def tag(rule), do: Map.fetch!(@tag_by_rule, rule)

  @doc "Inverse of `tag/1`. Returns `nil` for unrecognised strings."
  def from_tag(rule_tag), do: Map.get(@rule_by_tag, rule_tag)

  # Context passed to `detect_with_context` to enable the four context-bearing
  # probes. Each field is `nil` by default — the empty context is the identity
  # case: `detect_with_context(%Context{}, input)` equals `detect(input)`.
  #
  #   declared_encoding — the encoding label the caller claims their input is
  #     in. When set and not (case-insensitively) UTF-8, fires
  #     `encodingMismatch` immediately.
  #   rfc_rule — the RFC canonicalisation rule the caller is operating under.
  #     When set, scans `input` for violations and fires `signedMessageRule`.
  #   as_written — the original "as-written" form of an audit-log entry whose
  #     re-read is `input`. When set, fires `auditLogReinterpretation` on first
  #     divergence.
  #   server_bytes — the server-side recomputed bytes for a webhook signature.
  #     When set, fires `webhookSignatureDrift` on first divergence against
  #     `input`.
  defmodule Context do
    @moduledoc "Optional context enabling the four context-bearing probes."
    defstruct declared_encoding: nil, rfc_rule: nil, as_written: nil, server_bytes: nil
  end

  # ───────────────────────────────────────────────────────────────────
  # §2 Sub-threat / classification tags
  # ───────────────────────────────────────────────────────────────────

  @doc "Human-facing classification tag for a sub-threat map."
  def sub_threat_tag(%{kind: :normalization_drift}), do: "NormalizationDrift"
  def sub_threat_tag(%{kind: :trailing_whitespace}), do: "TrailingWhitespace"
  def sub_threat_tag(%{kind: :encoding_mismatch}), do: "EncodingMismatch"
  def sub_threat_tag(%{kind: :signed_message_rule}), do: "SignedMessageRule"
  def sub_threat_tag(%{kind: :audit_log_reinterpretation}), do: "AuditLogReinterpretation"
  def sub_threat_tag(%{kind: :webhook_signature_drift}), do: "WebhookSignatureDrift"

  @doc "True iff the classification is clear."
  def is_clear(%{kind: :clear}), do: true
  def is_clear(%{kind: :hazard}), do: false

  @doc "Human-facing tag for a hazard classification, or `nil` when clear."
  def classification_tag(%{kind: :clear}), do: nil
  def classification_tag(%{kind: :hazard, sub: sub}), do: sub_threat_tag(sub)

  @doc "Implicated positions of a classification (empty when clear)."
  def classification_positions(%{kind: :clear}), do: []
  def classification_positions(%{kind: :hazard, positions: positions}), do: positions

  # ───────────────────────────────────────────────────────────────────
  # §3 Canonicalisation pipeline
  # ───────────────────────────────────────────────────────────────────

  # True iff `cp` is an ASCII whitespace codepoint that line-oriented
  # hash-input protocols treat as framing rather than content: U+0020 SPACE,
  # U+0009 TAB, U+000A LF, U+000D CR.
  defp is_ascii_whitespace(cp),
    do: cp == 0x0020 or cp == 0x0009 or cp == 0x000A or cp == 0x000D

  # Count of trailing ASCII whitespace codepoints in `input`.
  defp count_trailing_whitespace(input),
    do: input |> Enum.reverse() |> Enum.take_while(&is_ascii_whitespace/1) |> length()

  # Strip trailing ASCII whitespace.
  defp trim_trailing(input) do
    keep = length(input) - count_trailing_whitespace(input)
    Enum.take(input, keep)
  end

  @doc "The hash-stable form of an input: NFC then trim, in spec order."
  def hash_stable(input), do: trim_trailing(Ucd.to_nfc(input))

  # ───────────────────────────────────────────────────────────────────
  # §5 Priority position-finder
  # ───────────────────────────────────────────────────────────────────

  # First position at which `a` and `b` diverge, or the length of the shared
  # prefix when one strictly extends the other. `nil` when identical.
  defp first_array_divergence(a, b) do
    n = min(length(a), length(b))
    pos = Enum.find(0..max(n - 1, 0), fn i -> n > 0 and Enum.at(a, i) != Enum.at(b, i) end)

    cond do
      pos != nil -> pos
      length(a) != length(b) -> n
      true -> nil
    end
  end

  # ───────────────────────────────────────────────────────────────────
  # §6 Context-bearing probes
  # ───────────────────────────────────────────────────────────────────

  # Lower-case an ASCII letter (U+0041..U+005A → U+0061..U+007A).
  defp ascii_lower(cp) do
    if cp >= 0x41 and cp <= 0x5A, do: cp + 0x20, else: cp
  end

  # True iff `label` (after ASCII case-fold) names UTF-8: accepts "utf-8",
  # "UTF-8", "UTF8", "utf8". Non-ASCII characters pass through unchanged.
  defp is_utf8_label(label) do
    normalised = label |> String.to_charlist() |> Enum.map(&ascii_lower/1)
    normalised == ~c"utf-8" or normalised == ~c"utf8"
  end

  # True iff `cp` is a valid Unicode scalar value: in `[0, 0x10FFFF]` and not a
  # surrogate `[0xD800, 0xDFFF]`.
  defp is_valid_scalar(cp),
    do: cp <= 0x10FFFF and not (cp >= 0xD800 and cp <= 0xDFFF)

  # First position in `input` holding a codepoint that is not a valid Unicode
  # scalar, or `nil` if every codepoint is valid.
  defp first_invalid_scalar(input),
    do: Enum.find_index(input, fn cp -> not is_valid_scalar(cp) end)

  # Probe: `encodingMismatch`. Validity is dispatched first — an invalid scalar
  # fires with detected = "invalid" regardless of the declared label; otherwise
  # a non-UTF-8 label fires with detected = "utf-8" at position 0. Returns
  # `{declared, detected, first_pos}` when firing, `nil` otherwise.
  defp encoding_mismatch_probe(declared, input) do
    case first_invalid_scalar(input) do
      nil ->
        if is_utf8_label(declared), do: nil, else: {declared, "utf-8", 0}

      pos ->
        {declared, "invalid", pos}
    end
  end

  # Probe: `signedMessageRule` for `pgp4880TrailingWhitespace`. Same condition
  # as `trailingWhitespace`; returns the first position of the trailing run.
  defp pgp4880_violation(input) do
    trailing = count_trailing_whitespace(input)
    if trailing > 0, do: length(input) - trailing, else: nil
  end

  # Probe: `signedMessageRule` for `pgp9580LineEnding`. First bare LF (U+000A
  # not preceded by CR) or bare CR (U+000D not followed by LF).
  defp pgp9580_violation(input), do: scan_line_endings(input, nil, 0)

  defp scan_line_endings([], _prev, _i), do: nil

  defp scan_line_endings([cp | rest], prev, i) do
    cond do
      cp == 0x000A ->
        # LF: violating iff not preceded by CR.
        if prev == 0x000D, do: scan_line_endings(rest, cp, i + 1), else: i

      cp == 0x000D ->
        # CR: violating iff not followed by LF.
        case rest do
          [next | _tail] when next == 0x000A -> scan_line_endings(rest, cp, i + 1)
          _rest -> i
        end

      true ->
        scan_line_endings(rest, cp, i + 1)
    end
  end

  # Probe: `signedMessageRule` for `rfc8785NfcRequirement`. Same condition as
  # `normalizationDrift`; returns the first NFC divergence position.
  defp rfc8785_violation(input) do
    nfc = Ucd.to_nfc(input)
    if input == nfc, do: nil, else: first_array_divergence(input, nfc)
  end

  # Probe: `signedMessageRule` for `rfc8259ControlChar`. First C0 control
  # (U+0000..U+001F) — the JSON-permitted whitespace still requires escaping,
  # so it also counts.
  defp rfc8259_violation(input), do: Enum.find_index(input, fn cp -> cp <= 0x1F end)

  # True iff `cp` is in the JWS Base64URL alphabet `[A-Za-z0-9_-]`.
  defp is_base64_url(cp) do
    (cp >= 0x41 and cp <= 0x5A) or
      (cp >= 0x61 and cp <= 0x7A) or
      (cp >= 0x30 and cp <= 0x39) or
      cp == 0x2D or
      cp == 0x5F
  end

  # Probe: `signedMessageRule` for `rfc7515JwsBase64Url`. First codepoint
  # outside `[A-Za-z0-9_-]`.
  defp rfc7515_violation(input),
    do: Enum.find_index(input, fn cp -> not is_base64_url(cp) end)

  # True iff `cp` is DKIM whitespace: U+0020 SPACE or U+0009 HTAB.
  defp is_dkim_whitespace(cp), do: cp == 0x20 or cp == 0x09

  # Probe: `signedMessageRule` for `rfc6376DkimRelaxed`. Position of the second
  # whitespace codepoint in the first internal whitespace run longer than one.
  defp rfc6376_violation(input), do: scan_dkim_runs(input, nil, 0)

  defp scan_dkim_runs([], _prev, _i), do: nil

  defp scan_dkim_runs([cp | rest], prev, i) do
    if is_dkim_whitespace(cp) and i > 0 and prev != nil and is_dkim_whitespace(prev),
      do: i,
      else: scan_dkim_runs(rest, cp, i + 1)
  end

  # Probe: `signedMessageRule` for `rfc5751SmimeLineEnding`. Reuses the PGP 9580
  # bare-line-ending rule.
  defp rfc5751_violation(input), do: pgp9580_violation(input)

  # Dispatch the RFC-rule probe. First violation position, or `nil` if clean.
  defp rfc_rule_violation(rule, input) do
    case rule do
      :pgp4880_trailing_whitespace -> pgp4880_violation(input)
      :pgp9580_line_ending -> pgp9580_violation(input)
      :rfc8785_nfc_requirement -> rfc8785_violation(input)
      :rfc8259_control_char -> rfc8259_violation(input)
      :rfc7515_jws_base64_url -> rfc7515_violation(input)
      :rfc6376_dkim_relaxed -> rfc6376_violation(input)
      :rfc5751_smime_line_ending -> rfc5751_violation(input)
    end
  end

  # ───────────────────────────────────────────────────────────────────
  # §7 Top-level detection
  # ───────────────────────────────────────────────────────────────────

  @doc """
  The full detection function. Runs all six probes in priority order, with the
  context-bearing probes ahead of the generic ones. Returns a verdict map with
  `input`, `classify`, `stable_form`, and `stable_size`.
  """
  def detect_with_context(%Context{} = ctx, input) do
    stable = hash_stable(input)

    # Probe 1: encodingMismatch.
    encoding_hit =
      case ctx.declared_encoding do
        nil -> nil
        label -> encoding_mismatch_probe(label, input)
      end

    # Probe 2: webhookSignatureDrift.
    webhook_hit =
      case ctx.server_bytes do
        nil -> nil
        server -> first_array_divergence(input, server)
      end

    # Probe 3: auditLogReinterpretation.
    audit_hit =
      case ctx.as_written do
        nil -> nil
        written -> first_array_divergence(written, input)
      end

    # Probe 4: signedMessageRule.
    rfc_hit =
      case ctx.rfc_rule do
        nil ->
          nil

        rule ->
          case rfc_rule_violation(rule, input) do
            nil -> nil
            pos -> {rule, pos}
          end
      end

    # Probe 5: trailingWhitespace.
    trailing_count = count_trailing_whitespace(input)

    # Probe 6: normalizationDrift.
    nfc = Ucd.to_nfc(input)
    non_nfc_pos = if input == nfc, do: nil, else: first_array_divergence(input, nfc)

    classification =
      classify(encoding_hit, webhook_hit, audit_hit, rfc_hit, trailing_count, length(input), non_nfc_pos)

    %{input: input, classify: classification, stable_form: stable, stable_size: length(stable)}
  end

  # The priority resolver: first hit wins, in the spec's fixed order.
  defp classify(encoding_hit, webhook_hit, audit_hit, rfc_hit, trailing_count, input_len, non_nfc_pos) do
    cond do
      encoding_hit != nil ->
        {declared, detected, pos} = encoding_hit

        %{
          kind: :hazard,
          sub: %{kind: :encoding_mismatch, declared_enc: declared, detected_enc: detected},
          positions: [pos]
        }

      webhook_hit != nil ->
        %{
          kind: :hazard,
          sub: %{kind: :webhook_signature_drift, first_pos: webhook_hit},
          positions: [webhook_hit]
        }

      audit_hit != nil ->
        %{
          kind: :hazard,
          sub: %{kind: :audit_log_reinterpretation, first_divergent_pos: audit_hit},
          positions: [audit_hit]
        }

      rfc_hit != nil ->
        {rule, pos} = rfc_hit

        %{
          kind: :hazard,
          sub: %{kind: :signed_message_rule, rfc_rule: tag(rule), first_pos: pos},
          positions: [pos]
        }

      trailing_count > 0 ->
        p = input_len - trailing_count

        %{
          kind: :hazard,
          sub: %{kind: :trailing_whitespace, count: trailing_count},
          positions: [p]
        }

      non_nfc_pos != nil ->
        %{
          kind: :hazard,
          sub: %{kind: :normalization_drift, first_divergent_pos: non_nfc_pos},
          positions: [non_nfc_pos]
        }

      true ->
        %{kind: :clear}
    end
  end

  @doc """
  Convenience wrapper over `detect_with_context/2` with the empty context —
  equivalent to running only the two bare-input probes (`trailingWhitespace`,
  `normalizationDrift`).
  """
  def detect(input), do: detect_with_context(%Context{}, input)
end
