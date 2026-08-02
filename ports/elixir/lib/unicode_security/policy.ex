defmodule UnicodeSecurity.Policy do
  alias UnicodeSecurity.Calculus
  alias UnicodeSecurity.Noncharacters
  alias UnicodeSecurity.Utf8
  alias UnicodeSecurity.Boundary.{ConfusableBidiCompound, CovertDisplayCompound}

  alias UnicodeSecurity.Covert.{
    BidiControlBalance,
    SurrogateReassembly,
    TagBlockPayload,
    VariationSelectorPayload,
    ZeroWidthPayload
  }

  alias UnicodeSecurity.Crypto.{Bip39Canonical, HashInputStability}
  alias UnicodeSecurity.Display.RtlInjection
  alias UnicodeSecurity.Form.{LocaleCaseInversion, NfcIdempotenceWitness, NormalizationBomb}
  alias UnicodeSecurity.Identity.HomoglyphConfusable

  @profiles [
    "gateway-header",
    "domain-name",
    "dns-label",
    "url",
    "username",
    "display-name",
    "chat-message",
    "source-code",
    "opaque-secret",
    "binary-blob"
  ]
  @modes ["observe", "warn", "enforce", "strict"]

  def profiles, do: @profiles
  def modes, do: @modes

  def policy_of_profile(profile) do
    case profile do
      p when p in ["gateway-header", "domain-name", "dns-label", "source-code"] ->
        %{level: :restrictive, crypto_context: :non_crypto, quarantine: false}

      "url" ->
        %{level: :moderate, crypto_context: :non_crypto, quarantine: false}

      "username" ->
        %{level: :moderate, crypto_context: :non_crypto, quarantine: true}

      p when p in ["display-name", "chat-message"] ->
        %{level: :minimal, crypto_context: :non_crypto, quarantine: true}

      "opaque-secret" ->
        %{level: :minimal, crypto_context: :hash_input, quarantine: false}

      "binary-blob" ->
        %{level: :minimal, crypto_context: :non_crypto, quarantine: false}
    end
  end

  def rejection_set(:restrictive) do
    MapSet.new([
      :malformed_utf8,
      :malformed_utf16,
      :malformed_utf32,
      :tag_block_payload,
      :variation_selector_payload,
      :zero_width_payload,
      :surrogate_reassembly,
      :bidi_control_balance,
      :noncharacter_control,
      :homoglyph_confusable,
      :mixed_script_admissibility,
      :emoji_zwj_integrity,
      :skin_tone_variation_forgery,
      :source_display_divergence,
      :filename_disguise,
      :rtl_injection,
      :renderer_divergence,
      :normalization_bomb,
      :stream_safe_violation,
      :locale_case_inversion,
      :case_expansion_mismatch,
      :width_class_confusion,
      :nfc_idempotence_witness,
      :identifier_form_drift,
      :covert_display_compound,
      :confusable_bidi_compound,
      :admissibility_form_drift
    ])
  end

  def rejection_set(:moderate) do
    MapSet.new([
      :malformed_utf8,
      :malformed_utf16,
      :malformed_utf32,
      :tag_block_payload,
      :variation_selector_payload,
      :zero_width_payload,
      :surrogate_reassembly,
      :bidi_control_balance,
      :noncharacter_control,
      :homoglyph_confusable,
      :mixed_script_admissibility,
      :skin_tone_variation_forgery,
      :source_display_divergence,
      :filename_disguise,
      :stream_safe_violation,
      :locale_case_inversion,
      :case_expansion_mismatch,
      :width_class_confusion,
      :nfc_idempotence_witness,
      :identifier_form_drift,
      :covert_display_compound,
      :confusable_bidi_compound,
      :admissibility_form_drift
    ])
  end

  def rejection_set(:minimal),
    do:
      MapSet.new([
        :malformed_utf8,
        :malformed_utf16,
        :malformed_utf32,
        :surrogate_reassembly,
        :bidi_control_balance,
        :noncharacter_control,
        :stream_safe_violation
      ])

  def family_slug(family) do
    family |> Atom.to_string() |> String.replace("_", "-")
  end

  def family_layer_code(family)
      when family in [
             :malformed_utf8,
             :malformed_utf16,
             :malformed_utf32,
             :tag_block_payload,
             :variation_selector_payload,
             :zero_width_payload,
             :surrogate_reassembly,
             :bidi_control_balance,
             :noncharacter_control
           ],
      do: "C"

  def family_layer_code(family)
      when family in [
             :homoglyph_confusable,
             :mixed_script_admissibility,
             :emoji_zwj_integrity,
             :skin_tone_variation_forgery
           ],
      do: "I"

  def family_layer_code(family)
      when family in [
             :source_display_divergence,
             :filename_disguise,
             :rtl_injection,
             :renderer_divergence
           ],
      do: "D"

  def family_layer_code(family)
      when family in [
             :normalization_bomb,
             :stream_safe_violation,
             :locale_case_inversion,
             :case_expansion_mismatch,
             :width_class_confusion,
             :nfc_idempotence_witness
           ],
      do: "F"

  def family_layer_code(family)
      when family in [
             :identifier_form_drift,
             :covert_display_compound,
             :confusable_bidi_compound,
             :admissibility_form_drift
           ],
      do: "X"

  def family_layer_code(_family), do: "K"

  def reason_code(family, sub \\ nil),
    do: "unicode.security.#{family_layer_code(family)}.#{family_slug(family)}.#{sub || "hazard"}"

  def family_blocks?(profile, family),
    do: policy_of_profile(profile).level |> rejection_set() |> MapSet.member?(family)

  def select_action(profile, mode, findings) do
    has_findings = findings != []
    has_blocking = Enum.any?(findings, fn f -> family_blocks?(profile, f.family) end)

    case mode do
      mode when mode in ["observe", "warn"] ->
        if has_findings, do: "observe", else: "allow"

      "enforce" ->
        if has_blocking,
          do: if(policy_of_profile(profile).quarantine, do: "quarantine", else: "reject"),
          else: "allow"

      "strict" ->
        if has_findings, do: "reject", else: "allow"
    end
  end

  def scan(profile, mode, input) do
    findings = []

    findings =
      push_detector(
        findings,
        :tag_block_payload,
        TagBlockPayload.detect(input),
        & &1.tag_positions
      )

    findings =
      push_detector(
        findings,
        :variation_selector_payload,
        VariationSelectorPayload.detect(input),
        & &1.vs_positions
      )

    findings =
      push_detector(
        findings,
        :zero_width_payload,
        ZeroWidthPayload.detect(input),
        & &1.zero_width_positions
      )

    findings =
      if SurrogateReassembly.looks_like_byte_stream?(input) do
        sr = SurrogateReassembly.detect(input)

        if sr.sub,
          do: push_finding(findings, :surrogate_reassembly, :hazard, sr.sub, sr.positions),
          else: findings
      else
        findings
      end

    bidi = BidiControlBalance.detect(input)

    findings =
      push_finding(findings, :bidi_control_balance, bidi.kind, bidi.sub, bidi.bidi_positions)

    findings =
      push_positional_hazard(
        findings,
        :noncharacter_control,
        "Noncharacter",
        positions_where(input, &Noncharacters.noncharacter?/1)
      )

    findings =
      push_positional_hazard(
        findings,
        :noncharacter_control,
        "C0Control",
        positions_where(input, &c0_control?/1)
      )

    findings =
      push_positional_hazard(
        findings,
        :noncharacter_control,
        "C1Control",
        positions_where(input, &c1_control?/1)
      )

    h = HomoglyphConfusable.detect(input)

    findings =
      if sub_tag(h.sub) != "CrossScriptMix",
        do:
          push_finding(
            findings,
            :homoglyph_confusable,
            h.kind,
            h.sub,
            if(h.kind == :clear, do: [], else: Enum.to_list(0..(length(input) - 1)))
          ),
        else: findings

    findings =
      if HomoglyphConfusable.mixed_script_admissibility?(input),
        do:
          push_finding(
            findings,
            :mixed_script_admissibility,
            :hazard,
            HomoglyphConfusable.mixed_script_subthreat(input),
            positions_all(input)
          ),
        else: findings

    rtl = RtlInjection.detect(input)

    findings =
      if rtl.sub,
        do: push_finding(findings, :rtl_injection, :hazard, rtl.sub, rtl.positions),
        else: findings

    cb = ConfusableBidiCompound.detect(input)

    findings =
      if cb.sub,
        do: push_finding(findings, :confusable_bidi_compound, :hazard, cb.sub, cb.positions),
        else: findings

    cd = CovertDisplayCompound.detect(input)

    findings =
      if cd.sub,
        do: push_finding(findings, :covert_display_compound, :hazard, cd.sub, cd.positions),
        else: findings

    verdict(profile, mode, input, findings, nil)
  end

  def scan_utf8(profile, mode, bytes) when is_list(bytes),
    do: scan_utf8(profile, mode, :binary.list_to_bin(bytes))

  def scan_utf8(profile, mode, bytes) do
    case Utf8.first_invalid_utf8_offset(bytes) do
      nil ->
        scan(profile, mode, Utf8.decode_to_codepoints(bytes))

      {offset, kind} ->
        malformed_decode_verdict(profile, mode, :malformed_utf8, Utf8.reject_tag(kind), offset)
    end
  end

  def scan_utf16be(profile, mode, bytes), do: scan_utf16(profile, mode, bytes, :big)
  def scan_utf16le(profile, mode, bytes), do: scan_utf16(profile, mode, bytes, :little)
  def scan_utf32be(profile, mode, bytes), do: scan_utf32(profile, mode, bytes, :big)
  def scan_utf32le(profile, mode, bytes), do: scan_utf32(profile, mode, bytes, :little)
  def scan_default(profile, input), do: scan(profile, "enforce", input)

  def scan_forms(profile, mode, input) do
    findings =
      [
        {:locale_case_inversion, LocaleCaseInversion.detect(input)},
        {:nfc_idempotence_witness, NfcIdempotenceWitness.detect(input)},
        {:normalization_bomb, NormalizationBomb.detect(input)}
      ]
      |> Enum.reduce([], fn {family, v}, acc ->
        if v.sub, do: push_finding(acc, family, :hazard, v.sub, v.positions), else: acc
      end)

    verdict(profile, mode, input, findings, nil)
  end

  def scan_bip39(profile, mode, input) do
    b = Bip39Canonical.detect(input)

    findings =
      if b.sub, do: push_finding([], :bip39_canonical, :hazard, b.sub, b.positions), else: []

    verdict(profile, mode, input, findings, b.canonical)
  end

  def scan_hash_input(profile, mode, input) do
    v = HashInputStability.detect(input)
    tag = HashInputStability.classification_tag(v.classify)
    positions = HashInputStability.classification_positions(v.classify)

    findings =
      if tag, do: push_finding([], :hash_input_stability, :hazard, tag, positions), else: []

    verdict(profile, mode, input, findings, v.stable_form)
  end

  def finding_to_wire(finding) do
    %{
      "code" => finding.code,
      "family" => family_slug(finding.family),
      "severity" => Calculus.severity_value(finding.severity),
      "positions" => finding.positions,
      "sub_threat" => finding.sub_threat,
      "detail" => finding.detail
    }
  end

  def verdict_to_wire(verdict) do
    %{
      "action" => verdict.action,
      "profile" => verdict.profile,
      "mode" => verdict.mode,
      "input" => verdict.input,
      "findings" => Enum.map(verdict.findings, &finding_to_wire/1),
      "normalized" => verdict.normalized
    }
  end

  def verdict_to_json(verdict), do: JSON.encode!(verdict_to_wire(verdict))

  defp scan_utf16(profile, mode, bytes, endian) do
    case decode_utf16_stream(bytes, endian) do
      {:ok, input} ->
        scan(profile, mode, input)

      {:error, sub, offset} ->
        malformed_decode_verdict(profile, mode, :malformed_utf16, sub, offset)
    end
  end

  defp scan_utf32(profile, mode, bytes, endian) do
    case decode_utf32_stream(bytes, endian) do
      {:ok, input} ->
        scan(profile, mode, input)

      {:error, sub, offset} ->
        malformed_decode_verdict(profile, mode, :malformed_utf32, sub, offset)
    end
  end

  defp decode_utf16_stream(bytes, endian), do: decode_utf16_stream(bytes, endian, 0, [])
  defp decode_utf16_stream([], _endian, _offset, acc), do: {:ok, Enum.reverse(acc)}

  defp decode_utf16_stream([_], _endian, offset, _acc),
    do: {:error, "TruncatedCodeUnit", offset + 1}

  defp decode_utf16_stream(bytes, endian, offset, acc) do
    [a, b | rest] = bytes
    unit = read_u16(a, b, endian)

    cond do
      unit >= 0xD800 and unit <= 0xDBFF ->
        case rest do
          [c, d | tail] ->
            low = read_u16(c, d, endian)

            if low >= 0xDC00 and low <= 0xDFFF,
              do:
                decode_utf16_stream(tail, endian, offset + 4, [
                  0x10000 + (unit - 0xD800) * 0x400 + (low - 0xDC00) | acc
                ]),
              else: {:error, "InvalidSurrogatePair", offset + 2}

          _ ->
            {:error, "TruncatedSurrogatePair", offset + length(rest) + 2}
        end

      unit >= 0xDC00 and unit <= 0xDFFF ->
        {:error, "LoneSurrogate", offset}

      true ->
        decode_utf16_stream(rest, endian, offset + 2, [unit | acc])
    end
  end

  defp decode_utf32_stream(bytes, _endian) when rem(length(bytes), 4) != 0,
    do: {:error, "TruncatedCodeUnit", length(bytes)}

  defp decode_utf32_stream(bytes, endian) do
    bytes
    |> Enum.chunk_every(4)
    |> Enum.with_index()
    |> Enum.reduce_while([], fn {[a, b, c, d], idx}, acc ->
      cp = read_u32(a, b, c, d, endian)
      offset = idx * 4

      cond do
        cp >= 0xD800 and cp <= 0xDFFF -> {:halt, {:error, "SurrogateCodepoint", offset}}
        cp > 0x10FFFF -> {:halt, {:error, "CodepointBeyondMax", offset}}
        true -> {:cont, [cp | acc]}
      end
    end)
    |> case do
      {:error, _sub, _offset} = err -> err
      acc -> {:ok, Enum.reverse(acc)}
    end
  end

  defp read_u16(a, b, :big), do: a * 0x100 + b
  defp read_u16(a, b, :little), do: a + b * 0x100
  defp read_u32(a, b, c, d, :big), do: a * 0x1000000 + b * 0x10000 + c * 0x100 + d
  defp read_u32(a, b, c, d, :little), do: a + b * 0x100 + c * 0x10000 + d * 0x1000000

  defp malformed_decode_verdict(profile, mode, family, sub, offset) do
    findings = [finding(family, :moderate, [offset], sub)]
    verdict(profile, mode, [], findings, nil)
  end

  defp verdict(profile, mode, input, findings, normalized) do
    findings = Enum.reverse(findings)

    %{
      input: input,
      profile: profile,
      mode: mode,
      action: select_action(profile, mode, findings),
      findings: findings,
      normalized: normalized
    }
  end

  defp push_detector(findings, family, detector, positions_fun),
    do: push_finding(findings, family, detector.kind, detector.sub, positions_fun.(detector))

  defp push_finding(findings, _family, :clear, _sub, _positions), do: findings

  defp push_finding(findings, family, kind, sub, positions),
    do: [finding(family, severity(kind), positions, sub) | findings]

  defp finding(family, severity, positions, sub) do
    tag = sub_tag(sub)

    %{
      code: reason_code(family, tag),
      family: family,
      severity: severity,
      positions: positions,
      sub_threat: tag,
      detail: family_slug(family)
    }
  end

  defp severity(:hazard), do: :moderate
  defp severity(:compound), do: :high
  defp severity(_), do: :informational

  defp sub_tag(nil), do: nil
  defp sub_tag(sub) when is_binary(sub), do: sub
  defp sub_tag(%{tag: tag}), do: tag
  defp sub_tag({:direct_ascii, _}), do: "DirectAscii"
  defp sub_tag({:language_tag_revival, _, _}), do: "LanguageTagRevival"
  defp sub_tag({:mixed_block, _, _}), do: "MixedBlock"
  defp sub_tag({:bare_tag_present, _}), do: "BareTagPresent"
  defp sub_tag({:direct_payload, _}), do: "DirectPayload"
  defp sub_tag({:illegal_target, _, _}), do: "IllegalTarget"
  defp sub_tag({:repeated_base, _, _}), do: "RepeatedBase"
  defp sub_tag({:annotation_misuse, _}), do: "AnnotationMisuse"
  defp sub_tag({:word_joiner_injection, _}), do: "WordJoinerInjection"
  defp sub_tag({:ai_watermark_nnbsp, _}), do: "AiWatermarkNNBSP"
  defp sub_tag({:binary_payload, _}), do: "BinaryPayload"
  defp sub_tag({:bare_zero_width, _}), do: "BareZeroWidth"

  defp push_positional_hazard(findings, family, sub, positions),
    do:
      if(positions == [],
        do: findings,
        else: push_finding(findings, family, :hazard, sub, positions)
      )

  defp positions_where(input, pred),
    do:
      input
      |> Enum.with_index()
      |> Enum.filter(fn {cp, _i} -> pred.(cp) end)
      |> Enum.map(fn {_cp, i} -> i end)

  defp positions_all([]), do: []
  defp positions_all(input), do: Enum.to_list(0..(length(input) - 1))

  defp c0_control?(cp),
    do: (cp >= 0 and cp <= 0x1F and cp not in [0x09, 0x0A, 0x0D]) or cp == 0x7F

  defp c1_control?(cp), do: cp >= 0x80 and cp <= 0x9F
end
