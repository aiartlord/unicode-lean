defmodule UnicodeSecurity.Crypto.AiWatermarkDetectability do
  @moduledoc """
  ai-watermark-detectability — character-level detector for inputs carrying
  codepoint patterns consistent with a known AI watermark scheme. Answers the
  question: does this input contain markers attributable to a watermarking
  protocol?

  Direct port of `Unicode/Security/Crypto/AiWatermarkDetectability.lean` (via
  the verified rust reference
  `ports/rust/src/security/crypto/ai_watermark_detectability.rs`).

  Threat model — provenance-attribution attacker. An input either (a) carries
  an AI provider's watermark codepoints (a legitimate provenance marker) or
  (b) carries injected markers that impersonate a provider's scheme to
  discredit the content as AI-generated. Character-level detection alone cannot
  distinguish (a) from (b); the detector reports the matched scheme and leaves
  provider-specific authentication to downstream code.

  Probe inventory (priority order, first match wins):

    1. `adversarial`              — NNBSP count >= 3 at arithmetic-progression positions.
    2. `gpt5ZwspModulo`           — ZWSP count >= 3 at arithmetic-progression positions.
    3. `unknown`                  — invisible markers from >= 2 distinct categories.
    4. `nnbspBoundary`            — single-category NNBSP.
    5. `variationSelectorCarrier` — VS NOT adjacent to an emoji codepoint.
    6. `zwjNonEmoji`              — ZWJ NOT adjacent to an emoji codepoint.
    7. `smartQuoteAlternation`    — paired curly quotes, no ASCII straight quotes.
    8. `emDashPattern`            — em-dashes, no ASCII hyphen-minus.
    9. `statisticalTokenChoice`   — input contains an AI-favored lexical pattern.
   10. `defaultIgnorableCarrier`  — single-category residual Default_Ignorable.

  The Emoji property table is bundled in the port's own `priv/data/emoji-data.txt`
  (UTS #51 17.0, byte-identical to the UCD source the Lean spec cites); the
  adjacency probe parses the `Emoji` rows from it, never a host emoji library.
  The Default_Ignorable predicate reuses the port's own `UnicodeSecurity.Ucd`
  UCD table, never a host normalizer.
  """

  alias UnicodeSecurity.Data
  alias UnicodeSecurity.Ucd

  # ───────────────────────────────────────────────────────────────────
  # §1 Cue class / sub-threat / classification tags
  # ───────────────────────────────────────────────────────────────────

  # The conceptual watermark cue class a sub-threat probes for, drawn from the
  # fixed vocabulary `Unicode.Generated.WatermarkSchemes.CueClass`:
  #
  #   :green_list_bias  — a codepoint-frequency bias toward a pinned "green
  #     list" of tokens.
  #   :pseudorandom_seq — a fixed-period or carrier-byte channel surfacing a
  #     pseudorandom function.
  #   :semantic_drift   — a stylistic-distribution drift away from natural
  #     human writing.

  @doc "Human-facing classification tag for a sub-threat map."
  def sub_threat_tag(%{kind: :nnbsp_boundary}), do: "NnbspBoundary"
  def sub_threat_tag(%{kind: :variation_selector_carrier}), do: "VariationSelectorCarrier"
  def sub_threat_tag(%{kind: :zwj_non_emoji}), do: "ZwjNonEmoji"
  def sub_threat_tag(%{kind: :default_ignorable_carrier}), do: "DefaultIgnorableCarrier"
  def sub_threat_tag(%{kind: :gpt5_zwsp_modulo}), do: "Gpt5ZwspModulo"
  def sub_threat_tag(%{kind: :em_dash_pattern}), do: "EmDashPattern"
  def sub_threat_tag(%{kind: :smart_quote_alternation}), do: "SmartQuoteAlternation"
  def sub_threat_tag(%{kind: :statistical_token_choice}), do: "StatisticalTokenChoice"
  def sub_threat_tag(%{kind: :adversarial}), do: "Adversarial"
  def sub_threat_tag(%{kind: :unknown}), do: "Unknown"

  @doc """
  Map a sub-threat map to the conceptual watermark cue class it probes for.
  Marker-encoded sub-threats route to `:pseudorandom_seq`; vocabulary-bias to
  `:green_list_bias`; stylistic-distribution to `:semantic_drift`; `:unknown`
  (multi-category mixing) implicates no single scheme, returning `nil`.
  """
  def cue_class(%{kind: :nnbsp_boundary}), do: :pseudorandom_seq
  def cue_class(%{kind: :variation_selector_carrier}), do: :pseudorandom_seq
  def cue_class(%{kind: :zwj_non_emoji}), do: :pseudorandom_seq
  def cue_class(%{kind: :default_ignorable_carrier}), do: :pseudorandom_seq
  def cue_class(%{kind: :gpt5_zwsp_modulo}), do: :pseudorandom_seq
  def cue_class(%{kind: :em_dash_pattern}), do: :semantic_drift
  def cue_class(%{kind: :smart_quote_alternation}), do: :semantic_drift
  def cue_class(%{kind: :statistical_token_choice}), do: :green_list_bias
  def cue_class(%{kind: :adversarial}), do: :pseudorandom_seq
  def cue_class(%{kind: :unknown}), do: nil

  @doc "True iff the classification is clear (no watermark marker detected)."
  def is_clear(%{kind: :clear}), do: true
  def is_clear(%{kind: :hazard}), do: false

  @doc "Human-facing tag for a hazard classification, or `nil` when clear."
  def classification_tag(%{kind: :clear}), do: nil
  def classification_tag(%{kind: :hazard, sub: sub}), do: sub_threat_tag(sub)

  @doc "Implicated positions of a classification (empty when clear)."
  def classification_positions(%{kind: :clear}), do: []
  def classification_positions(%{kind: :hazard, positions: positions}), do: positions

  # Optional context for the modulo-probe tolerances. Each field controls how
  # strictly the corresponding probe checks its arithmetic-progression
  # condition; the defaults of `0` require exact equality of consecutive gaps.
  #
  #   zwsp_modulo_tolerance — `0` requires the ZWSP-position arithmetic
  #     progression to be exact. `k > 0` accepts position gaps within +/- k of
  #     the first gap, catching modulo schedules with light jitter.
  #   adversarial_tolerance — same semantic as `zwsp_modulo_tolerance` but for
  #     the NNBSP positions (the `adversarial` probe).
  defmodule Context do
    @moduledoc "Optional context enabling the modulo-probe tolerances."
    defstruct zwsp_modulo_tolerance: 0, adversarial_tolerance: 0
  end

  # ───────────────────────────────────────────────────────────────────
  # §2 Emoji property table (bundled priv/data/emoji-data.txt, Emoji rows)
  # ───────────────────────────────────────────────────────────────────

  # Parse the `Emoji` (`Emoji=Yes`) closed intervals from emoji-data.txt. Each
  # non-comment row is `<range> ; <property> # <comment>`; keep only rows whose
  # property is exactly `Emoji`.
  defp emoji_ranges do
    Data.cached(:ai_watermark_emoji_ranges, fn ->
      Data.read("emoji-data.txt")
      |> String.split("\n")
      |> Enum.reduce([], fn line, acc ->
        [body | _rest] = String.split(line, "#", parts: 2)

        case String.trim(body) do
          "" ->
            acc

          stripped ->
            case String.split(stripped, ";") do
              [range_field, prop_field | _tail] ->
                if String.trim(prop_field) == "Emoji" do
                  case parse_emoji_range(String.trim(range_field)) do
                    {lo, hi} -> [{lo, hi} | acc]
                    :error -> acc
                  end
                else
                  acc
                end

              _fewer_fields ->
                acc
            end
        end
      end)
    end)
  end

  # Parse a `<lo>..<hi>` or single `<cp>` hex range, or `:error` if malformed.
  defp parse_emoji_range(range) do
    case String.split(range, "..", parts: 2) do
      [a, b] ->
        case {Integer.parse(String.trim(a), 16), Integer.parse(String.trim(b), 16)} do
          {{lo, ""}, {hi, ""}} -> {lo, hi}
          _malformed -> :error
        end

      [single] ->
        case Integer.parse(String.trim(single), 16) do
          {v, ""} -> {v, v}
          _malformed -> :error
        end
    end
  end

  # True iff `cp` has the `Emoji = Yes` property per emoji-data.txt.
  defp is_emoji(cp), do: Enum.any?(emoji_ranges(), fn {lo, hi} -> lo <= cp and cp <= hi end)

  # ───────────────────────────────────────────────────────────────────
  # §3 Codepoint probes
  # ───────────────────────────────────────────────────────────────────

  # True iff `cp` is U+202F NARROW NO-BREAK SPACE.
  defp is_nnbsp(cp), do: cp == 0x202F

  # True iff `cp` is U+200D ZERO WIDTH JOINER.
  defp is_zwj(cp), do: cp == 0x200D

  # True iff `cp` is a Variation Selector — the basic block U+FE00..U+FE0F
  # (VS1..VS16) or the Plane-14 IVS block U+E0100..U+E01EF (VS17..VS256).
  defp is_variation_selector(cp),
    do: (cp >= 0xFE00 and cp <= 0xFE0F) or (cp >= 0xE0100 and cp <= 0xE01EF)

  # True iff `cp` is Default_Ignorable_Code_Point per DerivedCoreProperties.txt.
  # Reuses the port's own UCD table, never a host normalizer.
  defp is_default_ignorable(cp), do: Ucd.default_ignorable?(cp)

  # True iff `cp` is U+200B ZERO WIDTH SPACE.
  defp is_zwsp(cp), do: cp == 0x200B

  # True iff `cp` is U+2014 EM DASH.
  defp is_em_dash(cp), do: cp == 0x2014

  # True iff `cp` is U+002D HYPHEN-MINUS (ASCII).
  defp is_hyphen_minus(cp), do: cp == 0x002D

  # True iff `cp` is one of the four "curly" quotation marks: U+2018 / U+2019
  # (single open/close) and U+201C / U+201D (double open/close).
  defp is_curly_quote(cp), do: cp == 0x2018 or cp == 0x2019 or cp == 0x201C or cp == 0x201D

  # True iff `cp` is an ASCII straight quote — U+0022 (double) or U+0027
  # (single / apostrophe).
  defp is_straight_quote(cp), do: cp == 0x0022 or cp == 0x0027

  # True iff `arr[i]` is adjacent (immediate predecessor OR immediate successor)
  # to an emoji codepoint. Two-sided check. `arr` is the input as a tuple and
  # `n` its length, giving O(1) neighbour access. Used by the VS and ZWJ probes
  # to exclude legitimate emoji-context occurrences.
  defp is_adjacent_to_emoji(arr, n, i) do
    prev_is_emoji = i > 0 and is_emoji(elem(arr, i - 1))
    next_is_emoji = i + 1 < n and is_emoji(elem(arr, i + 1))
    prev_is_emoji or next_is_emoji
  end

  # All positions in `input` matching predicate `p`.
  defp all_positions(p, input) do
    input
    |> Enum.with_index()
    |> Enum.filter(fn {cp, _idx} -> p.(cp) end)
    |> Enum.map(fn {_cp, idx} -> idx end)
  end

  # True iff `positions` forms an arithmetic progression with all consecutive
  # gaps within `tolerance` of the first gap. Empty + singleton lists are
  # vacuously arithmetic. `positions` is ascending (produced by `all_positions`),
  # so gaps are non-negative.
  defp positions_are_arithmetic_within(positions, tolerance) do
    case positions do
      [] ->
        true

      [_single] ->
        true

      [first, second | _rest] ->
        first_gap = second - first

        positions
        |> Enum.chunk_every(2, 1, :discard)
        |> Enum.all?(fn [a, b] ->
          gap = b - a
          gap <= first_gap + tolerance and first_gap <= gap + tolerance
        end)
    end
  end

  # First start-position at which `pattern` appears as a contiguous sub-slice of
  # `input`, or `nil` if absent.
  defp contains_sublist(pattern, input) do
    plen = length(pattern)
    ilen = length(input)

    if plen == 0 or plen > ilen do
      nil
    else
      max_start = ilen - plen
      Enum.find(0..max_start, fn start -> Enum.slice(input, start, plen) == pattern end)
    end
  end

  # The "AI-favored" lexical-pattern catalog (each word as its codepoint
  # sequence), transcribed verbatim from the pinned `aiFavoredVocabulary`
  # literal in the Lean spec (parsed from `Ucd/Security/AiFavoredVocabulary.txt`
  # and drift-gated there against a fresh parse).
  @ai_favored_vocabulary [
    [100, 101, 108, 118, 101],
    [100, 101, 108, 118, 105, 110, 103],
    [116, 97, 112, 101, 115, 116, 114, 121],
    [105, 110, 116, 114, 105, 99, 97, 116, 101],
    [110, 117, 97, 110, 99, 101, 100],
    [109, 111, 114, 101, 111, 118, 101, 114],
    [102, 117, 114, 116, 104, 101, 114, 109, 111, 114, 101],
    [114, 101, 97, 108, 109],
    [101, 108, 117, 99, 105, 100, 97, 116, 101],
    [115, 104, 111, 119, 99, 97, 115, 105, 110, 103],
    [117, 110, 100, 101, 114, 115, 99, 111, 114, 101, 115],
    [117, 110, 100, 101, 114, 115, 99, 111, 114, 101, 100],
    [112, 105, 118, 111, 116, 97, 108],
    [98, 111, 108, 115, 116, 101, 114],
    [109, 117, 108, 116, 105, 102, 97, 99, 101, 116, 101, 100],
    [116, 101, 115, 116, 97, 109, 101, 110, 116],
    [102, 111, 115, 116, 101, 114],
    [104, 111, 108, 105, 115, 116, 105, 99],
    [112, 97, 114, 97, 100, 105, 103, 109],
    [116, 114, 97, 110, 115, 102, 111, 114, 109, 97, 116, 105, 118, 101],
    [115, 112, 101, 97, 114, 104, 101, 97, 100],
    [109, 101, 116, 105, 99, 117, 108, 111, 117, 115],
    [109, 101, 116, 105, 99, 117, 108, 111, 117, 115, 108, 121],
    [101, 109, 112, 111, 119, 101, 114],
    [101, 109, 112, 111, 119, 101, 114, 105, 110, 103],
    [112, 114, 111, 102, 111, 117, 110, 100],
    [112, 114, 111, 102, 111, 117, 110, 100, 108, 121],
    [99, 111, 109, 112, 101, 108, 108, 105, 110, 103],
    [99, 111, 109, 112, 114, 101, 104, 101, 110, 115, 105, 118, 101],
    [99, 114, 117, 99, 105, 97, 108],
    [100, 97, 117, 110, 116, 105, 110, 103],
    [114, 111, 98, 117, 115, 116],
    [115, 116, 114, 101, 97, 109, 108, 105, 110, 101],
    [101, 110, 114, 105, 99, 104],
    [101, 120, 101, 109, 112, 108, 105, 102, 121],
    [99, 97, 112, 116, 105, 118, 97, 116, 105, 110, 103],
    [100, 105, 115, 99, 101, 114, 110, 105, 110, 103],
    [109, 101, 115, 109, 101, 114, 105, 122, 101],
    [105, 110, 116, 114, 105, 99, 97, 116, 101, 108, 121],
    [105, 109, 98, 117, 101],
    [112, 108, 97, 121, 115, 32, 97, 32, 99, 114, 117, 99, 105, 97, 108, 32, 114, 111, 108, 101],
    [112, 108, 97, 121, 115, 32, 97, 32, 112, 105, 118, 111, 116, 97, 108, 32, 114, 111, 108, 101],
    [105, 116, 32, 105, 115, 32, 105, 109, 112, 111, 114, 116, 97, 110, 116, 32, 116, 111, 32, 110, 111, 116, 101],
    [105, 116, 32, 105, 115, 32, 119, 111, 114, 116, 104, 32, 110, 111, 116, 105, 110, 103],
    [105, 110, 32, 99, 111, 110, 99, 108, 117, 115, 105, 111, 110],
    [105, 110, 32, 101, 115, 115, 101, 110, 99, 101],
    [100, 101, 108, 118, 101, 32, 105, 110, 116, 111],
    [100, 101, 108, 118, 105, 110, 103, 32, 105, 110, 116, 111],
    [116, 97, 112, 101, 115, 116, 114, 121, 32, 111, 102],
    [114, 101, 97, 108, 109, 32, 111, 102]
  ]

  @doc "The pinned AI-favored lexical-pattern catalog (codepoint sequences)."
  def ai_favored_vocabulary, do: @ai_favored_vocabulary

  # ───────────────────────────────────────────────────────────────────
  # §4 Top-level detection
  # ───────────────────────────────────────────────────────────────────

  @doc """
  The detection function. Runs every probe in the fixed priority order
  (most-specific first); the first hit wins. See the module header for the
  probe inventory and the ordering rationale. Returns a verdict map with
  `input`, `classify`, and `marker_count`.
  """
  def detect_with_context(%Context{} = ctx, input) do
    arr = List.to_tuple(input)
    n = length(input)

    nnbsp_positions = all_positions(&is_nnbsp/1, input)
    nnbsp_count = length(nnbsp_positions)

    # Probe 1: adversarial — NNBSP too-regular.
    adversarial_fires =
      nnbsp_count >= 3 and
        positions_are_arithmetic_within(nnbsp_positions, ctx.adversarial_tolerance)

    # Probe 2: gpt5ZwspModulo — ZWSP arithmetic progression.
    zwsp_positions = all_positions(&is_zwsp/1, input)
    zwsp_count = length(zwsp_positions)

    zwsp_modulo_fires =
      zwsp_count >= 3 and
        positions_are_arithmetic_within(zwsp_positions, ctx.zwsp_modulo_tolerance)

    vs_all_pos = all_positions(&is_variation_selector/1, input)
    vs_non_emoji_pos = Enum.filter(vs_all_pos, fn i -> not is_adjacent_to_emoji(arr, n, i) end)
    vs_non_emoji_count = length(vs_non_emoji_pos)

    zwj_all_pos = all_positions(&is_zwj/1, input)
    zwj_non_emoji_pos = Enum.filter(zwj_all_pos, fn i -> not is_adjacent_to_emoji(arr, n, i) end)
    zwj_non_emoji_count = length(zwj_non_emoji_pos)

    # Probe 7: smartQuoteAlternation — curly quotes only.
    curly_positions = all_positions(&is_curly_quote/1, input)
    curly_count = length(curly_positions)
    has_straight_quote = Enum.any?(input, &is_straight_quote/1)
    smart_quote_fires = curly_count >= 2 and not has_straight_quote

    # Probe 8: emDashPattern — em-dashes without hyphen-minus.
    em_dash_positions = all_positions(&is_em_dash/1, input)
    em_dash_count = length(em_dash_positions)
    has_hyphen_minus = Enum.any?(input, &is_hyphen_minus/1)
    em_dash_fires = em_dash_count >= 2 and not has_hyphen_minus

    # Probe 9: statisticalTokenChoice — scan the pinned vocabulary. Each word is
    # compared as a contiguous sub-slice of the input.
    vocab_hit = Enum.find_value(@ai_favored_vocabulary, fn pattern -> contains_sublist(pattern, input) end)

    # Residual default-ignorables (excluding VS and ZWJ, handled above).
    is_residual_di = fn cp ->
      is_default_ignorable(cp) and not is_variation_selector(cp) and not is_zwj(cp)
    end

    di_positions = all_positions(is_residual_di, input)
    di_count = length(di_positions)

    # Probe 3: unknown — invisible markers from >= 2 distinct categories.
    category_count =
      bool_to_int(nnbsp_count > 0) + bool_to_int(vs_non_emoji_count > 0) +
        bool_to_int(zwj_non_emoji_count > 0) + bool_to_int(di_count > 0)

    unknown_fires = category_count >= 2
    total_invisible_count = nnbsp_count + vs_non_emoji_count + zwj_non_emoji_count + di_count

    {classification, fired_count} =
      cond do
        adversarial_fires ->
          first_pos = List.first(nnbsp_positions, 0)

          {%{
             kind: :hazard,
             sub: %{kind: :adversarial, impersonated_scheme: "nnbspBoundary", first_pos: first_pos},
             positions: nnbsp_positions
           }, nnbsp_count}

        zwsp_modulo_fires ->
          first_pos = List.first(zwsp_positions, 0)

          {%{
             kind: :hazard,
             sub: %{kind: :gpt5_zwsp_modulo, first_pos: first_pos},
             positions: zwsp_positions
           }, zwsp_count}

        unknown_fires ->
          all_invisible_pos =
            input
            |> Enum.with_index()
            |> Enum.filter(fn {cp, _idx} ->
              is_nnbsp(cp) or is_variation_selector(cp) or is_zwj(cp) or is_default_ignorable(cp)
            end)
            |> Enum.map(fn {_cp, idx} -> idx end)

          {%{
             kind: :hazard,
             sub: %{kind: :unknown, anomaly_marker: total_invisible_count},
             positions: all_invisible_pos
           }, total_invisible_count}

        nnbsp_count > 0 ->
          {%{
             kind: :hazard,
             sub: %{kind: :nnbsp_boundary, marker_count: nnbsp_count},
             positions: nnbsp_positions
           }, nnbsp_count}

        vs_non_emoji_count > 0 ->
          {%{
             kind: :hazard,
             sub: %{kind: :variation_selector_carrier, marker_count: vs_non_emoji_count},
             positions: vs_non_emoji_pos
           }, vs_non_emoji_count}

        zwj_non_emoji_count > 0 ->
          {%{
             kind: :hazard,
             sub: %{kind: :zwj_non_emoji, marker_count: zwj_non_emoji_count},
             positions: zwj_non_emoji_pos
           }, zwj_non_emoji_count}

        smart_quote_fires ->
          first_pos = List.first(curly_positions, 0)

          {%{
             kind: :hazard,
             sub: %{kind: :smart_quote_alternation, first_pos: first_pos},
             positions: curly_positions
           }, curly_count}

        em_dash_fires ->
          first_pos = List.first(em_dash_positions, 0)

          {%{
             kind: :hazard,
             sub: %{kind: :em_dash_pattern, first_pos: first_pos},
             positions: em_dash_positions
           }, em_dash_count}

        vocab_hit != nil ->
          {%{
             kind: :hazard,
             sub: %{kind: :statistical_token_choice, first_pos: vocab_hit},
             positions: [vocab_hit]
           }, 1}

        di_count > 0 ->
          {%{
             kind: :hazard,
             sub: %{kind: :default_ignorable_carrier, marker_count: di_count},
             positions: di_positions
           }, di_count}

        true ->
          {%{kind: :clear}, 0}
      end

    %{input: input, classify: classification, marker_count: fired_count}
  end

  @doc """
  Convenience wrapper over `detect_with_context/2` with the empty context —
  exact-arithmetic settings (`zwsp_modulo_tolerance = 0`,
  `adversarial_tolerance = 0`).
  """
  def detect(input), do: detect_with_context(%Context{}, input)

  # Boolean → {0, 1}, mirroring the rust `usize::from(bool)` category counter.
  defp bool_to_int(true), do: 1
  defp bool_to_int(false), do: 0
end
