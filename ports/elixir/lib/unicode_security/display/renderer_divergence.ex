defmodule UnicodeSecurity.Display.RendererDivergence do
  @moduledoc """
  renderer-divergence — detection of codepoint/sequence shapes known to render
  differently across font + terminal + browser stacks (the display-layer
  detector D).

  Byte-faithful transliteration of the verified rust reference
  `ports/rust/src/security/display/renderer_divergence.rs`, itself a
  transcription of `Unicode/Security/Display/RendererDivergence.lean`.

  Threat model. An adversary crafts content that renders one way in the
  auditor's renderer (a benign glyph or an empty span) and a different way in
  the consumer's renderer (a misleading glyph, a wider glyph, or a different
  sequence). This is the "fingerprint stability" family — clear inputs render
  the same across the renderer cohort the Standard documents as stable.

  What the detector draws. A heuristic three-value split surfaced through the
  universal clear/hazard carrier: an input is clear when none of the documented
  variance triggers fire, and otherwise is classified by the first trigger in
  priority order.

  Sub-threats (priority order):
    1. `CombiningStackOverflow`    Zalgo-like combining-mark stack >= 4 on a base.
    2. `VariationSelectorVariance` any variation selector present.
    3. `UnregisteredZwjVariance`   ZWJ-containing input not in the RGI ZWJ set.
    4. `FullwidthVariance`         a fullwidth/halfwidth codepoint present.
    5. `MixedDirectionVariance`    both strong-LTR and strong-RTL codepoints.

  It reuses the port's own tables — the VariationSelectorPayload variation-
  selector predicate, the Grapheme segmentation `Grapheme_Cluster_Break =
  Extend` class, the EmojiZwjIntegrity RGI ZWJ registry, and the Ucd strong-bidi
  classes — never a host rendering or shaping library.
  """

  alias UnicodeSecurity.Covert.VariationSelectorPayload
  alias UnicodeSecurity.Identity.EmojiZwjIntegrity
  alias UnicodeSecurity.Segmentation.Grapheme
  alias UnicodeSecurity.Ucd

  # ───────────────────────────────────────────────────────────────────
  # §1 Constants
  # ───────────────────────────────────────────────────────────────────

  # The combining-mark stack depth (on a single base) at or beyond which the
  # input is treated as a Zalgo-style rendering-variance hazard.
  @min_combining_stack 4

  # The ZERO WIDTH JOINER codepoint.
  @zwj 0x200D

  @doc "The combining-mark stack overflow threshold (`MIN_COMBINING_STACK`)."
  def min_combining_stack, do: @min_combining_stack

  @doc "The ZERO WIDTH JOINER codepoint (`U+200D`)."
  def zwj, do: @zwj

  # ───────────────────────────────────────────────────────────────────
  # §2 Classification tags
  # ───────────────────────────────────────────────────────────────────

  @doc "Fixture-row tag string for a sub-threat map (matches `SubThreat.tag`)."
  def sub_threat_tag(%{kind: :combining_stack_overflow}), do: "CombiningStackOverflow"
  def sub_threat_tag(%{kind: :variation_selector_variance}), do: "VariationSelectorVariance"
  def sub_threat_tag(%{kind: :unregistered_zwj_variance}), do: "UnregisteredZwjVariance"
  def sub_threat_tag(%{kind: :fullwidth_variance}), do: "FullwidthVariance"
  def sub_threat_tag(%{kind: :mixed_direction_variance}), do: "MixedDirectionVariance"

  @doc "True iff the classification is `Clear` (i.e. stable)."
  def is_clear(%{kind: :clear}), do: true
  def is_clear(%{kind: :hazard}), do: false

  @doc "Human-facing tag for a hazard classification, or `nil` when clear."
  def classification_tag(%{kind: :clear}), do: nil
  def classification_tag(%{kind: :hazard, sub: sub}), do: sub_threat_tag(sub)

  @doc "Implicated codepoint positions of a classification (empty when clear)."
  def classification_positions(%{kind: :clear}), do: []
  def classification_positions(%{kind: :hazard, positions: positions}), do: positions

  # ───────────────────────────────────────────────────────────────────
  # §3 Core predicates (all reuse the port's own tables)
  # ───────────────────────────────────────────────────────────────────

  @doc "True iff `cp` is a variation selector (reuses the port's own predicate)."
  def is_variation_selector(cp), do: VariationSelectorPayload.variation_selector?(cp)

  @doc "True iff `cp` is the ZWJ codepoint."
  def is_zwj(cp), do: cp == @zwj

  @doc "True iff `cp` is in the Halfwidth/Fullwidth Forms block."
  def is_fullwidth_halfwidth(cp), do: cp >= 0xFF01 and cp <= 0xFFEF

  @doc "True iff `cp` has `Grapheme_Cluster_Break = Extend` (reuses the port's table)."
  def is_grapheme_extend(cp), do: Grapheme.lookup_gcb(cp) == :extend

  # ───────────────────────────────────────────────────────────────────
  # §4 Sub-detectors
  # ───────────────────────────────────────────────────────────────────

  defp count_vs(input), do: Enum.count(input, &is_variation_selector/1)
  defp count_combining(input), do: Enum.count(input, &is_grapheme_extend/1)
  defp count_fullwidth(input), do: Enum.count(input, &is_fullwidth_halfwidth/1)
  defp input_has_zwj(input), do: Enum.any?(input, &is_zwj/1)
  defp count_strong_ltr(input), do: Enum.count(input, &Ucd.strong_ltr?/1)
  defp count_strong_rtl(input), do: Enum.count(input, &Ucd.strong_rtl?/1)

  # Position and codepoint of the first variation selector, or `nil`.
  defp first_vs_pos(input) do
    input
    |> Enum.with_index()
    |> Enum.find_value(fn {cp, idx} ->
      if is_variation_selector(cp), do: {idx, cp}, else: nil
    end)
  end

  # Position of the first ZWJ, or `nil`.
  defp first_zwj_pos(input) do
    input
    |> Enum.with_index()
    |> Enum.find_value(fn {cp, idx} -> if is_zwj(cp), do: idx, else: nil end)
  end

  # Position and codepoint of the first fullwidth/halfwidth codepoint, or `nil`.
  defp first_fullwidth_pos(input) do
    input
    |> Enum.with_index()
    |> Enum.find_value(fn {cp, idx} ->
      if is_fullwidth_halfwidth(cp), do: {idx, cp}, else: nil
    end)
  end

  # The first base position (a non-Extend codepoint) immediately followed by
  # exactly `min_stack` consecutive Extend codepoints. Returns
  # `{base_pos, min_stack}` on hit, or `nil`.
  defp first_combining_stack(input, min_stack) do
    input
    |> Enum.with_index()
    |> Enum.find_value(fn {cp, idx} ->
      following = input |> Enum.drop(idx + 1) |> Enum.take(min_stack)

      if not is_grapheme_extend(cp) and length(following) == min_stack and
           Enum.all?(following, &is_grapheme_extend/1) do
        {idx, min_stack}
      else
        nil
      end
    end)
  end

  # ───────────────────────────────────────────────────────────────────
  # §5 Top-level detection
  # ───────────────────────────────────────────────────────────────────

  @doc """
  The RendererDivergence detection function. Returns a verdict map mirroring the
  Lean/rust `Verdict`: `input`, `classify`, `vs_count`, `combining_count`,
  `fullwidth_count`, `has_zwj`, `strong_ltr_count`, and `strong_rtl_count`.
  """
  def detect(input) do
    vs_count = count_vs(input)
    combining_count = count_combining(input)
    fullwidth_count = count_fullwidth(input)
    has_zwj = input_has_zwj(input)
    ltr_count = count_strong_ltr(input)
    rtl_count = count_strong_rtl(input)

    classify = classify(input, has_zwj, ltr_count, rtl_count)

    %{
      input: input,
      classify: classify,
      vs_count: vs_count,
      combining_count: combining_count,
      fullwidth_count: fullwidth_count,
      has_zwj: has_zwj,
      strong_ltr_count: ltr_count,
      strong_rtl_count: rtl_count
    }
  end

  # The priority ladder. The first trigger in priority order wins; when none
  # fires the input is `Clear`.
  defp classify(input, has_zwj, ltr_count, rtl_count) do
    cond do
      # Priority 1: combining-mark stack overflow (Zalgo).
      stack = first_combining_stack(input, @min_combining_stack) ->
        {base_pos, stack_len} = stack

        hazard(
          %{kind: :combining_stack_overflow, base_pos: base_pos, stack_len: stack_len},
          [base_pos]
        )

      # Priority 2: any variation selector triggers presentation variance.
      vs = first_vs_pos(input) ->
        {pos, cp} = vs
        hazard(%{kind: :variation_selector_variance, first_vs_pos: pos, first_vs_cp: cp}, [pos])

      # Priority 3: ZWJ-containing input not in the registered RGI set.
      has_zwj and not EmojiZwjIntegrity.is_registered_zwj_sequence?(input) ->
        case first_zwj_pos(input) do
          nil -> %{kind: :clear}
          pos -> hazard(%{kind: :unregistered_zwj_variance, first_zwj_pos: pos}, [pos])
        end

      # Priority 4: fullwidth/halfwidth display.
      fw = first_fullwidth_pos(input) ->
        {pos, cp} = fw
        hazard(%{kind: :fullwidth_variance, first_fw_pos: pos, first_fw_cp: cp}, [pos])

      # Priority 5: mixed direction.
      ltr_count > 0 and rtl_count > 0 ->
        hazard(%{kind: :mixed_direction_variance, ltr_count: ltr_count, rtl_count: rtl_count}, [])

      # Otherwise stable across the documented renderer cohort.
      true ->
        %{kind: :clear}
    end
  end

  defp hazard(sub, positions), do: %{kind: :hazard, sub: sub, positions: positions, decoded: []}
end
