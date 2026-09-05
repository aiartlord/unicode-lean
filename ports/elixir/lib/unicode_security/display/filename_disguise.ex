defmodule UnicodeSecurity.Display.FilenameDisguise do
  @moduledoc """
  filename-disguise — detection of filename/extension disguise attacks where the
  visible extension differs from the byte extension (the display-layer detector
  D).

  Byte-faithful transliteration of the verified rust reference implementation,
  itself a transcription of `Unicode/Security/Display/FilenameDisguise.lean`.

  Threat model. An adversary delivers a file whose rendered name looks like a
  benign type (`document.txt`) but whose actual byte extension is executable —
  the canonical attack inserts U+202E RIGHT-TO-LEFT OVERRIDE so
  `document<RLO>txt.exe` renders as `document exe.txt`.

  What the detector draws. Detection is presentation- and language-agnostic: it
  surfaces every codepoint that could cause display-vs-byte divergence in the
  filename — any purposeless bidi format-control anywhere (`BidiControlPurpose`:
  unbalanced, or a balanced span enclosing nothing right-to-left in a
  left-to-right context), and any fullwidth/halfwidth or combining (grapheme
  Extend) codepoint in the extension region (after the last `.`). Native-RTL
  names with no bidi controls clear, and so does a balanced embedding around an
  Arabic segment.

  Sub-threats (priority order):
    1. `RloFlip`            a purposeless bidi format-control in the input.
    2. `WidthClassExt`      a fullwidth/halfwidth codepoint in the extension.
    3. `CombiningInExt`     a combining (Extend) codepoint in the extension.
    4. `MultipleExtensions` >= 3 dots (advisory; e.g. legitimate `.tar.gz.sig`).

  It reuses the port's own tables — the bidi purpose rule, the Grapheme
  segmentation `Grapheme_Cluster_Break = Extend` class, and the inlined
  fullwidth range — never a host filesystem or rendering library.
  """

  alias UnicodeSecurity.Covert.BidiControlBalance
  alias UnicodeSecurity.Display.BidiControlPurpose
  alias UnicodeSecurity.Segmentation.Grapheme

  # ───────────────────────────────────────────────────────────────────
  # §1 Constants
  # ───────────────────────────────────────────────────────────────────

  # The count of `.` separators at or beyond which the name is treated as a
  # multiple-extension advisory hazard.
  @min_multi_ext 3

  @doc "The multiple-extension advisory threshold (`MIN_MULTI_EXT`)."
  def min_multi_ext, do: @min_multi_ext

  # ───────────────────────────────────────────────────────────────────
  # §2 Classification tags
  # ───────────────────────────────────────────────────────────────────

  @doc "Fixture-row tag string for a sub-threat map (matches `SubThreat.tag`)."
  def sub_threat_tag(%{kind: :rlo_flip}), do: "RloFlip"
  def sub_threat_tag(%{kind: :width_class_ext}), do: "WidthClassExt"
  def sub_threat_tag(%{kind: :combining_in_ext}), do: "CombiningInExt"
  def sub_threat_tag(%{kind: :multiple_extensions}), do: "MultipleExtensions"

  @doc "True iff the classification is `Clear`."
  def is_clear(%{kind: :clear}), do: true
  def is_clear(%{kind: :hazard}), do: false

  @doc "Human-facing tag for a hazard classification, or `nil` when clear."
  def classification_tag(%{kind: :clear}), do: nil
  def classification_tag(%{kind: :hazard, sub: sub}), do: sub_threat_tag(sub)

  @doc "Implicated codepoint positions of a classification (empty when clear)."
  def classification_positions(%{kind: :clear}), do: []
  def classification_positions(%{kind: :hazard, positions: positions}), do: positions

  # ───────────────────────────────────────────────────────────────────
  # §3 Core predicates (reuse the port's own tables)
  # ───────────────────────────────────────────────────────────────────

  @doc "True iff `cp` is U+002E FULL STOP (the extension separator)."
  def is_ascii_dot(cp), do: cp == 0x002E

  @doc "True iff `cp` is in the Halfwidth/Fullwidth Forms block."
  def is_fullwidth_halfwidth(cp), do: cp >= 0xFF01 and cp <= 0xFFEF

  @doc "True iff `cp` is a bidi format-control (reuses the port's own predicate)."
  def is_bidi_format_control(cp), do: BidiControlBalance.bidi_format_control?(cp)

  @doc "True iff `cp` has `Grapheme_Cluster_Break = Extend` (reuses the port's table)."
  def is_grapheme_extend(cp), do: Grapheme.lookup_gcb(cp) == :extend

  # ───────────────────────────────────────────────────────────────────
  # §4 Sub-detectors
  # ───────────────────────────────────────────────────────────────────

  # 0-based positions of every `.` in `input`.
  defp dot_positions(input) do
    input
    |> Enum.with_index()
    |> Enum.flat_map(fn {cp, idx} -> if is_ascii_dot(cp), do: [idx], else: [] end)
  end

  # Position and codepoint of the first purposeless bidi format-control, or
  # `nil`: unbalanced, or a balanced span enclosing nothing right-to-left in a
  # left-to-right context (`BidiControlPurpose.first_purposeless_control/1`). A
  # balanced embedding around an Arabic filename segment manages that segment
  # and is not a flip. Mirrors the Lean detect, which reads
  # `firstPurposelessControl`.
  defp first_bidi_control(input), do: BidiControlPurpose.first_purposeless_control(input)

  # Position and codepoint of the first fullwidth/halfwidth codepoint at or after
  # `start`, or `nil`.
  defp first_fullwidth_from(input, start) do
    input
    |> Enum.with_index()
    |> Enum.find_value(fn {cp, idx} ->
      if idx >= start and is_fullwidth_halfwidth(cp), do: {idx, cp}, else: nil
    end)
  end

  # Position and codepoint of the first Extend codepoint at or after `start`, or
  # `nil`.
  defp first_extend_from(input, start) do
    input
    |> Enum.with_index()
    |> Enum.find_value(fn {cp, idx} ->
      if idx >= start and is_grapheme_extend(cp), do: {idx, cp}, else: nil
    end)
  end

  # Count of fullwidth/halfwidth codepoints at or after `start`.
  defp count_fullwidth_from(input, start) do
    input
    |> Enum.with_index()
    |> Enum.count(fn {cp, idx} -> idx >= start and is_fullwidth_halfwidth(cp) end)
  end

  # Count of Extend codepoints at or after `start`.
  defp count_extend_from(input, start) do
    input
    |> Enum.with_index()
    |> Enum.count(fn {cp, idx} -> idx >= start and is_grapheme_extend(cp) end)
  end

  # ───────────────────────────────────────────────────────────────────
  # §5 Top-level detection
  # ───────────────────────────────────────────────────────────────────

  @doc """
  The FilenameDisguise detection function, reading its input as one filename.
  Mirrors the Lean detect, which is detectWithContext at the default context.
  """
  def detect(input), do: detect_with_context(false, input)

  @doc """
  The FilenameDisguise detection function under an explicit field context.
  Returns a verdict map mirroring the Lean/rust `Verdict`: `input`, `classify`,
  `dot_positions`, `last_dot_pos`, `bidi_control_count`, `fullwidth_in_ext`, and
  `combining_in_ext`. `running_text` mirrors the Lean `Context.runningText`: the
  extension rungs read the text after the last dot as a file extension, which a
  source file or a message does not have, so they do not run on running text;
  the purposeless-bidi-control rung holds of any field.
  """
  def detect_with_context(running_text, input) do
    dots = dot_positions(input)
    last_dot = List.last(dots)
    ext_start = if last_dot == nil, do: length(input), else: last_dot + 1

    bidi_count = Enum.count(input, &is_bidi_format_control/1)
    fw_in_ext = count_fullwidth_from(input, ext_start)
    ext_in_ext = count_extend_from(input, ext_start)

    classify = classify(input, dots, ext_start, running_text)

    %{
      input: input,
      classify: classify,
      dot_positions: dots,
      last_dot_pos: last_dot,
      bidi_control_count: bidi_count,
      fullwidth_in_ext: fw_in_ext,
      combining_in_ext: ext_in_ext
    }
  end

  # The priority ladder. The first trigger in priority order wins; when none
  # fires the input is `Clear`.
  defp classify(input, dots, ext_start, running_text) do
    cond do
      # Priority 1: a purposeless bidi format-control anywhere in the input.
      ctl = first_bidi_control(input) ->
        {pos, cp} = ctl
        hazard(%{kind: :rlo_flip, position: pos, control_cp: cp}, [pos])

      # The remaining rungs read an extension; running text has none.
      running_text ->
        %{kind: :clear}

      # Priority 2: fullwidth/halfwidth in the extension.
      fw = first_fullwidth_from(input, ext_start) ->
        {pos, cp} = fw
        hazard(%{kind: :width_class_ext, position: pos, cp: cp}, [pos])

      # Priority 3: combining mark in the extension.
      ext = first_extend_from(input, ext_start) ->
        {pos, cp} = ext
        hazard(%{kind: :combining_in_ext, position: pos, cp: cp}, [pos])

      # Priority 4: three or more extensions (advisory).
      length(dots) >= @min_multi_ext ->
        hazard(%{kind: :multiple_extensions, dot_count: length(dots)}, dots)

      # Otherwise the filename presents no display-vs-byte divergence trigger.
      true ->
        %{kind: :clear}
    end
  end

  defp hazard(sub, positions), do: %{kind: :hazard, sub: sub, positions: positions, decoded: []}
end
