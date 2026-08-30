defmodule UnicodeSecurity.Display.SourceDisplayDivergence do
  @moduledoc """
  source-display divergence — the aggregate "what a reviewer sees differs from
  what the machine runs" detector (the display-layer detector D).

  Byte-faithful transliteration of the verified rust reference
  `security/display/source_display_divergence.rs`, itself a transcription of
  `Security/Display/SourceDisplayDivergence.lean` (`detect` + `buildClassification`).

  Threat model. A single covert or identity trick may be individually
  benign-looking, but any hit means the rendered source diverges from its
  logical content; two or more is a strong compound signal. This detector runs
  the five constituent detectors on the same codepoint stream and aggregates:
  zero fire → clear, exactly one → pass-through that family's tag, two or more →
  `Compound`.

  What the detector draws. It reuses the port's own five constituent detectors
  in canonical aggregation order — the covert `TagBlockPayload`,
  `VariationSelectorPayload`, `ZeroWidthPayload`, and `BidiControlBalance`, plus
  the identity `HomoglyphConfusable` — and treats each as fired when its own
  classification kind is anything other than `Clear`. Never a host library and
  no new table: this detector is pure aggregation over existing port code.

  Positions are empty at this layer by the Lean spec (the per-family verdicts
  carry them), so this result carries only the sub-threat tag.
  """

  alias UnicodeSecurity.Covert.BidiControlBalance
  alias UnicodeSecurity.Covert.TagBlockPayload
  alias UnicodeSecurity.Covert.VariationSelectorPayload
  alias UnicodeSecurity.Covert.ZeroWidthPayload
  alias UnicodeSecurity.Identity.HomoglyphConfusable

  @typedoc """
  One source-display-divergence scan result. `sub` is `nil` for a clear input;
  a single constituent hit passes through its family tag; two or more yield
  `"Compound"`. Positions are always empty at this layer.
  """
  @type t :: %__MODULE__{
          kind: :clear | :hazard,
          sub: String.t() | nil,
          positions: [non_neg_integer()]
        }

  defstruct kind: :clear, sub: nil, positions: []

  # ───────────────────────────────────────────────────────────────────
  # §1 Classification accessors
  # ───────────────────────────────────────────────────────────────────

  @doc "True iff the classification is `Clear`."
  def is_clear(%__MODULE__{kind: :clear}), do: true
  def is_clear(%__MODULE__{kind: :hazard}), do: false

  @doc "Human-facing sub-threat tag for a hazard classification, or `nil` when clear."
  def classification_tag(%__MODULE__{kind: :clear}), do: nil
  def classification_tag(%__MODULE__{kind: :hazard, sub: sub}), do: sub

  @doc "Implicated codepoint positions of a classification (empty at this layer)."
  def classification_positions(%__MODULE__{positions: positions}), do: positions

  # ───────────────────────────────────────────────────────────────────
  # §2 Constituent firing
  # ───────────────────────────────────────────────────────────────────

  # A constituent has fired when its own classification kind is anything other
  # than `Clear`, mirroring the rust `fired(kind) = kind != Clear`.
  defp fired?(%{kind: :clear}), do: false
  defp fired?(%{kind: :hazard}), do: true
  defp fired?(%{kind: :compound}), do: true
  defp fired?(%{kind: :informational}), do: true

  # ───────────────────────────────────────────────────────────────────
  # §3 Top-level detection
  # ───────────────────────────────────────────────────────────────────

  @doc """
  Aggregate the five constituent detectors into a single display-layer verdict.
  Returns this module's struct; `sub` is `nil` (clear), a single family tag, or
  `"Compound"`.
  """
  def detect(input) do
    input |> fires() |> classify()
  end

  # The fired family tags in canonical aggregation order: tag-block,
  # variation-selector, zero-width, bidi-control, homoglyph.
  defp fires(input) do
    tag_block = if fired?(TagBlockPayload.detect(input)), do: ["TagBlock"], else: []
    variation = if fired?(VariationSelectorPayload.detect(input)), do: ["VariationSelector"], else: []
    zero_width = if fired?(ZeroWidthPayload.detect(input)), do: ["ZeroWidth"], else: []
    # Presence, not balance. A Trojan Source payload balances its controls --
    # an unbalanced run breaks the file it is hiding in -- so a constituent
    # built on the balance verdict is blind to the shape the attack takes.
    bidi =
      if Enum.any?(input, &BidiControlBalance.bidi_format_control?/1),
        do: ["BidiControl"],
        else: []
    homoglyph = if fired?(HomoglyphConfusable.detect(input)), do: ["IdentifierHomoglyph"], else: []

    tag_block ++ variation ++ zero_width ++ bidi ++ homoglyph
  end

  # Explicit dispatch on how many constituents fired: zero → clear, exactly one
  # → pass through that tag, two or more → `Compound`. The final clause is
  # unreachable (a list length is never negative) and raises rather than
  # silently absorbing an impossible count through a catch-all.
  defp classify(fires) do
    case length(fires) do
      0 -> %__MODULE__{kind: :clear}
      1 -> passthrough(fires)
      count when count >= 2 -> hazard("Compound")
      count -> raise "source-display-divergence: impossible fire count #{count}"
    end
  end

  # The single-fire pass-through: emit the one fired family's tag verbatim.
  defp passthrough([tag]), do: hazard(tag)

  defp hazard(sub), do: %__MODULE__{kind: :hazard, sub: sub, positions: []}
end
