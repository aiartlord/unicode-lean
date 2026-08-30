"""SourceDisplayDivergence — the aggregate "what a reviewer sees differs
from what the machine runs" detector (the display-layer aggregator).

Byte-faithful transliteration of the verified Rust reference
implementation (itself a transliteration of
``Unicode.Security.Display.SourceDisplayDivergence``).

Threat model. A single covert or identity trick may be individually
benign-looking, but any hit means the rendered source diverges from its
logical content; two or more is a strong compound signal. This detector
runs the five constituent detectors on the same codepoint stream and
aggregates: zero fire → clear, exactly one → pass-through that family's
tag, two or more → ``Compound``. Every constituent fires
region-agnostically — payloads inside string literals or comments count.

It reuses the port's own five constituent detectors — nothing new is
introduced here, no data table and no host library:

    1. :mod:`tag_block_payload`           → ``TagBlock``
    2. :mod:`variation_selector_payload`  → ``VariationSelector``
    3. :mod:`zero_width_payload`          → ``ZeroWidth``
    4. :mod:`bidi_control_balance`        → ``BidiControl``
    5. :mod:`homoglyph_confusable`        → ``IdentifierHomoglyph``

A constituent "fires" when its classification kind is not ``CLEAR``.
Positions are empty at this layer by the spec (the per-family verdicts
carry them), so the result carries only the sub-threat tag.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..calculus import ClassificationKind
from ..covert import (
    bidi_control_balance,
    tag_block_payload,
    variation_selector_payload,
    zero_width_payload,
)
from ..identity import homoglyph_confusable

# ─────────────────────────────────────────────────────────────────────
# §1 The aggregate verdict
# ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Detection:
    """One source-display-divergence scan result. ``sub`` is ``None`` for a
    clear input; a single constituent hit passes through its family tag;
    two or more yield ``"Compound"``. Positions are empty at this layer by
    the Lean spec (the per-family verdicts carry them), so this result
    carries only the sub-threat tag."""

    sub: str | None = None

    @property
    def tag(self) -> str | None:
        """Human-facing tag for a hazard, or ``None`` when clear."""
        return self.sub

    @property
    def is_clear(self) -> bool:
        """True iff no constituent detector fired."""
        return self.sub is None

    @property
    def kind(self) -> ClassificationKind:
        """The classification kind (``CLEAR`` or ``HAZARD``)."""
        return (
            ClassificationKind.CLEAR
            if self.sub is None
            else ClassificationKind.HAZARD
        )


# ─────────────────────────────────────────────────────────────────────
# §2 Constituent firing predicate
# ─────────────────────────────────────────────────────────────────────


def _fired(kind: ClassificationKind) -> bool:
    """A constituent detector fired iff its classification kind is not
    ``CLEAR``."""
    return kind is not ClassificationKind.CLEAR


# ─────────────────────────────────────────────────────────────────────
# §3 Top-level aggregation
# ─────────────────────────────────────────────────────────────────────


def detect(input_cps: list[int]) -> Detection:
    """Aggregate the five constituent detectors into a single verdict.

    Constituent family tags in canonical aggregation order: tag-block,
    variation-selector, zero-width, bidi-control, homoglyph. Each is the
    port's own ``detect``; a family fires when its verdict kind is not
    ``CLEAR``."""
    fires: list[str] = []
    if _fired(tag_block_payload.detect(input_cps).kind):
        fires.append("TagBlock")
    if _fired(variation_selector_payload.detect(input_cps).kind):
        fires.append("VariationSelector")
    if _fired(zero_width_payload.detect(input_cps).kind):
        fires.append("ZeroWidth")
    # Presence, not balance. A Trojan Source payload balances its controls --
    # an unbalanced run breaks the file it is hiding in -- so a constituent
    # built on the balance verdict is blind to the shape the attack takes.
    if any(bidi_control_balance.is_bidi_format_control(cp) for cp in input_cps):
        fires.append("BidiControl")
    if _fired(homoglyph_confusable.detect(input_cps).kind):
        fires.append("IdentifierHomoglyph")

    fire_count = len(fires)
    if fire_count == 0:
        return Detection(sub=None)
    if fire_count == 1:
        return Detection(sub=fires[0])
    return Detection(sub="Compound")
