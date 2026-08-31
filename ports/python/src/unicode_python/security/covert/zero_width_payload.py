"""Detection of payloads encoded in zero-width and near-zero-width
Unicode codepoints.

Threat model.  Tier A1.  Adversary embeds zero-width / no-glyph
codepoints inside otherwise-normal text to carry a covert binary
payload, to splice WORD JOINER / byte-order-mark sequences into
identifiers, or to emit a suspected AI-watermark NNBSP pattern.

Zero-width codepoint inventory:

    U+200B  ZERO WIDTH SPACE                (ZWSP)
    U+200C  ZERO WIDTH NON-JOINER           (ZWNJ)
    U+200D  ZERO WIDTH JOINER               (ZWJ)
    U+200E  LEFT-TO-RIGHT MARK              (LRM)
    U+200F  RIGHT-TO-LEFT MARK              (RLM)
    U+2060  WORD JOINER                     (WJ)
    U+2061..U+2064  invisible math operators
    U+202F  NARROW NO-BREAK SPACE           (NNBSP)
    U+FEFF  ZERO WIDTH NO-BREAK SPACE / BOM
    U+FFF9..U+FFFB  INTERLINEAR ANNOTATION marks

Every zero-width occurrence is recorded, but two of them carry meaning a
reader depends on and are not treated as suspicious: a ZWJ flanked by two
codepoints that both participate in some registered RGI emoji sequence, and
a ZWNJ in an RFC 5892 Appendix A.1 CONTEXTJ-valid position.  An input whose
zero-width characters are all sanctioned is clear.
"""

from dataclasses import dataclass, field
from typing import Union

from ..calculus import ClassificationKind
from ..identity import ucd
from ..identity.emoji_zwj_integrity import is_emoji_target


def _is_sibling_handled(cp: int) -> bool:
    """Sibling-detector codepoint ranges — these ARE
    Default_Ignorable per UAX #44 but are dispatched elsewhere:

      - U+FE00..U+FE0F      VariationSelectorPayload
      - U+E0100..U+E01EF    VariationSelectorPayload
      - U+E0000..U+E007F    TagBlockPayload
      - U+202A..U+202E      BidiControlBalance (LRE/RLE/PDF/LRO/RLO)
      - U+2066..U+2069      BidiControlBalance (LRI/RLI/FSI/PDI)

    LRM / RLM (U+200E / U+200F) are NOT excluded — they're
    direction markers, not push/pop bidi controls.
    """
    return (
        0xFE00 <= cp <= 0xFE0F
        or 0xE0100 <= cp <= 0xE01EF
        or 0xE0000 <= cp <= 0xE007F
        or 0x202A <= cp <= 0x202E
        or 0x2066 <= cp <= 0x2069
    )


def is_zero_width(cp: int) -> bool:
    """True iff `cp` is a Unicode codepoint that renders as
    nothing OR is in the explicit historical "tracked zero-width"
    set.  Built on the explicit hardcoded list PLUS UAX #44
    Default_Ignorable_Code_Point, with sibling-detector exclusions.
    """
    # Explicit historical set — preserves sub-threat dispatch.
    if cp in (0x200B, 0x200C, 0x200D, 0x200E, 0x200F):
        return True
    if 0x2060 <= cp <= 0x2064:
        return True
    if cp == 0x202F or cp == 0xFEFF:
        return True
    if 0xFFF9 <= cp <= 0xFFFB:
        return True
    # UAX #44 Default_Ignorable_Code_Point — catches everything
    # else invisible, modulo sibling-detector ranges.
    return ucd.is_default_ignorable(cp) and not _is_sibling_handled(cp)


def _is_legitimate_zwj_context(input_cps: list[int], i: int) -> bool:
    """True iff the ZWJ at index ``i`` is flanked by two codepoints that both
    participate in some registered RGI emoji ZWJ sequence.  The membership
    predicate is derived from ``emoji-zwj-sequences.txt`` itself rather than
    hand-listed, and is strictly narrower than "is an emoji": a codepoint
    carrying the Emoji property but appearing in no registered sequence does
    not sanction a ZWJ beside it.  A ZWJ in head or tail position is never
    legitimate."""
    if i == 0 or i + 1 >= len(input_cps):
        return False
    return is_emoji_target(input_cps[i - 1]) and is_emoji_target(input_cps[i + 1])


def _joining_type_before(input_cps: list[int], i: int) -> ucd.JoiningType | None:
    """The ``Joining_Type`` of the first non-Transparent codepoint before ``i``."""
    j = i
    while j > 0:
        j -= 1
        jt = ucd.joining_type(input_cps[j])
        if jt is not ucd.JoiningType.TRANSPARENT:
            return jt
    return None


def _joining_type_after(input_cps: list[int], i: int) -> ucd.JoiningType | None:
    """The ``Joining_Type`` of the first non-Transparent codepoint after ``i``."""
    j = i + 1
    while j < len(input_cps):
        jt = ucd.joining_type(input_cps[j])
        if jt is not ucd.JoiningType.TRANSPARENT:
            return jt
        j += 1
    return None


def _is_legitimate_zwnj_context(input_cps: list[int], i: int) -> bool:
    """True iff the ZWNJ at index ``i`` occupies a position where it is
    orthographically required, by RFC 5892 Appendix A.1: it follows a Virama,
    which is how a Devanagari conjunct is suppressed, or it sits between a
    left- or dual-joining character and a right- or dual-joining one, skipping
    Transparent characters on both sides, which is how a Persian word boundary
    is written inside a cursive run.

    A ZWNJ outside such a position carries no orthographic duty and stays
    reportable."""
    if i > 0 and ucd.is_virama(input_cps[i - 1]):
        return True
    left = _joining_type_before(input_cps, i)
    right = _joining_type_after(input_cps, i)
    return left in (
        ucd.JoiningType.LEFT_JOINING,
        ucd.JoiningType.DUAL_JOINING,
    ) and right in (
        ucd.JoiningType.RIGHT_JOINING,
        ucd.JoiningType.DUAL_JOINING,
    )


def is_nnbsp(cp: int) -> bool:
    return cp == 0x202F


def is_word_joiner(cp: int) -> bool:
    return cp == 0x2060


def is_annotation(cp: int) -> bool:
    return 0xFFF9 <= cp <= 0xFFFB


def is_zwj_or_zwsp(cp: int) -> bool:
    return cp in (0x200B, 0x200D)


@dataclass(frozen=True, slots=True)
class AnnotationMisuse:
    count: int


@dataclass(frozen=True, slots=True)
class WordJoinerInjection:
    count: int


@dataclass(frozen=True, slots=True)
class AiWatermarkNNBSP:
    count: int


@dataclass(frozen=True, slots=True)
class BinaryPayload:
    pair_count: int


@dataclass(frozen=True, slots=True)
class BareZeroWidth:
    cp: int


SubThreat = Union[
    AnnotationMisuse,
    WordJoinerInjection,
    AiWatermarkNNBSP,
    BinaryPayload,
    BareZeroWidth,
]


def sub_threat_tag(sub: SubThreat) -> str:
    if isinstance(sub, AnnotationMisuse):
        return "AnnotationMisuse"
    if isinstance(sub, WordJoinerInjection):
        return "WordJoinerInjection"
    if isinstance(sub, AiWatermarkNNBSP):
        return "AiWatermarkNNBSP"
    if isinstance(sub, BinaryPayload):
        return "BinaryPayload"
    return "BareZeroWidth"


@dataclass(slots=True)
class Verdict:
    kind: ClassificationKind
    sub: SubThreat | None = None
    zero_width_positions: list[int] = field(default_factory=list)


def detect(input_cps: list[int]) -> Verdict:
    v = Verdict(kind=ClassificationKind.CLEAR)
    annotation_count = 0
    word_joiner_count = 0
    nnbsp_count = 0
    zwj_zwsp_count = 0
    suspicious: list[int] = []

    for i, cp in enumerate(input_cps):
        if not is_zero_width(cp):
            continue
        v.zero_width_positions.append(i)
        if is_annotation(cp):
            annotation_count += 1
        elif is_word_joiner(cp):
            word_joiner_count += 1
        elif is_nnbsp(cp):
            nnbsp_count += 1
        elif is_zwj_or_zwsp(cp):
            zwj_zwsp_count += 1
        # The sanctioning model: a ZWJ inside a registered emoji sequence and
        # a ZWNJ in an RFC 5892 CONTEXTJ-valid position both carry meaning a
        # reader depends on, so they are recorded as present but not treated
        # as suspicious.
        sanctioned = (cp == 0x200D and _is_legitimate_zwj_context(input_cps, i)) or (
            cp == 0x200C and _is_legitimate_zwnj_context(input_cps, i)
        )
        if not sanctioned:
            suspicious.append(i)

    if not v.zero_width_positions or not suspicious:
        return v

    v.kind = ClassificationKind.HAZARD
    if annotation_count > 0:
        v.sub = AnnotationMisuse(count=annotation_count)
    elif word_joiner_count > 0:
        v.sub = WordJoinerInjection(count=word_joiner_count)
    elif nnbsp_count >= 2:
        v.sub = AiWatermarkNNBSP(count=nnbsp_count)
    elif zwj_zwsp_count >= 2:
        v.sub = BinaryPayload(pair_count=zwj_zwsp_count // 2)
    else:
        v.sub = BareZeroWidth(cp=input_cps[suspicious[0]])
    return v


__all__ = [
    "AiWatermarkNNBSP",
    "AnnotationMisuse",
    "BareZeroWidth",
    "BinaryPayload",
    "SubThreat",
    "Verdict",
    "WordJoinerInjection",
    "detect",
    "is_annotation",
    "is_nnbsp",
    "is_word_joiner",
    "is_zero_width",
    "is_zwj_or_zwsp",
    "sub_threat_tag",
]
