"""Which bidi format controls in an input serve a purpose, and which do not.

Direct port of ``Unicode/Security/Display/BidiControlPurpose.lean``. The nine
UAX #9 format controls exist to manage right-to-left text: a span is doing that
job when the text it encloses is right-to-left, or when it forces left-to-right
text inside a right-to-left context. A span enclosing no strong right-to-left
character in a left-to-right context manages nothing (``LRI user PDI`` around
Latin text, ``LRO return PDF`` around a keyword), and an unbalanced control
never manages anything. Every Trojan Source payload is a control of that kind;
a balanced embedding around an Arabic string literal is the opposite case and
renders the literal as written.

This is not source-region filtering: the question is asked of every control
wherever it sits, and it is decided from the codepoints the span encloses,
never from where a tokenizer would place it.

Rule, as the Lean ``walk`` states it:

* An opener pushes a span: its position, whether it is an isolate (closed by
  PDI) or an embedding/override (closed by PDF), and whether it is
  right-to-left in effect (RLE, RLO, RLI, FSI) or left-to-right (LRE, LRO, LRI).
* A strong right-to-left codepoint (Bidi_Class R or AL) marks every open span
  as having seen right-to-left text.
* PDF closes the top span when it is an embedding; against an isolate on top,
  or an empty stack, it is an orphan. PDI closes down to the innermost isolate,
  implicitly terminating the embeddings above it, which are thereby unbalanced;
  with no isolate open it is an orphan.
* A closed right-to-left span is purposeful iff it saw right-to-left text; a
  closed left-to-right span is purposeful iff it sits in right-to-left context
  (an open right-to-left span encloses it, or the paragraph's first strong
  character is right-to-left).
* Reported: every orphan, every opener still open at the end, every embedding a
  PDI terminated implicitly, and both ends of every closed span that was not
  purposeful.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..covert.bidi_control_balance import is_pdf, is_pdi
from ..identity import ucd


def opens_rtl_kind(cp: int) -> bool:
    """True iff ``cp`` opens a span that is right-to-left in effect: RLE, RLO,
    RLI, or FSI (whose direction resolves from its content). Mirrors
    ``opensRtlKind``."""
    return cp in (0x202B, 0x202E, 0x2067, 0x2068)


def opens_ltr_kind(cp: int) -> bool:
    """True iff ``cp`` opens a span that is left-to-right in effect: LRE, LRO,
    LRI. Mirrors ``opensLtrKind``."""
    return cp in (0x202A, 0x202D, 0x2066)


def opens_isolate_kind(cp: int) -> bool:
    """True iff ``cp`` opens an isolate (closed by PDI rather than PDF).
    Mirrors ``opensIsolateKind``."""
    return cp in (0x2066, 0x2067, 0x2068)


_CODE_SYNTAX = frozenset(
    (
        0x22, 0x27, 0x60, 0x28, 0x29, 0x5B, 0x5D, 0x7B, 0x7D, 0x2F, 0x5C, 0x2A,
        0x23, 0x3B, 0x3C, 0x3E, 0x3D, 0x2B, 0x7C, 0x26, 0x25, 0x24, 0x40, 0x5E,
        0x7E,
    )
)


def is_code_syntax(cp: int) -> bool:
    """ASCII code syntax: the codepoints a Trojan Source payload moves —
    quotes, brackets, comment markers, statement separators, operators. Prose
    punctuation, space and digits are not in the set. Mirrors
    ``isCodeSyntax``."""
    return cp in _CODE_SYNTAX


@dataclass(slots=True)
class _OpenSpan:
    """One open span: where it opened, how it closes, its direction in effect,
    and what has appeared directly inside it — strong right-to-left text,
    strong left-to-right text, ASCII code syntax. Mirrors ``OpenSpan``."""

    pos: int
    isolate: bool
    rtl_kind: bool
    saw_rtl: bool
    saw_ltr: bool
    saw_syntax: bool


def _in_rtl_context(enclosing: list[_OpenSpan], paragraph_rtl: bool) -> bool:
    return paragraph_rtl or any(span.rtl_kind for span in enclosing)


def _span_purposeful(
    span: _OpenSpan, enclosing: list[_OpenSpan], paragraph_rtl: bool
) -> bool:
    """A closed span is purposeful iff its direct content is exactly its own
    direction and carries no code syntax. Mirrors ``spanPurposeful``."""
    if span.rtl_kind:
        return span.saw_rtl and not span.saw_ltr and not span.saw_syntax
    return (
        _in_rtl_context(enclosing, paragraph_rtl)
        and span.saw_ltr
        and not span.saw_rtl
        and not span.saw_syntax
    )


def paragraph_is_rtl(input_cps: list[int]) -> bool:
    """UAX #9 P2/P3: the paragraph runs right-to-left iff its first strong
    character is right-to-left. Mirrors ``paragraphIsRtl``."""
    for cp in input_cps:
        if ucd.is_strong_rtl(cp):
            return True
        if ucd.is_strong_ltr(cp):
            return False
    return False


def purposeless_control_positions(input_cps: list[int]) -> list[int]:
    """Positions of the purposeless bidi format controls in ``input_cps``, in
    input order. Empty iff every control is balanced and manages right-to-left
    text. Mirrors ``purposelessControlPositions``."""
    paragraph_rtl = paragraph_is_rtl(input_cps)
    # The stack's top is the list's last element; the Lean list's head.
    stack: list[_OpenSpan] = []
    acc: set[int] = set()
    for idx, cp in enumerate(input_cps):
        if opens_rtl_kind(cp) or opens_ltr_kind(cp):
            stack.append(
                _OpenSpan(
                    pos=idx,
                    isolate=opens_isolate_kind(cp),
                    rtl_kind=opens_rtl_kind(cp),
                    saw_rtl=False,
                    saw_ltr=False,
                    saw_syntax=False,
                )
            )
        elif is_pdf(cp):
            if not stack or stack[-1].isolate:
                # PDF against an open isolate closes nothing (UAX #9 X7), and
                # against an empty stack it is an orphan.
                acc.add(idx)
            else:
                top = stack.pop()
                if not _span_purposeful(top, stack, paragraph_rtl):
                    acc.add(top.pos)
                    acc.add(idx)
        elif is_pdi(cp):
            iso_index = next(
                (i for i in range(len(stack) - 1, -1, -1) if stack[i].isolate),
                None,
            )
            if iso_index is None:
                acc.add(idx)
            else:
                # Embeddings above the isolate are terminated implicitly.
                for dropped in stack[iso_index + 1 :]:
                    acc.add(dropped.pos)
                iso = stack[iso_index]
                del stack[iso_index:]
                if not _span_purposeful(iso, stack, paragraph_rtl):
                    acc.add(iso.pos)
                    acc.add(idx)
        elif stack:
            # Content is recorded against the innermost open span only: a
            # nested span manages its own content (Lean ``markContent``).
            top = stack[-1]
            top.saw_rtl = top.saw_rtl or ucd.is_strong_rtl(cp)
            top.saw_ltr = top.saw_ltr or ucd.is_strong_ltr(cp)
            top.saw_syntax = top.saw_syntax or is_code_syntax(cp)
    for span in stack:
        acc.add(span.pos)
    return sorted(acc)


def has_purposeless_control(input_cps: list[int]) -> bool:
    """True iff ``input_cps`` carries at least one purposeless bidi format
    control. Mirrors ``hasPurposelessControl``."""
    return bool(purposeless_control_positions(input_cps))


def first_purposeless_control(input_cps: list[int]) -> tuple[int, int] | None:
    """Position and codepoint of the first purposeless control, if any. Mirrors
    ``firstPurposelessControl``."""
    positions = purposeless_control_positions(input_cps)
    if not positions:
        return None
    pos = positions[0]
    return (pos, input_cps[pos])


__all__ = [
    "first_purposeless_control",
    "has_purposeless_control",
    "is_code_syntax",
    "opens_isolate_kind",
    "opens_ltr_kind",
    "opens_rtl_kind",
    "paragraph_is_rtl",
    "purposeless_control_positions",
]
