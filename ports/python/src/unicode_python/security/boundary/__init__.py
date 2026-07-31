"""Cross-layer boundary detector family.

Compound detectors that fire only when hazards from two distinct
single-layer families co-occur — each member is materially more
dangerous than either of its constituents alone.  The confusable-in-
bidi-context compound (a homoglyph codepoint sharing an input with a
bidi format-control, CVE-2021-42574 class) is the first member.
"""

from . import confusable_bidi_compound

__all__ = [
    "confusable_bidi_compound",
]
