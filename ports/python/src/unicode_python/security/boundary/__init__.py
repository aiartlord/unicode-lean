"""Cross-layer boundary detector family.

Compound detectors that fire only when hazards from two distinct
single-layer families co-occur — each member is materially more
dangerous than either of its constituents alone.  The confusable-in-
bidi-context compound (a homoglyph codepoint sharing an input with a
bidi format-control, CVE-2021-42574 class) is the first member; the
covert-display compound (a bidi control co-located with an unregistered
variation selector or a tag-block character) is the second.  The
identifier-form-drift detector is a boundary-layer member of a different
shape: it fires on a single codepoint whose UTS #39 ``Identifier_Status``
disagrees with the status of its NFKD head, the two-stage validate-then-
normalise bypass.  The admissibility-form-drift detector is its whole-string
complement: it fires when the UTS #39 ``is_allowed_identifier`` verdict differs
between the input and its NFKC form.
"""

from . import (
    admissibility_form_drift,
    confusable_bidi_compound,
    covert_display_compound,
    identifier_form_drift,
)

__all__ = [
    "admissibility_form_drift",
    "confusable_bidi_compound",
    "covert_display_compound",
    "identifier_form_drift",
]
