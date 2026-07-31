"""Covert-display compound detector contract tests.

Ground truth: the ``detect_*`` spot-check theorems in
``Unicode/Security/Boundary/CovertDisplayCompound.lean`` (and their
mirror in the verified Rust port).  The compound fires only when a bidi
format-control shares the input with a covert channel — an unregistered
variation selector or a tag-block character — with the suspicious VS
outranking the tag-block class.
"""

from unicode_python.security.boundary import covert_display_compound
from unicode_python.security.policy import Mode, Profile, scan

_CODE = "unicode.security.X.covert-display-compound"


def _detector_sub(input_cps: list[int]) -> str | None:
    return covert_display_compound.detect(input_cps).sub


def _scan_sub(input_cps: list[int]) -> str | None:
    verdict = scan(Profile.GATEWAY_HEADER, Mode.OBSERVE, input_cps)
    for finding in verdict.findings:
        if finding.code.startswith(_CODE):
            return finding.sub_threat
    return None


def test_empty_is_clear() -> None:
    assert _detector_sub([]) is None
    assert _scan_sub([]) is None


def test_pure_ascii_is_clear() -> None:
    # "Hello" — no bidi control.
    assert _detector_sub([0x48, 0x65, 0x6C, 0x6C, 0x6F]) is None
    assert _scan_sub([0x48, 0x65, 0x6C, 0x6C, 0x6F]) is None


def test_bidi_alone_is_clear() -> None:
    # RLO alone — no covert channel.
    assert _detector_sub([0x202E]) is None
    assert _scan_sub([0x202E]) is None


def test_vs_without_bidi_is_clear() -> None:
    # A + VS1 alone — a suspicious VS but no bidi control.
    assert _detector_sub([0x0041, 0xFE00]) is None
    assert _scan_sub([0x0041, 0xFE00]) is None


def test_bidi_plus_unregistered_vs() -> None:
    # RLO + A + VS1 — the VS is not a registered (A, VS1) pair.
    assert _detector_sub([0x202E, 0x0041, 0xFE00]) == "BidiPlusUnregisteredVs"
    assert _scan_sub([0x202E, 0x0041, 0xFE00]) == "BidiPlusUnregisteredVs"


def test_bidi_plus_tag_block() -> None:
    # RLO + A + tag char — no suspicious VS, so the tag-block class fires.
    assert _detector_sub([0x202E, 0x0041, 0xE0001]) == "BidiPlusTagBlock"
    assert _scan_sub([0x202E, 0x0041, 0xE0001]) == "BidiPlusTagBlock"
