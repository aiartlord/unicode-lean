"""Surrogate-reassembly detector contract tests.

Ground truth: the ``detect_*`` spot-check theorems in
``Unicode/Security/Covert/SurrogateReassembly.lean``, each proven by
``decide``, and mirrored in
``ports/rust/src/security/covert/surrogate_reassembly.rs``.

The detector treats a codepoint list as a byte stream (one octet per
entry) only when every entry is ``< 0x100``; otherwise the family
does not apply and the verdict is clear.  On a byte stream it
projects the first strict-UTF-8 violation onto a covert-layer
sub-threat tag.
"""

from unicode_python.security.covert import surrogate_reassembly
from unicode_python.security.policy import Mode, Profile, scan

_SR_CODE = "unicode.security.C.surrogate-reassembly"


def _sub(input_cps: list[int]) -> str | None:
    """Sub-threat tag from the detector directly (``None`` = clear)."""
    return surrogate_reassembly.detect(input_cps).sub


def _sub_via_scan(input_cps: list[int]) -> str | None:
    """Sub-threat tag surfaced through the policy ``scan`` entry point.

    The family only fires on all-``< 0x100`` invalid-UTF-8 input, so
    at most one surrogate-reassembly finding is produced.
    """
    verdict = scan(Profile.GATEWAY_HEADER, Mode.OBSERVE, input_cps)
    subs = [
        finding.sub_threat
        for finding in verdict.findings
        if finding.code.startswith(_SR_CODE)
    ]
    assert len(subs) <= 1
    return subs[0] if subs else None


# ── clear: well-formed UTF-8 byte streams ────────────────────────────

def test_empty_is_clear() -> None:
    assert _sub([]) is None
    assert _sub_via_scan([]) is None


def test_ascii_is_clear() -> None:
    assert _sub([0x48, 0x65, 0x6C, 0x6C, 0x6F]) is None
    assert _sub_via_scan([0x48, 0x65, 0x6C, 0x6C, 0x6F]) is None


def test_e_acute_is_clear() -> None:
    assert _sub([0xC3, 0xA9]) is None  # é
    assert _sub_via_scan([0xC3, 0xA9]) is None


def test_han_is_clear() -> None:
    assert _sub([0xE4, 0xB8, 0xAD]) is None  # 中
    assert _sub_via_scan([0xE4, 0xB8, 0xAD]) is None


def test_emoji_is_clear() -> None:
    assert _sub([0xF0, 0x9F, 0x98, 0x80]) is None  # 😀
    assert _sub_via_scan([0xF0, 0x9F, 0x98, 0x80]) is None


# ── InvalidStartByte ─────────────────────────────────────────────────

def test_c0_80_invalid_start() -> None:
    assert _sub([0xC0, 0x80]) == "InvalidStartByte"
    assert _sub_via_scan([0xC0, 0x80]) == "InvalidStartByte"


def test_c0_af_invalid_start() -> None:
    assert _sub([0xC0, 0xAF]) == "InvalidStartByte"
    assert _sub_via_scan([0xC0, 0xAF]) == "InvalidStartByte"


def test_fe_invalid_start() -> None:
    assert _sub([0xFE]) == "InvalidStartByte"
    assert _sub_via_scan([0xFE]) == "InvalidStartByte"


def test_lone_continuation_invalid_start() -> None:
    assert _sub([0x80]) == "InvalidStartByte"
    assert _sub_via_scan([0x80]) == "InvalidStartByte"


def test_ff_invalid_start() -> None:
    assert _sub([0xFF]) == "InvalidStartByte"
    assert _sub_via_scan([0xFF]) == "InvalidStartByte"


# ── Overlong ─────────────────────────────────────────────────────────

def test_overlong_slash_3byte() -> None:
    assert _sub([0xE0, 0x80, 0xAF]) == "Overlong"
    assert _sub_via_scan([0xE0, 0x80, 0xAF]) == "Overlong"


def test_overlong_slash_4byte() -> None:
    assert _sub([0xF0, 0x80, 0x80, 0xAF]) == "Overlong"
    assert _sub_via_scan([0xF0, 0x80, 0x80, 0xAF]) == "Overlong"


# ── Cesu8 (surrogate codepoint) ──────────────────────────────────────

def test_cesu8_surrogate_low() -> None:
    assert _sub([0xED, 0xA0, 0x80]) == "Cesu8"
    assert _sub_via_scan([0xED, 0xA0, 0x80]) == "Cesu8"


def test_cesu8_surrogate_high() -> None:
    assert _sub([0xED, 0xAF, 0xBF]) == "Cesu8"
    assert _sub_via_scan([0xED, 0xAF, 0xBF]) == "Cesu8"


# ── Truncated ────────────────────────────────────────────────────────

def test_truncated_2byte() -> None:
    assert _sub([0xC3]) == "Truncated"
    assert _sub_via_scan([0xC3]) == "Truncated"


def test_truncated_4byte() -> None:
    assert _sub([0xF0, 0x9F, 0x98]) == "Truncated"
    assert _sub_via_scan([0xF0, 0x9F, 0x98]) == "Truncated"


# ── non-byte-stream ──────────────────────────────────────────────────
# The module `detect` clamps any value > 0xFF to 0xFF (mirroring the Lean
# `toBytes` helper), so a direct unit call surfaces InvalidStartByte. The
# scan orchestrator gates the family out on non-byte-stream input (mirroring
# `runAll`), so it stays clear end-to-end.

def test_astral_codepoint_clamps_at_unit_gated_at_scan() -> None:
    assert _sub([0x1F600]) == "InvalidStartByte"
    assert _sub_via_scan([0x1F600]) is None


def test_mixed_codepoint_array_clamps_at_unit_gated_at_scan() -> None:
    assert _sub([0x41, 0x100]) == "InvalidStartByte"
    assert _sub_via_scan([0x41, 0x100]) is None
