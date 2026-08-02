"""Stream-Safe-violation detector contract tests.

Mirrors the ``detect_*`` ground-truth theorems in
``Unicode/Security/Form/StreamSafeViolation.lean`` (via the verified Rust
reference ``security/form/stream_safe_violation.rs``), and drives the shared
cross-port fixture ``fixtures/security/detectors/stream_safe_violation.json``
through ``detect``, asserting the 30-clear / 31-hazard boundary, the reported
positions, and the stable reason code.
"""

import json
from pathlib import Path

from unicode_python.security.calculus import Family
from unicode_python.security.form.stream_safe_violation import (
    STREAM_SAFE_LIMIT,
    detect,
)
from unicode_python.security.policy import reason_code

# U+0301 COMBINING ACUTE ACCENT has CCC = 230 (a non-starter); ASCII letters
# have CCC = 0 (starters).
ACUTE = 0x0301

FIXTURE = (
    Path(__file__).resolve().parents[3]
    / "fixtures"
    / "security"
    / "detectors"
    / "stream_safe_violation.json"
)


def _a_plus_marks(n: int) -> list[int]:
    """Build "a" followed by ``n`` combining acute accents."""
    return [0x61] + [ACUTE] * n


def test_stream_safe_limit_is_thirty() -> None:
    assert STREAM_SAFE_LIMIT == 30


def test_detect_empty_clear() -> None:
    verdict = detect([])
    assert verdict.classify.is_clear()
    assert verdict.classify.tag() is None
    assert verdict.max_run_len == 0
    assert verdict.overrun_count == 0
    assert verdict.total_non_starters == 0


def test_detect_ascii_clear() -> None:
    verdict = detect([0x48, 0x65, 0x6C, 0x6C, 0x6F])
    assert verdict.classify.is_clear()
    assert verdict.max_run_len == 0
    assert verdict.total_non_starters == 0


def test_detect_one_combine_clear() -> None:
    verdict = detect([0x61, ACUTE])
    assert verdict.classify.is_clear()
    assert verdict.max_run_len == 1
    assert verdict.overrun_count == 0
    assert verdict.total_non_starters == 1


def test_detect_thirty_marks_clear() -> None:
    verdict = detect(_a_plus_marks(30))
    assert verdict.classify.is_clear()
    assert verdict.classify.tag() is None
    assert verdict.max_run_len == 30
    assert verdict.overrun_count == 0
    assert verdict.total_non_starters == 30


def test_detect_thirtyone_marks_hazard() -> None:
    verdict = detect(_a_plus_marks(31))
    assert not verdict.classify.is_clear()
    assert verdict.classify.tag() == "StreamSafeOverrun"
    assert verdict.classify.positions == (1,)
    assert verdict.classify.sub is not None
    assert verdict.classify.sub.base_pos == 1
    assert verdict.classify.sub.run_len == 31
    assert verdict.classify.decoded == ()
    assert verdict.max_run_len == 31
    assert verdict.overrun_count == 1
    assert verdict.total_non_starters == 31


def test_bare_mark_run_starts_at_zero() -> None:
    verdict = detect([ACUTE] * 31)
    assert verdict.classify.tag() == "StreamSafeOverrun"
    assert verdict.classify.positions == (0,)
    assert verdict.max_run_len == 31
    assert verdict.total_non_starters == 31


def test_two_short_runs_clear_totals_summed() -> None:
    verdict = detect(_a_plus_marks(30) + [0x62] + [ACUTE] * 30)
    assert verdict.classify.is_clear()
    assert verdict.max_run_len == 30
    assert verdict.overrun_count == 0
    assert verdict.total_non_starters == 60


def test_first_overrun_reports_long_run_start() -> None:
    verdict = detect(_a_plus_marks(5) + [0x62] + [ACUTE] * 31)
    assert verdict.classify.tag() == "StreamSafeOverrun"
    assert verdict.classify.positions == (7,)
    assert verdict.max_run_len == 31
    assert verdict.overrun_count == 1
    assert verdict.total_non_starters == 36


def test_shared_fixture_boundary_and_reason_code() -> None:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert fixture["schema"] == 1
    assert fixture["family"] == "stream-safe-violation"
    for case in fixture["cases"]:
        verdict = detect(case["input"])
        tag = verdict.classify.tag()
        codes = (
            set()
            if tag is None
            else {reason_code(Family.STREAM_SAFE_VIOLATION, tag)}
        )
        for required in case["required_findings"]:
            assert required in codes, (
                f"{case['name']}: missing {required} in {sorted(codes)}"
            )
        if not case["required_findings"]:
            assert verdict.classify.is_clear(), (
                f"{case['name']}: expected clear, got {tag}"
            )
