"""Stream-Safe-Text-Format-violation detector (F2).

Mirrors ``Unicode.Security.Form.StreamSafeViolation`` (direct port of the
verified Rust reference ``security/form/stream_safe_violation.rs``). Detects
inputs whose consecutive non-starter run exceeds the UAX #15 §13
``streamSafeLimit`` of 30 — the canonical "Zalgo" shape, a single base
codepoint followed by a long combining-mark run. Such an input forces
unbounded combining-mark buffers in receiver-side streaming normalization
(``toNFC`` / ``toNFD`` / ``toNFKC`` / ``toNFKD``) and is a known DoS vector.

UAX #15 §13 defines Stream-Safe Text Format as the remediation: insert
U+034F COMBINING GRAPHEME JOINER (a starter) after every 30 consecutive
non-starters, which bounds the normalization buffer. This detector is the
security verdict over the same property — distinct from renderer-divergence's
cosmetic four-mark threshold, it is the spec-mandated DoS-prevention bound.

A codepoint is a non-starter iff its Canonical_Combining_Class is non-zero
(UAX #15 D49). CCC is read from the port's own bundled UCD table via
``identity.ucd.ccc``, never a host normalizer.

Sub-threat ``StreamSafeOverrun(base_pos, run_len)`` fires on the first
non-starter run whose length exceeds ``STREAM_SAFE_LIMIT``; ``base_pos`` is
the index of that run's first non-starter codepoint.
"""

from dataclasses import dataclass, field

from ..identity.ucd import ccc

__all__ = [
    "STREAM_SAFE_LIMIT",
    "StreamSafeOverrun",
    "Classification",
    "Verdict",
    "detect",
]


# ─────────────────────────────────────────────────────────────────────
# §1 Run inventory
# ─────────────────────────────────────────────────────────────────────

# UAX #15 §13 Stream-Safe limit: the maximum number of consecutive
# non-starters permitted before a COMBINING GRAPHEME JOINER must be inserted.
STREAM_SAFE_LIMIT = 30


def _is_non_starter(cp: int) -> bool:
    """True iff ``cp`` is a non-starter — a codepoint with non-zero
    Canonical_Combining_Class (UAX #15 D49). Starters have CCC = 0."""
    return ccc(cp) != 0


def _non_starter_runs(input_cps: list[int]) -> list[tuple[int, int]]:
    """Inventory of ``(start_index, length)`` for every maximal non-starter
    run in ``input_cps``. A run opens on the first non-starter, its start
    index is fixed to that codepoint's absolute index, and it closes
    (emitting its ``(start, length)`` pair) on the next starter or at end of
    input."""
    runs: list[tuple[int, int]] = []
    cur_start: int | None = None
    cur_len = 0
    for index, cp in enumerate(input_cps):
        if _is_non_starter(cp):
            if cur_start is None:
                cur_start = index
            cur_len += 1
        else:
            if cur_start is not None:
                runs.append((cur_start, cur_len))
            cur_start = None
            cur_len = 0
    if cur_start is not None:
        runs.append((cur_start, cur_len))
    return runs


def _first_overrun(input_cps: list[int]) -> tuple[int, int] | None:
    """First non-starter run whose length exceeds ``STREAM_SAFE_LIMIT``, as
    ``(start_index, length)``; ``None`` when no run overruns."""
    for start, length in _non_starter_runs(input_cps):
        if length > STREAM_SAFE_LIMIT:
            return (start, length)
    return None


def _max_run_len(input_cps: list[int]) -> int:
    """Longest non-starter run length in ``input_cps``."""
    acc = 0
    for _start, length in _non_starter_runs(input_cps):
        if length > acc:
            acc = length
    return acc


def _overrun_count(input_cps: list[int]) -> int:
    """Number of distinct non-starter runs that exceed ``STREAM_SAFE_LIMIT``."""
    acc = 0
    for _start, length in _non_starter_runs(input_cps):
        if length > STREAM_SAFE_LIMIT:
            acc += 1
    return acc


def _total_non_starters(input_cps: list[int]) -> int:
    """Total non-starter codepoints in ``input_cps`` (sum of all run
    lengths)."""
    acc = 0
    for _start, length in _non_starter_runs(input_cps):
        acc += length
    return acc


# ─────────────────────────────────────────────────────────────────────
# §2 Types
# ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class StreamSafeOverrun:
    """The one sub-threat this detector fires: the first non-starter run whose
    length exceeds ``STREAM_SAFE_LIMIT``. ``base_pos`` is the index of the
    run's first non-starter codepoint; ``run_len`` is the run's length."""

    base_pos: int
    run_len: int

    def tag(self) -> str:
        """Human-facing classification tag for this sub-threat."""
        return "StreamSafeOverrun"


@dataclass(frozen=True, slots=True)
class Classification:
    """Top-level F2 classification. ``sub`` is ``None`` for a clear input (no
    non-starter run exceeds the Stream-Safe limit), else the sub-threat that
    fired together with its implicated positions. ``decoded`` mirrors the
    spec's ``Classification.hazard`` byte-context field and is always empty
    for this detector."""

    sub: StreamSafeOverrun | None
    positions: tuple[int, ...] = ()
    decoded: tuple[int, ...] = ()

    @staticmethod
    def clear() -> "Classification":
        """The clear classification — no run exceeds the Stream-Safe limit."""
        return Classification(sub=None, positions=(), decoded=())

    @staticmethod
    def hazard(
        sub: StreamSafeOverrun,
        positions: tuple[int, ...],
        decoded: tuple[int, ...],
    ) -> "Classification":
        """A hazard classification carrying the sub-threat, implicated
        positions, and (always empty) decoded byte context."""
        return Classification(sub=sub, positions=positions, decoded=decoded)

    def is_clear(self) -> bool:
        """True iff the input is clear."""
        return self.sub is None

    def tag(self) -> str | None:
        """Human-facing tag for a hazard, or ``None`` when clear."""
        if self.sub is None:
            return None
        return self.sub.tag()


@dataclass(frozen=True, slots=True)
class Verdict:
    """F2 verdict — the structured output of ``detect``. The run-inventory
    summaries (``max_run_len``, ``overrun_count``, ``total_non_starters``) are
    exposed so downstream callers can size the buffer pressure a streaming
    normalizer would see."""

    input: tuple[int, ...]
    classify: Classification
    max_run_len: int
    overrun_count: int
    total_non_starters: int = field(default=0)


# ─────────────────────────────────────────────────────────────────────
# §3 Top-level detection
# ─────────────────────────────────────────────────────────────────────


def detect(input_cps: list[int]) -> Verdict:
    """The F2 detection function. Fires ``StreamSafeOverrun`` on the first
    non-starter run whose length exceeds ``STREAM_SAFE_LIMIT``."""
    overrun = _first_overrun(input_cps)
    if overrun is not None:
        base_pos, run_len = overrun
        classification = Classification.hazard(
            sub=StreamSafeOverrun(base_pos=base_pos, run_len=run_len),
            positions=(base_pos,),
            decoded=(),
        )
    else:
        classification = Classification.clear()
    return Verdict(
        input=tuple(input_cps),
        classify=classification,
        max_run_len=_max_run_len(input_cps),
        overrun_count=_overrun_count(input_cps),
        total_non_starters=_total_non_starters(input_cps),
    )
