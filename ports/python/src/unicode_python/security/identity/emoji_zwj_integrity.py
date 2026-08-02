"""emoji-zwj-integrity — detection of malformed / unsanctioned emoji
ZWJ-sequence shapes per UTS #51 (the identity-layer detector I3).

Byte-faithful transliteration of the verified Rust reference
``ports/rust/src/security/identity/emoji_zwj_integrity.rs`` (itself a
transliteration of ``Unicode.Security.Identity.EmojiZwjIntegrity``).

Threat model. An adversary crafts an emoji-shaped codepoint sequence
containing one or more ``U+200D`` ZERO WIDTH JOINERs but violating the
sanctioned RGI ZWJ-sequence shape — by exceeding the RGI length cap, by
joining a non-emoji codepoint, by emitting adjacent ZWJ pairs, or by
overflowing the skin-tone count. Any non-RGI ZWJ-containing sequence is
renderer-dependent, and that renderer divergence is the attack surface.

Sanctioning data. UTS #51 defines the RGI ZWJ sequences in
``emoji-zwj-sequences.txt``, bundled in the port's own
``data/emoji-zwj-sequences.txt`` (never a host emoji library). The
registered set gives both the exact-match membership test
(:func:`is_registered_zwj_sequence`) and the ZWJ *alphabet* — every
distinct codepoint occurring at any position of any registered sequence,
excluding the joiner — which is the canonical "what may flank a ZWJ?"
predicate (:func:`is_emoji_target`).

Algorithm (one pass over ``input``).

    Phase 1 — collect ZWJ positions and the skin-tone count.
    Phase 2 — short-circuit ``Clear`` if there are no ZWJs and the
              skin-tone count is at most 1.
    Phase 3 — a registered RGI sequence is always ``Clear``.
    Phase 4 — check sub-threats by priority:
                1. ``DoubleZWJ``            ZWJ-ZWJ adjacency
                2. ``NonEmojiInjection``    ZWJ adjacent to a non-emoji cp
                3. ``OverLength``           sequence longer than the cap
                4. ``SkinToneOverflow``     skin-tone count >= 5
                5. ``UnregisteredSequence`` catch-all when ZWJs are present
                                            but the sequence is not registered.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Union

from ..calculus import ClassificationKind

# ─────────────────────────────────────────────────────────────────────
# §1 Constants
# ─────────────────────────────────────────────────────────────────────

# Conservative cap on the length of a sanctioned RGI ZWJ sequence
# (``maxRgiLength`` in the Lean spec). The longest current entry (a
# four-person family with skin tones) reaches ~13-14 codepoints; 16 is a
# safe upper bound.
MAX_RGI_LENGTH = 16

# The ZERO WIDTH JOINER codepoint.
ZWJ = 0x200D


# ─────────────────────────────────────────────────────────────────────
# §2 Sub-threat ADT + verdict
# ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class DoubleZwj:
    """ZWJ-ZWJ adjacency; ``positions`` are the first ZWJ of each pair."""

    positions: list[int]


@dataclass(frozen=True, slots=True)
class NonEmojiInjection:
    """A ZWJ flanked by a non-emoji codepoint (or sitting at an input
    edge). ``non_emoji_cp`` is the offending codepoint (0 for an edge
    ZWJ)."""

    zwj_pos: int
    non_emoji_cp: int


@dataclass(frozen=True, slots=True)
class OverLength:
    """The sequence is longer than :data:`MAX_RGI_LENGTH`."""

    length: int
    max_length: int


@dataclass(frozen=True, slots=True)
class SkinToneOverflow:
    """Five or more skin-tone modifiers (the family-emoji maximum is
    four)."""

    count: int


@dataclass(frozen=True, slots=True)
class UnregisteredSequence:
    """ZWJs are present and no other sub-threat matched, but the sequence
    is not a registered RGI ZWJ sequence."""

    chain_len: int


SubThreat = Union[
    DoubleZwj,
    NonEmojiInjection,
    OverLength,
    SkinToneOverflow,
    UnregisteredSequence,
]


def sub_threat_tag(sub: SubThreat) -> str:
    """Fixture-row tag string for a sub-threat (matches ``SubThreat.tag``
    in the Lean/Rust reference)."""
    if isinstance(sub, DoubleZwj):
        return "DoubleZWJ"
    if isinstance(sub, NonEmojiInjection):
        return "NonEmojiInjection"
    if isinstance(sub, OverLength):
        return "OverLength"
    if isinstance(sub, SkinToneOverflow):
        return "SkinToneOverflow"
    if isinstance(sub, UnregisteredSequence):
        return "UnregisteredSequence"
    raise TypeError(f"sub_threat_tag: unknown SubThreat variant {sub!r}")


@dataclass(frozen=True, slots=True)
class Classification:
    """Top-level EmojiZwjIntegrity classification. ``is_clear``
    distinguishes the ``Clear`` variant from the ``Hazard`` variant; a
    hazard carries its sub-threat, the codepoint positions it implicates,
    and the decoded-byte projection (always empty here, kept for shape
    parity with the Lean ``Classification.hazard``)."""

    is_clear: bool
    sub: SubThreat | None = None
    positions: list[int] = field(default_factory=list)
    decoded: list[int] = field(default_factory=list)

    @property
    def tag(self) -> str | None:
        """Human-facing tag for a hazard, or ``None`` when clear."""
        if self.is_clear or self.sub is None:
            return None
        return sub_threat_tag(self.sub)

    @property
    def kind(self) -> ClassificationKind:
        """The classification kind (``CLEAR`` or ``HAZARD``)."""
        return (
            ClassificationKind.CLEAR
            if self.is_clear
            else ClassificationKind.HAZARD
        )


@dataclass(frozen=True, slots=True)
class Verdict:
    """The structured output of :func:`detect` (mirrors the Lean
    ``Verdict``)."""

    input: list[int]
    classify: Classification
    zwj_positions: list[int]
    chain_length: int
    is_registered_rgi: bool
    skin_tone_count: int


# ─────────────────────────────────────────────────────────────────────
# §3 RGI ZWJ-sequence data (bundled data/emoji-zwj-sequences.txt)
# ─────────────────────────────────────────────────────────────────────

_DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"


def _parse_zwj_sequences() -> list[list[int]]:
    """Parse the registered RGI ZWJ sequences from
    emoji-zwj-sequences.txt. Each non-comment row is
    ``<cp> <cp> ... ; RGI_Emoji_ZWJ_Sequence ; <desc> # <cmt>``; the
    codepoint list is the space-separated hex field before the first
    ``;``."""
    with (_DATA_DIR / "emoji-zwj-sequences.txt").open(
        "r", encoding="utf-8"
    ) as f:
        raw = f.read()
    out: list[list[int]] = []
    for raw_line in raw.splitlines():
        hash_idx = raw_line.find("#")
        body = raw_line if hash_idx < 0 else raw_line[:hash_idx]
        stripped = body.strip()
        if not stripped:
            continue
        seq_field = stripped.split(";")[0]
        seq: list[int] = []
        parsed_ok = True
        for token in seq_field.split():
            try:
                seq.append(int(token, 16))
            except ValueError:
                parsed_ok = False
                break
        if parsed_ok and seq:
            out.append(seq)
    return out


_ZWJ_SEQUENCES: list[list[int]] | None = None
_ZWJ_ALPHABET: frozenset[int] | None = None


def zwj_sequences() -> list[list[int]]:
    """Return the parsed registered RGI ZWJ sequences (cached after first
    call)."""
    global _ZWJ_SEQUENCES
    if _ZWJ_SEQUENCES is None:
        _ZWJ_SEQUENCES = _parse_zwj_sequences()
    return _ZWJ_SEQUENCES


def _build_zwj_alphabet() -> frozenset[int]:
    """The ZWJ alphabet: every distinct codepoint occurring at any
    position of any registered RGI ZWJ sequence, excluding the joiner
    U+200D itself."""
    out: set[int] = set()
    for seq in zwj_sequences():
        for cp in seq:
            if cp != ZWJ:
                out.add(cp)
    return frozenset(out)


def zwj_alphabet() -> frozenset[int]:
    """Return the ZWJ alphabet (cached after first call)."""
    global _ZWJ_ALPHABET
    if _ZWJ_ALPHABET is None:
        _ZWJ_ALPHABET = _build_zwj_alphabet()
    return _ZWJ_ALPHABET


def is_registered_zwj_sequence(cps: list[int]) -> bool:
    """True iff ``cps`` is exactly a registered RGI ZWJ sequence."""
    return any(seq == cps for seq in zwj_sequences())


def is_emoji_target(cp: int) -> bool:
    """True iff ``cp`` appears at some position of a registered RGI ZWJ
    sequence (the canonical "what may flank a ZWJ?" predicate)."""
    return cp in zwj_alphabet()


# ─────────────────────────────────────────────────────────────────────
# §4 Core predicates
# ─────────────────────────────────────────────────────────────────────


def is_zwj(cp: int) -> bool:
    """True iff ``cp`` is the ZWJ codepoint."""
    return cp == ZWJ


def is_emoji_modifier(cp: int) -> bool:
    """True iff ``cp`` is an emoji skin-tone modifier
    (U+1F3FB..U+1F3FF)."""
    return 0x1F3FB <= cp <= 0x1F3FF


def zwj_positions(input_cps: list[int]) -> list[int]:
    """Positions of every ZWJ in ``input``."""
    return [idx for idx, cp in enumerate(input_cps) if is_zwj(cp)]


def skin_tone_count(input_cps: list[int]) -> int:
    """Count of skin-tone modifier codepoints."""
    return sum(1 for cp in input_cps if is_emoji_modifier(cp))


def double_zwj_positions(input_cps: list[int]) -> list[int]:
    """Positions of the first ZWJ in each ZWJ-ZWJ adjacent pair."""
    out: list[int] = []
    for idx in range(len(input_cps)):
        if (
            idx + 1 < len(input_cps)
            and is_zwj(input_cps[idx])
            and is_zwj(input_cps[idx + 1])
        ):
            out.append(idx)
    return out


def first_non_emoji_injection(
    input_cps: list[int],
) -> tuple[int, int] | None:
    """The first ZWJ position where either neighbour is a non-emoji
    codepoint, as ``(zwj_pos, offending_cp)``. A ZWJ at an input edge (no
    preceding or no following codepoint) is itself an injection-class
    hazard, reported with offending codepoint 0."""
    for idx in range(len(input_cps)):
        if not is_zwj(input_cps[idx]):
            continue
        prev = None if idx == 0 else input_cps[idx - 1]
        nxt = input_cps[idx + 1] if idx + 1 < len(input_cps) else None
        if prev is not None and nxt is not None:
            if not is_emoji_target(prev):
                return (idx, prev)
            if not is_emoji_target(nxt):
                return (idx, nxt)
        elif prev is None:
            return (idx, 0)
        else:
            # prev present, nxt is None (trailing-edge ZWJ).
            return (idx, 0)
    return None


# ─────────────────────────────────────────────────────────────────────
# §5 Top-level detection
# ─────────────────────────────────────────────────────────────────────


def detect(input_cps: list[int]) -> Verdict:
    """The EmojiZwjIntegrity detection function."""
    zwjs = zwj_positions(input_cps)
    st_count = skin_tone_count(input_cps)
    is_rgi = is_registered_zwj_sequence(input_cps)
    chain_len = 0 if not zwjs else len(input_cps)

    if not zwjs and st_count <= 1:
        return Verdict(
            input=list(input_cps),
            classify=Classification(is_clear=True),
            zwj_positions=[],
            chain_length=0,
            is_registered_rgi=is_rgi,
            skin_tone_count=st_count,
        )

    if is_rgi:
        # Phase 3: a registered RGI sequence is always clear.
        classification = Classification(is_clear=True)
    else:
        # Phase 4.1: ZWJ-ZWJ adjacency.
        dzwj = double_zwj_positions(input_cps)
        if dzwj:
            classification = Classification(
                is_clear=False,
                sub=DoubleZwj(positions=list(dzwj)),
                positions=list(dzwj),
            )
        else:
            injection = first_non_emoji_injection(input_cps)
            if injection is not None:
                # Phase 4.2: ZWJ adjacent to a non-emoji codepoint.
                zwj_pos, offend_cp = injection
                classification = Classification(
                    is_clear=False,
                    sub=NonEmojiInjection(
                        zwj_pos=zwj_pos, non_emoji_cp=offend_cp
                    ),
                    positions=[zwj_pos],
                )
            elif len(input_cps) > MAX_RGI_LENGTH:
                # Phase 4.3: length cap.
                classification = Classification(
                    is_clear=False,
                    sub=OverLength(
                        length=len(input_cps), max_length=MAX_RGI_LENGTH
                    ),
                    positions=[],
                )
            elif st_count >= 5:
                # Phase 4.4: skin-tone overflow.
                classification = Classification(
                    is_clear=False,
                    sub=SkinToneOverflow(count=st_count),
                    positions=[],
                )
            elif zwjs:
                # Phase 4.5: catch-all for unregistered ZWJ sequences.
                classification = Classification(
                    is_clear=False,
                    sub=UnregisteredSequence(chain_len=len(input_cps)),
                    positions=list(zwjs),
                )
            else:
                classification = Classification(is_clear=True)

    return Verdict(
        input=list(input_cps),
        classify=classification,
        zwj_positions=list(zwjs),
        chain_length=chain_len,
        is_registered_rgi=is_rgi,
        skin_tone_count=st_count,
    )
