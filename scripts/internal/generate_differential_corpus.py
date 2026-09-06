#!/usr/bin/env python3
"""Generate fixtures/security/differential_corpus.json from the Rust reference.

ROADMAP §7 asks for a differential runner covering all sixteen ports. The
existing runner under `ports/{rust,python,cpp}/tests/diff_runner.*` compares
three ports on one detector family, because each port that joins it needs its
own corpus parser, PRNG and emitter written in its own language.

This takes the other route. Every port already runs
`fixtures/security/verdict_contract.json` through a loop that calls
`scan(profile, mode, input)` and compares the wire verdict byte-for-byte, so a
generated corpus in that same `unicode-security-verdict-v0` schema is a
differential test across every port that reads it, with no new per-port
machinery. Going through `scan` also widens the comparison from one family to
every family the policy layer dispatches.

The input shape is the one the existing runner proved useful: the same
xorshift64 stream, the same seed, and the class mix of ASCII, Latin-Cyrillic
look-alikes, math-alpha and fullwidth, combining marks, default-ignorables and
free scalars, extended with four security-shaped classes the detectors' newer
rules need to be reached at all: bidi controls beside Hebrew, Arabic, Latin and
code syntax (the purpose rule), Latin words carrying dotless i, long s and
script g between separators (the ascii-confusable rung over identifier tokens),
Latin words beside Cyrillic and Greek look-alike words (per-token reading of
running text), and a per-position grab-bag over all of those pools. The profile
cycles so the policy layer is exercised alongside the detectors.

`ports/rust/tests/diff_runner.rs` carries the same generator in Rust for the
100k-input sanitizer stream; the two must draw from the PRNG in the same order
so a case index here names the same input there.

The corpus is written compact (no indentation) because sixteen copies of it are
vendored; the hand-written verdict contract stays indented for reading.

Verdicts come from the Rust reference in one batch through its `--jsonl` mode,
and are projected onto the wire shape with the same `FINDING_FIELDS` the
verdict-contract generator uses. That module is imported rather than copied, so
the projection and the port-copy sync cannot drift between the two fixtures.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "fixtures" / "security" / "differential_corpus.json"
DEFAULT_BIN = ROOT / "ports" / "rust" / "target" / "debug" / "unicode-security"

# The verdict-contract generator owns the projection onto the wire shape and the
# port-copy sync. Its filename is not an identifier, so it is loaded by path
# rather than imported by name; the alternative is a second copy of both, which
# is exactly the drift this fixture exists to catch.
_CONTRACT_PATH = ROOT / "scripts" / "regenerate-verdict-contract.py"
_spec = importlib.util.spec_from_file_location("verdict_contract_gen", _CONTRACT_PATH)
if _spec is None or _spec.loader is None:
    raise SystemExit(f"cannot load {_CONTRACT_PATH}")
_contract = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_contract)

FINDING_FIELDS = _contract.FINDING_FIELDS
sync_fixture = _contract.sync_fixture

# The stream is shared with ports/rust/tests/diff_runner.rs so a case index here
# names the same input there.
SEED = 0xC0FFEE_1234_5678
MAX_LEN = 32

# Every profile, so the corpus exercises the policy layer's grading and not only
# the detectors. `scan` derives its detector context from the profile, so a case
# under `username` asks a different question of the same bytes than one under
# `source-code`.
PROFILES = (
    "gateway-header",
    "domain-name",
    "dns-label",
    "url",
    "username",
    "display-name",
    "chat-message",
    "source-code",
    "opaque-secret",
    "binary-blob",
)

LATIN_CYRILLIC_LOOKALIKES = (
    0x61, 0x65, 0x6F, 0x70, 0x63, 0x79, 0x78,
    0x0430, 0x0435, 0x043E, 0x0440, 0x0441, 0x0443, 0x0445,
)
COMBINING_OR_LATIN = (0x0300, 0x0301, 0x0308, 0x0061)
DEFAULT_IGNORABLE_OR_SPACE = (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x202F)
# The nine explicit bidi controls: embeddings, overrides, isolates, PDF, PDI.
BIDI_CONTROLS = (0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069)
# Space plus the ASCII code syntax the bidi purpose rule treats as content that
# makes a span purposeless.
CODE_SYNTAX_OR_SPACE = (0x20, 0x22, 0x27, 0x28, 0x29, 0x2F, 0x3B, 0x3D, 0x5B, 0x5D, 0x7B, 0x7D)
# Latin letters whose skeleton is ASCII (dotless i, long s, script g) plus
# dotless j, which is restricted rather than confusable, so the two rungs sit
# side by side in one stream.
ASCII_CONFUSABLE_LATIN = (0x0131, 0x017F, 0x0237, 0x0261)
# Separators that end an identifier token: space, dot, underscore, hyphen, comma.
TOKEN_SEPARATORS = (0x20, 0x2E, 0x5F, 0x2D, 0x2C)
GREEK_LOOKALIKES = (0x03B1, 0x03BF, 0x03BD, 0x03C1)
HEBREW_LETTER_COUNT = 27  # U+05D0..U+05EA
ARABIC_LETTER_COUNT = 36  # U+0627..U+064A
# Twenty classes: 0-13 as documented on `gen_input`, 14-19 seeded. Six of
# twenty puts about thirty percent of the stream through the seed table.
INPUT_CLASS_COUNT = 20

# One input per detector-fixture case that fires a rung, taken verbatim from
# fixtures/security/detectors/*.json for the default-scan families. The seeded
# classes wrap one of these in random context, so every rung the detector
# fixtures pin is also decided by every port at a random offset, beside other
# text, under every profile. scripts/check-fixture-coverage.py is what proves
# the reach; this table is how the stream gets there by construction rather
# than by luck. Kept in step with the fixtures by hand; the reach gate fails
# the moment a rung goes unreached.
SEEDS: tuple[tuple[int, ...], ...] = (
    (0xFB01,),  # admissibility_form_drift/fi-ligature-drift
    (0x1112, 0x1161, 0x11AB),  # admissibility_form_drift/jamo-sequence-drift
    (0x0069, 0x0066, 0x0020, 0x202E, 0x0029, 0x007B),  # bidi_control_balance/unbalanced-embedding
    (0x202C,),  # bidi_control_balance/orphan-pop
    (0x2066,),  # bidi_control_balance/unbalanced-isolate
    (0x00DF,),  # case_expansion_mismatch/sharp-s-upper
    (0xFB01,),  # case_expansion_mismatch/fi-ligature-upper
    (0xFB03,),  # case_expansion_mismatch/ffi-ligature-upper
    (0x0130,),  # case_expansion_mismatch/dotted-I-lower
    (0x202E, 0x0430),  # confusable_bidi_compound/confusable-in-override
    (0x2066, 0x03BF),  # confusable_bidi_compound/confusable-in-isolate
    (0x202E, 0x0041, 0xFE00),  # covert_display_compound/bidi-plus-unregistered-vs
    (0x202E, 0x0041, 0xE0001),  # covert_display_compound/bidi-plus-tag-block
    (0x1F600, 0x200D, 0x200D, 0x1F600),  # emoji_zwj_integrity/double-zwj-hazard
    (0x1F600, 0x200D, 0x0061),  # emoji_zwj_integrity/non-emoji-injection-ascii-hazard
    (0x1F600, 0x200D, 0x1F4BB),  # emoji_zwj_integrity/grinning-laptop-non-emoji-injection-hazard
    (0x1F44B, 0x1F3FB, 0x1F3FC, 0x1F3FD, 0x1F3FE, 0x1F3FF),  # emoji_zwj_integrity/skin-tone-overflow-hazard
    (0x1F468, 0x200D, 0x1F469),  # emoji_zwj_integrity/unregistered-man-woman-hazard
    (0x1F468, 0x200D, 0x1F468, 0x200D, 0x1F468, 0x200D, 0x1F468, 0x200D, 0x1F468, 0x200D, 0x1F468, 0x200D, 0x1F468, 0x200D, 0x1F468, 0x200D, 0x1F468),  # emoji_zwj_integrity/over-length-chain-hazard
    (0x0064, 0x006F, 0x0063, 0x0075, 0x006D, 0x0065, 0x006E, 0x0074, 0x202E, 0x0074, 0x0078, 0x0074, 0x002E, 0x0065, 0x0078, 0x0065),  # filename_disguise/rlo-flip-hazard
    (0x0064, 0x006F, 0x0063, 0x2067, 0x0074, 0x0078, 0x0074, 0x002E, 0x0065, 0x0078, 0x0065, 0x2069),  # filename_disguise/isolate-flip-hazard
    (0x0066, 0x0069, 0x006C, 0x0065, 0x002E, 0xFF25, 0xFF38, 0xFF25),  # filename_disguise/fullwidth-ext-hazard
    (0x0066, 0x0069, 0x006C, 0x0065, 0x002E, 0x0065, 0x0301, 0x0078, 0x0065),  # filename_disguise/combining-in-ext-hazard
    (0x0073, 0x0065, 0x0074, 0x0075, 0x0070, 0x002E, 0x0074, 0x0061, 0x0072, 0x002E, 0x0067, 0x007A, 0x002E, 0x0073, 0x0069, 0x0067),  # filename_disguise/triple-extension-hazard
    (0x004E, 0x0065, 0x0074, 0x0068, 0x0065, 0x0072, 0x0435, 0x0075, 0x006D),  # homoglyph_confusable/nethereum-cyrillic-e-target
    (0x0430, 0x0070, 0x0070, 0x006C, 0x0065),  # homoglyph_confusable/apple-cyrillic-a-target
    (0x00E9, 0x0074, 0x0068, 0x0065, 0x0072, 0x0065, 0x0075, 0x006D),  # homoglyph_confusable/ethereum-precomposed-accent-target
    (0x1D400, 0x1D429, 0x1D429, 0x1D425, 0x1D41E),  # homoglyph_confusable/math-bold-apple-target-priority
    (0xFF30, 0xFF41, 0xFF59, 0xFF50, 0xFF41, 0xFF4C),  # homoglyph_confusable/fullwidth-paypal-target-priority
    (0x0065, 0x0078, 0x0070, 0x0072, 0x0065, 0x00DF),  # homoglyph_confusable/express-sharp-s-full-casefold-target
    (0x0065, 0x0078, 0x0070, 0x0072, 0x0065, 0x03B2),  # homoglyph_confusable/express-beta-confusable-full-casefold-target
    (0x0065, 0x0301),  # homoglyph_confusable/decomposed-e-acute
    (0x1D400,),  # homoglyph_confusable/math-bold-a
    (0xFF21,),  # homoglyph_confusable/fullwidth-a
    (0x0061, 0x0062, 0x0561, 0x0562),  # homoglyph_confusable/latin-armenian-cross-script-mix
    (0xE000,),  # homoglyph_confusable/private-use-restriction-low
    (0xFDD0,),  # homoglyph_confusable/noncharacter-restriction-low
    (0x0061, 0x0064, 0x006D, 0x0131, 0x006E),  # homoglyph_confusable/dotless-i-admin-ascii-confusable
    (0x1D44E,),  # identifier_form_drift/math-italic-a-shift
    (0xFF21,),  # identifier_form_drift/fullwidth-A-shift
    (0x24B6,),  # identifier_form_drift/circled-A-shift
    (0xFB01,),  # identifier_form_drift/fi-ligature-shift
    (0x2163,),  # identifier_form_drift/roman-iv-shift
    (0x0061, 0x0062, 0x03B1, 0x03B2),  # mixed_script_admissibility/latin-greek-script-mix
    (0x004E, 0x0065, 0x0074, 0x0068, 0x0065, 0x0072, 0x0435, 0x0075, 0x006D),  # mixed_script_admissibility/latin-cyrillic-target-match-also-mixed
    (0x0061, 0x0062, 0x0561, 0x0562),  # mixed_script_admissibility/latin-armenian-script-mix-other
    (0x0061, 0x0062, 0x0E01, 0x0E02),  # mixed_script_admissibility/latin-thai-script-mix-other
    (0xFDD0,),  # noncharacter_control/bmp-noncharacter
    (0x10FFFF,),  # noncharacter_control/plane-end-noncharacter
    (0x0041, 0x0000, 0x0042),  # noncharacter_control/c0-control
    (0x0041, 0x0080, 0x0042),  # noncharacter_control/c1-control
    (0x1F600, 0xFE0F),  # renderer_divergence/variation-selector-variance
    (0x1F468, 0x200D, 0x1F469),  # renderer_divergence/unregistered-zwj-variance
    (0x0061, 0x0301, 0x0302, 0x0303, 0x0304),  # renderer_divergence/combining-stack-overflow-zalgo
    (0xFF21,),  # renderer_divergence/fullwidth-variance
    (0x0041, 0x0042, 0x05D0, 0x05D1),  # renderer_divergence/mixed-direction-variance
    (0x0041, 0x202E, 0x0042),  # rtl_injection/rlo-in-ltr
    (0x0041, 0x202B, 0x0042, 0x0043, 0x202C),  # rtl_injection/rle-in-ltr
    (0x0041, 0x2066, 0x0042, 0x2069),  # rtl_injection/lri-in-ltr
    (0x05D0, 0x0042, 0x0043),  # rtl_injection/field-takeover-hebrew
    (0x0627, 0x0042, 0x0043),  # rtl_injection/field-takeover-arabic
    (0x0041, 0x0042, 0x05D0, 0x0044),  # rtl_injection/mid-stream-hebrew
    (0x0041, 0x0042, 0x05D0, 0x05D1, 0x05D2, 0x05D3, 0x0044),  # rtl_injection/overflow-hebrew
    (0xE0041, 0xE0042),  # source_display_divergence/tag-block-passthrough
    (0x0041, 0xFE0F),  # source_display_divergence/variation-selector-passthrough
    (0x0048, 0x200B, 0x0069),  # source_display_divergence/zero-width-passthrough
    (0x202E, 0x0041),  # source_display_divergence/bidi-control-passthrough
    (0x2066, 0x0041, 0x2069),  # source_display_divergence/bidi-control-balanced-passthrough
    (0x004E, 0x0065, 0x0074, 0x0068, 0x0065, 0x0072, 0x0435, 0x0075, 0x006D),  # source_display_divergence/identifier-homoglyph-passthrough
    (0x0041, 0xFE0F, 0x200B),  # source_display_divergence/compound-vs-plus-zero-width
    (0xE0041, 0xE0042, 0x200B),  # source_display_divergence/compound-tag-plus-zero-width
    (0x00C0, 0x0080),  # surrogate_reassembly/invalid-start-byte
    (0x00E0, 0x0080, 0x00AF),  # surrogate_reassembly/overlong
    (0x00ED, 0x00A0, 0x0080),  # surrogate_reassembly/cesu8-surrogate
    (0x00C3,),  # surrogate_reassembly/truncated
    (0xE0041, 0xE0042),  # tag_block_payload/tag-ascii-payload
    (0xE0001, 0xE0041),  # tag_block_payload/language-tag-revival
    (0x0048, 0xE0041),  # tag_block_payload/tag-mixed-block
    (0xE007F,),  # tag_block_payload/bare-tag-present
    (0x0041, 0xFE0F),  # variation_selector_payload/vs16-on-latin-illegal-target
    (0x4E00, 0xFE04, 0xFE01),  # variation_selector_payload/pair-aligned-direct-payload
    (0x0061, 0x200B, 0x0062),  # zero_width_payload/bare-zero-width
    (0x0061, 0x200C, 0x0062),  # zero_width_payload/latin-bare-zwnj
    (0x200C, 0x0061),  # zero_width_payload/zwnj-head-position
    # Rungs the detector fixtures leave thin or unreached, each seed verified
    # against the reference to fire the named rung.
    (0x00F4, 0x0090, 0x0080, 0x0080),  # surrogate_reassembly/CodepointBeyondMax
    (0x0061, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301, 0x0301),  # stream_safe_violation/StreamSafeOverrun
    (0xFDFB, 0xFDFB, 0xFDFB, 0xFDFB, 0xFDFB, 0xFDFB, 0xFDFB, 0xFDFB, 0xFDFB, 0xFDFB, 0xFDFB, 0xFDFB, 0xFDFB, 0xFDFB, 0xFDFB, 0xFDFB),  # normalization_bomb/NfkdHighExpansion (ratio 4.5 with 16 pad)
    (0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82, 0x1F82),  # normalization_bomb/NfdHighExpansion (ratio 3.25 with 8 pad)
    (0xFDFA,),  # normalization_bomb/SingleCpBlowup
    (0x1F600, 0xFE0E),  # skin_tone_variation_forgery/ForcedTextStyle
    (0x1F3FB, 0x1F3FB),  # skin_tone_variation_forgery/InvalidSkinToneTarget
    (0x004A, 0x0300),  # locale_case_inversion/LithuanianCaseDivergence
    (0x4E00, 0xFE00, 0xFE00, 0xFE00, 0xFE00),  # variation_selector_payload/RepeatedBase
    (0x0061, 0x2060, 0x0062),  # zero_width_payload/WordJoinerInjection
    (0x0061, 0x202F, 0x0062, 0x202F),  # zero_width_payload/AiWatermarkNNBSP
    (0x0061, 0xFFF9, 0x0062, 0xFFFB),  # zero_width_payload/AnnotationMisuse
    (0x0061, 0x200B, 0x0062, 0x200B),  # zero_width_payload/BinaryPayload
    (0x1F600, 0xFE0F, 0x0041, 0xFE00),  # variation_selector_payload/EmbeddedAfterRegistered
)
# Byte-like inputs (every codepoint below 0x100) that the surrogate-reassembly
# detector reads as a byte stream, so a seed padded with ASCII stays in that
# regime and the malformed-byte rungs are reached in context.
SEED_PAD_POOL_COUNT = 5

MASK64 = (1 << 64) - 1


class Xorshift:
    """xorshift64 with the constants used by the Rust runner."""

    def __init__(self, seed: int = SEED) -> None:
        self.state = seed

    def next_u64(self) -> int:
        x = self.state
        x ^= (x << 13) & MASK64
        x ^= x >> 7
        x ^= (x << 17) & MASK64
        self.state = x
        return x


def ascii_alnum(rng: Xorshift) -> int:
    r = rng.next_u64() % 62
    if r < 26:
        return 0x61 + r
    if r < 52:
        return 0x41 + (r - 26)
    return 0x30 + (r - 52)


def ascii_lower(rng: Xorshift) -> int:
    return 0x61 + rng.next_u64() % 26


def hebrew_letter(rng: Xorshift) -> int:
    return 0x05D0 + rng.next_u64() % HEBREW_LETTER_COUNT


def arabic_letter(rng: Xorshift) -> int:
    return 0x0627 + rng.next_u64() % ARABIC_LETTER_COUNT


def pick(rng: Xorshift, pool: tuple[int, ...]) -> int:
    return pool[rng.next_u64() % len(pool)]


def pad_codepoint(rng: Xorshift, pool: int) -> int:
    """One codepoint of seed context from pool 0-4: ASCII lower, ASCII
    alphanumeric, Hebrew, Latin-Cyrillic look-alike, code syntax or space."""
    if pool == 0:
        return ascii_lower(rng)
    if pool == 1:
        return ascii_alnum(rng)
    if pool == 2:
        return hebrew_letter(rng)
    if pool == 3:
        return pick(rng, LATIN_CYRILLIC_LOOKALIKES)
    return pick(rng, CODE_SYNTAX_OR_SPACE)


def seeded_input(rng: Xorshift) -> list[int]:
    """A detector-fixture seed at a random offset inside random context, with a
    second seed appended one time in three so compounds and rung priorities are
    decided against each other. Truncated to MAX_LEN; a seed longer than the
    room left is placed alone."""
    seed = list(pick_seed(rng))
    if len(seed) >= MAX_LEN:
        return seed[:MAX_LEN]
    # One seeded input in four is the bare seed: the whole-span rungs (a
    # tag-only input, a byte-stream shape) fire only without context.
    bare = rng.next_u64() % 4 == 0
    pad_total = 0 if bare else rng.next_u64() % (MAX_LEN - len(seed) + 1)
    prefix_len = rng.next_u64() % (pad_total + 1)
    pool = rng.next_u64() % SEED_PAD_POOL_COUNT
    out: list[int] = []
    for _index in range(prefix_len):
        out.append(pad_codepoint(rng, pool))
    out.extend(seed)
    for _index in range(pad_total - prefix_len):
        out.append(pad_codepoint(rng, pool))
    if rng.next_u64() % 3 == 0:
        second = list(pick_seed(rng))
        out.extend(second)
    return out[:MAX_LEN]


def pick_seed(rng: Xorshift) -> tuple[int, ...]:
    return SEEDS[rng.next_u64() % len(SEEDS)]


def gen_input(rng: Xorshift) -> list[int]:
    """One corpus input, drawn from the shared class mix.

    Classes 0-9 are the ones the Rust runner established; 10-13 are the
    security-shaped classes described in the module docstring; 14-19 wrap a
    detector-fixture seed in random context (`seeded_input`). The draw order
    is the contract with `ports/rust/tests/diff_runner.rs`.
    """
    length = rng.next_u64() % (MAX_LEN + 1)
    cls = rng.next_u64() % INPUT_CLASS_COUNT
    if cls >= 14:
        return seeded_input(rng)
    out: list[int] = []
    while len(out) < length:
        if cls <= 3:
            cp = ascii_alnum(rng)
        elif cls <= 5:
            cp = LATIN_CYRILLIC_LOOKALIKES[rng.next_u64() % len(LATIN_CYRILLIC_LOOKALIKES)]
        elif cls == 6:
            if rng.next_u64() % 2 == 0:
                cp = 0x1D400 + (rng.next_u64() % 0x400)
            else:
                cp = 0xFF21 + (rng.next_u64() % 0x5A)
        elif cls == 7:
            mark = COMBINING_OR_LATIN[rng.next_u64() % len(COMBINING_OR_LATIN)]
            cp = 0x0061 + (rng.next_u64() % 26) if mark == 0x0061 else mark
        elif cls == 8:
            cp = DEFAULT_IGNORABLE_OR_SPACE[rng.next_u64() % len(DEFAULT_IGNORABLE_OR_SPACE)]
        elif cls == 9:
            # The Rust runner truncates the draw to u32 before the modulus
            # (`rng.next_u64() as u32 % 0x110000`); the same order here keeps
            # the two streams equal.
            r = (rng.next_u64() & 0xFFFFFFFF) % 0x110000
            cp = r + 0x800 if 0xD800 <= r <= 0xDFFF else r
        elif cls == 10:
            # Bidi purpose: controls beside RTL letters, Latin and code syntax.
            r = rng.next_u64() % 8
            if r < 2:
                cp = pick(rng, BIDI_CONTROLS)
            elif r < 4:
                cp = hebrew_letter(rng)
            elif r == 4:
                cp = arabic_letter(rng)
            elif r < 7:
                cp = ascii_lower(rng)
            else:
                cp = pick(rng, CODE_SYNTAX_OR_SPACE)
        elif cls == 11:
            # Latin identifier tokens carrying an ascii-confusable letter.
            r = rng.next_u64() % 6
            if r < 4:
                cp = ascii_lower(rng)
            elif r == 4:
                cp = pick(rng, ASCII_CONFUSABLE_LATIN)
            else:
                cp = pick(rng, TOKEN_SEPARATORS)
        elif cls == 12:
            # Running text whose tokens mix Latin, Cyrillic and Greek.
            r = rng.next_u64() % 5
            if r < 2:
                cp = ascii_lower(rng)
            elif r == 2:
                cp = pick(rng, LATIN_CYRILLIC_LOOKALIKES)
            elif r == 3:
                cp = pick(rng, GREEK_LOOKALIKES)
            else:
                cp = pick(rng, TOKEN_SEPARATORS)
        else:
            # Grab-bag: every position draws its pool afresh.
            r = rng.next_u64() % 6
            if r == 0:
                cp = ascii_alnum(rng)
            elif r == 1:
                cp = pick(rng, BIDI_CONTROLS)
            elif r == 2:
                cp = hebrew_letter(rng)
            elif r == 3:
                cp = pick(rng, ASCII_CONFUSABLE_LATIN)
            elif r == 4:
                cp = pick(rng, LATIN_CYRILLIC_LOOKALIKES)
            else:
                cp = pick(rng, CODE_SYNTAX_OR_SPACE)
        out.append(cp)
    return out


def serialize_document(document: dict) -> str:
    """Compact JSON: one line per case would still be sixteen vendored copies."""
    return json.dumps(document, separators=(",", ":"), ensure_ascii=True) + "\n"


def reference_verdicts(
    binary: Path, cases: list[tuple[str, str, list[int]]]
) -> list[dict]:
    """Run every case through the reference in one batch.

    The CLI's `--jsonl` mode takes one profile and mode for the whole batch, so
    the cases are grouped by profile and each group is one invocation. That is
    ten subprocesses for the whole corpus rather than one per case.
    """
    verdicts: dict[str, dict] = {}
    for profile in PROFILES:
        group = [
            (name, cps) for name, case_profile, cps in cases if case_profile == profile
        ]
        if not group:
            continue
        records = "".join(
            json.dumps({"id": name, "text": "".join(chr(cp) for cp in cps)}) + "\n"
            for name, cps in group
        )
        completed = subprocess.run(
            [str(binary), "scan", "--jsonl", "--profile", profile, "--mode", "enforce"],
            input=records.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        emitted = [line for line in completed.stdout.decode().splitlines() if line.strip()]
        if len(emitted) != len(group):
            raise SystemExit(
                f"reference emitted {len(emitted)} verdicts for {len(group)} "
                f"{profile} cases: {completed.stderr.decode(errors='replace').strip()}"
            )
        for line in emitted:
            record = json.loads(line)
            name = record.pop("id")
            record["findings"] = [
                {field: finding[field] for field in FINDING_FIELDS}
                for finding in record["findings"]
            ]
            verdicts[name] = record
    return [verdicts[name] for name, _profile, _cps in cases]


def build_document(binary: Path, count: int) -> dict:
    rng = Xorshift()
    cases: list[tuple[str, str, list[int]]] = []
    for index in range(count):
        cps = gen_input(rng)
        profile = PROFILES[index % len(PROFILES)]
        cases.append((f"diff-{index:05d}", profile, cps))
    verdicts = reference_verdicts(binary, cases)
    return {
        # Same schema and contract name as verdict_contract.json, so a port
        # validates this file with the loop it already runs over that one.
        "schema": 1,
        "contract": "unicode-security-verdict-v0",
        "cases": [
            {
                "name": name,
                "profile": profile,
                "mode": "enforce",
                "input": cps,
                "verdict": verdict,
            }
            for (name, profile, cps), verdict in zip(cases, verdicts)
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=DEFAULT_BIN)
    parser.add_argument("--count", type=int, default=5000)
    parser.add_argument(
        "--check",
        action="store_true",
        help="report whether the committed fixture matches a fresh generation",
    )
    parser.add_argument("--sync-ports", action="store_true")
    args = parser.parse_args()

    if not args.binary.exists():
        print(f"reference CLI not found: {args.binary}", file=sys.stderr)
        print("build it with: cd ports/rust && cargo build", file=sys.stderr)
        return 2

    if args.check:
        if not FIXTURE.exists():
            print(f"missing {FIXTURE.relative_to(ROOT)}", file=sys.stderr)
            return 1
        committed_text = FIXTURE.read_text()
        # Regenerate at the committed corpus's own size rather than at --count.
        # The stream is seeded, so a run of N cases is a prefix of a run of more,
        # and comparing a longer fresh run against the committed file reports a
        # difference that is only the length. Taking the count from the file
        # makes this a true statement about the reference: the committed
        # verdicts are what the reference produces today.
        committed_count = len(json.loads(committed_text)["cases"])
        fresh = serialize_document(build_document(args.binary, committed_count))
        if committed_text == fresh:
            print(f"clean: {committed_count} corpus cases match the reference")
            return 0
        print(
            f"{FIXTURE.relative_to(ROOT)} differs from a fresh generation "
            f"at its own {committed_count} cases",
            file=sys.stderr,
        )
        return 1

    document = build_document(args.binary, args.count)
    serialized = serialize_document(document)

    FIXTURE.write_text(serialized)
    print(f"wrote {FIXTURE.relative_to(ROOT)} ({len(document['cases'])} cases)")
    if args.sync_ports:
        print(f"synced {sync_fixture(FIXTURE)} vendored copies")
    return 0


if __name__ == "__main__":
    sys.exit(main())
