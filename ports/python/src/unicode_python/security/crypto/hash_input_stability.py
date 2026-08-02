"""hash-input-stability detector — inputs that are not in canonical hash-input
form.

Direct port of ``Unicode.Security.Crypto.HashInputStability`` (and a faithful
transliteration of the verified Rust reference
``ports/rust/src/security/crypto/hash_input_stability.rs``). Per UTS #39 §6.1 +
RFC 4880 / 9580 + RFC 8785, an input hashed by a signer must be byte-identical
to the input hashed by the verifier; if the two ends pick different canonical
forms (NFC vs NFD, trim policy, line-ending convention) the resulting hashes
diverge silently while both sides believe they signed the same content.

The canonical (hash-stable) form is ``trim_trailing(to_nfc(input))``, where
``trim_trailing`` strips only ASCII whitespace {U+0020, U+0009, U+000A,
U+000D}; Unicode whitespace (U+00A0, U+2000..U+200A, U+3000) is content and is
not stripped. NFC is the port's :func:`to_nfc`, never a host normalizer.

Six probes run in strict priority order (first hit wins):

    1. ``encodingMismatch``         (context: ``declared_encoding``)
    2. ``webhookSignatureDrift``    (context: ``server_bytes``)
    3. ``auditLogReinterpretation`` (context: ``as_written``)
    4. ``signedMessageRule``        (context: ``rfc_rule``)
    5. ``trailingWhitespace``       (bare input)
    6. ``normalizationDrift``       (bare input)
    7. clear

Context-specific probes fire first because they carry more precise threat
information than the generic probes. :func:`detect` is the convenience wrapper
``detect_with_context(Context(), input)`` that leaves the four context-bearing
probes silent.
"""

from dataclasses import dataclass, field
from enum import Enum

from ..identity.ucd import to_nfc

# ─────────────────────────────────────────────────────────────────────
# §1 Types
# ─────────────────────────────────────────────────────────────────────


class RfcRule(Enum):
    """RFC canonicalisation profiles that the ``signedMessageRule`` probe checks
    against. Each variant names a specific canonicalisation rule from a
    published RFC; callers pass one as ``Context.rfc_rule`` to opt the probe
    in. The ``value`` is the fixture-string identifier used to round-trip rule
    selections."""

    # RFC 4880 §5.2.4 — detached signatures normalise trailing whitespace;
    # trailing whitespace in the body causes signature mismatch.
    PGP_4880_TRAILING_WHITESPACE = "pgp4880TrailingWhitespace"
    # RFC 9580 (current OpenPGP) — line-endings normalise to CRLF before
    # signing; a bare LF or bare CR violates the canonicalisation rule.
    PGP_9580_LINE_ENDING = "pgp9580LineEnding"
    # RFC 8785 §3.2.5 — JSON Canonicalization Scheme requires strings to be in
    # NFC before serialisation.
    RFC_8785_NFC_REQUIREMENT = "rfc8785NfcRequirement"
    # RFC 8259 §7 — JSON strings must escape control characters
    # (U+0000..U+001F); unescaped control bytes in a string violate.
    RFC_8259_CONTROL_CHAR = "rfc8259ControlChar"
    # RFC 7515 §2 — JWS Base64URL encoding; any character outside
    # [A-Za-z0-9_-] is a canonicalisation violation.
    RFC_7515_JWS_BASE64_URL = "rfc7515JwsBase64Url"
    # RFC 6376 §3.4.4 — DKIM relaxed body canonicalization collapses internal
    # whitespace runs to a single SP; a multi-char internal whitespace run
    # indicates the canonicalisation has not been applied.
    RFC_6376_DKIM_RELAXED = "rfc6376DkimRelaxed"
    # RFC 5751 §3.1.1 — S/MIME canonical text; like PGP 9580, a bare LF or
    # bare CR (not part of a CRLF pair) violates.
    RFC_5751_SMIME_LINE_ENDING = "rfc5751SmimeLineEnding"

    def tag(self) -> str:
        """Fixture-string identifier for this rule — used by the conformance
        harness's attribution parser to round-trip rule selections."""
        return self.value

    @staticmethod
    def from_tag(tag: str) -> "RfcRule | None":
        """Inverse of :meth:`tag`. Returns ``None`` for unrecognised strings."""
        for rule in RfcRule:
            if rule.value == tag:
                return rule
        return None


@dataclass(frozen=True, slots=True)
class Context:
    """Context passed to :func:`detect_with_context` to enable the four
    context-bearing probes. Each field is ``None`` by default — the empty
    context is the identity case: ``detect_with_context(Context(), input)``
    equals ``detect(input)``."""

    # The encoding label the caller claims their input is in. When set and not
    # (case-insensitively) UTF-8, fires ``encodingMismatch`` immediately.
    declared_encoding: str | None = None
    # The RFC canonicalisation rule the caller is operating under. When set,
    # scans ``input`` for violations and fires ``signedMessageRule``.
    rfc_rule: RfcRule | None = None
    # The original "as-written" form of an audit-log entry whose re-read is
    # ``input``. When set, fires ``auditLogReinterpretation`` on first
    # divergence.
    as_written: list[int] | None = None
    # The server-side recomputed bytes for a webhook signature. When set, fires
    # ``webhookSignatureDrift`` on first divergence against ``input``.
    server_bytes: list[int] | None = None


class SubThreatTag(Enum):
    """Sub-threats this detector can fire. Two probes fire from the raw input
    alone (``TrailingWhitespace``, ``NormalizationDrift``); the other four
    require the corresponding :class:`Context` field to be set."""

    NORMALIZATION_DRIFT = "NormalizationDrift"
    TRAILING_WHITESPACE = "TrailingWhitespace"
    ENCODING_MISMATCH = "EncodingMismatch"
    SIGNED_MESSAGE_RULE = "SignedMessageRule"
    AUDIT_LOG_REINTERPRETATION = "AuditLogReinterpretation"
    WEBHOOK_SIGNATURE_DRIFT = "WebhookSignatureDrift"


@dataclass(frozen=True, slots=True)
class SubThreat:
    """A fired sub-threat together with the fields the Lean/Rust variant
    carries. ``tag`` selects the variant; the remaining fields carry that
    variant's payload (``None`` when not applicable to the variant)."""

    tag: SubThreatTag
    # NormalizationDrift.first_divergent_pos / AuditLogReinterpretation.
    first_divergent_pos: int | None = None
    # TrailingWhitespace.count.
    count: int | None = None
    # EncodingMismatch.declared_enc.
    declared_enc: str | None = None
    # EncodingMismatch.detected_enc.
    detected_enc: str | None = None
    # SignedMessageRule.rfc_rule (fixture tag of the violated rule).
    rfc_rule: str | None = None
    # SignedMessageRule.first_pos / WebhookSignatureDrift.first_pos.
    first_pos: int | None = None


@dataclass(frozen=True, slots=True)
class Classification:
    """Top-level classification. ``is_clear`` distinguishes the ``Clear``
    variant from the ``Hazard`` variant; a hazard carries its sub-threat and
    the codepoint positions it implicates."""

    is_clear: bool
    sub: SubThreat | None = None
    positions: list[int] = field(default_factory=list)

    @property
    def tag(self) -> str | None:
        """Human-facing tag for a hazard, or ``None`` when clear."""
        if self.is_clear or self.sub is None:
            return None
        return self.sub.tag.value


@dataclass(frozen=True, slots=True)
class Verdict:
    """The structured output of :func:`detect`. ``stable_size`` is the
    codepoint count of the hash-stable canonical form; downstream callers
    compare it against ``len(input)`` to size the byte-drift their hash sees."""

    input: list[int]
    classify: Classification
    stable_form: list[int]
    stable_size: int


# ─────────────────────────────────────────────────────────────────────
# §3 Canonicalisation pipeline
# ─────────────────────────────────────────────────────────────────────


def is_ascii_whitespace(cp: int) -> bool:
    """True iff ``cp`` is an ASCII whitespace codepoint that line-oriented
    hash-input protocols treat as framing rather than content: U+0020 SPACE,
    U+0009 TAB, U+000A LF, U+000D CR."""
    return cp == 0x0020 or cp == 0x0009 or cp == 0x000A or cp == 0x000D


def count_trailing_whitespace(input_cps: list[int]) -> int:
    """Count of trailing ASCII whitespace codepoints in ``input``."""
    count = 0
    for cp in reversed(input_cps):
        if is_ascii_whitespace(cp):
            count += 1
        else:
            break
    return count


def trim_trailing(input_cps: list[int]) -> list[int]:
    """Strip trailing ASCII whitespace."""
    keep = len(input_cps) - count_trailing_whitespace(input_cps)
    return input_cps[:keep]


def hash_stable(input_cps: list[int]) -> list[int]:
    """The hash-stable form of an input: NFC then trim, in spec order."""
    return trim_trailing(to_nfc(input_cps))


# ─────────────────────────────────────────────────────────────────────
# §5 Priority position-finder
# ─────────────────────────────────────────────────────────────────────


def first_array_divergence(a: list[int], b: list[int]) -> int | None:
    """First position at which ``a`` and ``b`` diverge, or the length of the
    shared prefix when one strictly extends the other. ``None`` when
    identical."""
    common = min(len(a), len(b))
    for i in range(common):
        if a[i] != b[i]:
            return i
    if len(a) != len(b):
        return common
    return None


# ─────────────────────────────────────────────────────────────────────
# §6 Context-bearing probes
# ─────────────────────────────────────────────────────────────────────


def ascii_lower(cp: int) -> int:
    """Lower-case an ASCII letter (U+0041..U+005A → U+0061..U+007A)."""
    if 0x41 <= cp <= 0x5A:
        return cp + 0x20
    return cp


def is_utf8_label(label: str) -> bool:
    """True iff ``label`` (after ASCII case-fold) names UTF-8: accepts "utf-8",
    "UTF-8", "UTF8", "utf8". Non-ASCII characters pass through unchanged."""
    normalised = "".join(chr(ascii_lower(ord(c))) for c in label)
    return normalised == "utf-8" or normalised == "utf8"


def is_valid_scalar(cp: int) -> bool:
    """True iff ``cp`` is a valid Unicode scalar value: in [0, 0x10FFFF] and
    not a surrogate [0xD800, 0xDFFF]."""
    return 0 <= cp <= 0x10FFFF and not (0xD800 <= cp <= 0xDFFF)


def first_invalid_scalar(input_cps: list[int]) -> int | None:
    """First position in ``input`` holding a codepoint that is not a valid
    Unicode scalar, or ``None`` if every codepoint is valid."""
    for index, cp in enumerate(input_cps):
        if not is_valid_scalar(cp):
            return index
    return None


def encoding_mismatch_probe(
    declared: str, input_cps: list[int]
) -> tuple[str, str, int] | None:
    """Probe: ``encodingMismatch``. Validity is dispatched first — an invalid
    scalar fires with ``detected_enc = "invalid"`` regardless of the declared
    label; otherwise a non-UTF-8 label fires with ``detected_enc = "utf-8"`` at
    position 0. Returns ``(declared, detected, first_pos)`` when firing."""
    pos = first_invalid_scalar(input_cps)
    if pos is not None:
        return (declared, "invalid", pos)
    if is_utf8_label(declared):
        return None
    return (declared, "utf-8", 0)


def pgp4880_violation(input_cps: list[int]) -> int | None:
    """Probe: ``signedMessageRule`` for ``pgp4880TrailingWhitespace``. Same
    condition as ``trailingWhitespace``; returns the first position of the
    trailing run."""
    trailing = count_trailing_whitespace(input_cps)
    if trailing > 0:
        return len(input_cps) - trailing
    return None


def pgp9580_violation(input_cps: list[int]) -> int | None:
    """Probe: ``signedMessageRule`` for ``pgp9580LineEnding``. First bare LF
    (U+000A not preceded by CR) or bare CR (U+000D not followed by LF)."""
    for i, cp in enumerate(input_cps):
        if cp == 0x000A:
            # LF: violating iff not preceded by CR.
            preceded_by_cr = i > 0 and input_cps[i - 1] == 0x000D
            if not preceded_by_cr:
                return i
        elif cp == 0x000D:
            # CR: violating iff not followed by LF.
            followed_by_lf = i + 1 < len(input_cps) and input_cps[i + 1] == 0x000A
            if not followed_by_lf:
                return i
    return None


def rfc8785_violation(input_cps: list[int]) -> int | None:
    """Probe: ``signedMessageRule`` for ``rfc8785NfcRequirement``. Same
    condition as ``normalizationDrift``; returns the first NFC divergence
    position."""
    nfc = to_nfc(input_cps)
    if input_cps == nfc:
        return None
    return first_array_divergence(input_cps, nfc)


def rfc8259_violation(input_cps: list[int]) -> int | None:
    """Probe: ``signedMessageRule`` for ``rfc8259ControlChar``. First C0 control
    (U+0000..U+001F) — the JSON-permitted whitespace still requires escaping,
    so it also counts."""
    for index, cp in enumerate(input_cps):
        if cp <= 0x1F:
            return index
    return None


def is_base64_url(cp: int) -> bool:
    """True iff ``cp`` is in the JWS Base64URL alphabet [A-Za-z0-9_-]."""
    return (
        (0x41 <= cp <= 0x5A)  # A-Z
        or (0x61 <= cp <= 0x7A)  # a-z
        or (0x30 <= cp <= 0x39)  # 0-9
        or cp == 0x2D  # '-'
        or cp == 0x5F  # LOW LINE
    )


def rfc7515_violation(input_cps: list[int]) -> int | None:
    """Probe: ``signedMessageRule`` for ``rfc7515JwsBase64Url``. First codepoint
    outside [A-Za-z0-9_-]."""
    for index, cp in enumerate(input_cps):
        if not is_base64_url(cp):
            return index
    return None


def is_dkim_whitespace(cp: int) -> bool:
    """True iff ``cp`` is DKIM whitespace: U+0020 SPACE or U+0009 HTAB."""
    return cp == 0x20 or cp == 0x09


def rfc6376_violation(input_cps: list[int]) -> int | None:
    """Probe: ``signedMessageRule`` for ``rfc6376DkimRelaxed``. Position of the
    second whitespace codepoint in the first internal whitespace run longer
    than one."""
    for i, cp in enumerate(input_cps):
        if is_dkim_whitespace(cp) and i > 0 and is_dkim_whitespace(input_cps[i - 1]):
            return i
    return None


def rfc5751_violation(input_cps: list[int]) -> int | None:
    """Probe: ``signedMessageRule`` for ``rfc5751SmimeLineEnding``. Reuses the
    PGP 9580 bare-line-ending rule."""
    return pgp9580_violation(input_cps)


def rfc_rule_violation(rule: RfcRule, input_cps: list[int]) -> int | None:
    """Dispatch the RFC-rule probe. First violation position, or ``None`` if
    clean."""
    if rule is RfcRule.PGP_4880_TRAILING_WHITESPACE:
        return pgp4880_violation(input_cps)
    if rule is RfcRule.PGP_9580_LINE_ENDING:
        return pgp9580_violation(input_cps)
    if rule is RfcRule.RFC_8785_NFC_REQUIREMENT:
        return rfc8785_violation(input_cps)
    if rule is RfcRule.RFC_8259_CONTROL_CHAR:
        return rfc8259_violation(input_cps)
    if rule is RfcRule.RFC_7515_JWS_BASE64_URL:
        return rfc7515_violation(input_cps)
    if rule is RfcRule.RFC_6376_DKIM_RELAXED:
        return rfc6376_violation(input_cps)
    return rfc5751_violation(input_cps)


# ─────────────────────────────────────────────────────────────────────
# §7 Top-level detection
# ─────────────────────────────────────────────────────────────────────


def classify(
    encoding_hit: tuple[str, str, int] | None,
    webhook_hit: int | None,
    audit_hit: int | None,
    rfc_hit: tuple[RfcRule, int] | None,
    trailing_count: int,
    input_len: int,
    non_nfc_pos: int | None,
) -> Classification:
    """The priority resolver: first hit wins, in the spec's fixed order."""
    if encoding_hit is not None:
        declared, detected, pos = encoding_hit
        return Classification(
            is_clear=False,
            sub=SubThreat(
                tag=SubThreatTag.ENCODING_MISMATCH,
                declared_enc=declared,
                detected_enc=detected,
            ),
            positions=[pos],
        )
    if webhook_hit is not None:
        return Classification(
            is_clear=False,
            sub=SubThreat(
                tag=SubThreatTag.WEBHOOK_SIGNATURE_DRIFT, first_pos=webhook_hit
            ),
            positions=[webhook_hit],
        )
    if audit_hit is not None:
        return Classification(
            is_clear=False,
            sub=SubThreat(
                tag=SubThreatTag.AUDIT_LOG_REINTERPRETATION,
                first_divergent_pos=audit_hit,
            ),
            positions=[audit_hit],
        )
    if rfc_hit is not None:
        rule, pos = rfc_hit
        return Classification(
            is_clear=False,
            sub=SubThreat(
                tag=SubThreatTag.SIGNED_MESSAGE_RULE,
                rfc_rule=rule.tag(),
                first_pos=pos,
            ),
            positions=[pos],
        )
    if trailing_count > 0:
        p = input_len - trailing_count
        return Classification(
            is_clear=False,
            sub=SubThreat(tag=SubThreatTag.TRAILING_WHITESPACE, count=trailing_count),
            positions=[p],
        )
    if non_nfc_pos is not None:
        return Classification(
            is_clear=False,
            sub=SubThreat(
                tag=SubThreatTag.NORMALIZATION_DRIFT, first_divergent_pos=non_nfc_pos
            ),
            positions=[non_nfc_pos],
        )
    return Classification(is_clear=True, sub=None, positions=[])


def detect_with_context(ctx: Context, input_cps: list[int]) -> Verdict:
    """The full detection function. Runs all six probes in priority order, with
    the context-bearing probes ahead of the generic ones."""
    stable = hash_stable(input_cps)

    # Probe 1: encodingMismatch.
    if ctx.declared_encoding is not None:
        encoding_hit = encoding_mismatch_probe(ctx.declared_encoding, input_cps)
    else:
        encoding_hit = None

    # Probe 2: webhookSignatureDrift.
    if ctx.server_bytes is not None:
        webhook_hit = first_array_divergence(input_cps, ctx.server_bytes)
    else:
        webhook_hit = None

    # Probe 3: auditLogReinterpretation.
    if ctx.as_written is not None:
        audit_hit = first_array_divergence(ctx.as_written, input_cps)
    else:
        audit_hit = None

    # Probe 4: signedMessageRule.
    if ctx.rfc_rule is not None:
        pos = rfc_rule_violation(ctx.rfc_rule, input_cps)
        rfc_hit = (ctx.rfc_rule, pos) if pos is not None else None
    else:
        rfc_hit = None

    # Probe 5: trailingWhitespace.
    trailing_count = count_trailing_whitespace(input_cps)

    # Probe 6: normalizationDrift.
    nfc = to_nfc(input_cps)
    non_nfc_pos = None if input_cps == nfc else first_array_divergence(input_cps, nfc)

    classification = classify(
        encoding_hit,
        webhook_hit,
        audit_hit,
        rfc_hit,
        trailing_count,
        len(input_cps),
        non_nfc_pos,
    )

    return Verdict(
        input=list(input_cps),
        classify=classification,
        stable_form=stable,
        stable_size=len(stable),
    )


def detect(input_cps: list[int]) -> Verdict:
    """Convenience wrapper over :func:`detect_with_context` with the empty
    context — equivalent to running only the two bare-input probes
    (``trailingWhitespace``, ``normalizationDrift``)."""
    return detect_with_context(Context(), input_cps)
