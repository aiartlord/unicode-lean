"""Product-facing security policy contract.

This module mirrors ``Unicode.Security.Policy``: named profiles, runtime
modes, stable reason codes, and a ``scan`` verdict over decoded codepoints.
"""

import json
from dataclasses import dataclass, field
from enum import Enum

from ..noncharacters import is_noncharacter
from ..strict import Utf8RejectKind
from ..utf8 import decode_to_codepoints, first_invalid_utf8_offset
from .calculus import ClassificationKind, Family, Severity
from .display import rtl_injection
from .covert import (
    bidi_control_balance,
    tag_block_payload,
    variation_selector_payload,
    zero_width_payload,
)
from .identity import homoglyph_confusable


class Action(Enum):
    """Runtime action recommended for the current payload."""

    ALLOW = "allow"
    REJECT = "reject"
    QUARANTINE = "quarantine"
    REWRITE = "rewrite"
    OBSERVE = "observe"


class Mode(Enum):
    """Operator-selected runtime mode."""

    OBSERVE = "observe"
    WARN = "warn"
    ENFORCE = "enforce"
    STRICT = "strict"


class Profile(Enum):
    """Product context profile."""

    GATEWAY_HEADER = "gateway-header"
    DOMAIN_NAME = "domain-name"
    DNS_LABEL = "dns-label"
    URL = "url"
    USERNAME = "username"
    DISPLAY_NAME = "display-name"
    CHAT_MESSAGE = "chat-message"
    SOURCE_CODE = "source-code"
    OPAQUE_SECRET = "opaque-secret"
    BINARY_BLOB = "binary-blob"


class PolicyLevel(Enum):
    """Policy strictness level."""

    RESTRICTIVE = "restrictive"
    MODERATE = "moderate"
    MINIMAL = "minimal"


class CryptoContext(Enum):
    """Optional crypto-shaped policy context."""

    NON_CRYPTO = "non-crypto"
    BIP39_MNEMONIC = "bip39-mnemonic"
    HASH_INPUT = "hash-input"
    AI_ATTRIBUTION = "ai-attribution"


@dataclass(frozen=True, slots=True)
class ProfilePolicy:
    """Runtime policy derived from a named profile."""

    level: PolicyLevel
    crypto_context: CryptoContext
    quarantine: bool


@dataclass(frozen=True, slots=True)
class Finding:
    """Product-facing finding."""

    code: str
    family: Family
    severity: Severity
    positions: list[int] = field(default_factory=list)
    sub_threat: str | None = None
    detail: str = ""


@dataclass(frozen=True, slots=True)
class Verdict:
    """Runtime verdict returned by ``scan``."""

    input: list[int]
    profile: Profile
    mode: Mode
    action: Action
    findings: list[Finding] = field(default_factory=list)
    normalized: list[int] | None = None


def finding_to_wire(finding: Finding) -> dict[str, object]:
    """Return the stable JSON-compatible finding shape."""
    return {
        "code": finding.code,
        "family": family_slug(finding.family),
        "severity": finding.severity.value,
        "positions": finding.positions,
        "sub_threat": finding.sub_threat,
        "detail": finding.detail,
    }


def verdict_to_wire(verdict: Verdict) -> dict[str, object]:
    """Return the stable JSON-compatible verdict shape."""
    return {
        "action": verdict.action.value,
        "profile": verdict.profile.value,
        "mode": verdict.mode.value,
        "input": verdict.input,
        "findings": [finding_to_wire(finding) for finding in verdict.findings],
        "normalized": verdict.normalized,
    }


def verdict_to_json(verdict: Verdict) -> str:
    """Serialize a verdict to the stable compact JSON verdict shape."""
    return json.dumps(verdict_to_wire(verdict), separators=(",", ":"))


_RESTRICTIVE_REJECTION_SET = (
    Family.MALFORMED_UTF8,
    Family.MALFORMED_UTF16,
    Family.MALFORMED_UTF32,
    Family.TAG_BLOCK_PAYLOAD,
    Family.VARIATION_SELECTOR_PAYLOAD,
    Family.ZERO_WIDTH_PAYLOAD,
    Family.SURROGATE_REASSEMBLY,
    Family.BIDI_CONTROL_BALANCE,
    Family.NONCHARACTER_CONTROL,
    Family.HOMOGLYPH_CONFUSABLE,
    Family.MIXED_SCRIPT_ADMISSIBILITY,
    Family.EMOJI_ZWJ_INTEGRITY,
    Family.SKIN_TONE_VARIATION_FORGERY,
    Family.SOURCE_DISPLAY_DIVERGENCE,
    Family.FILENAME_DISGUISE,
    Family.RTL_INJECTION,
    Family.RENDERER_DIVERGENCE,
    Family.NORMALIZATION_BOMB,
    Family.STREAM_SAFE_VIOLATION,
    Family.LOCALE_CASE_INVERSION,
    Family.CASE_EXPANSION_MISMATCH,
    Family.WIDTH_CLASS_CONFUSION,
    Family.NFC_IDEMPOTENCE_WITNESS,
    Family.IDENTIFIER_FORM_DRIFT,
    Family.COVERT_DISPLAY_COMPOUND,
    Family.CONFUSABLE_BIDI_COMPOUND,
    Family.ADMISSIBILITY_FORM_DRIFT,
)

_MODERATE_REJECTION_SET = (
    Family.MALFORMED_UTF8,
    Family.MALFORMED_UTF16,
    Family.MALFORMED_UTF32,
    Family.TAG_BLOCK_PAYLOAD,
    Family.VARIATION_SELECTOR_PAYLOAD,
    Family.ZERO_WIDTH_PAYLOAD,
    Family.SURROGATE_REASSEMBLY,
    Family.BIDI_CONTROL_BALANCE,
    Family.NONCHARACTER_CONTROL,
    Family.HOMOGLYPH_CONFUSABLE,
    Family.MIXED_SCRIPT_ADMISSIBILITY,
    Family.SKIN_TONE_VARIATION_FORGERY,
    Family.SOURCE_DISPLAY_DIVERGENCE,
    Family.FILENAME_DISGUISE,
    Family.STREAM_SAFE_VIOLATION,
    Family.LOCALE_CASE_INVERSION,
    Family.CASE_EXPANSION_MISMATCH,
    Family.WIDTH_CLASS_CONFUSION,
    Family.NFC_IDEMPOTENCE_WITNESS,
    Family.IDENTIFIER_FORM_DRIFT,
    Family.COVERT_DISPLAY_COMPOUND,
    Family.CONFUSABLE_BIDI_COMPOUND,
    Family.ADMISSIBILITY_FORM_DRIFT,
)

_MINIMAL_REJECTION_SET = (
    Family.MALFORMED_UTF8,
    Family.MALFORMED_UTF16,
    Family.MALFORMED_UTF32,
    Family.SURROGATE_REASSEMBLY,
    Family.BIDI_CONTROL_BALANCE,
    Family.NONCHARACTER_CONTROL,
    Family.STREAM_SAFE_VIOLATION,
)


def _crypto_families(context: CryptoContext) -> tuple[Family, ...]:
    if context is CryptoContext.BIP39_MNEMONIC:
        return (Family.BIP39_CANONICAL,)
    if context is CryptoContext.HASH_INPUT:
        return (Family.HASH_INPUT_STABILITY,)
    if context is CryptoContext.AI_ATTRIBUTION:
        return (Family.AI_WATERMARK_DETECTABILITY,)
    return ()


def rejection_set(level: PolicyLevel) -> tuple[Family, ...]:
    """Families whose findings block at ``level``."""
    if level is PolicyLevel.RESTRICTIVE:
        return _RESTRICTIVE_REJECTION_SET
    if level is PolicyLevel.MODERATE:
        return _MODERATE_REJECTION_SET
    return _MINIMAL_REJECTION_SET


def policy_of_profile(profile: Profile) -> ProfilePolicy:
    """Default policy for a named profile."""
    if profile in {
        Profile.GATEWAY_HEADER,
        Profile.DOMAIN_NAME,
        Profile.DNS_LABEL,
        Profile.SOURCE_CODE,
    }:
        return ProfilePolicy(
            PolicyLevel.RESTRICTIVE, CryptoContext.NON_CRYPTO, False
        )
    if profile is Profile.URL:
        return ProfilePolicy(
            PolicyLevel.MODERATE, CryptoContext.NON_CRYPTO, False
        )
    if profile is Profile.USERNAME:
        return ProfilePolicy(
            PolicyLevel.MODERATE, CryptoContext.NON_CRYPTO, True
        )
    if profile in {Profile.DISPLAY_NAME, Profile.CHAT_MESSAGE}:
        return ProfilePolicy(
            PolicyLevel.MINIMAL, CryptoContext.NON_CRYPTO, True
        )
    if profile is Profile.OPAQUE_SECRET:
        return ProfilePolicy(PolicyLevel.MINIMAL, CryptoContext.HASH_INPUT, False)
    return ProfilePolicy(PolicyLevel.MINIMAL, CryptoContext.NON_CRYPTO, False)


def family_layer_code(family: Family) -> str:
    """Stable reason-code layer letter."""
    if family in {
        Family.MALFORMED_UTF8,
        Family.MALFORMED_UTF16,
        Family.MALFORMED_UTF32,
        Family.TAG_BLOCK_PAYLOAD,
        Family.VARIATION_SELECTOR_PAYLOAD,
        Family.ZERO_WIDTH_PAYLOAD,
        Family.SURROGATE_REASSEMBLY,
        Family.BIDI_CONTROL_BALANCE,
        Family.NONCHARACTER_CONTROL,
    }:
        return "C"
    if family in {
        Family.HOMOGLYPH_CONFUSABLE,
        Family.MIXED_SCRIPT_ADMISSIBILITY,
        Family.EMOJI_ZWJ_INTEGRITY,
        Family.SKIN_TONE_VARIATION_FORGERY,
    }:
        return "I"
    if family in {
        Family.SOURCE_DISPLAY_DIVERGENCE,
        Family.FILENAME_DISGUISE,
        Family.RTL_INJECTION,
        Family.RENDERER_DIVERGENCE,
    }:
        return "D"
    if family in {
        Family.NORMALIZATION_BOMB,
        Family.STREAM_SAFE_VIOLATION,
        Family.LOCALE_CASE_INVERSION,
        Family.CASE_EXPANSION_MISMATCH,
        Family.WIDTH_CLASS_CONFUSION,
        Family.NFC_IDEMPOTENCE_WITNESS,
    }:
        return "F"
    if family in {
        Family.IDENTIFIER_FORM_DRIFT,
        Family.COVERT_DISPLAY_COMPOUND,
        Family.CONFUSABLE_BIDI_COMPOUND,
        Family.ADMISSIBILITY_FORM_DRIFT,
    }:
        return "X"
    return "K"


_FAMILY_SLUGS = {
    Family.MALFORMED_UTF8: "malformed-utf8",
    Family.MALFORMED_UTF16: "malformed-utf16",
    Family.MALFORMED_UTF32: "malformed-utf32",
    Family.TAG_BLOCK_PAYLOAD: "tag-block-payload",
    Family.VARIATION_SELECTOR_PAYLOAD: "variation-selector-payload",
    Family.ZERO_WIDTH_PAYLOAD: "zero-width-payload",
    Family.SURROGATE_REASSEMBLY: "surrogate-reassembly",
    Family.BIDI_CONTROL_BALANCE: "bidi-control-balance",
    Family.NONCHARACTER_CONTROL: "noncharacter-control",
    Family.HOMOGLYPH_CONFUSABLE: "homoglyph-confusable",
    Family.MIXED_SCRIPT_ADMISSIBILITY: "mixed-script-admissibility",
    Family.EMOJI_ZWJ_INTEGRITY: "emoji-zwj-integrity",
    Family.SKIN_TONE_VARIATION_FORGERY: "skin-tone-variation-forgery",
    Family.SOURCE_DISPLAY_DIVERGENCE: "source-display-divergence",
    Family.FILENAME_DISGUISE: "filename-disguise",
    Family.RTL_INJECTION: "rtl-injection",
    Family.RENDERER_DIVERGENCE: "renderer-divergence",
    Family.NORMALIZATION_BOMB: "normalization-bomb",
    Family.STREAM_SAFE_VIOLATION: "stream-safe-violation",
    Family.LOCALE_CASE_INVERSION: "locale-case-inversion",
    Family.CASE_EXPANSION_MISMATCH: "case-expansion-mismatch",
    Family.WIDTH_CLASS_CONFUSION: "width-class-confusion",
    Family.NFC_IDEMPOTENCE_WITNESS: "nfc-idempotence-witness",
    Family.IDENTIFIER_FORM_DRIFT: "identifier-form-drift",
    Family.COVERT_DISPLAY_COMPOUND: "covert-display-compound",
    Family.CONFUSABLE_BIDI_COMPOUND: "confusable-bidi-compound",
    Family.ADMISSIBILITY_FORM_DRIFT: "admissibility-form-drift",
    Family.BIP39_CANONICAL: "bip39-canonical",
    Family.HASH_INPUT_STABILITY: "hash-input-stability",
    Family.AI_WATERMARK_DETECTABILITY: "ai-watermark-detectability",
}


def family_slug(family: Family) -> str:
    """Stable reason-code family slug."""
    return _FAMILY_SLUGS[family]


def reason_base(family: Family) -> str:
    """Stable reason-code base for a detector family."""
    return f"unicode.security.{family_layer_code(family)}.{family_slug(family)}"


def reason_code(family: Family, sub_threat: str | None = None) -> str:
    """Stable reason code for a detector result."""
    if sub_threat is None:
        return f"{reason_base(family)}.hazard"
    return f"{reason_base(family)}.{sub_threat}"


def utf8_reject_tag(kind: Utf8RejectKind) -> str:
    """Stable sub-threat tag for a strict UTF-8 reject kind."""
    return kind.value


def _malformed_decode_verdict(
    profile: Profile,
    mode: Mode,
    family: Family,
    sub_threat: str,
    offset: int,
) -> Verdict:
    findings = [
        Finding(
            code=reason_code(family, sub_threat),
            family=family,
            severity=Severity.MODERATE,
            positions=[offset],
            sub_threat=sub_threat,
            detail=family_slug(family),
        )
    ]
    return Verdict(
        input=[],
        profile=profile,
        mode=mode,
        action=select_action(profile, mode, findings),
        findings=findings,
    )


def family_blocks(profile: Profile, family: Family) -> bool:
    """True when a detector family blocks under the profile."""
    policy = policy_of_profile(profile)
    return family in rejection_set(policy.level) or family in _crypto_families(
        policy.crypto_context
    )


def blocking_findings(profile: Profile, findings: list[Finding]) -> list[Finding]:
    """Findings that block under the profile."""
    return [f for f in findings if family_blocks(profile, f.family)]


def select_action(
    profile: Profile, mode: Mode, findings: list[Finding]
) -> Action:
    """Select the action for a profile/mode/findings tuple."""
    has_findings = bool(findings)
    has_blocking = any(family_blocks(profile, f.family) for f in findings)
    if mode in {Mode.OBSERVE, Mode.WARN}:
        return Action.OBSERVE if has_findings else Action.ALLOW
    if mode is Mode.ENFORCE:
        if not has_blocking:
            return Action.ALLOW
        return (
            Action.QUARANTINE
            if policy_of_profile(profile).quarantine
            else Action.REJECT
        )
    return Action.REJECT if has_findings else Action.ALLOW


def _default_policy_severity(kind: ClassificationKind) -> Severity:
    if kind is ClassificationKind.HAZARD:
        return Severity.MODERATE
    if kind is ClassificationKind.COMPOUND:
        return Severity.HIGH
    return Severity.INFORMATIONAL


def _append_finding(
    findings: list[Finding],
    family: Family,
    kind: ClassificationKind,
    sub_threat: str | None,
    positions: list[int],
) -> None:
    if kind is ClassificationKind.CLEAR:
        return
    findings.append(
        Finding(
            code=reason_code(family, sub_threat),
            family=family,
            severity=_default_policy_severity(kind),
            positions=positions,
            sub_threat=sub_threat,
            detail=family_slug(family),
        )
    )


def _positions_where(input_cps: list[int], predicate) -> list[int]:
    return [index for index, cp in enumerate(input_cps) if predicate(cp)]


def _append_positional_hazard(
    findings: list[Finding],
    family: Family,
    sub_threat: str,
    positions: list[int],
) -> None:
    if not positions:
        return
    _append_finding(
        findings,
        family,
        ClassificationKind.HAZARD,
        sub_threat,
        positions,
    )


def _is_c0_control(cp: int) -> bool:
    return (0 <= cp <= 0x1F and cp not in {0x09, 0x0A, 0x0D}) or cp == 0x7F


def _is_c1_control(cp: int) -> bool:
    return 0x80 <= cp <= 0x9F


def scan(profile: Profile, mode: Mode, input_cps: list[int]) -> Verdict:
    """Scan decoded codepoints with the implemented native detectors."""
    findings: list[Finding] = []

    tag = tag_block_payload.detect(input_cps)
    _append_finding(
        findings,
        Family.TAG_BLOCK_PAYLOAD,
        tag.kind,
        tag_block_payload.sub_threat_tag(tag.sub) if tag.sub else None,
        tag.tag_positions,
    )

    vs = variation_selector_payload.detect(input_cps)
    _append_finding(
        findings,
        Family.VARIATION_SELECTOR_PAYLOAD,
        vs.kind,
        variation_selector_payload.sub_threat_tag(vs.sub) if vs.sub else None,
        vs.vs_positions,
    )

    zw = zero_width_payload.detect(input_cps)
    _append_finding(
        findings,
        Family.ZERO_WIDTH_PAYLOAD,
        zw.kind,
        zero_width_payload.sub_threat_tag(zw.sub) if zw.sub else None,
        zw.zero_width_positions,
    )

    bidi = bidi_control_balance.detect(input_cps)
    _append_finding(
        findings,
        Family.BIDI_CONTROL_BALANCE,
        bidi.kind,
        bidi_control_balance.sub_threat_tag(bidi.sub) if bidi.sub else None,
        bidi.bidi_positions,
    )

    _append_positional_hazard(
        findings,
        Family.NONCHARACTER_CONTROL,
        "Noncharacter",
        _positions_where(input_cps, is_noncharacter),
    )
    _append_positional_hazard(
        findings,
        Family.NONCHARACTER_CONTROL,
        "C0Control",
        _positions_where(input_cps, _is_c0_control),
    )
    _append_positional_hazard(
        findings,
        Family.NONCHARACTER_CONTROL,
        "C1Control",
        _positions_where(input_cps, _is_c1_control),
    )

    homoglyph = homoglyph_confusable.detect(input_cps)
    homoglyph_sub = (
        homoglyph_confusable.sub_threat_tag(homoglyph.sub) if homoglyph.sub else None
    )
    if homoglyph_sub != "CrossScriptMix":
        _append_finding(
            findings,
            Family.HOMOGLYPH_CONFUSABLE,
            homoglyph.kind,
            homoglyph_sub,
            [] if homoglyph.kind is ClassificationKind.CLEAR else list(range(len(input_cps))),
        )
    if homoglyph_confusable.has_mixed_script_admissibility(input_cps):
        _append_finding(
            findings,
            Family.MIXED_SCRIPT_ADMISSIBILITY,
            ClassificationKind.HAZARD,
            homoglyph_confusable.mixed_script_subthreat(input_cps),
            list(range(len(input_cps))),
        )

    rtl = rtl_injection.detect(input_cps)
    if rtl.sub is not None:
        _append_finding(
            findings,
            Family.RTL_INJECTION,
            ClassificationKind.HAZARD,
            rtl.sub,
            list(rtl.positions),
        )

    return Verdict(
        input=list(input_cps),
        profile=profile,
        mode=mode,
        action=select_action(profile, mode, findings),
        findings=findings,
    )


def scan_utf8(profile: Profile, mode: Mode, data: bytes) -> Verdict:
    """Scan raw UTF-8 bytes with strict decoding before codepoint policy."""
    invalid = first_invalid_utf8_offset(data)
    if invalid is not None:
        offset, kind = invalid
        sub_threat = utf8_reject_tag(kind)
        return _malformed_decode_verdict(
            profile, mode, Family.MALFORMED_UTF8, sub_threat, offset
        )

    return scan(profile, mode, decode_to_codepoints(data))


def _decode_utf16_stream(
    data: bytes, byteorder: str
) -> tuple[list[int] | None, str | None, int | None]:
    input_cps: list[int] = []
    offset = 0
    while offset < len(data):
        if offset + 2 > len(data):
            return None, "TruncatedCodeUnit", len(data)
        unit = int.from_bytes(data[offset : offset + 2], byteorder)
        unit_offset = offset
        offset += 2
        if 0xD800 <= unit <= 0xDBFF:
            if offset + 2 > len(data):
                return None, "TruncatedSurrogatePair", len(data)
            low = int.from_bytes(data[offset : offset + 2], byteorder)
            if not 0xDC00 <= low <= 0xDFFF:
                return None, "InvalidSurrogatePair", offset
            input_cps.append(0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00))
            offset += 2
        elif 0xDC00 <= unit <= 0xDFFF:
            return None, "LoneSurrogate", unit_offset
        else:
            input_cps.append(unit)
    return input_cps, None, None


def _decode_utf32_stream(
    data: bytes, byteorder: str
) -> tuple[list[int] | None, str | None, int | None]:
    if len(data) % 4 != 0:
        return None, "TruncatedCodeUnit", len(data)

    input_cps: list[int] = []
    for offset in range(0, len(data), 4):
        cp = int.from_bytes(data[offset : offset + 4], byteorder)
        if 0xD800 <= cp <= 0xDFFF:
            return None, "SurrogateCodepoint", offset
        if cp > 0x10FFFF:
            return None, "CodepointBeyondMax", offset
        input_cps.append(cp)
    return input_cps, None, None


def _scan_utf16(profile: Profile, mode: Mode, data: bytes, byteorder: str) -> Verdict:
    input_cps, sub_threat, offset = _decode_utf16_stream(data, byteorder)
    if input_cps is None:
        assert sub_threat is not None and offset is not None
        return _malformed_decode_verdict(
            profile, mode, Family.MALFORMED_UTF16, sub_threat, offset
        )
    return scan(profile, mode, input_cps)


def _scan_utf32(profile: Profile, mode: Mode, data: bytes, byteorder: str) -> Verdict:
    input_cps, sub_threat, offset = _decode_utf32_stream(data, byteorder)
    if input_cps is None:
        assert sub_threat is not None and offset is not None
        return _malformed_decode_verdict(
            profile, mode, Family.MALFORMED_UTF32, sub_threat, offset
        )
    return scan(profile, mode, input_cps)


def scan_utf16be(profile: Profile, mode: Mode, data: bytes) -> Verdict:
    """Scan raw UTF-16 big-endian bytes before codepoint policy."""
    return _scan_utf16(profile, mode, data, "big")


def scan_utf16le(profile: Profile, mode: Mode, data: bytes) -> Verdict:
    """Scan raw UTF-16 little-endian bytes before codepoint policy."""
    return _scan_utf16(profile, mode, data, "little")


def scan_utf32be(profile: Profile, mode: Mode, data: bytes) -> Verdict:
    """Scan raw UTF-32 big-endian bytes before codepoint policy."""
    return _scan_utf32(profile, mode, data, "big")


def scan_utf32le(profile: Profile, mode: Mode, data: bytes) -> Verdict:
    """Scan raw UTF-32 little-endian bytes before codepoint policy."""
    return _scan_utf32(profile, mode, data, "little")


def scan_default(profile: Profile, input_cps: list[int]) -> Verdict:
    """Scan in default enforce mode."""
    return scan(profile, Mode.ENFORCE, input_cps)


def permits(profile: Profile, mode: Mode, input_cps: list[int]) -> bool:
    """True when policy passes or only observes the input."""
    return scan(profile, mode, input_cps).action in {
        Action.ALLOW,
        Action.OBSERVE,
        Action.REWRITE,
    }


__all__ = [
    "Action",
    "CryptoContext",
    "Finding",
    "Mode",
    "PolicyLevel",
    "Profile",
    "ProfilePolicy",
    "Verdict",
    "blocking_findings",
    "family_blocks",
    "family_layer_code",
    "family_slug",
    "finding_to_wire",
    "permits",
    "policy_of_profile",
    "reason_base",
    "reason_code",
    "rejection_set",
    "scan",
    "scan_default",
    "scan_utf16be",
    "scan_utf16le",
    "scan_utf32be",
    "scan_utf32le",
    "scan_utf8",
    "select_action",
    "utf8_reject_tag",
    "verdict_to_json",
    "verdict_to_wire",
]
