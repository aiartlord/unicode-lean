#!/usr/bin/env bash
# Validate the shared runtime policy fixture without pytest or native toolchains.

set -euo pipefail

cd "$(dirname "$0")/.."

check_go_fixture_copy() {
  local rel="$1"
  local source="fixtures/security/$rel"
  local copy="ports/go/security/testdata/fixtures/security/$rel"
  [[ -f "$copy" ]] || {
    echo "FATAL: missing Go fixture copy: $copy" >&2
    exit 1
  }
  cmp -s "$source" "$copy" || {
    echo "FATAL: Go fixture copy drifted from fixtures/security/$rel" >&2
    exit 1
  }
}

check_haskell_fixture_copy() {
  local rel="$1"
  local source="fixtures/security/$rel"
  local copy="ports/haskell/testdata/fixtures/security/$rel"
  [[ -f "$copy" ]] || {
    echo "FATAL: missing Haskell fixture copy: $copy" >&2
    exit 1
  }
  cmp -s "$source" "$copy" || {
    echo "FATAL: Haskell fixture copy drifted from fixtures/security/$rel" >&2
    exit 1
  }
}

check_jvm_fixture_copy() {
  local rel="$1"
  local source="fixtures/security/$rel"
  local copy="ports/jvm/testdata/fixtures/security/$rel"
  [[ -f "$copy" ]] || {
    echo "FATAL: missing JVM fixture copy: $copy" >&2
    exit 1
  }
  cmp -s "$source" "$copy" || {
    echo "FATAL: JVM fixture copy drifted from fixtures/security/$rel" >&2
    exit 1
  }
}

check_typescript_fixture_copy() {
  local rel="$1"
  local source="fixtures/security/$rel"
  local copy="ports/typescript/testdata/fixtures/security/$rel"
  [[ -f "$copy" ]] || {
    echo "FATAL: missing TypeScript fixture copy: $copy" >&2
    exit 1
  }
  cmp -s "$source" "$copy" || {
    echo "FATAL: TypeScript fixture copy drifted from fixtures/security/$rel" >&2
    exit 1
  }
}

check_dotnet_fixture_copy() {
  local rel="$1"
  local source="fixtures/security/$rel"
  local copy="ports/dotnet/testdata/fixtures/security/$rel"
  [[ -f "$copy" ]] || {
    echo "FATAL: missing .NET fixture copy: $copy" >&2
    exit 1
  }
  cmp -s "$source" "$copy" || {
    echo "FATAL: .NET fixture copy drifted from fixtures/security/$rel" >&2
    exit 1
  }
}

check_swift_fixture_copy() {
  local rel="$1"
  local source="fixtures/security/$rel"
  local copy="ports/swift/ContractTests/Resources/fixtures/security/$rel"
  [[ -f "$copy" ]] || {
    echo "FATAL: missing Swift fixture copy: $copy" >&2
    exit 1
  }
  cmp -s "$source" "$copy" || {
    echo "FATAL: Swift fixture copy drifted from fixtures/security/$rel" >&2
    exit 1
  }
}

check_zig_fixture_copy() {
  local rel="$1"
  local source="fixtures/security/$rel"
  local copy="ports/zig/testdata/fixtures/security/$rel"
  [[ -f "$copy" ]] || {
    echo "FATAL: missing Zig fixture copy: $copy" >&2
    exit 1
  }
  cmp -s "$source" "$copy" || {
    echo "FATAL: Zig fixture copy drifted from fixtures/security/$rel" >&2
    exit 1
  }
}

check_cpp_fixture_copy() {
  local rel="$1"
  local source="fixtures/security/$rel"
  local copy="ports/cpp/testdata/fixtures/security/$rel"
  [[ -f "$copy" ]] || {
    echo "FATAL: missing C++ fixture copy: $copy" >&2
    exit 1
  }
  cmp -s "$source" "$copy" || {
    echo "FATAL: C++ fixture copy drifted from fixtures/security/$rel" >&2
    exit 1
  }
}

for rel in \
  policy_contract.json \
  verdict_contract.json \
  decode_contract.json \
  decode_multiencoding_contract.json \
  detectors/bidi_control_balance.json \
  detectors/homoglyph_confusable.json \
  detectors/mixed_script_admissibility.json \
  detectors/noncharacter_control.json \
  detectors/tag_block_payload.json \
  detectors/variation_selector_payload.json \
  detectors/zero_width_payload.json
do
  check_haskell_fixture_copy "$rel"
  check_cpp_fixture_copy "$rel"
  check_go_fixture_copy "$rel"
  check_jvm_fixture_copy "$rel"
  check_typescript_fixture_copy "$rel"
  check_dotnet_fixture_copy "$rel"
  check_swift_fixture_copy "$rel"
  check_zig_fixture_copy "$rel"
done

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=ports/python/src python3 - <<'PY'
import json
from pathlib import Path

from unicode_python.security import Family
from unicode_python.security.policy import (
    Action,
    Mode,
    Profile,
    reason_code,
    scan,
    scan_utf16be,
    scan_utf16le,
    scan_utf32be,
    scan_utf32le,
    scan_utf8,
    verdict_to_json,
    verdict_to_wire,
)
from unicode_python.security.identity import homoglyph_confusable

fixture = Path("fixtures/security/policy_contract.json")
payload = json.loads(fixture.read_text(encoding="utf-8"))
verdict_fixture = Path("fixtures/security/verdict_contract.json")
verdict_payload = json.loads(verdict_fixture.read_text(encoding="utf-8"))
decode_fixture = Path("fixtures/security/decode_contract.json")
decode_payload = json.loads(decode_fixture.read_text(encoding="utf-8"))
multiencoding_decode_fixture = Path("fixtures/security/decode_multiencoding_contract.json")
multiencoding_decode_payload = json.loads(
    multiencoding_decode_fixture.read_text(encoding="utf-8")
)
detector_fixtures = sorted(Path("fixtures/security/detectors").glob("*.json"))
restriction_low_audit_fixture = Path(
    "fixtures/security/audits/homoglyph_restriction_low.json"
)

if payload.get("contract") != "unicode-security-policy-v0":
    raise SystemExit("policy contract name mismatch")

expected_codes = {
    reason_code(Family.TAG_BLOCK_PAYLOAD, "DirectAscii"),
    reason_code(Family.BIDI_CONTROL_BALANCE),
    reason_code(Family.HOMOGLYPH_CONFUSABLE, "TargetMatch"),
    reason_code(Family.MIXED_SCRIPT_ADMISSIBILITY, "CrossScriptMix"),
    reason_code(Family.NONCHARACTER_CONTROL, "Noncharacter"),
}
required_codes = {
    "unicode.security.C.tag-block-payload.DirectAscii",
    "unicode.security.C.bidi-control-balance.hazard",
    "unicode.security.I.homoglyph-confusable.TargetMatch",
    "unicode.security.I.mixed-script-admissibility.CrossScriptMix",
    "unicode.security.C.noncharacter-control.Noncharacter",
    "unicode.security.C.malformed-utf8.InvalidStartByte",
}
expected_codes.add(reason_code(Family.MALFORMED_UTF8, "InvalidStartByte"))
if expected_codes != required_codes:
    raise SystemExit("policy reason-code mapping drifted")

profiles = {profile.value: profile for profile in Profile}
modes = {mode.value: mode for mode in Mode}

for case in payload["cases"]:
    verdict = scan(profiles[case["profile"]], modes[case["mode"]], case["input"])
    if verdict.action is not Action(case["action"]):
        raise SystemExit(
            f"{case['name']}: expected action {case['action']}, "
            f"got {verdict.action.value}"
        )
    actual = {finding.code for finding in verdict.findings}
    missing = set(case["required_findings"]) - actual
    if missing:
        raise SystemExit(
            f"{case['name']}: missing required findings {sorted(missing)}"
        )

if verdict_payload.get("contract") != "unicode-security-verdict-v0":
    raise SystemExit("verdict contract name mismatch")

for case in verdict_payload["cases"]:
    verdict = scan(profiles[case["profile"]], modes[case["mode"]], case["input"])
    expected = case["verdict"]
    actual = verdict_to_wire(verdict)
    if actual != expected:
        raise SystemExit(
            f"{case['name']}: verdict contract mismatch\n"
            f"actual={actual!r}\nexpected={expected!r}"
        )
    expected_json = json.dumps(expected, separators=(",", ":"))
    actual_json = verdict_to_json(verdict)
    if actual_json != expected_json:
        raise SystemExit(
            f"{case['name']}: verdict JSON mismatch\n"
            f"actual={actual_json}\nexpected={expected_json}"
        )

if decode_payload.get("contract") != "unicode-security-decode-v0":
    raise SystemExit("decode contract name mismatch")

for case in decode_payload["cases"]:
    verdict = scan_utf8(
        profiles[case["profile"]],
        modes[case["mode"]],
        bytes(case["input_bytes"]),
    )
    if verdict.action is not Action(case["action"]):
        raise SystemExit(
            f"{case['name']}: expected action {case['action']}, "
            f"got {verdict.action.value}"
        )
    if verdict.input != case["input"]:
        raise SystemExit(
            f"{case['name']}: decoded input mismatch "
            f"actual={verdict.input!r} expected={case['input']!r}"
        )
    by_code = {finding.code: finding.positions for finding in verdict.findings}
    missing = set(case["required_findings"]) - set(by_code)
    if missing:
        raise SystemExit(
            f"{case['name']}: missing required findings {sorted(missing)}"
        )
    for expected in case["required_positions"]:
        actual_positions = by_code.get(expected["code"])
        if actual_positions != expected["positions"]:
            raise SystemExit(
                f"{case['name']}: positions for {expected['code']} "
                f"actual={actual_positions!r} expected={expected['positions']!r}"
            )

if multiencoding_decode_payload.get("contract") != "unicode-security-multiencoding-decode-v0":
    raise SystemExit("multi-encoding decode contract name mismatch")

scanners = {
    "utf-8": scan_utf8,
    "utf-16be": scan_utf16be,
    "utf-16le": scan_utf16le,
    "utf-32be": scan_utf32be,
    "utf-32le": scan_utf32le,
}

for case in multiencoding_decode_payload["cases"]:
    verdict = scanners[case["encoding"]](
        profiles[case["profile"]],
        modes[case["mode"]],
        bytes(case["input_bytes"]),
    )
    if verdict.action is not Action(case["action"]):
        raise SystemExit(
            f"{case['name']}: expected action {case['action']}, "
            f"got {verdict.action.value}"
        )
    if verdict.input != case["input"]:
        raise SystemExit(
            f"{case['name']}: decoded input mismatch "
            f"actual={verdict.input!r} expected={case['input']!r}"
        )
    by_code = {finding.code: finding.positions for finding in verdict.findings}
    missing = set(case["required_findings"]) - set(by_code)
    if missing:
        raise SystemExit(
            f"{case['name']}: missing required findings {sorted(missing)}"
        )
    for expected in case["required_positions"]:
        actual_positions = by_code.get(expected["code"])
        if actual_positions != expected["positions"]:
            raise SystemExit(
                f"{case['name']}: positions for {expected['code']} "
                f"actual={actual_positions!r} expected={expected['positions']!r}"
            )

if not detector_fixtures:
    raise SystemExit("no detector fixtures found")

for detector_fixture in detector_fixtures:
    detector_payload = json.loads(detector_fixture.read_text(encoding="utf-8"))
    if detector_payload.get("schema") != 1:
        raise SystemExit(f"{detector_fixture}: detector schema mismatch")
    for case in detector_payload["cases"]:
        verdict = scan(Profile.GATEWAY_HEADER, Mode.OBSERVE, case["input"])
        actual = {finding.code for finding in verdict.findings}
        missing = set(case["required_findings"]) - actual
        if missing:
            raise SystemExit(
                f"{detector_fixture}:{case['name']}: "
                f"missing required findings {sorted(missing)}"
            )

if restriction_low_audit_fixture.exists():
    audit_payload = json.loads(
        restriction_low_audit_fixture.read_text(encoding="utf-8")
    )
    if audit_payload.get("schema") != 1:
        raise SystemExit("homoglyph restriction-low audit schema mismatch")
    if audit_payload.get("audit") != "homoglyph-restriction-low-priority-v0":
        raise SystemExit("homoglyph restriction-low audit name mismatch")
    if audit_payload.get("shared_runtime_fixture") is not False:
        raise SystemExit("restriction-low audit must not be a shared runtime fixture")
    for case in audit_payload["cases"]:
        verdict = scan(Profile.GATEWAY_HEADER, Mode.OBSERVE, case["input"])
        homoglyph = homoglyph_confusable.detect(case["input"])
        actual_level = homoglyph.restriction_level.value
        if actual_level != case["restriction_level"]:
            raise SystemExit(
                f"{case['name']}: restriction level actual={actual_level!r} "
                f"expected={case['restriction_level']!r}"
            )
        actual_sub = homoglyph_confusable.sub_threat_tag(homoglyph.sub)
        if actual_sub != case["expected_sub_threat"]:
            raise SystemExit(
                f"{case['name']}: sub-threat actual={actual_sub!r} "
                f"expected={case['expected_sub_threat']!r}"
            )
        if case.get("restriction_low_emitted") is False and actual_sub == "RestrictionLow":
            raise SystemExit(f"{case['name']}: RestrictionLow unexpectedly emitted")
        actual_codes = {finding.code for finding in verdict.findings}
        missing = set(case["required_findings"]) - actual_codes
        if missing:
            raise SystemExit(
                f"{case['name']}: missing required audit findings {sorted(missing)}"
            )

print("clean: shared security contract fixtures pass")
PY
