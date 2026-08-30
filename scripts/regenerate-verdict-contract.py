#!/usr/bin/env python3
"""Regenerate fixtures/security/verdict_contract.json from the Rust reference.

The fixture pins one wire verdict per case and is checked by fifteen ports.
Rust is not one of them, and it is the port that tracks the proven
specification: Unicode/Security/RunAll.lean dispatches all twenty-seven
detector families, and Rust dispatches twenty-four of them on plain input,
excluding only the three crypto families, which judge a candidate against a
wordlist, a hashing rule or a watermark cue that a plain scan does not supply.

The fixture as committed records what the other fifteen ports do, which is
narrower. Regenerating it from Rust moves the pinned expectation onto the
specification; the fifteen ports then have to widen their scan paths to match,
and they fail this fixture until they do. That is the intended order, and it is
why this is a script that is run deliberately rather than a build step.

The case list -- name, profile, mode, input -- is preserved exactly. Only the
verdicts are recomputed, so a regenerated fixture never silently changes what is
being tested, and `--check` reports the difference without writing.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "security" / "verdict_contract.json"
DEFAULT_BIN = ROOT / "ports" / "rust" / "target" / "debug" / "unicode-security"

# The fixture's finding shape is a projection of the CLI's. byte_spans is a
# presentation concern of the Rust command-line surface and is not part of the
# cross-port wire contract, so it is dropped rather than pinned into a fixture
# fifteen ports would then have to reproduce.
FINDING_FIELDS = ("code", "family", "severity", "positions", "sub_threat", "detail")


def verdict_for(binary: Path, profile: str, mode: str, codepoints: list[int]) -> dict:
    """Run one case through the reference and project it onto the wire shape."""
    payload = "".join(chr(cp) for cp in codepoints).encode("utf-8")
    completed = subprocess.run(
        [str(binary), "scan", "--profile", profile, "--mode", mode, "--json"],
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    # The exit status is the scanner's verdict channel -- non-zero means a
    # threat was found -- so it carries no information about whether the run
    # succeeded. A run that failed is one that did not emit a verdict.
    try:
        verdict = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise SystemExit(
            f"reference emitted no verdict for {profile}/{mode} "
            f"(exit {completed.returncode}): {completed.stderr.decode(errors='replace').strip()}"
        ) from exc
    verdict["findings"] = [
        {field: finding[field] for field in FINDING_FIELDS}
        for finding in verdict["findings"]
    ]
    return verdict


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--binary",
        type=Path,
        default=DEFAULT_BIN,
        help="the Rust reference CLI (default: the port's debug build)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="report cases whose pinned verdict differs from the reference, write nothing",
    )
    args = parser.parse_args()

    if not args.binary.exists():
        print(f"FATAL: reference binary not found: {args.binary}", file=sys.stderr)
        print("build it with: cd ports/rust && cargo build", file=sys.stderr)
        return 1

    document = json.loads(FIXTURE.read_text())

    differing = []
    for case in document["cases"]:
        fresh = verdict_for(args.binary, case["profile"], case["mode"], case["input"])
        if fresh != case["verdict"]:
            pinned_count = len(case["verdict"]["findings"])
            fresh_count = len(fresh["findings"])
            differing.append((case["name"], pinned_count, fresh_count))
        if not args.check:
            case["verdict"] = fresh

    if args.check:
        if not differing:
            print(f"clean: all {len(document['cases'])} cases match the reference")
            return 0
        print(f"{len(differing)} of {len(document['cases'])} cases differ from the reference:")
        for name, pinned, fresh in differing:
            print(f"  {name}: pinned {pinned} finding(s), reference {fresh}")
        return 1

    FIXTURE.write_text(json.dumps(document, indent=2) + "\n")
    print(f"regenerated {FIXTURE.relative_to(ROOT)} from {args.binary.name}")
    print(f"{len(differing)} of {len(document['cases'])} case verdicts changed")
    for name, pinned, fresh in differing:
        print(f"  {name}: {pinned} -> {fresh} finding(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
