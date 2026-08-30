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


def sync_fixture(canonical_path: Path) -> int:
    """Copy one canonical fixture over every port's vendored copy of it.

    Each port reads its own copy so that the port stays buildable on its own,
    and `scripts/check-policy-contract.sh` compares those copies byte-for-byte
    against this one. Regenerating without syncing therefore fails that check
    before any port's tests even run, which reports the wrong problem. The
    copies are discovered from the index rather than listed here, so a port
    added later is picked up without editing this script.
    """
    listing = subprocess.run(
        ["git", "ls-files", f"*{canonical_path.name}"],
        cwd=ROOT, stdout=subprocess.PIPE, text=True, check=True,
    )
    canonical = canonical_path.read_bytes()
    copied = 0
    for line in listing.stdout.split():
        target = ROOT / line
        if target.resolve() == canonical_path.resolve():
            continue
        target.write_bytes(canonical)
        copied += 1
    return copied


def gate(document: dict, binary: Path) -> int:
    """Enforce what must hold between the reference and the shared contract.

    The fixture records what fifteen ports agree on, and the reference detects
    more than that, so the two are not equal and pinning the reference to the
    fixture verbatim would fail on cases that are not defects. What must hold is
    weaker and still meaningful: the reference decides every case the same way,
    and it never reports fewer findings than the ports have agreed on.

    That makes this a real gate on the reference, which nothing else gates --
    the fixture is checked by fifteen ports and Rust is not one of them, which is
    how the reference came to diverge unnoticed. A dropped finding or a changed
    action now fails here, while the extra findings the reference legitimately
    produces do not.
    """
    action_failures = []
    subset_failures = []
    extra_total = 0
    for case in document["cases"]:
        fresh = verdict_for(binary, case["profile"], case["mode"], case["input"])
        pinned_codes = {f["code"] for f in case["verdict"]["findings"]}
        fresh_codes = {f["code"] for f in fresh["findings"]}
        if fresh["action"] != case["verdict"]["action"]:
            action_failures.append((case["name"], case["verdict"]["action"], fresh["action"]))
        dropped = pinned_codes - fresh_codes
        if dropped:
            subset_failures.append((case["name"], sorted(dropped)))
        extra_total += len(fresh_codes - pinned_codes)

    total = len(document["cases"])
    if action_failures or subset_failures:
        for name, pinned, fresh in action_failures:
            print(f"ACTION CHANGED: {name}: contract {pinned}, reference {fresh}")
        for name, dropped in subset_failures:
            print(f"FINDING DROPPED: {name}: {', '.join(dropped)}")
        print(f"FAIL: {len(action_failures)} action change(s), {len(subset_failures)} dropped finding(s)")
        return 1

    print(f"clean: reference decides all {total} contract cases identically")
    print(f"       and reports every finding they pin, plus {extra_total} more")
    return 0


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
    parser.add_argument(
        "--sync-ports",
        action="store_true",
        help="copy the fixture over every port's vendored copy after writing it",
    )
    parser.add_argument(
        "--sync-only",
        type=Path,
        help="copy the named canonical fixture over its vendored copies and exit",
    )
    parser.add_argument(
        "--gate",
        action="store_true",
        help="enforce the reference's standing relationship to the contract; write nothing",
    )
    args = parser.parse_args()

    if not args.binary.exists():
        print(f"FATAL: reference binary not found: {args.binary}", file=sys.stderr)
        print("build it with: cd ports/rust && cargo build", file=sys.stderr)
        return 1

    if args.sync_only:
        print(f"synced {sync_fixture(args.sync_only)} vendored copies of {args.sync_only.name}")
        return 0

    document = json.loads(FIXTURE.read_text())

    if args.gate:
        return gate(document, args.binary)

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
    if args.sync_ports:
        print(f"synced {sync_fixture(FIXTURE)} vendored copies")
    print(f"{len(differing)} of {len(document['cases'])} case verdicts changed")
    for name, pinned, fresh in differing:
        print(f"  {name}: {pinned} -> {fresh} finding(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
