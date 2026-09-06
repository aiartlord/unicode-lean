#!/usr/bin/env python3
"""Reach gate over the shared verdict fixtures.

A green cross-port run is only evidence about the rungs the fixtures reach. The
first widening of the differential corpus found the reference reporting the
wrong positions for AsciiConfusable over identifier tokens, the second found it
reporting every bidi control for an OrphanPop, and a third found a port
reporting the whole input for a compound pair -- each a rung the earlier
fixtures never asked about in that position shape. This gate makes "the
fixtures do not ask" a failure instead of a silence.

It reads fixtures/security/reason_codes.json, the registry of every reason
code the default scan can emit (one family per Lean detector the policy
dispatches, one tag per Lean Classification.tag), and the two verdict-level
fixtures every port replays byte for byte: verdict_contract.json and
differential_corpus.json. For every registered code it requires:

  * at least --min-cases cases firing it, under at least two profiles;
  * for a code the Lean localises (not in the family's positionless list):
    every firing carries positions; at least one firing's positions are a
    strict, nonempty subset of the input's positions; at least one firing's
    first position is not 0. Whole-span and leading-only firings are exactly
    the shapes that let a port report the wrong thing and stay green;
  * for a positionless code: every firing carries an empty positions list.

Any code a fixture emits that the registry does not list fails the gate, so a
new rung cannot appear in the reference without being registered and reached.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "fixtures" / "security" / "reason_codes.json"
FIXTURES = (
    ROOT / "fixtures" / "security" / "verdict_contract.json",
    ROOT / "fixtures" / "security" / "differential_corpus.json",
)
CODE_PREFIX = "unicode.security."


class Reach:
    def __init__(self) -> None:
        self.cases = 0
        self.profiles: set[str] = set()
        self.subset_firing = False
        self.offset_firing = False
        self.empty_firings = 0
        self.full_span_firings = 0
        self.example = ""


POSITIONED = "positioned"
POSITIONLESS = "positionless"
WHOLE_SPAN = "whole_span"
UNREACHABLE = "unreachable"


def registered_codes(registry: dict) -> dict[str, str]:
    """Map every registered reason code to its position shape or to
    `unreachable`."""
    codes: dict[str, str] = {}
    for family, spec in registry["families"].items():
        subs = set(spec["sub_threats"])
        shapes: dict[str, str] = {}
        for shape in (POSITIONLESS, WHOLE_SPAN):
            for sub in spec.get(shape, []):
                if sub not in subs:
                    raise SystemExit(f"{family}: {shape} names unregistered sub-threat {sub}")
                if sub in shapes:
                    raise SystemExit(f"{family}: {sub} listed under both {shapes[sub]} and {shape}")
                shapes[sub] = shape
        for sub in spec.get(UNREACHABLE, {}):
            if sub not in subs:
                raise SystemExit(f"{family}: unreachable names unregistered sub-threat {sub}")
            if sub in shapes:
                raise SystemExit(f"{family}: {sub} listed under both {shapes[sub]} and unreachable")
            shapes[sub] = UNREACHABLE
        for sub in spec["sub_threats"]:
            codes[f"{CODE_PREFIX}{spec['layer']}.{family}.{sub}"] = shapes.get(sub, POSITIONED)
    return codes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--min-cases", type=int, default=3)
    parser.add_argument("--min-profiles", type=int, default=2)
    parser.add_argument("--registry", type=Path, default=REGISTRY)
    parser.add_argument(
        "--report",
        action="store_true",
        help="print the reach table for every registered code, not only the shortfalls",
    )
    args = parser.parse_args()

    registry = json.loads(args.registry.read_text(encoding="utf-8"))
    if registry.get("contract") != "unicode-security-reason-codes-v0":
        raise SystemExit(f"{args.registry}: unexpected contract {registry.get('contract')!r}")
    codes = registered_codes(registry)

    reach: dict[str, Reach] = defaultdict(Reach)
    unregistered: dict[str, str] = {}
    total_cases = 0
    for fixture in FIXTURES:
        payload = json.loads(fixture.read_text(encoding="utf-8"))
        for case in payload["cases"]:
            total_cases += 1
            span = len(case["input"])
            for finding in case["verdict"]["findings"]:
                code = finding["code"]
                if code not in codes:
                    unregistered.setdefault(code, f"{fixture.name}:{case['name']}")
                    continue
                positions = finding["positions"]
                r = reach[code]
                r.cases += 1
                r.profiles.add(case["profile"])
                if not r.example:
                    r.example = f"{fixture.name}:{case['name']}"
                if not positions:
                    r.empty_firings += 1
                    continue
                if len(positions) == span:
                    r.full_span_firings += 1
                elif 0 < len(positions) < span:
                    r.subset_firing = True
                if min(positions) > 0:
                    r.offset_firing = True

    failures: list[str] = []
    for code, source in sorted(unregistered.items()):
        failures.append(f"unregistered reason code {code} emitted by {source}")

    rows: list[str] = []
    for code, kind in sorted(codes.items()):
        r = reach[code]
        problems: list[str] = []
        if kind == UNREACHABLE:
            if r.cases:
                problems.append(f"declared unreachable but reached {r.cases} time(s), first {r.example}")
            rows.append(f"{code[len(CODE_PREFIX):]:<58} cases={r.cases:<5} unreachable (declared)" + ("" if not problems else "  <-- " + "; ".join(problems)))
            for problem in problems:
                failures.append(f"{code}: {problem}")
            continue
        if r.cases < args.min_cases:
            problems.append(f"reached {r.cases} < {args.min_cases}")
        if len(r.profiles) < args.min_profiles:
            problems.append(f"profiles {len(r.profiles)} < {args.min_profiles}")
        if kind == POSITIONLESS:
            if r.cases and r.empty_firings != r.cases:
                problems.append(f"declared positionless but {r.cases - r.empty_firings} firings carry positions")
        elif kind == WHOLE_SPAN:
            if r.empty_firings:
                problems.append(f"{r.empty_firings} firings carry no positions")
            if r.subset_firing:
                problems.append("declared whole-span but fired on a strict subset")
        else:
            if r.empty_firings:
                problems.append(f"{r.empty_firings} firings carry no positions")
            if r.cases and not r.subset_firing:
                problems.append("never a strict subset of the input")
            if r.cases and not r.offset_firing:
                problems.append("never at a non-zero offset")
        shape = kind if kind != POSITIONED else (
            f"subset={'y' if r.subset_firing else 'n'} offset={'y' if r.offset_firing else 'n'} full={r.full_span_firings}"
        )
        row = f"{code[len(CODE_PREFIX):]:<58} cases={r.cases:<5} profiles={len(r.profiles):<2} {shape}"
        rows.append(row + ("" if not problems else "  <-- " + "; ".join(problems)))
        for problem in problems:
            failures.append(f"{code}: {problem}")

    if args.report or failures:
        print(f"reach over {total_cases} fixture cases, {len(codes)} registered reason codes")
        for row in rows:
            print("  " + row)
    if failures:
        print(f"{len(failures)} reach shortfall(s):", file=sys.stderr)
        for failure in failures:
            print("  " + failure, file=sys.stderr)
        return 1
    print(
        f"clean: all {len(codes)} registered reason codes reached by >= {args.min_cases} cases "
        f"under >= {args.min_profiles} profiles with spec-shaped positions"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
