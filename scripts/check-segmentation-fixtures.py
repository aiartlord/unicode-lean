#!/usr/bin/env python3
"""Sync and reach gate over the shared segmentation vector fixtures.

The segmentation algorithms are judged two ways. The published corpora
(LineBreakTest.txt, GraphemeBreakTest.txt) are the authority: a port must agree
with every row, and must separately account for the whole file so a row lost
between the file and the fold fails rather than shrinking the denominator.
On top of that each port replays a shared vector fixture, one case per rule, so
every port asks the same questions instead of a per-port selection of them.

That only holds if the vendored copies are the root fixture. This gate checks
it, and reports which ports do not yet replay the fixture, so a port carrying a
weaker set is visible rather than silent.

  python3 scripts/check-segmentation-fixtures.py

Exit 0 when every vendored copy matches the root and every port that has a
segmentation test replays both fixtures. `--list` reports the inventory without
failing on a port that does not replay them yet.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "fixtures" / "segmentation"
FIXTURES = ("line_break_vectors.json", "grapheme_vectors.json")

# Where each port keeps the fixtures it is tested against. Kept in step with
# scripts/internal/generate_segmentation_fixtures.py, which writes the copies.
# The Python port reads the root fixtures directly and vendors none.
PORT_FIXTURE_ROOTS = {
    "cobol": "ports/cobol/testdata/fixtures",
    "cpp": "ports/cpp/testdata/fixtures",
    "dotnet": "ports/dotnet/testdata/fixtures",
    "elixir": "ports/elixir/test/fixtures",
    "erlang": "ports/erlang/test/fixtures",
    "go": "ports/go/security/testdata/fixtures",
    "haskell": "ports/haskell/testdata/fixtures",
    "jvm": "ports/jvm/testdata/fixtures",
    "lua": "ports/lua/testdata/fixtures",
    "php": "ports/php/testdata/fixtures",
    "ruby": "ports/ruby/testdata/fixtures",
    "rust": "ports/rust/testdata/fixtures",
    "swift": "ports/swift/ContractTests/Resources/fixtures",
    "typescript": "ports/typescript/testdata/fixtures",
    "zig": "ports/zig/testdata/fixtures",
}

# Where each port's tests live, for the reach half of the gate.
PORT_TEST_ROOTS = {
    "cobol": ["ports/cobol/testdata", "ports/cobol/src"],
    "cpp": ["ports/cpp/test"],
    "dotnet": ["ports/dotnet/test"],
    "elixir": ["ports/elixir/test"],
    "erlang": ["ports/erlang/test"],
    "go": ["ports/go/segmentation", "ports/go/security"],
    "haskell": ["ports/haskell/test"],
    "jvm": ["ports/jvm/src/test"],
    "lua": ["ports/lua/test"],
    "php": ["ports/php/test"],
    "python": ["ports/python/tests"],
    "ruby": ["ports/ruby/test"],
    "rust": ["ports/rust/tests"],
    "swift": ["ports/swift/ContractTests"],
    "typescript": ["ports/typescript/test"],
    "zig": ["ports/zig/test"],
}


def read_fixture(path: Path) -> bytes:
    if not path.is_file():
        return b""
    return path.read_bytes()


def describe(document: dict) -> str:
    return "%d cases, %d published rows" % (
        len(document["cases"]), document["published_row_count"])


def replays(port: str, fixture: str) -> bool:
    """Whether any of the port's test sources name the fixture."""
    stem = fixture.rsplit(".", 1)[0]
    for root in PORT_TEST_ROOTS.get(port, []):
        directory = ROOT / root
        if not directory.is_dir():
            continue
        for path in directory.rglob("*"):
            if not path.is_file() or path.suffix == ".json":
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if stem in text:
                return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--list", action="store_true",
        help="report the inventory without failing on a port that does not "
             "replay the fixtures yet")
    args = parser.parse_args()

    failures: list[str] = []
    pending: list[str] = []

    roots: dict[str, bytes] = {}
    for fixture in FIXTURES:
        path = FIXTURE_DIR / fixture
        payload = read_fixture(path)
        if not payload:
            failures.append("missing root fixture: %s"
                            % path.relative_to(ROOT))
            continue
        roots[fixture] = payload
        document = json.loads(payload)
        print("== %s: %s" % (fixture, describe(document)))

    if failures:
        for failure in failures:
            print("FATAL: %s" % failure, file=sys.stderr)
        return 1

    for port in sorted(PORT_FIXTURE_ROOTS):
        for fixture, payload in roots.items():
            copy = ROOT / PORT_FIXTURE_ROOTS[port] / "segmentation" / fixture
            vendored = read_fixture(copy)
            if not vendored:
                failures.append("%s: missing vendored copy %s"
                                % (port, copy.relative_to(ROOT)))
            elif vendored != payload:
                failures.append(
                    "%s: vendored %s differs from the root fixture; "
                    "regenerate with "
                    "scripts/internal/generate_segmentation_fixtures.py"
                    % (port, fixture))

    for port in sorted(PORT_TEST_ROOTS):
        for fixture in roots:
            if not replays(port, fixture):
                pending.append("%s does not replay %s" % (port, fixture))

    for failure in failures:
        print("FATAL: %s" % failure, file=sys.stderr)
    for item in pending:
        print("PENDING: %s" % item)

    if failures:
        return 1
    if pending and not args.list:
        print(
            "FATAL: %d port/fixture pair(s) do not replay the shared vectors"
            % len(pending), file=sys.stderr)
        return 1
    print("clean: segmentation vector fixtures are in sync"
          + ("" if pending else " and every port replays them"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
