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
import hashlib
import json
import re
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
    # Go's segmentation is its own package, so its fixtures sit in that
    # package's testdata: a Go test reads testdata relative to its own package.
    "go": "ports/go/segmentation/testdata/fixtures",
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


# The published corpus each fixture's algorithm is judged against. A port that
# names neither the corpus nor the fixture has no suite for that algorithm at
# all, which is a different thing from a suite carrying a weaker set, so the
# gate reports the two separately instead of calling both pending.
FIXTURE_CORPUS = {
    "line_break_vectors.json": "LineBreakTest.txt",
    "grapheme_vectors.json": "GraphemeBreakTest.txt",
}


def mentions(
    port: str,
    needles: str | tuple[str, ...],
    skip: frozenset[Path] = frozenset(),
) -> bool:
    """Whether one of the port's test sources names every needle.

    All needles must land in the SAME file, so a marker can be a pairing — a
    namespace plus a member — that neither half establishes alone.

    `skip` excludes generated data modules. A transcription names the fixture
    it came from in its own header, so counting it would report a port as
    replaying vectors no test has been pointed at yet.
    """
    wanted = (needles,) if isinstance(needles, str) else needles
    for root in PORT_TEST_ROOTS.get(port, []):
        directory = ROOT / root
        if not directory.is_dir():
            continue
        for path in directory.rglob("*"):
            if not path.is_file() or path.suffix == ".json":
                continue
            if path.resolve() in skip:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if all(needle in text for needle in wanted):
                return True
    return False


def replays(port: str, fixture: str) -> bool:
    """Whether the port's tests replay the shared fixture.

    A port consuming a transcription is counted by the case constants its
    tests name, not by the transcription's own header.
    """
    generated = frozenset(
        (ROOT / relative).resolve()
        for relative, _entries in TRANSCRIPTIONS.values())
    if port in TRANSCRIPTIONS:
        _relative, entries = TRANSCRIPTIONS[port]
        _digest, marker = entries[fixture]
        return mentions(port, marker, skip=generated)
    return mentions(port, fixture.rsplit(".", 1)[0], skip=generated)


def has_suite(port: str, fixture: str) -> bool:
    """Whether the port judges this algorithm against its published corpus."""
    return mentions(port, FIXTURE_CORPUS[fixture])


# A port with no JSON reader consumes a generated transcription of the fixture
# instead of parsing it. The transcription records the digest of the fixture it
# came from, so a transcription left behind by a regenerated fixture is a
# failure here rather than a silent divergence.
# Per fixture: the constant holding that fixture's digest, and the symbol a
# test names to replay its cases. The two differ by language.
TRANSCRIPTIONS = {
    "rust": (
        "ports/rust/tests/corpus/vector_cases.rs",
        {"line_break_vectors.json": ("LINE_BREAK_FIXTURE_DIGEST",
                                     "LINE_BREAK_CASES"),
         "grapheme_vectors.json": ("GRAPHEME_FIXTURE_DIGEST",
                                   "GRAPHEME_CASES")},
    ),
    # A marker is every needle that must appear in ONE test source. The C++
    # tests reach the cases through a namespace alias, so naming `kCases`
    # alone would not say which algorithm, and naming the namespace alone
    # would also match that algorithm's corpus header.
    "cpp": (
        "ports/cpp/test/vector_cases.hpp",
        {"line_break_vectors.json": (
            "line_break::kFixtureDigest",
            ("unicode_cpp::test::line_break", "kCases")),
         "grapheme_vectors.json": (
            "grapheme::kFixtureDigest",
            ("unicode_cpp::test::grapheme", "kCases"))},
    ),
}

# How a transcription spells the constant holding a digest, per language. The
# gate reads the digest out of the generated source, so it has to know the
# shape the generator wrote.
DIGEST_PATTERNS = (
    # Rust: `pub const NAME: &str = "<64 hex>";`
    r'{name}:\s*&str\s*=\s*"([0-9a-f]{{64}})"',
    # C++: `inline constexpr char kFixtureDigest[] =\n    "<64 hex>";`
    r'{name}\[\]\s*=\s*"([0-9a-f]{{64}})"',
)


def transcription_failures(roots: dict[str, bytes]) -> list[str]:
    """Every transcription whose recorded digest is not its fixture's."""
    out: list[str] = []
    for port, (relative, entries) in sorted(TRANSCRIPTIONS.items()):
        path = ROOT / relative
        if not path.is_file():
            out.append("%s: missing transcription %s" % (port, relative))
            continue
        # A C++ constant is namespace-qualified in the map but written bare in
        # the source, so the digest is looked for inside that namespace.
        text = path.read_text(encoding="utf-8")
        for fixture, (constant, _marker) in sorted(entries.items()):
            namespace, _, bare = constant.rpartition("::")
            haystack = text
            if namespace:
                start = text.find("namespace %s {" % namespace)
                if start < 0:
                    out.append("%s: %s has no namespace %s"
                               % (port, relative, namespace))
                    continue
                end = text.find("}  // namespace %s" % namespace, start)
                haystack = text[start:end if end > start else len(text)]
            match = None
            for pattern in DIGEST_PATTERNS:
                match = re.search(
                    pattern.format(name=re.escape(bare)), haystack)
                if match is not None:
                    break
            if match is None:
                out.append("%s: %s records no %s"
                           % (port, relative, constant))
                continue
            expected = hashlib.sha256(roots[fixture]).hexdigest()
            if match.group(1) != expected:
                out.append(
                    "%s: %s was transcribed from an older %s; regenerate with "
                    "scripts/internal/generate_segmentation_fixtures.py"
                    % (port, relative, fixture))
    return out


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

    # A copy under a port's tree that no port root claims is a stray: a
    # fixture root that moved, or a hand-made copy. It is not read by anything,
    # so it drifts silently unless the gate names it.
    expected_copies = {
        (ROOT / PORT_FIXTURE_ROOTS[port] / "segmentation" / fixture).resolve()
        for port in PORT_FIXTURE_ROOTS
        for fixture in FIXTURES
    }
    strays = sorted(
        path.relative_to(ROOT)
        for path in (ROOT / "ports").rglob("fixtures/segmentation/*.json")
        if path.resolve() not in expected_copies
    )

    failures.extend(transcription_failures(roots))

    absent: list[str] = []
    for port in sorted(PORT_TEST_ROOTS):
        for fixture in roots:
            if replays(port, fixture):
                continue
            if has_suite(port, fixture):
                pending.append(
                    "%s judges %s against its corpus but does not replay the "
                    "shared vectors" % (port, FIXTURE_CORPUS[fixture]))
            else:
                absent.append(
                    "%s has no suite for %s" % (port, FIXTURE_CORPUS[fixture]))

    for failure in failures:
        print("FATAL: %s" % failure, file=sys.stderr)
    for item in pending:
        print("PENDING: %s" % item)
    for item in absent:
        print("ABSENT:  %s" % item)
    for path in strays:
        print("STRAY:   %s is under no port's fixture root; delete it" % path)

    if strays and not args.list:
        print("FATAL: %d stray segmentation fixture copy/copies" % len(strays),
              file=sys.stderr)
        return 1
    if failures:
        return 1
    if pending and not args.list:
        print(
            "FATAL: %d port(s) judge a corpus but carry a weaker vector set "
            "than their siblings" % len(pending), file=sys.stderr)
        return 1
    print("clean: segmentation vector fixtures are in sync"
          + ("" if pending else " and every port with a suite replays them"))
    if absent:
        print("note: %d port/algorithm pair(s) have no suite at all; that is "
              "a missing implementation, not a weaker check" % len(absent))
    return 0


if __name__ == "__main__":
    sys.exit(main())
