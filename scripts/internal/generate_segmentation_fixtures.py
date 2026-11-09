#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
#                  // scripts // internal // segmentation-fixtures
# ─────────────────────────────────────────────────────────────────────────────
#
# Writes the shared segmentation vector fixtures and vendors a byte-identical
# copy into every port, so each port's segmentation tests ask the same
# questions rather than a per-port selection of them:
#
#   fixtures/segmentation/line_break_vectors.json
#       One case per UAX #14 rule the algorithm implements, each naming the
#       rule it pins, plus the published row count of LineBreakTest.txt.
#   fixtures/segmentation/grapheme_vectors.json
#       One case per UAX #29 rule, plus the published row count of
#       GraphemeBreakTest.txt.
#
# This is the mechanism the security layer already uses: a root fixture under
# `fixtures/`, a committed copy under each port's own fixture root, and a gate
# that the copies match. A port's test iterates the fixture, so adding a case
# here adds it to all sixteen ports at once and no port can quietly carry a
# weaker set.
#
# The two corpus gates stay separate from these vectors and remain the
# authority: agree with every published row, and account for the whole file so
# a lost row fails rather than shrinking the denominator. Hand-chosen vectors
# cannot establish a segmentation algorithm — its rules read context on both
# sides of a boundary — so these cases document which rule each boundary
# exercises and keep the ports honest about carrying the same set. The expected
# masks are computed here from the Python port, which answers every row of both
# published corpora; each of the other ports then has to agree with the same
# recorded bytes, so a wrong expectation would have to be wrong identically in
# every independent implementation.
#
#   python3 scripts/internal/generate_segmentation_fixtures.py
#
# Run from anywhere. Writing the root fixtures and the vendored copies is the
# whole effect.

import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

UCD = os.path.join(ROOT, "Unicode", "Ucd")
LINE_BREAK_TEST_TXT = os.path.join(UCD, "LineBreakTest.txt")
GRAPHEME_BREAK_TEST_TXT = os.path.join(UCD, "GraphemeBreakTest.txt")

sys.path.insert(0, os.path.join(ROOT, "ports", "python", "src"))

# The markers the published break corpora write at each boundary.
BREAK_MARKER = "÷"
NO_BREAK_MARKER = "×"

# Where each port keeps the fixtures it is tested against. Measured from the
# committed copies of the security fixtures: most ports vendor under
# `testdata/fixtures`, and the five that do not are the five named here.
# The Python port reads the root fixtures directly and vendors none, so it has
# no entry.
PORT_FIXTURE_ROOTS = {
    "cobol": "ports/cobol/testdata/fixtures",
    "cpp": "ports/cpp/testdata/fixtures",
    "dotnet": "ports/dotnet/testdata/fixtures",
    "elixir": "ports/elixir/test/fixtures",
    "erlang": "ports/erlang/test/fixtures",
    # Go's segmentation is its own package, so its fixtures go in that
    # package's testdata rather than the security package's: a Go test reads
    # testdata relative to its own package directory.
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

# One case per UAX #14 rule, as (rule, name, codepoints, expected classes).
# The name states what the boundary does, so a failure reads as a sentence
# rather than an index. The expected classes are asserted here against the
# reference's LB1-resolved lookup, and recorded in the fixture so each port
# checks its own tables against the same values: a case can only claim to
# exercise a rule whose classes it actually carries. An empty expectation
# records the classes without asserting them.
#
# The aksara classes are the reason this is asserted rather than trusted. A
# plausible-looking Gurmukhi sign stood in for an LB28a cluster base while
# resolving to CM, which made the case a restatement of LB9.
LINE_BREAK_CASES = [
    ("LB2/LB3", "start of text never breaks and end of text always does",
     [0x61, 0x62], ["AL", "AL"]),
    ("LB4", "a mandatory break character breaks after itself",
     [0x61, 0x000C, 0x62], ["AL", "BK", "AL"]),
    ("LB5", "carriage return line feed is not split",
     [0x0D, 0x0A, 0x61], ["CR", "LF", "AL"]),
    ("LB6", "no break falls before a mandatory break character",
     [0x61, 0x000A], ["AL", "LF"]),
    ("LB7", "no break falls before a space", [0x61, 0x20], ["AL", "SP"]),
    ("LB8", "a zero width space breaks after itself",
     [0x61, 0x200B, 0x62], ["AL", "ZW", "AL"]),
    ("LB8a", "a zero width joiner glues what follows it",
     [0x61, 0x200D, 0x62], ["AL", "ZWJ", "AL"]),
    ("LB9", "a combining mark takes the class of its base",
     [0x61, 0x0301], ["AL", "CM"]),
    ("LB10", "a combining mark with no base stands alone",
     [0x0301, 0x61], ["CM", "AL"]),
    ("LB11", "a word joiner glues both sides",
     [0x61, 0x2060, 0x62], ["AL", "WJ", "AL"]),
    ("LB12", "a non-breaking space glues what follows it",
     [0x61, 0x00A0, 0x62], ["AL", "GL", "AL"]),
    ("LB13", "no break falls before a closing parenthesis",
     [0x61, 0x29, 0x62], ["AL", "CP", "AL"]),
    ("LB14", "no break falls after an opening parenthesis",
     [0x28, 0x20, 0x61], ["OP", "SP", "AL"]),
    ("LB15a", "an opening quote outside a word glues what follows",
     [0x20, 0x2018, 0x61], ["SP", "QU", "AL"]),
    ("LB15b", "a closing quote before a space glues what precedes",
     [0x61, 0x2019, 0x20, 0x62], ["AL", "QU", "SP", "AL"]),
    ("LB15c", "a space before a number opening period breaks",
     [0x61, 0x20, 0x2E, 0x33, 0x35], ["AL", "SP", "IS", "NU", "NU"]),
    ("LB16", "a closing parenthesis and a following small kana hold together",
     [0x29, 0x3041], ["CP", "NS"]),
    ("LB17", "an em dash pair holds together across a space",
     [0x2014, 0x20, 0x2014], ["B2", "SP", "B2"]),
    ("LB19", "a quotation mark glues both of its sides",
     [0x61, 0x0022, 0x62], ["AL", "QU", "AL"]),
    ("LB20", "a contingent break opportunity breaks on both sides",
     [0x61, 0xFFFC, 0x62], ["AL", "CB", "AL"]),
    ("LB21", "a break-after character glues what precedes it",
     [0x61, 0x00AD, 0x62], ["AL", "BA", "AL"]),
    ("LB21a", "a Hebrew letter and a hyphen glue what follows",
     [0x05D0, 0x002D, 0x61], ["HL", "HY", "AL"]),
    ("LB21b", "a solidus and a following Hebrew letter hold together",
     [0x002F, 0x05D0], ["SY", "HL"]),
    ("LB22", "no break falls before an inseparable",
     [0x61, 0x2026, 0x62], ["AL", "IN", "AL"]),
    ("LB23", "a letter and a digit hold together", [0x61, 0x31],
     ["AL", "NU"]),
    ("LB23a", "a currency symbol and an ideograph hold together",
     [0x0024, 0x4E00], ["PR", "ID"]),
    ("LB24", "a prefix and a letter hold together", [0x0024, 0x61],
     ["PR", "AL"]),
    ("LB25", "a numeric chain holds together across its separator",
     [0x31, 0x2C, 0x30, 0x30, 0x30], ["NU", "IS", "NU", "NU", "NU"]),
    ("LB26", "Hangul jamo hold together", [0x1100, 0x1161, 0x11A8],
     ["JL", "JV", "JT"]),
    ("LB27", "a Hangul syllable and a following inseparable hold together",
     [0xAC00, 0x2026], ["H2", "IN"]),
    ("LB28", "two letters hold together", [0x61, 0x62], ["AL", "AL"]),
    ("LB28a.1", "an aksara pre-base glues the cluster base after it",
     [0x11003, 0x1B05], ["AP", "AK"]),
    ("LB28a.2", "a cluster base glues a following vowel form",
     [0x1B05, 0x1BF2], ["AK", "VF"]),
    ("LB28a.3", "a virama between cluster bases glues both",
     [0x1B05, 0x1B44, 0x1B05], ["AK", "VI", "AK"]),
    ("LB28a.4", "two cluster bases glue when a vowel form follows",
     [0x1B05, 0x1B05, 0x1BF2], ["AK", "AK", "VF"]),
    ("LB29", "a full stop and a following letter hold together",
     [0x002E, 0x61], ["IS", "AL"]),
    ("LB30", "a letter and an opening parenthesis hold together",
     [0x61, 0x28, 0x31], ["AL", "OP", "NU"]),
    ("LB30a", "regional indicators pair off",
     [0x1F1EF, 0x1F1F5, 0x1F1FA, 0x1F1F8], ["RI", "RI", "RI", "RI"]),
    ("LB30b", "an emoji modifier stays on its base",
     [0x1F466, 0x1F3FB], ["EB", "EM"]),
    ("LB31", "a space opens the next line", [0x61, 0x20, 0x62],
     ["AL", "SP", "AL"]),
    ("LB1", "an empty sequence carries one boundary", [], []),
]

# One case per UAX #29 rule, as (rule, name, codepoints, expected classes).
# The classes are Grapheme_Cluster_Break values, asserted and recorded the same
# way.
GRAPHEME_CASES = [
    ("GB1/GB2", "start and end of text are both boundaries", [0x61],
     ["Other"]),
    ("GB3", "carriage return line feed is one cluster", [0x0D, 0x0A],
     ["CR", "LF"]),
    ("GB4", "a control character ends its cluster", [0x0D, 0x61],
     ["CR", "Other"]),
    ("GB5", "a control character starts its own cluster", [0x61, 0x0D],
     ["Other", "CR"]),
    ("GB6", "a leading jamo and a vowel jamo hold together",
     [0x1100, 0x1161], ["L", "V"]),
    ("GB7", "a vowel jamo and a trailing jamo hold together",
     [0x1161, 0x11A8], ["V", "T"]),
    ("GB8", "a syllable and a trailing jamo hold together",
     [0xAC01, 0x11A8], ["LVT", "T"]),
    ("GB9", "a combining mark joins its base", [0x65, 0x0301],
     ["Other", "Extend"]),
    ("GB9a", "a spacing mark joins its base", [0x0915, 0x093E],
     ["Other", "SpacingMark"]),
    ("GB9b", "a prepended concatenation mark joins what follows",
     [0x0600, 0x0661], ["Prepend", "Other"]),
    ("GB9c", "an Indic conjunct holds together across its linker",
     [0x0915, 0x094D, 0x0916], ["Other", "Extend", "Other"]),
    ("GB11", "an emoji zero-width-joiner sequence is one cluster",
     [0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467],
     ["Other", "ZWJ", "Other", "ZWJ", "Other"]),
    ("GB12/GB13", "regional indicators pair off",
     [0x1F1EF, 0x1F1F5, 0x1F1FA, 0x1F1F8],
     ["Regional_Indicator", "Regional_Indicator",
      "Regional_Indicator", "Regional_Indicator"]),
    ("GB999", "two letters are two clusters", [0x61, 0x62],
     ["Other", "Other"]),
    ("GB1", "an empty sequence carries one boundary", [], []),
]


def strip_comment(line):
    return line.split("#", 1)[0].strip()


def count_published_rows(path):
    """How many data rows a published break corpus carries, validating each.

    A row alternates boundary markers and code points, starting and ending
    with a marker, so it carries one more flag than code points. A row that
    does not is a corpus a test cannot read, and the count it would report
    would be wrong rather than short.
    """
    count = 0
    with open(path, "r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            body = strip_comment(line)
            if not body:
                continue
            codepoints = 0
            flags = 0
            expecting_marker = True
            for token in body.split():
                if token in (BREAK_MARKER, NO_BREAK_MARKER):
                    if not expecting_marker:
                        raise SystemExit(
                            "%s line %d has two markers in a row"
                            % (os.path.basename(path), number))
                    flags += 1
                    expecting_marker = False
                else:
                    if expecting_marker:
                        raise SystemExit(
                            "%s line %d has two code points in a row"
                            % (os.path.basename(path), number))
                    int(token, 16)
                    codepoints += 1
                    expecting_marker = True
            if expecting_marker:
                raise SystemExit(
                    "%s line %d ends at a code point rather than a boundary "
                    "marker" % (os.path.basename(path), number))
            if flags != codepoints + 1:
                raise SystemExit(
                    "%s line %d carries %d flags for %d code points"
                    % (os.path.basename(path), number, flags, codepoints))
            count += 1
    return count


def build_cases(cases, breaks_of, class_of):
    """Each case with its boundary mask and per-code-point class.

    The mask comes from the reference and is what every port must reproduce.

    The classes are recorded as canonical UCD property values and asserted
    against the case's declaration, so a case cannot claim a rule whose classes
    it does not carry. A case declaring no classes records them unasserted.
    They are documentation plus an optional second check: the ports spell a
    class differently inside themselves -- `CR`, `Cr`, `:cr`, `LbCR` -- so a
    port asserts them only where it can name a class in the canonical form.
    """
    out = []
    seen = set()
    for rule, name, codepoints, expected_classes in cases:
        if name in seen:
            raise SystemExit("two cases share the name %r" % name)
        seen.add(name)

        mask = breaks_of(codepoints)
        if len(mask) != len(codepoints) + 1:
            raise SystemExit(
                "case %r produced %d flags for %d code points"
                % (name, len(mask), len(codepoints)))

        classes = [str(class_of(cp)) for cp in codepoints]
        if expected_classes and classes != list(expected_classes):
            raise SystemExit(
                "case %r (%s) declares classes %s but its code points carry %s"
                % (name, rule, list(expected_classes), classes))

        out.append({
            "rule": rule,
            "name": name,
            "input": list(codepoints),
            "classes": classes,
            "breaks": [bool(flag) for flag in mask],
        })
    return out


def render(document):
    """The fixture as bytes, in the shape the security fixtures are written."""
    return json.dumps(document, indent=2, ensure_ascii=True) + "\n"


def rust_cases(prefix, document, text):
    """One algorithm's cases as a Rust slice of `VectorCase`.

    The Rust crate carries no dependencies at all, so its tests have no JSON
    reader; it already consumes its published corpora as generated source
    rather than parsing the files at run time, and the vectors arrive the same
    way. The fixture stays the single source of truth: the digest below is of
    the fixture this was generated from, and the gate recomputes it, so a
    transcription that falls behind the fixture is a failure rather than a
    silent divergence.
    """
    lines = [
        "/// The algorithm %s's cases judge." % prefix.lower(),
        'pub const %s_ALGORITHM: &str = "%s";'
        % (prefix, document["algorithm"]),
        "",
        "/// SHA-256 of the fixture these cases were transcribed from.",
        'pub const %s_FIXTURE_DIGEST: &str = "%s";'
        % (prefix, hashlib.sha256(text.encode("utf-8")).hexdigest()),
        "",
        "/// How many rows the algorithm's published corpus carries, so the",
        "/// corpus gate and the vector gate cannot drift apart.",
        "pub const %s_PUBLISHED_ROW_COUNT: usize = %d;"
        % (prefix, document["published_row_count"]),
        "",
        "/// One case per rule, the same bytes every port replays.",
        "pub static %s_CASES: &[VectorCase] = &[" % prefix,
    ]
    for case in document["cases"]:
        points = ", ".join("0x%04X" % cp for cp in case["input"])
        classes = ", ".join('"%s"' % value for value in case["classes"])
        marks = ", ".join("true" if flag else "false" for flag in case["breaks"])
        lines.append("    VectorCase {")
        lines.append('        rule: "%s",' % case["rule"])
        lines.append('        name: "%s",' % case["name"])
        lines.append("        input: &[%s]," % points)
        lines.append("        classes: &[%s]," % classes)
        lines.append("        breaks: &[%s]," % marks)
        lines.append("    },")
    lines.append("];")
    return "\n".join(lines)


def rust_vector_module(documents, texts):
    """The Rust transcription of both shared vector fixtures."""
    return "\n".join([
        "//! The shared segmentation vector fixtures, as data.",
        "//!",
        "//! One case per UAX rule, the same bytes every port replays, so each",
        "//! port's segmentation tests ask the same questions instead of a",
        "//! per-port selection of them. The published corpora in this module's",
        "//! siblings are the authority; these name which rule each boundary",
        "//! exercises.",
        "//!",
        "//! Transcribed from `fixtures/segmentation/line_break_vectors.json`",
        "//! and `fixtures/segmentation/grapheme_vectors.json`. This crate has",
        "//! no dependencies, so its tests have no JSON reader; it already",
        "//! consumes its published corpora as generated source, and the",
        "//! vectors arrive the same way. Each digest below is of the fixture",
        "//! its cases came from, and the fixture gate recomputes it.",
        "//!",
        "//! Generated by `scripts/internal/generate_segmentation_fixtures.py`.",
        "//! Edit that script and regenerate rather than editing this file.",
        "",
        "/// One published case: the rule it pins, what the boundary does, the",
        "/// code points, each code point's canonical UCD class, and the",
        "/// expected boundary mask.",
        "///",
        "/// The mask is the contract every port reproduces. The classes are",
        "/// recorded for reading: this crate names a class `Al` where the UCD",
        "/// writes `AL`, so comparing them would test a spelling rather than a",
        "/// property.",
        "pub struct VectorCase {",
        "    pub rule: &'static str,",
        "    pub name: &'static str,",
        "    pub input: &'static [u32],",
        "    pub classes: &'static [&'static str],",
        "    pub breaks: &'static [bool],",
        "}",
        "",
        rust_cases("LINE_BREAK", documents["line_break"], texts["line_break"]),
        "",
        rust_cases("GRAPHEME", documents["grapheme"], texts["grapheme"]),
        "",
    ])


def write_file(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


def main():
    from unicode_python.segmentation.grapheme import grapheme_breaks, lookup_gcb
    from unicode_python.segmentation.line_break import line_breaks, resolved_class

    line_break_document = {
        "schema": 1,
        "algorithm": "uax14-line-break",
        "corpus": "LineBreakTest.txt",
        "class_property": "Line_Break, LB1-resolved, as UCD property values",
        "published_row_count": count_published_rows(LINE_BREAK_TEST_TXT),
        "cases": build_cases(LINE_BREAK_CASES, line_breaks, resolved_class),
    }
    grapheme_document = {
        "schema": 1,
        "algorithm": "uax29-grapheme-cluster",
        "corpus": "GraphemeBreakTest.txt",
        "class_property": "Grapheme_Cluster_Break, as UCD property values",
        "published_row_count": count_published_rows(GRAPHEME_BREAK_TEST_TXT),
        "cases": build_cases(GRAPHEME_CASES, grapheme_breaks, lookup_gcb),
    }

    written = []
    texts = {}
    for key, name, document in (
        ("line_break", "line_break_vectors.json", line_break_document),
        ("grapheme", "grapheme_vectors.json", grapheme_document),
    ):
        text = render(document)
        texts[key] = text
        root_path = os.path.join(ROOT, "fixtures", "segmentation", name)
        write_file(root_path, text)
        written.append(os.path.relpath(root_path, ROOT))
        for port in sorted(PORT_FIXTURE_ROOTS):
            copy = os.path.join(
                ROOT, PORT_FIXTURE_ROOTS[port], "segmentation", name)
            write_file(copy, text)
            written.append(os.path.relpath(copy, ROOT))

    # The Rust crate has no dependencies, so it consumes a transcription rather
    # than parsing the fixture at run time.
    rust_module = os.path.join(
        ROOT, "ports", "rust", "tests", "corpus", "vector_cases.rs")
    write_file(rust_module, rust_vector_module(
        {"line_break": line_break_document, "grapheme": grapheme_document},
        texts))
    written.append(os.path.relpath(rust_module, ROOT))

    sys.stdout.write(
        "line-break vectors: %d cases, %d published rows\n"
        % (len(line_break_document["cases"]),
           line_break_document["published_row_count"]))
    sys.stdout.write(
        "grapheme vectors:   %d cases, %d published rows\n"
        % (len(grapheme_document["cases"]),
           grapheme_document["published_row_count"]))
    sys.stdout.write("wrote %d files (1 root + %d ports, per algorithm)\n"
                     % (len(written), len(PORT_FIXTURE_ROOTS)))


if __name__ == "__main__":
    main()
