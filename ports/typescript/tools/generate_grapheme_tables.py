#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
#                       // tools // generate // grapheme-tables
# ─────────────────────────────────────────────────────────────────────────────
#
# Emits the property tables the UAX #29 grapheme cluster breaker reads and
# vendors the published corpus it is judged against, from the pinned UCD files
# in the repository root:
#
#   src/segmentation/grapheme-tables.js
#       Two of the three properties the algorithm reads —
#       Grapheme_Cluster_Break, a port of
#       `Unicode.Generated.GraphemeBreakProperty`, and Indic_Conjunct_Break, a
#       port of `Unicode.Generated.IndicConjunctBreak` — plus the corpus row
#       count.
#
#       The third, Extended_Pictographic, is already in this directory:
#       `isExtendedPictographic` in line-break.js serves LB30b, and GB11 reads
#       the same property from the same table.
#   testdata/GraphemeBreakTest.txt
#       The published corpus, which the test reads at run time.
#
# The tables are generated into source rather than read from `src/data/`. The
# package serves its data tables only through the digest-verifying reader
# `security.js` installs, which refuses an unpinned or altered table; a
# segmentation module opening a data file itself would be a second data path
# outside that gate. A generated table is code, so it sits behind the same
# trust anchor as the algorithm reading it, and the module needs no host file
# access — which is also what lets it run on the edge build.
#
# Each table carries coalesced inclusive ranges sorted by lower bound, held as
# parallel typed arrays so a lookup binary-searches without allocating.
# Coalescing rejects overlapping rows, which is what makes the search agree
# with the linear first-match of the Lean reference: with disjoint ranges the
# covering range is unique, so whichever one a search finds is the one a scan
# in file order would have found first.
#
#   python3 ports/typescript/tools/generate_grapheme_tables.py
#
# Run from anywhere. Writing the table module and the corpus is the whole
# effect.

import os
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

UCD = os.path.join(ROOT, "Unicode", "Ucd")
GRAPHEME_BREAK_PROPERTY_TXT = os.path.join(UCD, "GraphemeBreakProperty.txt")
DERIVED_CORE_PROPERTIES_TXT = os.path.join(UCD, "DerivedCoreProperties.txt")
GRAPHEME_BREAK_TEST_TXT = os.path.join(UCD, "GraphemeBreakTest.txt")

PORT = os.path.join(ROOT, "ports", "typescript")
TABLES_JS = os.path.join(PORT, "src", "segmentation", "grapheme-tables.js")
VENDORED_CORPUS = os.path.join(PORT, "testdata", "GraphemeBreakTest.txt")

# The markers the published break corpora write at each boundary.
BREAK_MARKER = "÷"
NO_BREAK_MARKER = "×"

# The 14 Grapheme_Cluster_Break property values UAX #29 defines. Other leads
# the list so index 0 is the value a code point no range covers carries, which
# GraphemeBreakProperty.txt declares in its own
# `@missing: 0000..10FFFF; Other` header. The rest mirror the Lean parseGCB?.
GCB_VALUES = [
    "Other", "CR", "LF", "Control", "Extend", "ZWJ", "Regional_Indicator",
    "Prepend", "SpacingMark", "L", "V", "T", "LV", "LVT",
]

# The four Indic_Conjunct_Break values, None leading for the same reason —
# DerivedCoreProperties.txt declares `@missing: 0000..10FFFF; InCB; None`.
INCB_VALUES = ["None", "Consonant", "Extend", "Linker"]

# The literal that marks a DerivedCoreProperties.txt row as carrying the
# Indic_Conjunct_Break sub-property. Such a row has three fields — the range,
# this literal, and the value — where a row for any other property has two.
INCB_TAG = "InCB"


def strip_comment(line):
    return line.split("#", 1)[0].strip()


def parse_range_field(text):
    text = text.strip()
    if ".." in text:
        lo_text, hi_text = text.split("..", 1)
        return int(lo_text, 16), int(hi_text, 16)
    point = int(text, 16)
    return point, point


def read_grapheme_cluster_break_rows():
    """Explicit (lo, hi, value) rows of GraphemeBreakProperty.txt.

    A value the generator does not carry is a file naming a property value
    this port has no entry for, so the emitted table would silently omit
    those code points. That aborts rather than writing a short table.
    """
    rows = []
    with open(GRAPHEME_BREAK_PROPERTY_TXT, "r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            body = strip_comment(line)
            if not body:
                continue
            fields = body.split(";")
            if len(fields) < 2:
                continue
            value = fields[1].strip()
            if value not in GCB_VALUES:
                raise SystemExit(
                    "GraphemeBreakProperty.txt line %d names a "
                    "Grapheme_Cluster_Break value the generator does not "
                    "carry: %r" % (number, value))
            lo, hi = parse_range_field(fields[0])
            rows.append((lo, hi, value))
    if not rows:
        raise SystemExit(
            "GraphemeBreakProperty.txt names no Grapheme_Cluster_Break range")
    return rows


def read_indic_conjunct_break_rows():
    """Explicit (lo, hi, value) InCB rows of DerivedCoreProperties.txt.

    The file carries many properties; a row belongs to this one when its
    second field is the InCB literal, and then its third field is the value.
    """
    rows = []
    with open(DERIVED_CORE_PROPERTIES_TXT, "r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            body = strip_comment(line)
            if not body:
                continue
            fields = body.split(";")
            if len(fields) < 3 or fields[1].strip() != INCB_TAG:
                continue
            value = fields[2].strip()
            if value not in INCB_VALUES:
                raise SystemExit(
                    "DerivedCoreProperties.txt line %d names an "
                    "Indic_Conjunct_Break value the generator does not carry: "
                    "%r" % (number, value))
            lo, hi = parse_range_field(fields[0])
            rows.append((lo, hi, value))
    if not rows:
        raise SystemExit(
            "DerivedCoreProperties.txt names no Indic_Conjunct_Break range")
    return rows


def count_break_test_rows():
    """How many data rows GraphemeBreakTest.txt carries, validating each.

    A row alternates boundary markers and code points, starting and ending
    with a marker, so it carries one more flag than code points. A row that
    does not is a corpus the test cannot read, and the count it would report
    would be wrong rather than short.
    """
    count = 0
    with open(GRAPHEME_BREAK_TEST_TXT, "r", encoding="utf-8") as handle:
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
                            "GraphemeBreakTest.txt line %d has two markers in "
                            "a row" % number)
                    flags += 1
                    expecting_marker = False
                else:
                    if expecting_marker:
                        raise SystemExit(
                            "GraphemeBreakTest.txt line %d has two code "
                            "points in a row" % number)
                    int(token, 16)
                    codepoints += 1
                    expecting_marker = True
            if expecting_marker:
                raise SystemExit(
                    "GraphemeBreakTest.txt line %d ends at a code point "
                    "rather than a boundary marker" % number)
            if flags != codepoints + 1:
                raise SystemExit(
                    "GraphemeBreakTest.txt line %d carries %d flags for %d "
                    "code points" % (number, flags, codepoints))
            count += 1
    return count


def coalesce(rows):
    """Sorted, coalesced ranges: adjacent rows of one value become one range.

    Rejects overlapping rows, since a property whose ranges overlap has no
    unique covering range and a binary search over it would be ill-defined.
    """
    ordered = sorted(rows, key=lambda row: row[0])
    out = []
    for lo, hi, value in ordered:
        if out:
            prev_lo, prev_hi, prev_value = out[-1]
            if lo <= prev_hi:
                raise SystemExit(
                    "property ranges overlap: U+%04X..U+%04X and "
                    "U+%04X..U+%04X" % (prev_lo, prev_hi, lo, hi))
            if value == prev_value and lo == prev_hi + 1:
                out[-1] = (prev_lo, hi, value)
                continue
        out.append((lo, hi, value))
    return out


def wrapped(values, per_line, render):
    """One `render`ed value per element, `per_line` to a line, indented."""
    lines = []
    current = []
    for value in values:
        current.append(render(value))
        if len(current) == per_line:
            lines.append("  " + ", ".join(current) + ",")
            current = []
    if current:
        lines.append("  " + ", ".join(current) + ",")
    return "\n".join(lines)


def format_class_list(name, doc, values):
    return "\n".join([
        doc,
        "export const %s = Object.freeze([" % name,
        wrapped(values, 6, lambda value: '"%s"' % value),
        "]);",
    ])


def format_table(name, doc, ranges, values):
    """Three parallel typed arrays: starts, ends and class indices."""
    index_of = {value: index for index, value in enumerate(values)}
    return "\n".join([
        doc,
        "export const %s = Object.freeze({" % name,
        "  start: Uint32Array.from([",
        wrapped([row[0] for row in ranges], 10, lambda cp: "0x%04X" % cp),
        "  ]),",
        "  end: Uint32Array.from([",
        wrapped([row[1] for row in ranges], 10, lambda cp: "0x%04X" % cp),
        "  ]),",
        "  cls: Uint8Array.from([",
        wrapped([index_of[row[2]] for row in ranges], 20, lambda i: "%d" % i),
        "  ]),",
        "});",
    ])


def write_file(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    sys.stdout.write("wrote %s (%d lines)\n" % (
        os.path.relpath(path, ROOT), text.count("\n")))


def main():
    gcb_ranges = coalesce(read_grapheme_cluster_break_rows())
    incb_ranges = coalesce(read_indic_conjunct_break_rows())
    published_rows = count_break_test_rows()

    write_file(TABLES_JS, "\n".join([
        "// GENERATED FILE - DO NOT EDIT.",
        "// Regenerate with tools/generate_grapheme_tables.py.",
        "//",
        "// Property tables the UAX #29 grapheme cluster breaker reads, from the",
        "// pinned UCD 17.0.0 files -- ports of",
        "// Unicode.Generated.{GraphemeBreakProperty,IndicConjunctBreak}. Same",
        "// property values, same ranges.",
        "//",
        "// The third property the rules read, Extended_Pictographic, is the one",
        "// LB30b reads: GB11 calls isExtendedPictographic from line-break.js",
        "// rather than carrying a second copy.",
        "//",
        "// Grapheme_Cluster_Break ranges: %d, Indic_Conjunct_Break ranges: %d."
        % (len(gcb_ranges), len(incb_ranges)),
        "//",
        "// These are code rather than entries under src/data/ on purpose. The",
        "// package serves its data tables only through the digest-verifying",
        "// reader security.js installs, which refuses an unpinned or altered",
        "// table; a segmentation module opening a data file itself would be a",
        "// second data path outside that gate. As code these sit behind the same",
        "// trust anchor as the algorithm reading them, and the module needs no",
        "// host file access.",
        "//",
        "// Each table is three parallel typed arrays -- range starts, range ends",
        "// and class indices into the matching class list -- sorted by start and",
        "// coalesced, so a lookup binary-searches without allocating. The ranges",
        "// of each property are disjoint, so the covering range is unique and the",
        "// search agrees with the Lean reference's linear first-match.",
        "",
        format_class_list(
            "GRAPHEME_CLUSTER_BREAK_VALUES",
            "// The 14 Grapheme_Cluster_Break property values, indexed by class\n"
            '// code. "Other" is index 0, the value a codepoint outside every\n'
            "// range carries.",
            GCB_VALUES),
        "",
        format_class_list(
            "INDIC_CONJUNCT_BREAK_VALUES",
            "// The four Indic_Conjunct_Break values, indexed by class code,\n"
            "// which GB9c reads. \"None\" is index 0, the value a codepoint the\n"
            "// file does not list carries.",
            INCB_VALUES),
        "",
        format_table(
            "GRAPHEME_CLUSTER_BREAK_RANGES",
            '// Grapheme_Cluster_Break ranges. A codepoint no range covers is\n'
            '// "Other", which the file\'s own `@missing: 0000..10FFFF; Other`\n'
            "// header declares.",
            gcb_ranges, GCB_VALUES),
        "",
        format_table(
            "INDIC_CONJUNCT_BREAK_RANGES",
            "// Indic_Conjunct_Break ranges, which GB9c reads. A codepoint the\n"
            '// file does not list is "None", which its own\n'
            "// `@missing: 0000..10FFFF; InCB; None` header declares.",
            incb_ranges, INCB_VALUES),
        "",
        "// How many data rows the pinned corpus carries, counted from the",
        "// canonical GraphemeBreakTest.txt at generation. The corpus gate asserts",
        "// the rows it reads from the vendored copy against this, so a row lost",
        "// between the two fails rather than quietly shrinking the denominator.",
        "export const GRAPHEME_PUBLISHED_ROW_COUNT = %d;" % published_rows,
        "",
    ]))

    os.makedirs(os.path.dirname(VENDORED_CORPUS), exist_ok=True)
    shutil.copyfile(GRAPHEME_BREAK_TEST_TXT, VENDORED_CORPUS)
    sys.stdout.write("wrote %s (%d published rows)\n" % (
        os.path.relpath(VENDORED_CORPUS, ROOT), published_rows))


if __name__ == "__main__":
    main()
