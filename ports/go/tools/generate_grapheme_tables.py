#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
#                       // tools // generate // grapheme-tables
# ─────────────────────────────────────────────────────────────────────────────
#
# Emits the property tables the UAX #29 grapheme cluster breaker reads and
# vendors the published corpus it is judged against, from the pinned UCD files
# in the repository root:
#
#   segmentation/grapheme_tables.go
#       Two of the three properties the algorithm reads —
#       Grapheme_Cluster_Break, a port of
#       `Unicode.Generated.GraphemeBreakProperty`, and Indic_Conjunct_Break,
#       a port of `Unicode.Generated.IndicConjunctBreak` — plus the corpus row
#       count.
#
#       The third, Extended_Pictographic, is already in this package:
#       `IsExtendedPictographic` in line_break_tables.go serves LB30b, and
#       GB11 reads the same property from the same table.
#   segmentation/testdata/GraphemeBreakTest.txt
#       The published corpus, where the go tool's own testdata convention puts
#       a package's fixtures.
#
# The tables are generated into source rather than parsed at load, so a
# segmentation package takes code points and needs no data directory.
#
# Each table carries coalesced inclusive ranges sorted by lower bound, so a
# lookup binary-searches for the one range covering a code point. Coalescing
# rejects overlapping rows, which is what makes the search agree with the
# linear first-match of the Lean reference: with disjoint ranges the covering
# range is unique, so whichever one a search finds is the one a scan in file
# order would have found first. Every element is a constant, so the tables are
# static data rather than work done at init.
#
#   python3 ports/go/tools/generate_grapheme_tables.py
#
# Run from anywhere. Writing the table file and the corpus is the whole effect.

import os
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

UCD = os.path.join(ROOT, "Unicode", "Ucd")
GRAPHEME_BREAK_PROPERTY_TXT = os.path.join(UCD, "GraphemeBreakProperty.txt")
DERIVED_CORE_PROPERTIES_TXT = os.path.join(UCD, "DerivedCoreProperties.txt")
GRAPHEME_BREAK_TEST_TXT = os.path.join(UCD, "GraphemeBreakTest.txt")

PORT = os.path.join(ROOT, "ports", "go")
GRAPHEME_TABLES_GO = os.path.join(PORT, "segmentation", "grapheme_tables.go")
VENDORED_CORPUS = os.path.join(
    PORT, "segmentation", "testdata", "GraphemeBreakTest.txt")

# The markers the published break corpora write at each boundary.
BREAK_MARKER = "÷"
NO_BREAK_MARKER = "×"

# The 14 Grapheme_Cluster_Break property values UAX #29 defines, as the UCD
# spells each one and as the generated Go constant does. A UCD value is a
# property value name and may carry an underscore; a Go constant is written in
# the language's own case convention.
#
# Other leads the list so it is the zero value of the type, which is what a
# code point no range covers carries: GraphemeBreakProperty.txt declares the
# default in its own `@missing: 0000..10FFFF; Other` header. The remaining
# order mirrors the Lean parseGCB?.
GCB_VALUES = [
    ("Other", "Other"),
    ("CR", "CR"),
    ("LF", "LF"),
    ("Control", "Control"),
    ("Extend", "Extend"),
    ("ZWJ", "ZWJ"),
    ("Regional_Indicator", "RegionalIndicator"),
    ("Prepend", "Prepend"),
    ("SpacingMark", "SpacingMark"),
    ("L", "L"),
    ("V", "V"),
    ("T", "T"),
    ("LV", "LV"),
    ("LVT", "LVT"),
]

# The four Indic_Conjunct_Break values, None leading for the same reason —
# DerivedCoreProperties.txt declares `@missing: 0000..10FFFF; InCB; None`.
INCB_VALUES = [
    ("None", "None"),
    ("Consonant", "Consonant"),
    ("Extend", "Extend"),
    ("Linker", "Linker"),
]

# The literal that marks a DerivedCoreProperties.txt row as carrying the
# Indic_Conjunct_Break sub-property. Such a row has three fields — the range,
# this literal, and the value — where a row for any other property has two.
INCB_TAG = "InCB"


def strip_comment(line):
    return line.split("#", 1)[0].strip()


def parse_range_field(field):
    field = field.strip()
    if ".." in field:
        lo_text, hi_text = field.split("..", 1)
        return int(lo_text, 16), int(hi_text, 16)
    point = int(field, 16)
    return point, point


def read_grapheme_cluster_break_rows():
    """Explicit (lo, hi, value) rows of GraphemeBreakProperty.txt.

    A value the generator does not carry is a file naming a property value
    this port has no constant for, so the emitted table would silently omit
    those code points. That aborts rather than writing a short table.
    """
    admitted = {ucd for ucd, _go in GCB_VALUES}
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
            if value not in admitted:
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
    admitted = {ucd for ucd, _go in INCB_VALUES}
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
            if value not in admitted:
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


def format_enum(doc, type_name, prefix, values, underlying_doc):
    lines = [
        "// %s" % doc,
        "type %s uint8" % type_name,
        "",
        "// %s" % underlying_doc,
        "const (",
    ]
    for index, (_ucd, go_name) in enumerate(values):
        suffix = " %s = iota" % type_name if index == 0 else ""
        lines.append("\t%s%s%s" % (prefix, go_name, suffix))
    lines.append(")")
    return "\n".join(lines)


def format_range_type(name, class_type):
    return "\n".join([
        "// %s is one inclusive range of the property, [lo, hi]." % name,
        "type %s struct {" % name,
        "\tlo    uint32",
        "\thi    uint32",
        "\tclass %s" % class_type,
        "}",
    ])


def format_table(array, range_type, prefix, values, ranges):
    constant = {ucd: go_name for ucd, go_name in values}
    lines = ["var %s = [%d]%s{" % (array, len(ranges), range_type)]
    for lo, hi, value in ranges:
        lines.append("\t{0x%04X, 0x%04X, %s%s},"
                     % (lo, hi, prefix, constant[value]))
    lines.append("}")
    return "\n".join(lines)


def format_lookup(func, doc, array, class_type, default):
    return "\n".join([
        "// %s" % doc,
        "//",
        "// The ranges are sorted by lower bound and disjoint, so the covering",
        "// range is unique and a binary search finds it.",
        "func %s(cp uint32) %s {" % (func, class_type),
        "\tlo, hi := 0, len(%s)" % array,
        "\tfor lo < hi {",
        "\t\tmid := lo + (hi-lo)/2",
        "\t\tentry := %s[mid]" % array,
        "\t\tswitch {",
        "\t\tcase cp < entry.lo:",
        "\t\t\thi = mid",
        "\t\tcase cp > entry.hi:",
        "\t\t\tlo = mid + 1",
        "\t\tdefault:",
        "\t\t\treturn entry.class",
        "\t\t}",
        "\t}",
        "\treturn %s" % default,
        "}",
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

    write_file(GRAPHEME_TABLES_GO, "\n".join([
        "// Code generated by tools/generate_grapheme_tables.py. DO NOT EDIT.",
        "",
        "package segmentation",
        "",
        "// Property tables the UAX #29 grapheme cluster breaker reads,",
        "// generated from the pinned UCD 17.0.0 files — ports of",
        "// Unicode.Generated.{GraphemeBreakProperty,IndicConjunctBreak}. Same",
        "// ranges, same class values.",
        "//",
        "// The third property the rules read, Extended_Pictographic, is the one",
        "// LB30b reads: GB11 calls IsExtendedPictographic from",
        "// line_break_tables.go rather than carrying a second copy.",
        "//",
        "// Grapheme_Cluster_Break ranges: %d, Indic_Conjunct_Break ranges: %d."
        % (len(gcb_ranges), len(incb_ranges)),
        "//",
        "// Every table is sorted by lower bound and coalesced, and every element",
        "// is a constant, so each table is static data rather than work done at",
        "// init.",
        "",
        format_enum(
            "Gcb is a UAX #29 Grapheme_Cluster_Break property value.",
            "Gcb", "Gcb", GCB_VALUES,
            "The 14 Grapheme_Cluster_Break values. GcbOther leads, so the zero\n"
            "// value of the type is the one a code point outside every range\n"
            "// carries."),
        "",
        format_enum(
            "Incb is a UAX #29 Indic_Conjunct_Break property value, the "
            "sub-property\n// GB9c reads.",
            "Incb", "Incb", INCB_VALUES,
            "The four Indic_Conjunct_Break values. IncbNone leads, so the zero\n"
            "// value of the type is the one a code point outside every range\n"
            "// carries."),
        "",
        format_range_type("gcbRange", "Gcb"),
        "",
        format_range_type("incbRange", "Incb"),
        "",
        format_table("gcbRanges", "gcbRange", "Gcb", GCB_VALUES, gcb_ranges),
        "",
        format_table("incbRanges", "incbRange", "Incb", INCB_VALUES,
                     incb_ranges),
        "",
        format_lookup(
            "GcbOf",
            "GcbOf returns the Grapheme_Cluster_Break class of cp, GcbOther\n"
            "// when no range covers it — the default\n"
            "// GraphemeBreakProperty.txt's own @missing: 0000..10FFFF; Other\n"
            "// header declares.",
            "gcbRanges", "Gcb", "GcbOther"),
        "",
        format_lookup(
            "IncbOf",
            "IncbOf returns the Indic_Conjunct_Break class of cp, IncbNone\n"
            "// when no range covers it — the default\n"
            "// DerivedCoreProperties.txt's own @missing: 0000..10FFFF; InCB;\n"
            "// None header declares.",
            "incbRanges", "Incb", "IncbNone"),
        "",
        "// GraphemePublishedRowCount is how many data rows the pinned corpus",
        "// carries, counted from the canonical GraphemeBreakTest.txt at",
        "// generation. The corpus gate asserts the rows it reads from the",
        "// vendored copy against this, so a row lost between the two fails",
        "// rather than quietly shrinking the denominator.",
        "const GraphemePublishedRowCount = %d" % published_rows,
        "",
    ]))

    os.makedirs(os.path.dirname(VENDORED_CORPUS), exist_ok=True)
    shutil.copyfile(GRAPHEME_BREAK_TEST_TXT, VENDORED_CORPUS)
    sys.stdout.write("wrote %s (%d published rows)\n" % (
        os.path.relpath(VENDORED_CORPUS, ROOT), published_rows))


if __name__ == "__main__":
    main()
