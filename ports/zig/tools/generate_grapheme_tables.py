#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
#                       // tools // generate // grapheme-tables
# ─────────────────────────────────────────────────────────────────────────────
#
# Emits the property tables the UAX #29 grapheme cluster breaker reads and
# vendors the published corpus it is judged against, from the pinned UCD files
# in the repository root:
#
#   src/grapheme_data.zig
#       The two properties this port did not already carry —
#       Grapheme_Cluster_Break, a port of
#       `Unicode.Generated.GraphemeBreakProperty`, and Indic_Conjunct_Break, a
#       port of `Unicode.Generated.IndicConjunctBreak` — plus the corpus row
#       count.
#   testdata/GraphemeBreakTest.txt
#       The published corpus, which the test reads at run time.
#
# Extended_Pictographic is not emitted. `src/line_break_data.zig` already
# carries it for LB30b, and `grapheme.zig` reads that table through
# `line_break.isExtendedPictographic`, so GB11 and LB30b answer from one copy.
#
# Each table emitted here carries coalesced inclusive ranges sorted by lower
# bound, so a lookup binary-searches for the one range covering a code point.
# Coalescing rejects overlapping rows, which is what makes the search agree
# with the linear first-match of the Lean reference: with disjoint ranges the
# covering range is unique, so whichever one a search finds is the one a scan
# in file order would have found first.
#
#   python3 ports/zig/tools/generate_grapheme_tables.py
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

PORT = os.path.join(ROOT, "ports", "zig")
GRAPHEME_DATA_ZIG = os.path.join(PORT, "src", "grapheme_data.zig")
VENDORED_CORPUS = os.path.join(PORT, "testdata", "GraphemeBreakTest.txt")

# The markers the published break corpora write at each boundary.
BREAK_MARKER = "÷"
NO_BREAK_MARKER = "×"

# The 14 Grapheme_Cluster_Break property values UAX #29 defines, as the UCD
# spells each one and as the generated Zig enum field does.
#
# The line-break generator lowercases a UCD value to get its field, which
# suffices for an alphabet of short acronyms. These values are words, so the
# mapping is written out: `SpacingMark` becomes `.spacing_mark` rather than
# `.spacingmark`, which is the port's own convention for a multi-word field.
#
# Other leads the list so it is the first field, which is the value a code
# point no range covers carries: GraphemeBreakProperty.txt declares the default
# in its own `@missing: 0000..10FFFF; Other` header. The rest mirror the Lean
# parseGCB?.
GCB_VALUES = [
    ("Other", "other"),
    ("CR", "cr"),
    ("LF", "lf"),
    ("Control", "control"),
    ("Extend", "extend"),
    ("ZWJ", "zwj"),
    ("Regional_Indicator", "regional_indicator"),
    ("Prepend", "prepend"),
    ("SpacingMark", "spacing_mark"),
    ("L", "l"),
    ("V", "v"),
    ("T", "t"),
    ("LV", "lv"),
    ("LVT", "lvt"),
]

# The four Indic_Conjunct_Break values, None leading for the same reason —
# DerivedCoreProperties.txt declares `@missing: 0000..10FFFF; InCB; None`.
# None of the four collides with a Zig keyword.
INCB_VALUES = [
    ("None", "none"),
    ("Consonant", "consonant"),
    ("Extend", "extend"),
    ("Linker", "linker"),
]

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
    this port has no enum field for, so the emitted table would silently omit
    those code points. That aborts rather than writing a short table.
    """
    admitted = {ucd for ucd, _field in GCB_VALUES}
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
    admitted = {ucd for ucd, _field in INCB_VALUES}
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


def format_enum(doc, name, values):
    lines = ["// %s" % doc, "pub const %s = enum {" % name]
    for _ucd, field in values:
        lines.append("    %s," % field)
    lines.append("};")
    return "\n".join(lines)


def format_range_struct(name, class_type):
    return "\n".join([
        "// One inclusive range of the property, [start, end].",
        "pub const %s = struct {" % name,
        "    start: u32,",
        "    end: u32,",
        "    class: %s," % class_type,
        "};",
    ])


def format_table(name, doc, range_type, values, ranges):
    field_of = {ucd: field for ucd, field in values}
    lines = [doc, "pub const %s = [_]%s{" % (name, range_type)]
    for lo, hi, value in ranges:
        lines.append("    .{ .start = 0x%04X, .end = 0x%04X, .class = .%s },"
                     % (lo, hi, field_of[value]))
    lines.append("};")
    return "\n".join(lines)


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

    write_file(GRAPHEME_DATA_ZIG, "\n".join([
        "// GENERATED FILE - DO NOT EDIT.",
        "// Source: Unicode/Ucd/{GraphemeBreakProperty.txt,"
        "DerivedCoreProperties.txt}",
        "// Regenerate with tools/generate_grapheme_tables.py.",
        "//",
        "// Ports of Unicode.Generated.{GraphemeBreakProperty,"
        "IndicConjunctBreak}:",
        "// the same property values and the same ranges.",
        "//",
        "// Grapheme_Cluster_Break ranges: %d, Indic_Conjunct_Break ranges: %d."
        % (len(gcb_ranges), len(incb_ranges)),
        "//",
        "// Extended_Pictographic is not here: line_break_data.zig already",
        "// carries it for LB30b, and grapheme.zig reads that table through",
        "// line_break.isExtendedPictographic, so GB11 and LB30b answer from one",
        "// copy.",
        "//",
        "// Every table below is sorted by start and coalesced, so a lookup",
        "// binary-searches it. The ranges of each property are disjoint, so the",
        "// covering range is unique and the search agrees with the Lean",
        "// reference's linear first-match.",
        "",
        format_enum(
            "A UAX #29 Grapheme_Cluster_Break property value.", "Gcb",
            GCB_VALUES),
        "",
        format_enum(
            "A UAX #29 Indic_Conjunct_Break value, the sub-property GB9c "
            "reads.",
            "Incb", INCB_VALUES),
        "",
        format_range_struct("GcbRange", "Gcb"),
        "",
        format_range_struct("IncbRange", "Incb"),
        "",
        format_table(
            "grapheme_cluster_break",
            "// Grapheme_Cluster_Break ranges. A codepoint no range covers is\n"
            "// .other, which the file's own `@missing: 0000..10FFFF; Other`\n"
            "// header declares and so is the value of a binary-search miss.",
            "GcbRange", GCB_VALUES, gcb_ranges),
        "",
        format_table(
            "indic_conjunct_break",
            "// Indic_Conjunct_Break ranges, which GB9c reads. A codepoint the\n"
            "// file does not list is .none, which its own\n"
            "// `@missing: 0000..10FFFF; InCB; None` header declares.",
            "IncbRange", INCB_VALUES, incb_ranges),
        "",
        "// How many data rows the pinned corpus carries, counted from the",
        "// canonical GraphemeBreakTest.txt at generation. The corpus gate",
        "// asserts the rows it reads from the vendored copy against this, so a",
        "// row lost between the two fails rather than quietly shrinking the",
        "// denominator.",
        "pub const published_row_count: usize = %d;" % published_rows,
        "",
    ]))

    os.makedirs(os.path.dirname(VENDORED_CORPUS), exist_ok=True)
    shutil.copyfile(GRAPHEME_BREAK_TEST_TXT, VENDORED_CORPUS)
    sys.stdout.write("wrote %s (%d published rows)\n" % (
        os.path.relpath(VENDORED_CORPUS, ROOT), published_rows))


if __name__ == "__main__":
    main()
