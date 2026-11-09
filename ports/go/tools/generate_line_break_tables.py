#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
#                      // tools // generate // line-break-tables
# ─────────────────────────────────────────────────────────────────────────────
#
# Emits the property tables the UAX #14 line breaker reads and vendors the
# published corpus it is judged against, from the pinned UCD files in the
# repository root:
#
#   segmentation/line_break_tables.go
#       The four properties the algorithm reads — Line_Break, a port of
#       `Unicode.Generated.LineBreakProperty`; General_Category, a port of
#       `Unicode.Generated.DerivedGeneralCategory`; East_Asian_Width, a port of
#       `Unicode.Generated.EastAsianWidth`; and Extended_Pictographic, a port of
#       `Unicode.Generated.EmojiData` — plus the corpus row count.
#
#       Extended_Pictographic serves two rules in this package, LB30b and
#       GB11, from the one table here.
#   segmentation/testdata/LineBreakTest.txt
#       The published corpus, where the go tool's own testdata convention puts
#       a package's fixtures.
#
# The tables are generated into source rather than parsed at load, so a
# segmentation package takes code points and needs no data directory. The
# security package's own East_Asian_Width table is not an alternative: it and
# its class type are unexported, so nothing outside that package can read them.
#
# Each table carries coalesced inclusive ranges sorted by lower bound, so a
# lookup binary-searches for the one range covering a code point. The ranges of
# each property partition the code space, so that range is unique and agrees
# with the linear first-match the Lean reference uses. Every element is a
# constant, so the tables are static data rather than work done at init.
#
#   python3 ports/go/tools/generate_line_break_tables.py
#
# Run from anywhere. Writing the table file and the corpus is the whole effect.

import os
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

UCD = os.path.join(ROOT, "Unicode", "Ucd")
LINE_BREAK_TXT = os.path.join(UCD, "LineBreak.txt")
LINE_BREAK_TEST_TXT = os.path.join(UCD, "LineBreakTest.txt")
UNICODE_DATA_TXT = os.path.join(UCD, "UnicodeData.txt")
EAST_ASIAN_WIDTH_TXT = os.path.join(UCD, "EastAsianWidth.txt")
EMOJI_DATA_TXT = os.path.join(UCD, "emoji-data.txt")

PORT = os.path.join(ROOT, "ports", "go")
LINE_BREAK_TABLES_GO = os.path.join(
    PORT, "segmentation", "line_break_tables.go")
VENDORED_CORPUS = os.path.join(
    PORT, "segmentation", "testdata", "LineBreakTest.txt")

# The markers the published break corpora write at each boundary.
BREAK_MARKER = "÷"
NO_BREAK_MARKER = "×"

# The 49 Line_Break property values UAX #14 defines.
LB_VALUES = [
    "AI", "AK", "AL", "AP", "AS", "B2", "BA", "BB", "BK", "CB", "CJ", "CL",
    "CM", "CP", "CR", "EB", "EM", "EX", "GL", "H2", "H3", "HH", "HL", "HY",
    "ID", "IN", "IS", "JL", "JT", "JV", "LF", "NL", "NS", "NU", "OP", "PO",
    "PR", "QU", "RI", "SA", "SG", "SP", "SY", "VF", "VI", "WJ", "XX", "ZW",
    "ZWJ",
]

# The 30 General_Category values of UAX #44 section 5.7.1.
GC_VALUES = [
    "Lu", "Ll", "Lt", "Lm", "Lo",
    "Mn", "Mc", "Me",
    "Nd", "Nl", "No",
    "Pc", "Pd", "Ps", "Pe", "Pi", "Pf", "Po",
    "Sm", "Sc", "Sk", "So",
    "Zs", "Zl", "Zp",
    "Cc", "Cf", "Cs", "Co", "Cn",
]

# The six East_Asian_Width values of UAX #11.
EAW_VALUES = ["A", "F", "H", "N", "Na", "W"]


def strip_comment(line):
    return line.split("#", 1)[0].strip()


def parse_range_field(field):
    field = field.strip()
    if ".." in field:
        lo_text, hi_text = field.split("..", 1)
        return int(lo_text, 16), int(hi_text, 16)
    point = int(field, 16)
    return point, point


def read_two_field_rows(path, admitted, label):
    """Explicit (lo, hi, value) rows of a two-field UCD property file."""
    rows = []
    with open(path, "r", encoding="utf-8") as handle:
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
                    "%s line %d names a %s value the generator does not "
                    "carry: %r"
                    % (os.path.basename(path), number, label, value))
            lo, hi = parse_range_field(fields[0])
            rows.append((lo, hi, value))
    return rows


def read_general_category_rows():
    """Explicit (lo, hi, value) rows of UnicodeData.txt, in file order.

    A code point range appears as two rows whose names end `, First>` and
    `, Last>`; every other row covers one code point.
    """
    rows = []
    pending_first = None
    with open(UNICODE_DATA_TXT, "r", encoding="utf-8") as handle:
        for line in handle:
            fields = line.rstrip("\n").split(";")
            if len(fields) < 3:
                continue
            point = int(fields[0], 16)
            name = fields[1]
            value = fields[2].strip()
            if value not in GC_VALUES:
                raise SystemExit(
                    "UnicodeData.txt names a General_Category the generator "
                    "does not carry: %r" % value)
            if name.endswith(", First>"):
                pending_first = (point, value)
                continue
            if name.endswith(", Last>"):
                if pending_first is None:
                    raise SystemExit(
                        "UnicodeData.txt has a Last row with no First row at "
                        "U+%04X" % point)
                first_point, first_value = pending_first
                if first_value != value:
                    raise SystemExit(
                        "UnicodeData.txt range U+%04X..U+%04X disagrees on "
                        "General_Category" % (first_point, point))
                rows.append((first_point, point, value))
                pending_first = None
                continue
            rows.append((point, point, value))
    if pending_first is not None:
        raise SystemExit("UnicodeData.txt ends inside an unclosed range")
    return rows


def read_extended_pictographic_rows():
    """The Extended_Pictographic ranges of emoji-data.txt as (lo, hi, True).

    LB30b and GB11 both read the property, from this one table. Only that one
    property value is taken; the file carries several.
    """
    rows = []
    with open(EMOJI_DATA_TXT, "r", encoding="utf-8") as handle:
        for line in handle:
            body = strip_comment(line)
            if not body:
                continue
            fields = body.split(";")
            if len(fields) < 2:
                continue
            if fields[1].strip() != "Extended_Pictographic":
                continue
            lo, hi = parse_range_field(fields[0])
            rows.append((lo, hi, True))
    if not rows:
        raise SystemExit(
            "emoji-data.txt names no Extended_Pictographic range")
    return rows


def count_break_test_rows():
    """How many data rows LineBreakTest.txt carries, validating each.

    A row alternates boundary markers and code points, starting and ending
    with a marker, so it carries one more flag than code points. A row that
    does not is a corpus the test cannot read, and the count it would report
    would be wrong rather than short.
    """
    count = 0
    with open(LINE_BREAK_TEST_TXT, "r", encoding="utf-8") as handle:
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
                            "LineBreakTest.txt line %d has two markers in a "
                            "row" % number)
                    flags += 1
                    expecting_marker = False
                else:
                    if expecting_marker:
                        raise SystemExit(
                            "LineBreakTest.txt line %d has two code points in "
                            "a row" % number)
                    int(token, 16)
                    codepoints += 1
                    expecting_marker = True
            if expecting_marker:
                raise SystemExit(
                    "LineBreakTest.txt line %d ends at a code point rather "
                    "than a boundary marker" % number)
            if flags != codepoints + 1:
                raise SystemExit(
                    "LineBreakTest.txt line %d carries %d flags for %d code "
                    "points" % (number, flags, codepoints))
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
    for index, value in enumerate(values):
        suffix = " %s = iota" % type_name if index == 0 else ""
        lines.append("\t%s%s%s" % (prefix, value, suffix))
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


def format_table(array, range_type, prefix, ranges):
    lines = ["var %s = [%d]%s{" % (array, len(ranges), range_type)]
    for lo, hi, value in ranges:
        lines.append("\t{0x%04X, 0x%04X, %s%s}," % (lo, hi, prefix, value))
    lines.append("}")
    return "\n".join(lines)


def format_lookup(func, doc, array, class_type, default):
    return "\n".join([
        "// %s" % doc,
        "//",
        "// The ranges partition the code space and are sorted by lower bound,",
        "// so the covering range is unique and a binary search finds it.",
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


def format_flag_table(array, ranges):
    lines = ["var %s = [%d]cpRange{" % (array, len(ranges))]
    for lo, hi, _value in ranges:
        lines.append("\t{0x%04X, 0x%04X}," % (lo, hi))
    lines.append("}")
    return "\n".join(lines)


def write_file(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    sys.stdout.write("wrote %s (%d lines)\n" % (
        os.path.relpath(path, ROOT), text.count("\n")))


def main():
    lb_ranges = coalesce(read_two_field_rows(
        LINE_BREAK_TXT, LB_VALUES, "Line_Break"))
    gc_ranges = coalesce(read_general_category_rows())
    eaw_ranges = coalesce(read_two_field_rows(
        EAST_ASIAN_WIDTH_TXT, EAW_VALUES, "East_Asian_Width"))
    ext_pict_ranges = coalesce(read_extended_pictographic_rows())
    published_rows = count_break_test_rows()

    write_file(LINE_BREAK_TABLES_GO, "\n".join([
        "// Code generated by tools/generate_line_break_tables.py. DO NOT EDIT.",
        "",
        "package segmentation",
        "",
        "// Property tables the UAX #14 line breaker reads, generated from the",
        "// pinned UCD 17.0.0 files — ports of",
        "// Unicode.Generated.{LineBreakProperty,DerivedGeneralCategory,"
        "EastAsianWidth}.",
        "// Same ranges, same class values.",
        "//",
        "// Line_Break ranges: %d, General_Category ranges: %d,"
        % (len(lb_ranges), len(gc_ranges)),
        "// East_Asian_Width ranges: %d, Extended_Pictographic ranges: %d."
        % (len(eaw_ranges), len(ext_pict_ranges)),
        "//",
        "// Every table is sorted by lower bound and coalesced, and every element",
        "// is a constant, so each table is static data rather than work done at",
        "// init.",
        "",
        format_enum(
            "Lb is a UAX #14 Line_Break property value.", "Lb", "Lb",
            LB_VALUES,
            "The 49 Line_Break values. These are raw, before UAX #14 LB1\n"
            "// tailors them; ResolvedClass applies LB1."),
        "",
        format_enum(
            "GeneralCategory is a UAX #44 section 5.7.1 General_Category "
            "value.",
            "GeneralCategory", "Gc", GC_VALUES,
            "The 30 General_Category values."),
        "",
        format_enum(
            "EastAsianWidth is a UAX #11 East_Asian_Width value.",
            "EastAsianWidth", "Eaw", EAW_VALUES,
            "The six East_Asian_Width values."),
        "",
        format_range_type("lbRange", "Lb"),
        "",
        format_range_type("gcRange", "GeneralCategory"),
        "",
        format_range_type("eawRange", "EastAsianWidth"),
        "",
        "// cpRange is one inclusive range of a boolean property, [lo, hi].",
        "type cpRange struct {",
        "\tlo uint32",
        "\thi uint32",
        "}",
        "",
        format_table("lbRanges", "lbRange", "Lb", lb_ranges),
        "",
        format_table("gcRanges", "gcRange", "Gc", gc_ranges),
        "",
        format_table("eawRanges", "eawRange", "Eaw", eaw_ranges),
        "",
        format_flag_table("extPictRanges", ext_pict_ranges),
        "",
        format_lookup(
            "RawClass",
            "RawClass returns the Line_Break class of cp before LB1. A code\n"
            "// point no range covers is LbXX, the default LineBreak.txt's own\n"
            "// @missing: 0000..10FFFF; XX header declares.",
            "lbRanges", "Lb", "LbXX"),
        "",
        format_lookup(
            "CategoryOf",
            "CategoryOf returns the General_Category of cp, GcCn when no range\n"
            "// covers it — the default UnicodeData.txt declares for unassigned\n"
            "// code points.",
            "gcRanges", "GeneralCategory", "GcCn"),
        "",
        format_lookup(
            "WidthOf",
            "WidthOf returns the East_Asian_Width of cp, EawN when the file\n"
            "// omits it.",
            "eawRanges", "EastAsianWidth", "EawN"),
        "",
        "\n".join([
            "// IsExtendedPictographic reports whether cp has the",
            "// Extended_Pictographic property, which LB30b and GB11 read.",
            "//",
            "// The ranges are sorted by lower bound and disjoint, so a binary",
            "// search decides membership.",
            "func IsExtendedPictographic(cp uint32) bool {",
            "\tlo, hi := 0, len(extPictRanges)",
            "\tfor lo < hi {",
            "\t\tmid := lo + (hi-lo)/2",
            "\t\tentry := extPictRanges[mid]",
            "\t\tswitch {",
            "\t\tcase cp < entry.lo:",
            "\t\t\thi = mid",
            "\t\tcase cp > entry.hi:",
            "\t\t\tlo = mid + 1",
            "\t\tdefault:",
            "\t\t\treturn true",
            "\t\t}",
            "\t}",
            "\treturn false",
            "}",
        ]),
        "",
        "// PublishedRowCount is how many data rows the pinned corpus carries,",
        "// counted from the canonical LineBreakTest.txt at generation. The corpus",
        "// gate asserts the rows it reads from the vendored copy against this, so",
        "// a row lost between the two fails rather than quietly shrinking the",
        "// denominator.",
        "const PublishedRowCount = %d" % published_rows,
        "",
    ]))

    os.makedirs(os.path.dirname(VENDORED_CORPUS), exist_ok=True)
    shutil.copyfile(LINE_BREAK_TEST_TXT, VENDORED_CORPUS)
    sys.stdout.write("wrote %s (%d published rows)\n" % (
        os.path.relpath(VENDORED_CORPUS, ROOT), published_rows))


if __name__ == "__main__":
    main()
