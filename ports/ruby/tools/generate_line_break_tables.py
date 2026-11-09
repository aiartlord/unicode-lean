#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
#                      // tools // generate // line-break-tables
# ─────────────────────────────────────────────────────────────────────────────
#
# Emits the property tables the UAX #14 line breaker reads and vendors the
# published corpus it is judged against, from the pinned UCD files in the
# repository root:
#
#   lib/unicode_ruby/segmentation/line_break_tables.rb
#       The three properties the algorithm reads — Line_Break, a port of
#       `Unicode.Generated.LineBreakProperty`; General_Category, a port of
#       `Unicode.Generated.DerivedGeneralCategory`; and East_Asian_Width, a
#       port of `Unicode.Generated.EastAsianWidth` — plus the corpus row count.
#   testdata/LineBreakTest.txt
#       The published corpus, bundled beside GraphemeBreakTest.txt so the port
#       stays self-contained.
#
# The tables are generated into source rather than parsed at load, which is the
# route `segmentation/grapheme_tables.rb` already takes: a segmentation module
# takes code points and nothing else, while the security layer parses its own
# tables out of the port's `data/` directory. Following that split leaves the
# security layer's East_Asian_Width parse untouched and gives the line breaker
# no runtime data dependency.
#
# Each table carries coalesced inclusive ranges sorted by lower bound, so a
# lookup binary-searches for the one range covering a code point. The ranges of
# each property partition the code space, so that range is unique and agrees
# with the linear first-match the Lean reference uses. The grapheme tables
# beside these are grouped by class instead and scanned linearly; sorting is
# what lets the line breaker answer a corpus of this size.
#
#   python3 ports/ruby/tools/generate_line_break_tables.py
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

PORT = os.path.join(ROOT, "ports", "ruby")
LINE_BREAK_TABLES_RB = os.path.join(
    PORT, "lib", "unicode_ruby", "segmentation", "line_break_tables.rb")
VENDORED_CORPUS = os.path.join(PORT, "testdata", "LineBreakTest.txt")

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


def symbol(value):
    """The Ruby symbol naming a UCD property value.

    The port writes a property class as a lowercase symbol — `:prepend`,
    `:regional_indicator` in the grapheme tables — so `AL` becomes `:al`,
    `ZWJ` `:zwj`, and `Na` `:na`.
    """
    return ":" + value.lower()


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


def format_table(name, doc, ranges):
    lines = ["      # %s" % doc, "      %s = [" % name]
    for lo, hi, value in ranges:
        lines.append("        [0x%04X, 0x%04X, %s]," % (lo, hi, symbol(value)))
    lines.append("      ].freeze")
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
    published_rows = count_break_test_rows()

    write_file(LINE_BREAK_TABLES_RB, "\n".join([
        "# frozen_string_literal: true",
        "",
        "# Property tables the UAX #14 line breaker reads, generated from the",
        "# pinned UCD 17.0.0 files — ports of",
        "# `Unicode.Generated.{LineBreakProperty,DerivedGeneralCategory,"
        "EastAsianWidth}`.",
        "# Same ranges, same class values.  Do not edit by hand: regenerate with",
        "# `python3 ports/ruby/tools/generate_line_break_tables.py`.",
        "#",
        "# Line_Break ranges: %d, General_Category ranges: %d, East_Asian_Width"
        % (len(lb_ranges), len(gc_ranges)),
        "# ranges: %d." % len(eaw_ranges),
        "#",
        "# Unlike the grapheme tables beside these, every table here is sorted by",
        "# lower bound and coalesced, so a lookup binary-searches it.  The ranges",
        "# of each property partition the code space, so the covering range is",
        "# unique and the search agrees with the Lean reference's linear",
        "# first-match.",
        "",
        "module UnicodeRuby",
        "  module Segmentation",
        "    # The three UCD properties UAX #14 reads.  A code point uncovered by",
        "    # LB_RANGES has Line_Break +:xx+, the default the file's own",
        "    # `@missing: 0000..10FFFF; XX` header declares; one uncovered by",
        "    # GC_RANGES has General_Category +:cn+, the default UnicodeData.txt",
        "    # declares for unassigned code points; one uncovered by EAW_RANGES has",
        "    # East_Asian_Width +:n+.  Those defaults are not stored in the tables.",
        "    module LineBreakTables",
        "",
        format_table(
            "LB_RANGES",
            "Line_Break ranges: +[first, last, class]+.  The classes are raw,"
            "\n      # before UAX #14 LB1 tailors them; LineBreak.resolved_class"
            "\n      # applies LB1.",
            lb_ranges),
        "",
        format_table(
            "GC_RANGES",
            "General_Category ranges: +[first, last, category]+.  LB1 reads it"
            "\n      # to resolve SA, the quote refinements read Pi and Pf, and"
            "\n      # LB30b reads Cn.",
            gc_ranges),
        "",
        format_table(
            "EAW_RANGES",
            "East_Asian_Width ranges: +[first, last, width]+.  LB19a, LB25 and"
            "\n      # LB30 read it.",
            eaw_ranges),
        "",
        "      # How many data rows the pinned corpus carries, counted from the",
        "      # canonical LineBreakTest.txt at generation.  The corpus gate",
        "      # asserts the rows it reads from the vendored copy against this, so",
        "      # a row lost between the two fails rather than quietly shrinking",
        "      # the denominator.",
        "      PUBLISHED_ROW_COUNT = %d" % published_rows,
        "    end",
        "  end",
        "end",
        "",
    ]))

    os.makedirs(os.path.dirname(VENDORED_CORPUS), exist_ok=True)
    shutil.copyfile(LINE_BREAK_TEST_TXT, VENDORED_CORPUS)
    sys.stdout.write("wrote %s (%d published rows)\n" % (
        os.path.relpath(VENDORED_CORPUS, ROOT), published_rows))


if __name__ == "__main__":
    main()
