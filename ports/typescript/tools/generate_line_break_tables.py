#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
#                      // tools // generate // line-break-tables
# ─────────────────────────────────────────────────────────────────────────────
#
# Emits the property tables the UAX #14 line breaker reads and vendors the
# published corpus it is judged against, from the pinned UCD files in the
# repository root:
#
#   src/segmentation/line-break-tables.js
#       The four properties the algorithm reads — Line_Break, a port of
#       `Unicode.Generated.LineBreakProperty`; General_Category, a port of
#       `Unicode.Generated.DerivedGeneralCategory`; East_Asian_Width, a port of
#       `Unicode.Generated.EastAsianWidth`; and Extended_Pictographic, a port
#       of `Unicode.Generated.EmojiData` — plus the corpus row count.
#   testdata/LineBreakTest.txt
#       The published corpus, which the test reads at run time.
#
# The tables are generated into source rather than read from `src/data/`. The
# package's data tables are served only through the digest-verifying reader
# `security.js` installs, which refuses an unpinned or altered table; a
# segmentation module opening a data file itself would be a second data path
# outside that gate. A generated table is code, so it sits behind the same
# trust anchor as the algorithm reading it, and the module needs no host file
# access — which is also what lets it run on the edge build.
#
# Each table carries coalesced inclusive ranges sorted by lower bound, held as
# parallel typed arrays so a lookup binary-searches without allocating. The
# ranges of each property partition the code space, so the covering range is
# unique and agrees with the linear first-match the Lean reference uses.
#
#   python3 ports/typescript/tools/generate_line_break_tables.py
#
# Run from anywhere. Writing the table module and the corpus is the whole
# effect.

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

PORT = os.path.join(ROOT, "ports", "typescript")
TABLES_JS = os.path.join(
    PORT, "src", "segmentation", "line-break-tables.js")
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


def strip_comment(line):
    return line.split("#", 1)[0].strip()


def parse_range_field(text):
    text = text.strip()
    if ".." in text:
        lo_text, hi_text = text.split("..", 1)
        return int(lo_text, 16), int(hi_text, 16)
    point = int(text, 16)
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
        wrapped(values, 8, lambda value: '"%s"' % value),
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


def format_flag_table(name, doc, ranges):
    """Two parallel typed arrays: starts and ends of a boolean property."""
    return "\n".join([
        doc,
        "export const %s = Object.freeze({" % name,
        "  start: Uint32Array.from([",
        wrapped([row[0] for row in ranges], 10, lambda cp: "0x%04X" % cp),
        "  ]),",
        "  end: Uint32Array.from([",
        wrapped([row[1] for row in ranges], 10, lambda cp: "0x%04X" % cp),
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
    lb_ranges = coalesce(read_two_field_rows(
        LINE_BREAK_TXT, LB_VALUES, "Line_Break"))
    gc_ranges = coalesce(read_general_category_rows())
    eaw_ranges = coalesce(read_two_field_rows(
        EAST_ASIAN_WIDTH_TXT, EAW_VALUES, "East_Asian_Width"))
    ext_pict_ranges = coalesce(read_extended_pictographic_rows())
    published_rows = count_break_test_rows()

    write_file(TABLES_JS, "\n".join([
        "// GENERATED FILE - DO NOT EDIT.",
        "// Regenerate with tools/generate_line_break_tables.py.",
        "//",
        "// Property tables the UAX #14 line breaker reads, from the pinned UCD",
        "// 17.0.0 files -- ports of Unicode.Generated.{LineBreakProperty,",
        "// DerivedGeneralCategory,EastAsianWidth,EmojiData}. Same property",
        "// values, same ranges.",
        "//",
        "// Line_Break ranges: %d, General_Category ranges: %d," % (
            len(lb_ranges), len(gc_ranges)),
        "// East_Asian_Width ranges: %d, Extended_Pictographic ranges: %d." % (
            len(eaw_ranges), len(ext_pict_ranges)),
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
        "// of each property partition the codepoint space, so the covering range",
        "// is unique and the search agrees with the Lean reference's linear",
        "// first-match.",
        "",
        format_class_list(
            "LINE_BREAK_CLASSES",
            "// The 49 Line_Break property values, indexed by class code. These\n"
            "// are raw, before UAX #14 LB1 tailors them; resolvedClass applies\n"
            "// LB1.",
            LB_VALUES),
        "",
        format_class_list(
            "GENERAL_CATEGORY_VALUES",
            "// The 30 General_Category values, indexed by category code.",
            GC_VALUES),
        "",
        format_class_list(
            "EAST_ASIAN_WIDTH_VALUES",
            "// The six East_Asian_Width values, indexed by width code.",
            EAW_VALUES),
        "",
        format_table(
            "LINE_BREAK_RANGES",
            '// Line_Break ranges. A codepoint no range covers is "XX", which\n'
            "// the file's own `@missing: 0000..10FFFF; XX` header declares.",
            lb_ranges, LB_VALUES),
        "",
        format_table(
            "GENERAL_CATEGORY_RANGES",
            "// General_Category ranges. LB1 reads the property to resolve SA,\n"
            '// the quote refinements read "Pi" and "Pf", and LB30b reads "Cn",\n'
            "// which is also the default UnicodeData.txt declares for an\n"
            "// unassigned codepoint.",
            gc_ranges, GC_VALUES),
        "",
        format_table(
            "EAST_ASIAN_WIDTH_RANGES",
            "// East_Asian_Width ranges, which LB19a, LB25 and LB30 read. A\n"
            '// codepoint the file omits is "N" by its @missing line.',
            eaw_ranges, EAW_VALUES),
        "",
        format_flag_table(
            "EXTENDED_PICTOGRAPHIC_RANGES",
            "// Extended_Pictographic ranges, which LB30b and GB11 both read.\n"
            "// The cluster breaker imports isExtendedPictographic rather than\n"
            "// carrying a second copy of this table.",
            ext_pict_ranges),
        "",
        "// How many data rows the pinned corpus carries, counted from the",
        "// canonical LineBreakTest.txt at generation. The corpus gate asserts",
        "// the rows it reads from the vendored copy against this, so a row lost",
        "// between the two fails rather than quietly shrinking the denominator.",
        "export const PUBLISHED_ROW_COUNT = %d;" % published_rows,
        "",
    ]))

    os.makedirs(os.path.dirname(VENDORED_CORPUS), exist_ok=True)
    shutil.copyfile(LINE_BREAK_TEST_TXT, VENDORED_CORPUS)
    sys.stdout.write("wrote %s (%d published rows)\n" % (
        os.path.relpath(VENDORED_CORPUS, ROOT), published_rows))


if __name__ == "__main__":
    main()
