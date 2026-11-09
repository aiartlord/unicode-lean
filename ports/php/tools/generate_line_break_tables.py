#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
#                      // tools // generate // line-break-tables
# ─────────────────────────────────────────────────────────────────────────────
#
# Emits the property tables the UAX #14 line breaker reads and vendors the
# published corpus it is judged against, from the pinned UCD files in the
# repository root:
#
#   src/Segmentation/LineBreakTables.php
#       The four properties the algorithm reads — Line_Break, a port of
#       `Unicode.Generated.LineBreakProperty`; General_Category, a port of
#       `Unicode.Generated.DerivedGeneralCategory`; East_Asian_Width, a port
#       of `Unicode.Generated.EastAsianWidth`; and Extended_Pictographic, a
#       port of `Unicode.Generated.EmojiData`.
#   testdata/LineBreakTest.txt
#       The published corpus, which the test reads at run time.
#
# The tables are generated into source rather than read from `data/`, so the
# segmentation classes stay a pure function of their code points and the
# package's one data path remains `Data`. The East_Asian_Width the security
# surface carries is a separate enum of its own under
# `UnicodePhp\Security\Identity`, serving the width-confusion detector.
#
# Where the grapheme tables are grouped by property value and scanned
# linearly, these are sorted by range start and searched by bisection: the
# published line-break corpus is 19338 rows against the grapheme corpus's
# 766, over tables an order of magnitude larger, and four properties are read
# per code point rather than three.
#
#   python3 ports/php/tools/generate_line_break_tables.py
#
# Run from anywhere. Writing the table file and the corpus is the whole
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

PORT = os.path.join(ROOT, "ports", "php")
TABLES_PHP = os.path.join(PORT, "src", "Segmentation", "LineBreakTables.php")
VENDORED_CORPUS = os.path.join(PORT, "testdata", "LineBreakTest.txt")

# The markers the published break corpora write at each boundary.
BREAK_MARKER = "÷"
NO_BREAK_MARKER = "×"

# The 49 Line_Break property values UAX #14 defines, each with the PHP enum
# case the generated file gives it.
LB_VALUES = [
    ("AI", "Ai"), ("AK", "Ak"), ("AL", "Al"), ("AP", "Ap"), ("AS", "As"),
    ("B2", "B2"), ("BA", "Ba"), ("BB", "Bb"), ("BK", "Bk"), ("CB", "Cb"),
    ("CJ", "Cj"), ("CL", "Cl"), ("CM", "Cm"), ("CP", "Cp"), ("CR", "Cr"),
    ("EB", "Eb"), ("EM", "Em"), ("EX", "Ex"), ("GL", "Gl"), ("H2", "H2"),
    ("H3", "H3"), ("HH", "Hh"), ("HL", "Hl"), ("HY", "Hy"), ("ID", "Id"),
    ("IN", "In"), ("IS", "Is"), ("JL", "Jl"), ("JT", "Jt"), ("JV", "Jv"),
    ("LF", "Lf"), ("NL", "Nl"), ("NS", "Ns"), ("NU", "Nu"), ("OP", "Op"),
    ("PO", "Po"), ("PR", "Pr"), ("QU", "Qu"), ("RI", "Ri"), ("SA", "Sa"),
    ("SG", "Sg"), ("SP", "Sp"), ("SY", "Sy"), ("VF", "Vf"), ("VI", "Vi"),
    ("WJ", "Wj"), ("XX", "Xx"), ("ZW", "Zw"), ("ZWJ", "Zwj"),
]

# The 30 General_Category values of UAX #44 section 5.7.1. The UCD
# abbreviations are already valid PHP enum case names.
GC_VALUES = [
    ("Lu", "Lu"), ("Ll", "Ll"), ("Lt", "Lt"), ("Lm", "Lm"), ("Lo", "Lo"),
    ("Mn", "Mn"), ("Mc", "Mc"), ("Me", "Me"),
    ("Nd", "Nd"), ("Nl", "Nl"), ("No", "No"),
    ("Pc", "Pc"), ("Pd", "Pd"), ("Ps", "Ps"), ("Pe", "Pe"), ("Pi", "Pi"),
    ("Pf", "Pf"), ("Po", "Po"),
    ("Sm", "Sm"), ("Sc", "Sc"), ("Sk", "Sk"), ("So", "So"),
    ("Zs", "Zs"), ("Zl", "Zl"), ("Zp", "Zp"),
    ("Cc", "Cc"), ("Cf", "Cf"), ("Cs", "Cs"), ("Co", "Co"), ("Cn", "Cn"),
]

# The six East_Asian_Width values of UAX #11.
EAW_VALUES = [("A", "A"), ("F", "F"), ("H", "H"), ("N", "N"), ("Na", "Na"),
              ("W", "W")]


def ucd_names(values):
    return [ucd for ucd, _case in values]


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
    admitted = ucd_names(GC_VALUES)
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
            if value not in admitted:
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

    LB30b reads the property. Only that one property value is taken; the file
    carries several.
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
    unique covering range and a bisection over it would be ill-defined.
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


def format_enum(name, property_name, values):
    """One property's values as a PHP enum, in UCD order."""
    lines = ["/** %s property value. */" % property_name,
             "enum %s" % name, "{"]
    for ucd, case in values:
        lines.append("    /** %s = `%s`. */" % (property_name, ucd))
        lines.append("    case %s;" % case)
    lines.append("}")
    return "\n".join(lines)


def format_classed_table(name, enum, doc, ranges, values):
    """Classed ranges as a PHP constant of `[first, last, class]` triples."""
    case_of = {ucd: case for ucd, case in values}
    lines = ["    /**"]
    lines.extend("     * %s" % line for line in doc)
    lines.extend([
        "     *",
        "     * @var list<array{0: int, 1: int, 2: %s}>" % enum,
        "     */",
        "    public const %s = [" % name,
    ])
    for lo, hi, value in ranges:
        lines.append("        [%d, %d, %s::%s]," % (lo, hi, enum,
                                                    case_of[value]))
    lines.append("    ];")
    return "\n".join(lines)


def format_flag_table(name, doc, ranges):
    """Boolean-property ranges as a PHP constant of `[first, last]` pairs."""
    lines = ["    /**"]
    lines.extend("     * %s" % line for line in doc)
    lines.extend([
        "     *",
        "     * @var list<array{0: int, 1: int}>",
        "     */",
        "    public const %s = [" % name,
    ])
    for lo, hi, _value in ranges:
        lines.append("        [%d, %d]," % (lo, hi))
    lines.append("    ];")
    return "\n".join(lines)


def write_file(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    sys.stdout.write("wrote %s (%d lines)\n" % (
        os.path.relpath(path, ROOT), text.count("\n")))


def main():
    lb_ranges = coalesce(read_two_field_rows(
        LINE_BREAK_TXT, ucd_names(LB_VALUES), "Line_Break"))
    gc_ranges = coalesce(read_general_category_rows())
    eaw_ranges = coalesce(read_two_field_rows(
        EAST_ASIAN_WIDTH_TXT, ucd_names(EAW_VALUES), "East_Asian_Width"))
    ext_pict_ranges = coalesce(read_extended_pictographic_rows())
    published_rows = count_break_test_rows()

    write_file(TABLES_PHP, "\n".join([
        "<?php",
        "",
        "declare(strict_types=1);",
        "",
        "namespace UnicodePhp\\Segmentation;",
        "",
        "// Property tables the UAX #14 line breaker reads, transcribed from the",
        "// pinned UCD 17.0.0 files -- ports of",
        "// Unicode.Generated.{LineBreakProperty,DerivedGeneralCategory,",
        "// EastAsianWidth,EmojiData}. Same property values, same ranges.",
        "//",
        "// Every table is sorted by range start and its ranges are disjoint, so",
        "// the covering range is unique and a lookup finds it by bisection.",
        "//",
        "// Line_Break ranges: %d, General_Category ranges: %d," % (
            len(lb_ranges), len(gc_ranges)),
        "// East_Asian_Width ranges: %d, Extended_Pictographic ranges: %d." % (
            len(eaw_ranges), len(ext_pict_ranges)),
        "//",
        "// Do not edit by hand. Regenerate with",
        "// tools/generate_line_break_tables.py.",
        "",
        format_enum("Lb", "Line_Break", LB_VALUES),
        "",
        format_enum("Gc", "General_Category", GC_VALUES),
        "",
        format_enum("Eaw", "East_Asian_Width", EAW_VALUES),
        "",
        "/**",
        " * Static line-break property tables consulted by the UAX #14 rules.",
        " * Range triples are `[first, last, class]`, sorted by `first`.",
        " */",
        "final class LineBreakTables",
        "{",
        "    /**",
        "     * How many data rows the pinned corpus carries, counted from the",
        "     * canonical LineBreakTest.txt at generation. The corpus gate",
        "     * asserts the rows it reads from the vendored copy against this,",
        "     * so a row lost between the two fails rather than quietly",
        "     * shrinking the denominator.",
        "     */",
        "    public const PUBLISHED_ROW_COUNT = %d;" % published_rows,
        "",
        format_classed_table(
            "LB_RANGES", "Lb",
            ["Line_Break ranges: `[first, last, class]`. The classes are raw,",
             "before UAX #14 LB1 tailors them."],
            lb_ranges, LB_VALUES),
        "",
        format_classed_table(
            "GC_RANGES", "Gc",
            ["General_Category ranges: `[first, last, class]`. LB1 reads the",
             "property to resolve SA, LB15a and LB15b to tell an initial quote",
             "from a final one, and LB30b to recognise an unassigned",
             "pictograph."],
            gc_ranges, GC_VALUES),
        "",
        format_classed_table(
            "EAW_RANGES", "Eaw",
            ["East_Asian_Width ranges: `[first, last, class]`, read by LB19a,",
             "LB25 and LB30."],
            eaw_ranges, EAW_VALUES),
        "",
        format_flag_table(
            "EXTPICT_RANGES",
            ["Extended_Pictographic ranges: `[first, last]`, read by LB30b."],
            ext_pict_ranges),
        "}",
        "",
    ]))

    os.makedirs(os.path.dirname(VENDORED_CORPUS), exist_ok=True)
    shutil.copyfile(LINE_BREAK_TEST_TXT, VENDORED_CORPUS)
    sys.stdout.write("wrote %s (%d published rows)\n" % (
        os.path.relpath(VENDORED_CORPUS, ROOT), published_rows))


if __name__ == "__main__":
    main()
