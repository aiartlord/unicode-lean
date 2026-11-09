#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
#                      // tools // generate // line-break-tables
# ─────────────────────────────────────────────────────────────────────────────
#
# Emits the generated property tables the UAX #14 line breaker reads, plus the
# published corpus it is judged against, from the pinned UCD files in the
# repository root:
#
#   src/unicode_python/general_category.py
#       General_Category ranges, mirroring
#       `Unicode.Generated.DerivedGeneralCategory`.
#   src/unicode_python/east_asian_width.py
#       East_Asian_Width ranges, mirroring
#       `Unicode.Generated.EastAsianWidth`.
#   src/unicode_python/segmentation/line_break_tables.py
#       Line_Break ranges, mirroring `Unicode.Generated.LineBreakProperty`.
#   tests/corpus/line_break_rows.py
#       Every row of the published line-break corpus.
#   tests/corpus/grapheme_rows.py
#       Every row of the published grapheme-cluster corpus. The `corpus`
#       package's two gates were written for every published break corpus, and
#       the grapheme suite had no rows module to feed them, so its only
#       evidence was a handful of hand-written masks.
#
# The two property modules sit above `security` and above `segmentation` so
# both layers can read them, which is where the Lean keeps its generated
# property modules. Each table carries coalesced inclusive ranges sorted by
# lower bound, so a lookup binary-searches for the one range covering a code
# point; the ranges of each property partition the code space, so that range is
# unique and agrees with the linear first-match the Lean uses.
#
#   python3 ports/python/tools/generate_line_break_tables.py
#
# Run from the repository root. Writing the files is the whole effect.

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

UCD = os.path.join(ROOT, "Unicode", "Ucd")
LINE_BREAK_TXT = os.path.join(UCD, "LineBreak.txt")
LINE_BREAK_TEST_TXT = os.path.join(UCD, "LineBreakTest.txt")
GRAPHEME_BREAK_TEST_TXT = os.path.join(UCD, "GraphemeBreakTest.txt")
UNICODE_DATA_TXT = os.path.join(UCD, "UnicodeData.txt")
EAST_ASIAN_WIDTH_TXT = os.path.join(UCD, "EastAsianWidth.txt")

PKG = os.path.join(ROOT, "ports", "python", "src", "unicode_python")
GENERAL_CATEGORY_PY = os.path.join(PKG, "general_category.py")
EAST_ASIAN_WIDTH_PY = os.path.join(PKG, "east_asian_width.py")
LINE_BREAK_TABLES_PY = os.path.join(
    PKG, "segmentation", "line_break_tables.py")
CORPUS_DIR = os.path.join(ROOT, "ports", "python", "tests", "corpus")
LINE_BREAK_ROWS_PY = os.path.join(CORPUS_DIR, "line_break_rows.py")
GRAPHEME_ROWS_PY = os.path.join(CORPUS_DIR, "grapheme_rows.py")

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


def read_break_test_rows(path):
    """The published rows of a UAX break corpus as (codepoints, flags).

    A row alternates boundary markers and code points, starting and ending
    with a marker, so it carries one more flag than code points. Every
    published break corpus writes that one format, so one reader serves them
    all.
    """
    name = os.path.basename(path)
    rows = []
    with open(path, "r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            body = strip_comment(line)
            if not body:
                continue
            codepoints = []
            flags = []
            expecting_marker = True
            for token in body.split():
                if token in (BREAK_MARKER, NO_BREAK_MARKER):
                    if not expecting_marker:
                        raise SystemExit(
                            "%s line %d has two markers in a row"
                            % (name, number))
                    flags.append(token == BREAK_MARKER)
                    expecting_marker = False
                else:
                    if expecting_marker:
                        raise SystemExit(
                            "%s line %d has two code points in a row"
                            % (name, number))
                    codepoints.append(int(token, 16))
                    expecting_marker = True
            if expecting_marker:
                raise SystemExit(
                    "%s line %d ends at a code point rather than a boundary "
                    "marker" % (name, number))
            if len(flags) != len(codepoints) + 1:
                raise SystemExit(
                    "%s line %d carries %d flags for %d code points"
                    % (name, number, len(flags), len(codepoints)))
            rows.append((codepoints, flags))
    return rows


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


def format_table(name, comment, ranges):
    lines = [
        "# %s" % comment,
        "%s: list[tuple[int, int, str]] = [" % name,
    ]
    for lo, hi, value in ranges:
        lines.append("    (%d, %d, %r)," % (lo, hi, value))
    lines.append("]")
    return "\n".join(lines)


def format_lookup(func, doc, table, default):
    return "\n".join([
        "def %s(cp: int) -> str:" % func,
        '    """%s' % doc,
        "",
        "    The ranges partition the code space and are sorted by lower",
        "    bound, so the covering range is unique and a binary search finds",
        '    it."""',
        "    lo = 0",
        "    hi = len(%s)" % table,
        "    while lo < hi:",
        "        mid = lo + (hi - lo) // 2",
        "        range_lo, range_hi, value = %s[mid]" % table,
        "        if cp < range_lo:",
        "            hi = mid",
        "        elif cp > range_hi:",
        "            lo = mid + 1",
        "        else:",
        "            return value",
        "    return %s" % default,
    ])


def format_rows_module(uax, algorithm, corpus, rows):
    """A corpus rows module: the published rows of one break corpus, as data.

    The `corpus` package's two gates read `PUBLISHED_ROWS` and
    `PUBLISHED_COUNT`, so each published corpus gets one of these and the
    gates serve them all.
    """
    row_lines = ["PUBLISHED_ROWS: list[tuple[list[int], list[bool]]] = ["]
    for codepoints, flags in rows:
        row_lines.append("    ([%s], [%s])," % (
            ", ".join(str(cp) for cp in codepoints),
            ", ".join("True" if flag else "False" for flag in flags)))
    row_lines.append("]")

    return "\n".join([
        '"""The published UAX #%s %s corpus, ``%s``.' % (uax, algorithm, corpus),
        "",
        "Hand-written vectors cannot establish a segmentation algorithm: its",
        "rules read context on both sides of a boundary and the answer",
        "depends on state carried from earlier in the sequence, so a wrong",
        "rule survives any vector a person would pick. The Unicode Consortium",
        "publishes a corpus per algorithm for that reason, and this is it, as",
        "data.",
        "",
        "Each row is the code points of one test case and the boundary flags",
        "the file writes for it, ``True`` for a break opportunity. A row",
        "carries one more flag than code points.",
        "",
        "Generated by ``tools/generate_line_break_tables.py``. Edit that",
        'script and regenerate rather than editing this file."""',
        "",
        "from __future__ import annotations",
        "",
        "# How many rows the pinned corpus carries, counted at generation.",
        "# The corpus gate asserts the emitted row count against this, so a",
        "# row lost between the file and the table fails rather than quietly",
        "# shrinking the denominator.",
        "PUBLISHED_COUNT = %d" % len(rows),
        "",
        "\n".join(row_lines),
        "",
    ])


def write_file(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    sys.stdout.write("wrote %s (%d lines)\n" % (
        os.path.relpath(path, ROOT), text.count("\n")))


def main():
    gc_ranges = coalesce(read_general_category_rows())
    eaw_ranges = coalesce(read_two_field_rows(
        EAST_ASIAN_WIDTH_TXT, EAW_VALUES, "East_Asian_Width"))
    lb_ranges = coalesce(read_two_field_rows(
        LINE_BREAK_TXT, LB_VALUES, "Line_Break"))
    test_rows = read_break_test_rows(LINE_BREAK_TEST_TXT)
    grapheme_rows = read_break_test_rows(GRAPHEME_BREAK_TEST_TXT)

    write_file(GENERAL_CATEGORY_PY, "\n".join([
        '"""General_Category ranges from UCD ``UnicodeData.txt``.',
        "",
        "A port of ``Unicode.Generated.DerivedGeneralCategory``: the same 30",
        "property values, the same coalesced inclusive ranges, and the same",
        "``Cn`` default for a code point no range covers.",
        "",
        "This module sits above both the security and segmentation layers so",
        "either can read the property, which is where the Lean keeps it.",
        "",
        "Generated by ``tools/generate_line_break_tables.py``. Edit that",
        'script and regenerate rather than editing this file."""',
        "",
        "from __future__ import annotations",
        "",
        "# General_Category of a code point no range covers, the default",
        "# UnicodeData.txt declares for unassigned code points.",
        'DEFAULT_GC = "Cn"',
        "",
        format_table(
            "GC_RANGES", "(first, last, General_Category value)", gc_ranges),
        "",
        "",
        format_lookup(
            "general_category",
            "``General_Category`` of ``cp``, ``DEFAULT_GC`` when uncovered.",
            "GC_RANGES", "DEFAULT_GC"),
        "",
    ]))

    write_file(EAST_ASIAN_WIDTH_PY, "\n".join([
        '"""East_Asian_Width ranges from UCD ``EastAsianWidth.txt``.',
        "",
        "A port of ``Unicode.Generated.EastAsianWidth``: the six UAX #11",
        "property values, coalesced inclusive ranges, and the ``N`` default",
        "the file declares for every code point it does not list explicitly.",
        "",
        "This module sits above both the security and segmentation layers so",
        "either can read the property, which is where the Lean keeps it.",
        "",
        "Generated by ``tools/generate_line_break_tables.py``. Edit that",
        'script and regenerate rather than editing this file."""',
        "",
        "from __future__ import annotations",
        "",
        "# East_Asian_Width of a code point the file does not list.",
        'DEFAULT_EAST_ASIAN_WIDTH = "N"',
        "",
        format_table(
            "EAST_ASIAN_WIDTH_RANGES",
            "(first, last, East_Asian_Width value)", eaw_ranges),
        "",
        "",
        format_lookup(
            "east_asian_width_value",
            "``East_Asian_Width`` of ``cp``, ``N`` when the file omits it.",
            "EAST_ASIAN_WIDTH_RANGES", "DEFAULT_EAST_ASIAN_WIDTH"),
        "",
    ]))

    write_file(LINE_BREAK_TABLES_PY, "\n".join([
        '"""Line_Break ranges from UCD ``LineBreak.txt``.',
        "",
        "A port of ``Unicode.Generated.LineBreakProperty``: the same 49",
        "property values, the same inclusive ranges, and the same ``XX``",
        "default for a code point no range covers, which the file's own",
        "``@missing: 0000..10FFFF; XX`` header declares.",
        "",
        "The classes here are raw, before UAX #14 LB1 tailors them;",
        "``line_break.resolved_class`` applies LB1.",
        "",
        "Generated by ``tools/generate_line_break_tables.py``. Edit that",
        'script and regenerate rather than editing this file."""',
        "",
        "from __future__ import annotations",
        "",
        "# Line_Break class of a code point no range covers.",
        'DEFAULT_LB = "XX"',
        "",
        format_table(
            "LB_RANGES", "(first, last, Line_Break value)", lb_ranges),
        "",
        "",
        format_lookup(
            "raw_class",
            "Raw ``Line_Break`` class of ``cp``, before LB1.",
            "LB_RANGES", "DEFAULT_LB"),
        "",
    ]))

    write_file(LINE_BREAK_ROWS_PY, format_rows_module(
        "14", "line-break", "LineBreakTest.txt", test_rows))
    write_file(GRAPHEME_ROWS_PY, format_rows_module(
        "29", "grapheme-cluster", "GraphemeBreakTest.txt", grapheme_rows))


if __name__ == "__main__":
    main()
