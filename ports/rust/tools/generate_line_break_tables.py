#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
#                      // tools // generate // line-break-tables
# ─────────────────────────────────────────────────────────────────────────────
#
# Emits the two generated Rust property tables the UAX #14 line breaker reads,
# from the pinned UCD files in the repository root:
#
#   src/general_category.rs          General_Category ranges, mirroring
#                                    `Unicode.Generated.DerivedGeneralCategory`
#   src/segmentation/line_break_tables.rs
#                                    Line_Break ranges, mirroring
#                                    `Unicode.Generated.LineBreakProperty`
#
# Both tables carry coalesced inclusive ranges sorted by lower bound, so a
# lookup binary-searches for the one range covering a code point. The ranges of
# each property partition the code space, so the covering range is unique and
# agrees with the linear first-match `find?` the Lean reference uses.
#
#   python3 ports/rust/tools/generate_line_break_tables.py
#
# Run from the repository root. Writing the files is the whole effect; the
# script reads no state and takes no arguments.

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

LINE_BREAK_TXT = os.path.join(ROOT, "Unicode", "Ucd", "LineBreak.txt")
LINE_BREAK_TEST_TXT = os.path.join(ROOT, "Unicode", "Ucd", "LineBreakTest.txt")
UNICODE_DATA_TXT = os.path.join(ROOT, "Unicode", "Ucd", "UnicodeData.txt")
EAST_ASIAN_WIDTH_TXT = os.path.join(
    ROOT, "Unicode", "Ucd", "EastAsianWidth.txt")

EAST_ASIAN_WIDTH_RS = os.path.join(
    ROOT, "ports", "rust", "src", "east_asian_width.rs")
GENERAL_CATEGORY_RS = os.path.join(
    ROOT, "ports", "rust", "src", "general_category.rs")
LINE_BREAK_TABLES_RS = os.path.join(
    ROOT, "ports", "rust", "src", "segmentation", "line_break_tables.rs")
LINE_BREAK_ROWS_RS = os.path.join(
    ROOT, "ports", "rust", "tests", "corpus", "line_break_rows.rs")

# The markers the published break corpora write at each boundary.
BREAK_MARKER = "÷"
NO_BREAK_MARKER = "×"

# The 49 Line_Break property values UAX #14 defines, in the order
# `Unicode.Generated.LineBreakProperty.parseLB?` lists them.
LB_VALUES = [
    "AI", "AK", "AL", "AP", "AS", "B2", "BA", "BB", "BK", "CB", "CJ", "CL",
    "CM", "CP", "CR", "EB", "EM", "EX", "GL", "H2", "H3", "HH", "HL", "HY",
    "ID", "IN", "IS", "JL", "JT", "JV", "LF", "NL", "NS", "NU", "OP", "PO",
    "PR", "QU", "RI", "SA", "SG", "SP", "SY", "VF", "VI", "WJ", "XX", "ZW",
    "ZWJ",
]

# The six East_Asian_Width values of UAX #11.
EAW_VALUES = ["A", "F", "H", "N", "Na", "W"]

# The 30 General_Category values of UAX #44 section 5.7.1, in the order
# `Unicode.Generated.DerivedGeneralCategory.GC` declares them.
GC_VALUES = [
    "Lu", "Ll", "Lt", "Lm", "Lo",
    "Mn", "Mc", "Me",
    "Nd", "Nl", "No",
    "Pc", "Pd", "Ps", "Pe", "Pi", "Pf", "Po",
    "Sm", "Sc", "Sk", "So",
    "Zs", "Zl", "Zp",
    "Cc", "Cf", "Cs", "Co", "Cn",
]


def rust_variant(value):
    """The Rust enum variant naming a UCD property value.

    A UCD code is written in Rust's variant case, as the crate's other property
    enums write it: `AL` becomes `Al`, `ZWJ` becomes `Zwj`, and a code already
    in that case, such as `B2` or `Mn`, is unchanged.
    """
    return value.capitalize()


def strip_comment(line):
    body = line.split("#", 1)[0]
    return body.strip()


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

    A code point range appears in UnicodeData.txt as two rows whose names end
    `, First>` and `, Last>`; every other row covers one code point.
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


def read_break_test_rows():
    """The published rows of LineBreakTest.txt as (codepoints, flags).

    A row alternates boundary markers and code points, starting and ending with
    a marker, so it carries one more flag than code points. The leading marker
    is the start-of-text boundary and the trailing one the end-of-text
    boundary.
    """
    rows = []
    with open(LINE_BREAK_TEST_TXT, "r", encoding="utf-8") as handle:
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
                            "LineBreakTest.txt line %d has two markers in a "
                            "row" % number)
                    flags.append(token == BREAK_MARKER)
                    expecting_marker = False
                else:
                    if expecting_marker:
                        raise SystemExit(
                            "LineBreakTest.txt line %d has two code points in "
                            "a row" % number)
                    codepoints.append(int(token, 16))
                    expecting_marker = True
            if expecting_marker:
                raise SystemExit(
                    "LineBreakTest.txt line %d ends at a code point rather "
                    "than a boundary marker" % number)
            if len(flags) != len(codepoints) + 1:
                raise SystemExit(
                    "LineBreakTest.txt line %d carries %d flags for %d code "
                    "points" % (number, len(flags), len(codepoints)))
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


def format_table(name, element_type, ranges):
    lines = [
        "pub(crate) static %s: &[(u32, u32, %s)] = &["
        % (name, element_type)
    ]
    for lo, hi, value in ranges:
        lines.append(
            "    (0x%04X, 0x%04X, %s::%s),"
            % (lo, hi, element_type, rust_variant(value)))
    lines.append("];")
    return "\n".join(lines)


def format_enum(doc, name, values, derives):
    lines = ["/// %s" % doc, "#[derive(%s)]" % derives, "pub enum %s {" % name]
    for value in values:
        lines.append("    /// `%s`." % value)
        lines.append("    %s," % rust_variant(value))
    lines.append("}")
    return "\n".join(lines)


GENERAL_CATEGORY_HEADER = '''//! General_Category ranges from UCD `UnicodeData.txt`.
//!
//! A transcription of `Unicode.Generated.DerivedGeneralCategory`: the same 30
//! property values in the same order, the same coalesced inclusive ranges, and
//! the same `Cn` default for a code point no range covers.
//!
//! Generated by `tools/generate_line_break_tables.py`. Edit that script and
//! regenerate rather than editing this file.
'''

LINE_BREAK_TABLES_HEADER = '''//! Line_Break ranges from UCD `LineBreak.txt`.
//!
//! A transcription of `Unicode.Generated.LineBreakProperty`: the same 49
//! property values, the same inclusive ranges, and the same `XX` default for a
//! code point no range covers, which the file's own
//! `@missing: 0000..10FFFF; XX` header declares.
//!
//! The classes here are raw, before UAX #14 LB1 tailors them;
//! `super::line_break::resolved_class` applies LB1.
//!
//! Generated by `tools/generate_line_break_tables.py`. Edit that script and
//! regenerate rather than editing this file.
'''


LINE_BREAK_ROWS_HEADER = '''//! The published UAX #14 line-break corpus, `LineBreakTest.txt`.
//!
//! Hand-written vectors cannot establish a segmentation algorithm: its rules
//! read context on both sides of a boundary and the answer depends on state
//! carried from earlier in the sequence, so a wrong rule survives any vector a
//! person would pick. The Unicode Consortium publishes a corpus per algorithm
//! for that reason, and this is it, as data.
//!
//! Each row is the code points of one test case and the boundary flags the file
//! writes for it, `true` for a break opportunity. A row carries one more flag
//! than code points.
//!
//! Generated by `tools/generate_line_break_tables.py`. Edit that script and
//! regenerate rather than editing this file.
'''


def format_rows(rows):
    lines = ["pub static PUBLISHED_ROWS: &[(&[u32], &[bool])] = &["]
    for codepoints, flags in rows:
        points = ", ".join("0x%04X" % cp for cp in codepoints)
        marks = ", ".join("true" if flag else "false" for flag in flags)
        lines.append("    (&[%s], &[%s])," % (points, marks))
    lines.append("];")
    return "\n".join(lines)


def write_file(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    line_count = text.count("\n")
    sys.stdout.write("wrote %s (%d lines)\n" % (
        os.path.relpath(path, ROOT), line_count))


EAST_ASIAN_WIDTH_HEADER = '''//! East_Asian_Width ranges from UCD `EastAsianWidth.txt`.
//!
//! A transcription of `Unicode.Generated.EastAsianWidth`: the six UAX #11
//! property values, coalesced inclusive ranges, and the `N` default the file
//! declares for every code point it does not list explicitly.
//!
//! This module sits above both the security and segmentation layers so either
//! can read the property, which is where the Lean keeps it.
//!
//! Generated by `tools/generate_line_break_tables.py`. Edit that script and
//! regenerate rather than editing this file.
'''


def main():
    gc_ranges = coalesce(read_general_category_rows())
    eaw_ranges = coalesce(read_two_field_rows(
        EAST_ASIAN_WIDTH_TXT, EAW_VALUES, "East_Asian_Width"))
    lb_ranges = coalesce(read_two_field_rows(
        LINE_BREAK_TXT, LB_VALUES, "Line_Break"))

    write_file(EAST_ASIAN_WIDTH_RS, "\n".join([
        EAST_ASIAN_WIDTH_HEADER,
        format_enum(
            "A UAX #11 East_Asian_Width class.",
            "EastAsianWidthClass", EAW_VALUES,
            "Debug, Clone, Copy, PartialEq, Eq"),
        "",
        "/// East_Asian_Width of a code point the file does not list.",
        "pub const DEFAULT_EAST_ASIAN_WIDTH: EastAsianWidthClass =",
        "    EastAsianWidthClass::N;",
        "",
        format_table(
            "EAST_ASIAN_WIDTH_RANGES", "EastAsianWidthClass", eaw_ranges),
        "",
        "/// `East_Asian_Width` of `cp`, `N` when the file omits it.",
        "///",
        "/// The ranges partition the code space and are sorted by lower bound,",
        "/// so the covering range is unique and a binary search finds it.",
        "pub fn east_asian_width(cp: u32) -> EastAsianWidthClass {",
        "    let mut lo = 0usize;",
        "    let mut hi = EAST_ASIAN_WIDTH_RANGES.len();",
        "    while lo < hi {",
        "        let mid = lo + (hi - lo) / 2;",
        "        let (range_lo, range_hi, class) = EAST_ASIAN_WIDTH_RANGES[mid];",
        "        if cp < range_lo {",
        "            hi = mid;",
        "        } else if cp > range_hi {",
        "            lo = mid + 1;",
        "        } else {",
        "            return class;",
        "        }",
        "    }",
        "    DEFAULT_EAST_ASIAN_WIDTH",
        "}",
        "",
    ]))

    write_file(GENERAL_CATEGORY_RS, "\n".join([
        GENERAL_CATEGORY_HEADER,
        format_enum(
            "A UAX #44 section 5.7.1 General_Category value.",
            "Gc", GC_VALUES, "Debug, Clone, Copy, PartialEq, Eq"),
        "",
        "/// General_Category of a code point no range covers, the default",
        "/// `UnicodeData.txt` declares for unassigned code points.",
        "pub const DEFAULT_GC: Gc = Gc::Cn;",
        "",
        format_table("GC_RANGES", "Gc", gc_ranges),
        "",
        "/// `General_Category` of `cp`, [`DEFAULT_GC`] when no range covers it.",
        "///",
        "/// The ranges partition the code space and are sorted by lower bound,",
        "/// so the covering range is unique and a binary search finds it.",
        "pub fn general_category(cp: u32) -> Gc {",
        "    let mut lo = 0usize;",
        "    let mut hi = GC_RANGES.len();",
        "    while lo < hi {",
        "        let mid = lo + (hi - lo) / 2;",
        "        let (range_lo, range_hi, gc) = GC_RANGES[mid];",
        "        if cp < range_lo {",
        "            hi = mid;",
        "        } else if cp > range_hi {",
        "            lo = mid + 1;",
        "        } else {",
        "            return gc;",
        "        }",
        "    }",
        "    DEFAULT_GC",
        "}",
        "",
    ]))

    write_file(LINE_BREAK_TABLES_RS, "\n".join([
        LINE_BREAK_TABLES_HEADER,
        format_enum(
            "A UAX #14 Line_Break property value.",
            "Lb", LB_VALUES, "Debug, Clone, Copy, PartialEq, Eq"),
        "",
        "/// Line_Break class of a code point no range covers.",
        "pub const DEFAULT_LB: Lb = Lb::Xx;",
        "",
        format_table("LB_RANGES", "Lb", lb_ranges),
        "",
    ]))

    test_rows = read_break_test_rows()
    write_file(LINE_BREAK_ROWS_RS, "\n".join([
        LINE_BREAK_ROWS_HEADER,
        "/// How many rows the pinned `LineBreakTest.txt` carries, counted at",
        "/// generation. The corpus gate asserts the emitted row count against",
        "/// this, so a row lost between the file and the table fails rather",
        "/// than quietly shrinking the denominator.",
        "pub const PUBLISHED_COUNT: usize = %d;" % len(test_rows),
        "",
        format_rows(test_rows),
        "",
    ]))


if __name__ == "__main__":
    main()
