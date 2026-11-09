#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
#                      // tools // generate // line-break-tables
# ─────────────────────────────────────────────────────────────────────────────
#
# Emits the property tables the UAX #14 line breaker reads and vendors the
# published corpus it is judged against, from the pinned UCD files in the
# repository root:
#
#   src/line_break_data.zig
#       The three properties this port did not already carry — Line_Break, a
#       port of `Unicode.Generated.LineBreakProperty`; General_Category, a port
#       of `Unicode.Generated.DerivedGeneralCategory`; and
#       Extended_Pictographic, a port of `Unicode.Generated.EmojiData` — plus
#       the corpus row count.
#   testdata/LineBreakTest.txt
#       The published corpus, which the test reads at run time.
#
# East_Asian_Width is not emitted. `src/east_asian_width_data.zig` already
# carries it as a generated, importable table of ranges sorted by start, and a
# second copy would be a duplicate; `line_break.zig` binary-searches that one.
#
# Extended_Pictographic is emitted because LB30b reads it and this port carries
# no grapheme clustering to borrow a table from.
#
# Each table emitted here carries coalesced inclusive ranges sorted by lower
# bound, so a lookup binary-searches for the one range covering a code point.
# The ranges of each property partition the code space, so that range is unique
# and agrees with the linear first-match the Lean reference uses.
#
#   python3 ports/zig/tools/generate_line_break_tables.py
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
EMOJI_DATA_TXT = os.path.join(UCD, "emoji-data.txt")

PORT = os.path.join(ROOT, "ports", "zig")
LINE_BREAK_DATA_ZIG = os.path.join(PORT, "src", "line_break_data.zig")
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


def field(value):
    """The Zig enum field naming a UCD property value.

    The port writes a property class as a lowercase field — `.na`, `.w` in
    east_asian_width_data.zig — so `AL` becomes `.al`, `ZWJ` `.zwj`, and `Mn`
    `.mn`. None of the 79 values collides with a Zig keyword.
    """
    return value.lower()


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

    LB30b reads the property, and this port has no grapheme clustering to
    borrow a table from. Only that one property value is taken; the file
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
    for value in values:
        lines.append("    %s," % field(value))
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


def format_table(name, doc, range_type, ranges):
    lines = [doc, "pub const %s = [_]%s{" % (name, range_type)]
    for lo, hi, value in ranges:
        lines.append("    .{ .start = 0x%04X, .end = 0x%04X, .class = .%s },"
                     % (lo, hi, field(value)))
    lines.append("};")
    return "\n".join(lines)


def format_flag_table(name, doc, ranges):
    lines = [doc, "pub const %s = [_]CodepointRange{" % name]
    for lo, hi, _value in ranges:
        lines.append("    .{ .start = 0x%04X, .end = 0x%04X }," % (lo, hi))
    lines.append("};")
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
    ext_pict_ranges = coalesce(read_extended_pictographic_rows())
    published_rows = count_break_test_rows()

    write_file(LINE_BREAK_DATA_ZIG, "\n".join([
        "// GENERATED FILE - DO NOT EDIT.",
        "// Source: Unicode/Ucd/{LineBreak.txt,UnicodeData.txt,emoji-data.txt}",
        "// Regenerate with tools/generate_line_break_tables.py.",
        "//",
        "// Ports of Unicode.Generated.{LineBreakProperty,"
        "DerivedGeneralCategory,EmojiData}:",
        "// the same property values and the same ranges.",
        "//",
        "// Line_Break ranges: %d, General_Category ranges: %d,"
        % (len(lb_ranges), len(gc_ranges)),
        "// Extended_Pictographic ranges: %d." % len(ext_pict_ranges),
        "//",
        "// East_Asian_Width is not here: east_asian_width_data.zig already",
        "// carries it, and line_break.zig binary-searches that table.",
        "//",
        "// Every table below is sorted by start and coalesced, so a lookup",
        "// binary-searches it. The ranges of each property partition the",
        "// codepoint space, so the covering range is unique and the search",
        "// agrees with the Lean reference's linear first-match.",
        "",
        format_enum(
            "A UAX #14 Line_Break property value.", "Lb", LB_VALUES),
        "",
        format_enum(
            "A UAX #44 section 5.7.1 General_Category value.", "Gc",
            GC_VALUES),
        "",
        format_range_struct("LbRange", "Lb"),
        "",
        format_range_struct("GcRange", "Gc"),
        "",
        "// One inclusive range of a boolean property, [start, end].",
        "pub const CodepointRange = struct {",
        "    start: u32,",
        "    end: u32,",
        "};",
        "",
        format_table(
            "line_break",
            "// Line_Break ranges. The classes are raw, before UAX #14 LB1\n"
            "// tailors them; line_break.resolvedClass applies LB1. A codepoint\n"
            "// no range covers is .xx, which the file's own\n"
            "// `@missing: 0000..10FFFF; XX` header declares.",
            "LbRange", lb_ranges),
        "",
        format_table(
            "general_category",
            "// General_Category ranges. LB1 reads the property to resolve SA,\n"
            "// the quote refinements read .pi and .pf, and LB30b reads .cn,\n"
            "// which is also the default UnicodeData.txt declares for an\n"
            "// unassigned codepoint and so for a binary-search miss.",
            "GcRange", gc_ranges),
        "",
        format_flag_table(
            "extended_pictographic",
            "// Extended_Pictographic ranges, which LB30b reads. This port\n"
            "// carries no grapheme clustering, so the property has its own\n"
            "// table here rather than being borrowed from one.",
            ext_pict_ranges),
        "",
        "// How many data rows the pinned corpus carries, counted from the",
        "// canonical LineBreakTest.txt at generation. The corpus gate asserts",
        "// the rows it reads from the vendored copy against this, so a row lost",
        "// between the two fails rather than quietly shrinking the denominator.",
        "pub const published_row_count: usize = %d;" % published_rows,
        "",
    ]))

    os.makedirs(os.path.dirname(VENDORED_CORPUS), exist_ok=True)
    shutil.copyfile(LINE_BREAK_TEST_TXT, VENDORED_CORPUS)
    sys.stdout.write("wrote %s (%d published rows)\n" % (
        os.path.relpath(VENDORED_CORPUS, ROOT), published_rows))


if __name__ == "__main__":
    main()
