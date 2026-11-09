#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
#                      // tools // generate // line-break-tables
# ─────────────────────────────────────────────────────────────────────────────
#
# Emits the property tables the UAX #14 line breaker reads and vendors the
# published corpus it is judged against, from the pinned UCD files in the
# repository root:
#
#   lib/unicode_security/segmentation/line_break_tables.ex
#       The four properties the algorithm reads — Line_Break, a port of
#       `Unicode.Generated.LineBreakProperty`; General_Category, a port of
#       `Unicode.Generated.DerivedGeneralCategory`; East_Asian_Width, a port
#       of `Unicode.Generated.EastAsianWidth`; and Extended_Pictographic, a
#       port of `Unicode.Generated.EmojiData`.
#   test/fixtures/LineBreakTest.txt
#       The published corpus, which the test reads at run time.
#
# Where the grapheme tables are lists grouped by property value and scanned
# with `Enum.find`, these are tuples sorted by range start. A list cannot be
# indexed in constant time, so a bisection needs `elem/2`; and the scale
# demands one — the line-break corpus is 19338 rows against the grapheme
# corpus's 766, over tables an order of magnitude larger, with four properties
# read per code point.
#
#   python3 ports/elixir/tools/generate_line_break_tables.py
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

PORT = os.path.join(ROOT, "ports", "elixir")
TABLES_EX = os.path.join(
    PORT, "lib", "unicode_security", "segmentation", "line_break_tables.ex")
VENDORED_CORPUS = os.path.join(PORT, "test", "fixtures", "LineBreakTest.txt")

# The markers the published break corpora write at each boundary.
BREAK_MARKER = "÷"
NO_BREAK_MARKER = "×"

# How many ranges go on one line of an emitted tuple.
PER_LINE = 4

# The 49 Line_Break property values UAX #14 defines, each with the atom the
# generated module gives it.
LB_VALUES = [
    ("AI", "ai"), ("AK", "ak"), ("AL", "al"), ("AP", "ap"), ("AS", "as"),
    ("B2", "b2"), ("BA", "ba"), ("BB", "bb"), ("BK", "bk"), ("CB", "cb"),
    ("CJ", "cj"), ("CL", "cl"), ("CM", "cm"), ("CP", "cp"), ("CR", "cr"),
    ("EB", "eb"), ("EM", "em"), ("EX", "ex"), ("GL", "gl"), ("H2", "h2"),
    ("H3", "h3"), ("HH", "hh"), ("HL", "hl"), ("HY", "hy"), ("ID", "id"),
    ("IN", "in"), ("IS", "is"), ("JL", "jl"), ("JT", "jt"), ("JV", "jv"),
    ("LF", "lf"), ("NL", "nl"), ("NS", "ns"), ("NU", "nu"), ("OP", "op"),
    ("PO", "po"), ("PR", "pr"), ("QU", "qu"), ("RI", "ri"), ("SA", "sa"),
    ("SG", "sg"), ("SP", "sp"), ("SY", "sy"), ("VF", "vf"), ("VI", "vi"),
    ("WJ", "wj"), ("XX", "xx"), ("ZW", "zw"), ("ZWJ", "zwj"),
]

# The 30 General_Category values of UAX #44 section 5.7.1.
GC_VALUES = [
    ("Lu", "lu"), ("Ll", "ll"), ("Lt", "lt"), ("Lm", "lm"), ("Lo", "lo"),
    ("Mn", "mn"), ("Mc", "mc"), ("Me", "me"),
    ("Nd", "nd"), ("Nl", "nl"), ("No", "no"),
    ("Pc", "pc"), ("Pd", "pd"), ("Ps", "ps"), ("Pe", "pe"), ("Pi", "pi"),
    ("Pf", "pf"), ("Po", "po"),
    ("Sm", "sm"), ("Sc", "sc"), ("Sk", "sk"), ("So", "so"),
    ("Zs", "zs"), ("Zl", "zl"), ("Zp", "zp"),
    ("Cc", "cc"), ("Cf", "cf"), ("Cs", "cs"), ("Co", "co"), ("Cn", "cn"),
]

# The six East_Asian_Width values of UAX #11.
EAW_VALUES = [("A", "a"), ("F", "f"), ("H", "h"), ("N", "n"), ("Na", "na"),
              ("W", "w")]


def ucd_names(values):
    return [ucd for ucd, _atom in values]


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


def format_classed_tuple(name, doc, ranges, values):
    """Classed ranges as an Elixir tuple of `{first, last, class}` tuples."""
    atom_of = {ucd: atom for ucd, atom in values}
    lines = []
    for line in doc:
        lines.append("  # %s" % line)
    lines.append("  @%s {" % name)
    rendered = ["{%d, %d, :%s}" % (lo, hi, atom_of[value])
                for lo, hi, value in ranges]
    for at in range(0, len(rendered), PER_LINE):
        batch = rendered[at:at + PER_LINE]
        lines.append("    " + ", ".join(batch) + ",")
    # A tuple literal cannot carry a trailing comma.
    lines[-1] = lines[-1].rstrip(",")
    lines.append("  }")
    return "\n".join(lines)


def format_flag_tuple(name, doc, ranges):
    """Boolean-property ranges as an Elixir tuple of `{first, last}` tuples."""
    lines = []
    for line in doc:
        lines.append("  # %s" % line)
    lines.append("  @%s {" % name)
    rendered = ["{%d, %d}" % (lo, hi) for lo, hi, _value in ranges]
    for at in range(0, len(rendered), PER_LINE + 2):
        batch = rendered[at:at + PER_LINE + 2]
        lines.append("    " + ", ".join(batch) + ",")
    lines[-1] = lines[-1].rstrip(",")
    lines.append("  }")
    return "\n".join(lines)


def accessor(name, doc):
    return "\n".join([
        "  @doc \"%s\"" % doc,
        "  @spec %s() :: tuple()" % name,
        "  def %s, do: @%s" % (name, name),
    ])


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

    write_file(TABLES_EX, "\n".join([
        "defmodule UnicodeSecurity.Segmentation.LineBreakTables do",
        '  @moduledoc """',
        "  Property tables for UAX #14 default line breaking, transcribed from",
        "  the pinned UCD 17.0.0 files — ports of",
        "  `Unicode.Generated.{LineBreakProperty,DerivedGeneralCategory,`",
        "  `EastAsianWidth,EmojiData}`. Same property values, same ranges.",
        "",
        "  Four tables are exposed, each a tuple of ranges sorted by first code",
        "  point, with disjoint ranges, so the covering range is unique and a",
        "  lookup finds it by bisection. They are tuples rather than lists",
        "  because a list cannot be indexed in constant time and a bisection",
        "  needs `elem/2`.",
        "",
        "    * `lb_ranges/0` — Line_Break, `{first, last, class}`, the class raw",
        "      as the file states it, before UAX #14 LB1 tailors it. A code",
        "      point no range covers is `:xx`, the default LineBreak.txt",
        "      declares in its own `@missing: 0000..10FFFF; XX` header.",
        "    * `gc_ranges/0` — General_Category, `{first, last, class}`. LB1",
        "      reads it to resolve SA, LB15a and LB15b to tell an initial quote",
        "      from a final one, and LB30b to recognise an unassigned",
        "      pictograph. An uncovered code point is `:cn`.",
        "    * `eaw_ranges/0` — East_Asian_Width, `{first, last, class}`, read",
        "      by LB19a, LB25 and LB30. An uncovered code point is `:n`.",
        "    * `extpict_ranges/0` — Extended_Pictographic, `{first, last}`,",
        "      read by LB30b.",
        "",
        "  Line_Break ranges: %d, General_Category ranges: %d," % (
            len(lb_ranges), len(gc_ranges)),
        "  East_Asian_Width ranges: %d, Extended_Pictographic ranges: %d." % (
            len(eaw_ranges), len(ext_pict_ranges)),
        "",
        "  Do not edit by hand. Regenerate with",
        "  `tools/generate_line_break_tables.py`.",
        '  """',
        "",
        "  @doc \"\"\"",
        "  How many data rows the pinned corpus carries, counted from the",
        "  canonical LineBreakTest.txt at generation. The corpus gate asserts",
        "  the rows it reads from the vendored copy against this, so a row lost",
        "  between the two fails rather than quietly shrinking the denominator.",
        "  \"\"\"",
        "  @spec published_row_count() :: pos_integer()",
        "  def published_row_count, do: %d" % published_rows,
        "",
        format_classed_tuple(
            "lb_ranges",
            ["Line_Break ranges, sorted by first code point."],
            lb_ranges, LB_VALUES),
        "",
        accessor("lb_ranges", "Line_Break ranges, `{first, last, class}`."),
        "",
        format_classed_tuple(
            "gc_ranges",
            ["General_Category ranges, sorted by first code point."],
            gc_ranges, GC_VALUES),
        "",
        accessor("gc_ranges",
                 "General_Category ranges, `{first, last, class}`."),
        "",
        format_classed_tuple(
            "eaw_ranges",
            ["East_Asian_Width ranges, sorted by first code point."],
            eaw_ranges, EAW_VALUES),
        "",
        accessor("eaw_ranges",
                 "East_Asian_Width ranges, `{first, last, class}`."),
        "",
        format_flag_tuple(
            "extpict_ranges",
            ["Extended_Pictographic ranges, sorted by first code point."],
            ext_pict_ranges),
        "",
        accessor("extpict_ranges",
                 "Extended_Pictographic ranges, `{first, last}`."),
        "end",
        "",
    ]))

    os.makedirs(os.path.dirname(VENDORED_CORPUS), exist_ok=True)
    shutil.copyfile(LINE_BREAK_TEST_TXT, VENDORED_CORPUS)
    sys.stdout.write("wrote %s (%d published rows)\n" % (
        os.path.relpath(VENDORED_CORPUS, ROOT), published_rows))


if __name__ == "__main__":
    main()
