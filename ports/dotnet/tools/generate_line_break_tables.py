#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
#                      // tools // generate // line-break-tables
# ─────────────────────────────────────────────────────────────────────────────
#
# Emits the property tables the UAX #14 line breaker reads and vendors the
# published corpus it is judged against, from the pinned UCD files in the
# repository root:
#
#   src/UnicodeSecurity/Segmentation/LineBreakTables.cs
#       The four properties the algorithm reads — Line_Break, a port of
#       `Unicode.Generated.LineBreakProperty`; General_Category, a port of
#       `Unicode.Generated.DerivedGeneralCategory`; East_Asian_Width, a port
#       of `Unicode.Generated.EastAsianWidth`; and Extended_Pictographic, a
#       port of `Unicode.Generated.EmojiData`.
#   testdata/LineBreakTest.txt
#       The published corpus, which the contract suite reads at run time.
#
# The tables are generated into source rather than read from `Data/`.
# `Security` serves its UCD tables through `ReadDataFile` behind a map of
# pinned SHA-256 digests, and its East_Asian_Width is unreachable from
# elsewhere in the assembly: the enum, the table and the lookup are all
# private to that class.
#
# A table is three parallel arrays of primitives — starts, ends and class
# codes — rather than one array of tuples. Roslyn emits a primitive array
# initialiser as a metadata blob that `InitializeArray` copies in one call,
# so a table of this length is data in the assembly; an initialiser of
# tuples is element-wise assignment inside a method instead.
#
#   python3 ports/dotnet/tools/generate_line_break_tables.py
#
# Run from anywhere. Writing the table class and the corpus is the whole
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

PORT = os.path.join(ROOT, "ports", "dotnet")
TABLES_CS = os.path.join(
    PORT, "src", "UnicodeSecurity", "Segmentation", "LineBreakTables.cs")
VENDORED_CORPUS = os.path.join(PORT, "testdata", "LineBreakTest.txt")

# The markers the published break corpora write at each boundary.
BREAK_MARKER = "÷"
NO_BREAK_MARKER = "×"

# How many ranges go on one line of an emitted array.
PER_LINE = 12

# The 49 Line_Break property values UAX #14 defines, each with the C#
# identifier the generated enum gives it.
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
# abbreviations are already valid C# identifiers.
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
    return [ucd for ucd, _identifier in values]


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
    does not is a corpus the suite cannot read, and the count it would report
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


def format_enum(name, property_name, values):
    """One property's values as a C# enum, in class-code order."""
    lines = ["/// <summary>%s property value.</summary>" % property_name,
             "public enum %s" % name, "{"]
    for ucd, identifier in values:
        lines.append("    /// <summary>%s = <c>%s</c>.</summary>"
                     % (property_name, ucd))
        lines.append("    %s," % identifier)
    lines.append("}")
    return "\n".join(lines)


def format_uint_array(name, doc, points):
    """One bound of every range as a C# array of unsigned hex literals."""
    lines = ["    /// <summary>%s</summary>" % doc,
             "    public static readonly uint[] %s =" % name, "    {"]
    for at in range(0, len(points), PER_LINE):
        batch = points[at:at + PER_LINE]
        lines.append("        " + " ".join("0x%04X," % point
                                           for point in batch))
    lines.append("    };")
    return "\n".join(lines)


def format_class_array(name, doc, codes):
    """Every range's class code as a C# byte array."""
    lines = ["    /// <summary>%s</summary>" % doc,
             "    public static readonly byte[] %s =" % name, "    {"]
    for at in range(0, len(codes), PER_LINE * 2):
        batch = codes[at:at + PER_LINE * 2]
        lines.append("        " + " ".join("%d," % code for code in batch))
    lines.append("    };")
    return "\n".join(lines)


def split_ranges(ranges, values):
    """Ranges as parallel lists of starts, ends and class codes."""
    index_of = {ucd: index for index, (ucd, _ident) in enumerate(values)}
    return ([lo for lo, _hi, _value in ranges],
            [hi for _lo, hi, _value in ranges],
            [index_of[value] for _lo, _hi, value in ranges])


def format_lookup(name, returns, table, default, doc):
    """A binary search over one classed table."""
    return "\n".join([
        "    /// <summary>%s</summary>" % doc,
        "    public static %s %s(uint cp)" % (returns, name),
        "    {",
        "        var low = 0;",
        "        var high = %sStart.Length;" % table,
        "        while (low < high)",
        "        {",
        "            var mid = low + ((high - low) / 2);",
        "            if (cp < %sStart[mid])" % table,
        "            {",
        "                high = mid;",
        "            }",
        "            else if (cp > %sEnd[mid])" % table,
        "            {",
        "                low = mid + 1;",
        "            }",
        "            else",
        "            {",
        "                return (%s)%sClass[mid];" % (returns, table),
        "            }",
        "        }",
        "",
        "        return %s;" % default,
        "    }",
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

    lb_start, lb_end, lb_class = split_ranges(lb_ranges, LB_VALUES)
    gc_start, gc_end, gc_class = split_ranges(gc_ranges, GC_VALUES)
    eaw_start, eaw_end, eaw_class = split_ranges(eaw_ranges, EAW_VALUES)
    ext_start = [lo for lo, _hi, _value in ext_pict_ranges]
    ext_end = [hi for _lo, hi, _value in ext_pict_ranges]

    write_file(TABLES_CS, "\n".join([
        "// Property tables the UAX #14 line breaker reads, from the pinned",
        "// UCD 17.0.0 files -- ports of Unicode.Generated.{LineBreakProperty,",
        "// DerivedGeneralCategory,EastAsianWidth,EmojiData}. Same property",
        "// values, same ranges.",
        "// Line_Break ranges: %d, General_Category ranges: %d,"
        % (len(lb_ranges), len(gc_ranges)),
        "// East_Asian_Width ranges: %d, Extended_Pictographic ranges: %d."
        % (len(eaw_ranges), len(ext_pict_ranges)),
        "//",
        "// These are code rather than entries under Data/. Security serves",
        "// its UCD tables through ReadDataFile behind a map of pinned",
        "// SHA-256 digests, and the East_Asian_Width it holds is private to",
        "// that class along with its enum and its lookup.",
        "//",
        "// Each table is three parallel arrays of primitives, which Roslyn",
        "// emits as a metadata blob that InitializeArray copies in one call.",
        "// The ranges are sorted by start and disjoint, so the covering",
        "// range is unique and a lookup binary-searches for it.",
        "//",
        "// Do not edit by hand. Regenerate with",
        "// tools/generate_line_break_tables.py.",
        "",
        "namespace UnicodeSecurity.Segmentation;",
        "",
        format_enum("Lb", "Line_Break", LB_VALUES),
        "",
        format_enum("Gc", "General_Category", GC_VALUES),
        "",
        format_enum("Eaw", "East_Asian_Width", EAW_VALUES),
        "",
        "/// <summary>",
        "/// The Line_Break, General_Category, East_Asian_Width and",
        "/// Extended_Pictographic tables UAX #14 reads, with the lookup each",
        "/// property answers.",
        "/// </summary>",
        "public static class LineBreakTables",
        "{",
        "    /// <summary>",
        "    /// How many data rows the pinned corpus carries, counted from the",
        "    /// canonical LineBreakTest.txt at generation. The corpus gate",
        "    /// asserts the rows it reads from the vendored copy against this,",
        "    /// so a row lost between the two fails rather than quietly",
        "    /// shrinking the denominator.",
        "    /// </summary>",
        "    public const int PublishedRowCount = %d;" % published_rows,
        "",
        format_uint_array("LbStart", "First code point of each Line_Break "
                          "range.", lb_start),
        "",
        format_uint_array("LbEnd", "Last code point of each Line_Break "
                          "range.", lb_end),
        "",
        format_class_array("LbClass", "The <see cref=\"Lb\"/> of each "
                           "Line_Break range.", lb_class),
        "",
        format_uint_array("GcStart", "First code point of each "
                          "General_Category range.", gc_start),
        "",
        format_uint_array("GcEnd", "Last code point of each General_Category "
                          "range.", gc_end),
        "",
        format_class_array("GcClass", "The <see cref=\"Gc\"/> of each "
                           "General_Category range.", gc_class),
        "",
        format_uint_array("EawStart", "First code point of each "
                          "East_Asian_Width range.", eaw_start),
        "",
        format_uint_array("EawEnd", "Last code point of each "
                          "East_Asian_Width range.", eaw_end),
        "",
        format_class_array("EawClass", "The <see cref=\"Eaw\"/> of each "
                           "East_Asian_Width range.", eaw_class),
        "",
        format_uint_array("ExtPictStart", "First code point of each "
                          "Extended_Pictographic range.", ext_start),
        "",
        format_uint_array("ExtPictEnd", "Last code point of each "
                          "Extended_Pictographic range.", ext_end),
        "",
        format_lookup(
            "RawClass", "Lb", "Lb", "Lb.Xx",
            "The Line_Break class of <paramref name=\"cp\"/> before LB1. A "
            "code point no range covers is <c>XX</c>, the default "
            "LineBreak.txt declares in its own <c>@missing: 0000..10FFFF; "
            "XX</c> header."),
        "",
        format_lookup(
            "CategoryOf", "Gc", "Gc", "Gc.Cn",
            "The General_Category of <paramref name=\"cp\"/>, <c>Cn</c> when "
            "no range covers it -- the default UnicodeData.txt declares for "
            "unassigned code points."),
        "",
        format_lookup(
            "WidthOf", "Eaw", "Eaw", "Eaw.N",
            "The East_Asian_Width of <paramref name=\"cp\"/>, <c>N</c> when "
            "the file omits it."),
        "",
        "    /// <summary>",
        "    /// Whether <paramref name=\"cp\"/> carries the",
        "    /// Extended_Pictographic property, which LB30b reads.",
        "    /// </summary>",
        "    public static bool IsExtendedPictographic(uint cp)",
        "    {",
        "        var low = 0;",
        "        var high = ExtPictStart.Length;",
        "        while (low < high)",
        "        {",
        "            var mid = low + ((high - low) / 2);",
        "            if (cp < ExtPictStart[mid])",
        "            {",
        "                high = mid;",
        "            }",
        "            else if (cp > ExtPictEnd[mid])",
        "            {",
        "                low = mid + 1;",
        "            }",
        "            else",
        "            {",
        "                return true;",
        "            }",
        "        }",
        "",
        "        return false;",
        "    }",
        "}",
        "",
    ]))

    os.makedirs(os.path.dirname(VENDORED_CORPUS), exist_ok=True)
    shutil.copyfile(LINE_BREAK_TEST_TXT, VENDORED_CORPUS)
    sys.stdout.write("wrote %s (%d published rows)\n" % (
        os.path.relpath(VENDORED_CORPUS, ROOT), published_rows))


if __name__ == "__main__":
    main()
