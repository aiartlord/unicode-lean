#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
#                      // tools // generate // line-break-tables
# ─────────────────────────────────────────────────────────────────────────────
#
# Emits the property tables the UAX #14 line breaker reads and vendors the
# published corpus it is judged against, from the pinned UCD files in the
# repository root:
#
#   src/main/java/com/unicodesecurity/LineBreakTables.java
#       The four properties the algorithm reads — Line_Break, a port of
#       `Unicode.Generated.LineBreakProperty`; General_Category, a port of
#       `Unicode.Generated.DerivedGeneralCategory`; East_Asian_Width, a port
#       of `Unicode.Generated.EastAsianWidth`; and Extended_Pictographic, a
#       port of `Unicode.Generated.EmojiData`.
#   testdata/LineBreakTest.txt
#       The published corpus, which the test reads at run time.
#
# The tables are generated into source rather than read from the package's
# resources. `Security` serves its UCD tables only through `readResource`
# behind a map of pinned SHA-256 digests, and the self-contained gate refuses
# any host file read under `src/main/java`; a segmentation class opening a data
# file would be a second data path outside that gate. Its East_Asian_Width is
# also unreachable: the enum and the lookup are both private.
#
# A table is encoded as fixed-width hex in string constants rather than an
# array initialiser, because a Java method's bytecode may not exceed 64 KB and
# an array initialiser of this length is one method. Each range is six hex
# digits of start, six of end, and two of class index; a boolean property omits
# the class. The strings are chunked well under the 65,535-byte constant-pool
# limit for one literal, and a static initialiser decodes them into parallel
# arrays once.
#
#   python3 ports/jvm/tools/generate_line_break_tables.py
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

PORT = os.path.join(ROOT, "ports", "jvm")
TABLES_JAVA = os.path.join(
    PORT, "src", "main", "java", "com", "unicodesecurity",
    "LineBreakTables.java")
VENDORED_CORPUS = os.path.join(PORT, "testdata", "LineBreakTest.txt")

# The markers the published break corpora write at each boundary.
BREAK_MARKER = "÷"
NO_BREAK_MARKER = "×"

# How many characters of encoded table go in one string literal. Far under the
# 65,535-byte limit on a single constant-pool entry, and a multiple of both
# record widths so no range straddles a chunk.
CHUNK_CHARS = 19992

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
    """The Extended_Pictographic ranges of emoji-data.txt as (lo, hi).

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


def encode_ranges(ranges, values):
    """Ranges as fixed-width hex: six digits of start, six of end, two of class."""
    index_of = {value: index for index, value in enumerate(values)}
    return "".join(
        "%06X%06X%02X" % (lo, hi, index_of[value]) for lo, hi, value in ranges)


def encode_flag_ranges(ranges):
    """Boolean-property ranges as six digits of start and six of end."""
    return "".join("%06X%06X" % (lo, hi) for lo, hi, _value in ranges)


def chunk_literals(encoded, indent):
    """One encoded table as a Java array of string literals."""
    chunks = [encoded[at:at + CHUNK_CHARS]
              for at in range(0, len(encoded), CHUNK_CHARS)]
    return ("\n" + indent).join('"%s",' % chunk for chunk in chunks)


def format_constants(prefix, values):
    """One `static final int` per property value, named for the value."""
    return "\n".join(
        "  static final int %s_%s = %d;" % (prefix, value.upper(), index)
        for index, value in enumerate(values))


def format_names(name, values):
    """The property values as a Java array, indexed by class code."""
    return "\n".join([
        "  static final String[] %s = {" % name,
        "    " + ", ".join('"%s"' % value for value in values),
        "  };",
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

    write_file(TABLES_JAVA, "\n".join([
        "package com.unicodesecurity;",
        "",
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
        "// These are code rather than entries under the package's resources.",
        "// Security serves its UCD tables only through readResource behind a",
        "// map of pinned SHA-256 digests, and the self-contained gate refuses",
        "// any host file read under src/main/java; a segmentation class opening",
        "// a data file would be a second data path outside that gate. The",
        "// East_Asian_Width Security holds is also unreachable from here: the",
        "// enum and the lookup are both private.",
        "//",
        "// A table is fixed-width hex in string constants rather than an array",
        "// initialiser, because a method's bytecode may not exceed 64 KB and an",
        "// initialiser of this length is one method. Each range is six hex",
        "// digits of start, six of end and two of class index; a boolean",
        "// property omits the class. A static initialiser decodes them once",
        "// into arrays sorted by range start, so a lookup binary-searches.",
        "//",
        "// GENERATED FILE - DO NOT EDIT. Regenerate with",
        "// tools/generate_line_break_tables.py.",
        "final class LineBreakTables {",
        "  private LineBreakTables() {}",
        "",
        "  // How many data rows the pinned corpus carries, counted at",
        "  // generation. The corpus gate asserts the rows it reads against",
        "  // this, so a row lost between the file and the fold fails rather",
        "  // than quietly shrinking the denominator.",
        "  static final int PUBLISHED_ROW_COUNT = %d;" % published_rows,
        "",
        "  // The Line_Break values, raw, before UAX #14 LB1 tailors them.",
        format_constants("LB", LB_VALUES),
        "",
        format_names("LINE_BREAK_CLASSES", LB_VALUES),
        "",
        "  // The General_Category values.",
        format_constants("GC", GC_VALUES),
        "",
        format_names("GENERAL_CATEGORY_VALUES", GC_VALUES),
        "",
        "  // The East_Asian_Width values.",
        format_constants("EAW", EAW_VALUES),
        "",
        format_names("EAST_ASIAN_WIDTH_VALUES", EAW_VALUES),
        "",
        "  private static final String[] LB_ENCODED = {",
        "    " + chunk_literals(encode_ranges(lb_ranges, LB_VALUES), "    "),
        "  };",
        "",
        "  private static final String[] GC_ENCODED = {",
        "    " + chunk_literals(encode_ranges(gc_ranges, GC_VALUES), "    "),
        "  };",
        "",
        "  private static final String[] EAW_ENCODED = {",
        "    " + chunk_literals(encode_ranges(eaw_ranges, EAW_VALUES), "    "),
        "  };",
        "",
        "  private static final String[] EXT_PICT_ENCODED = {",
        "    " + chunk_literals(encode_flag_ranges(ext_pict_ranges), "    "),
        "  };",
        "",
        "  static final int[] LB_START;",
        "  static final int[] LB_END;",
        "  static final byte[] LB_CLASS;",
        "  static final int[] GC_START;",
        "  static final int[] GC_END;",
        "  static final byte[] GC_CLASS;",
        "  static final int[] EAW_START;",
        "  static final int[] EAW_END;",
        "  static final byte[] EAW_CLASS;",
        "  static final int[] EXT_PICT_START;",
        "  static final int[] EXT_PICT_END;",
        "",
        "  // One decoded table: starts, ends and class codes, in range order.",
        "  private record Decoded(int[] start, int[] end, byte[] cls) {}",
        "",
        "  // A classed table: fourteen hex digits per range.",
        "  private static Decoded decodeClassed(String[] chunks) {",
        "    String joined = String.join(\"\", chunks);",
        "    int count = joined.length() / 14;",
        "    int[] start = new int[count];",
        "    int[] end = new int[count];",
        "    byte[] cls = new byte[count];",
        "    for (int i = 0; i < count; i++) {",
        "      int at = i * 14;",
        "      start[i] = Integer.parseInt(joined.substring(at, at + 6), 16);",
        "      end[i] = Integer.parseInt(joined.substring(at + 6, at + 12), 16);",
        "      cls[i] = (byte) Integer.parseInt(",
        "          joined.substring(at + 12, at + 14), 16);",
        "    }",
        "    return new Decoded(start, end, cls);",
        "  }",
        "",
        "  // A boolean table: twelve hex digits per range, no class.",
        "  private static Decoded decodeFlagged(String[] chunks) {",
        "    String joined = String.join(\"\", chunks);",
        "    int count = joined.length() / 12;",
        "    int[] start = new int[count];",
        "    int[] end = new int[count];",
        "    for (int i = 0; i < count; i++) {",
        "      int at = i * 12;",
        "      start[i] = Integer.parseInt(joined.substring(at, at + 6), 16);",
        "      end[i] = Integer.parseInt(joined.substring(at + 6, at + 12), 16);",
        "    }",
        "    return new Decoded(start, end, new byte[0]);",
        "  }",
        "",
        "  static {",
        "    Decoded lb = decodeClassed(LB_ENCODED);",
        "    LB_START = lb.start();",
        "    LB_END = lb.end();",
        "    LB_CLASS = lb.cls();",
        "    Decoded gc = decodeClassed(GC_ENCODED);",
        "    GC_START = gc.start();",
        "    GC_END = gc.end();",
        "    GC_CLASS = gc.cls();",
        "    Decoded eaw = decodeClassed(EAW_ENCODED);",
        "    EAW_START = eaw.start();",
        "    EAW_END = eaw.end();",
        "    EAW_CLASS = eaw.cls();",
        "    Decoded extPict = decodeFlagged(EXT_PICT_ENCODED);",
        "    EXT_PICT_START = extPict.start();",
        "    EXT_PICT_END = extPict.end();",
        "  }",
        "}",
        "",
    ]))

    os.makedirs(os.path.dirname(VENDORED_CORPUS), exist_ok=True)
    shutil.copyfile(LINE_BREAK_TEST_TXT, VENDORED_CORPUS)
    sys.stdout.write("wrote %s (%d published rows)\n" % (
        os.path.relpath(VENDORED_CORPUS, ROOT), published_rows))


if __name__ == "__main__":
    main()
