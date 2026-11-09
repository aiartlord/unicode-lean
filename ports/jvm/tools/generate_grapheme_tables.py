#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
#                       // tools // generate // grapheme-tables
# ─────────────────────────────────────────────────────────────────────────────
#
# Emits the property tables the UAX #29 grapheme cluster breaker reads and
# vendors the published corpus it is judged against, from the pinned UCD files
# in the repository root:
#
#   src/main/java/com/unicodesecurity/GraphemeTables.java
#       The three properties the algorithm reads — Grapheme_Cluster_Break, a
#       port of `Unicode.Generated.GraphemeBreakProperty`; Indic_Conjunct_Break,
#       a port of `Unicode.Generated.IndicConjunctBreak`, which GB9c reads; and
#       Extended_Pictographic, a port of `Unicode.Generated.EmojiData`, which
#       GB11 reads.
#   testdata/GraphemeBreakTest.txt
#       The published corpus, which the test reads at run time.
#
# The tables are generated into source rather than read from the package's
# resources, for the reason the line-break tables carry: `Security` serves its
# UCD tables only through `readResource` behind a map of pinned SHA-256
# digests, and the self-contained gate refuses any host file read under
# `src/main/java`.
#
# A table is encoded as fixed-width hex in string constants rather than an
# array initialiser, because a Java method's bytecode may not exceed 64 KB and
# an array initialiser of this length is one method. Each range is six hex
# digits of start, six of end, and two of class index; a boolean property omits
# the class. A static initialiser decodes them once into parallel arrays sorted
# by range start, so a lookup binary-searches.
#
#   python3 ports/jvm/tools/generate_grapheme_tables.py
#
# Run from anywhere. Writing the table class and the corpus is the whole
# effect.

import os
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

UCD = os.path.join(ROOT, "Unicode", "Ucd")
GRAPHEME_BREAK_PROPERTY_TXT = os.path.join(UCD, "GraphemeBreakProperty.txt")
DERIVED_CORE_PROPERTIES_TXT = os.path.join(UCD, "DerivedCoreProperties.txt")
EMOJI_DATA_TXT = os.path.join(UCD, "emoji-data.txt")
GRAPHEME_BREAK_TEST_TXT = os.path.join(UCD, "GraphemeBreakTest.txt")

PORT = os.path.join(ROOT, "ports", "jvm")
TABLES_JAVA = os.path.join(
    PORT, "src", "main", "java", "com", "unicodesecurity",
    "GraphemeTables.java")
VENDORED_CORPUS = os.path.join(PORT, "testdata", "GraphemeBreakTest.txt")

# The markers the published break corpora write at each boundary.
BREAK_MARKER = "÷"
NO_BREAK_MARKER = "×"

# How many characters of encoded table go in one string literal. Far under the
# 65,535-byte limit on a single constant-pool entry, and a multiple of both
# record widths so no range straddles a chunk.
CHUNK_CHARS = 19992

# The 13 Grapheme_Cluster_Break values GraphemeBreakProperty.txt assigns, each
# with the Java constant name the generated class gives it. A code point no row
# covers is Grapheme_Cluster_Break = Other, which the lookup answers with its
# own OTHER constant rather than a table entry.
GCB_VALUES = [
    ("Prepend", "PREPEND"),
    ("CR", "CR"),
    ("LF", "LF"),
    ("Control", "CONTROL"),
    ("Extend", "EXTEND"),
    ("Regional_Indicator", "REGIONAL_INDICATOR"),
    ("SpacingMark", "SPACING_MARK"),
    ("L", "L"),
    ("V", "V"),
    ("T", "T"),
    ("LV", "LV"),
    ("LVT", "LVT"),
    ("ZWJ", "ZWJ"),
]

# The three Indic_Conjunct_Break values. An uncovered code point is
# Indic_Conjunct_Break = None.
INCB_VALUES = [
    ("Linker", "LINKER"),
    ("Consonant", "CONSONANT"),
    ("Extend", "EXTEND"),
]


def strip_comment(line):
    return line.split("#", 1)[0].strip()


def parse_range_field(text):
    text = text.strip()
    if ".." in text:
        lo_text, hi_text = text.split("..", 1)
        return int(lo_text, 16), int(hi_text, 16)
    point = int(text, 16)
    return point, point


def read_gcb_rows():
    """Explicit (lo, hi, value) rows of GraphemeBreakProperty.txt."""
    admitted = [ucd for ucd, _name in GCB_VALUES]
    rows = []
    with open(GRAPHEME_BREAK_PROPERTY_TXT, "r", encoding="utf-8") as handle:
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
                    "GraphemeBreakProperty.txt line %d names a "
                    "Grapheme_Cluster_Break value the generator does not "
                    "carry: %r" % (number, value))
            lo, hi = parse_range_field(fields[0])
            rows.append((lo, hi, value))
    if not rows:
        raise SystemExit("GraphemeBreakProperty.txt carries no row")
    return rows


def read_incb_rows():
    """The Indic_Conjunct_Break rows of DerivedCoreProperties.txt.

    An InCB row carries three fields rather than two — the range, the literal
    `InCB`, and the value — so the value is the third, not the second.
    """
    admitted = [ucd for ucd, _name in INCB_VALUES]
    rows = []
    with open(DERIVED_CORE_PROPERTIES_TXT, "r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            body = strip_comment(line)
            if not body:
                continue
            fields = [field.strip() for field in body.split(";")]
            if len(fields) < 3 or fields[1] != "InCB":
                continue
            value = fields[2]
            if value not in admitted:
                raise SystemExit(
                    "DerivedCoreProperties.txt line %d names an "
                    "Indic_Conjunct_Break value the generator does not carry: "
                    "%r" % (number, value))
            lo, hi = parse_range_field(fields[0])
            rows.append((lo, hi, value))
    if not rows:
        raise SystemExit("DerivedCoreProperties.txt carries no InCB row")
    return rows


def read_extended_pictographic_rows():
    """The Extended_Pictographic ranges of emoji-data.txt as (lo, hi, True).

    GB11 reads the property. Only that one property value is taken; the file
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
    """How many data rows GraphemeBreakTest.txt carries, validating each.

    A row alternates boundary markers and code points, starting and ending
    with a marker, so it carries one more flag than code points. A row that
    does not is a corpus the test cannot read, and the count it would report
    would be wrong rather than short.
    """
    count = 0
    with open(GRAPHEME_BREAK_TEST_TXT, "r", encoding="utf-8") as handle:
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
                            "GraphemeBreakTest.txt line %d has two markers in "
                            "a row" % number)
                    flags += 1
                    expecting_marker = False
                else:
                    if expecting_marker:
                        raise SystemExit(
                            "GraphemeBreakTest.txt line %d has two code "
                            "points in a row" % number)
                    int(token, 16)
                    codepoints += 1
                    expecting_marker = True
            if expecting_marker:
                raise SystemExit(
                    "GraphemeBreakTest.txt line %d ends at a code point "
                    "rather than a boundary marker" % number)
            if flags != codepoints + 1:
                raise SystemExit(
                    "GraphemeBreakTest.txt line %d carries %d flags for %d "
                    "code points" % (number, flags, codepoints))
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
    index_of = {ucd: index for index, (ucd, _name) in enumerate(values)}
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


def format_constants(prefix, values, extra=None):
    """One `static final int` per property value, named for the value."""
    lines = [
        "  static final int %s_%s = %d;" % (prefix, name, index)
        for index, (_ucd, name) in enumerate(values)
    ]
    if extra is not None:
        lines.append("  static final int %s_%s = %d;"
                     % (prefix, extra, len(values)))
    return "\n".join(lines)


def format_names(name, values, extra=None):
    """The property values as a Java array, indexed by class code."""
    rendered = ['"%s"' % ucd for ucd, _name in values]
    if extra is not None:
        rendered.append('"%s"' % extra)
    return "\n".join([
        "  static final String[] %s = {" % name,
        "    " + ", ".join(rendered),
        "  };",
    ])


def write_file(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    sys.stdout.write("wrote %s (%d lines)\n" % (
        os.path.relpath(path, ROOT), text.count("\n")))


def main():
    gcb_ranges = coalesce(read_gcb_rows())
    incb_ranges = coalesce(read_incb_rows())
    ext_pict_ranges = coalesce(read_extended_pictographic_rows())
    published_rows = count_break_test_rows()

    write_file(TABLES_JAVA, "\n".join([
        "package com.unicodesecurity;",
        "",
        "// Property tables the UAX #29 grapheme cluster breaker reads, from",
        "// the pinned UCD 17.0.0 files -- ports of",
        "// Unicode.Generated.{GraphemeBreakProperty,IndicConjunctBreak,",
        "// EmojiData}. Same property values, same ranges.",
        "//",
        "// Grapheme_Cluster_Break ranges: %d, Indic_Conjunct_Break ranges: %d,"
        % (len(gcb_ranges), len(incb_ranges)),
        "// Extended_Pictographic ranges: %d." % len(ext_pict_ranges),
        "//",
        "// These are code rather than entries under the package's resources.",
        "// Security serves its UCD tables only through readResource behind a",
        "// map of pinned SHA-256 digests, and the self-contained gate refuses",
        "// any host file read under src/main/java.",
        "//",
        "// A table is fixed-width hex in string constants rather than an array",
        "// initialiser, because a method's bytecode may not exceed 64 KB and an",
        "// initialiser of this length is one method. Each range is six hex",
        "// digits of start, six of end and two of class index; a boolean",
        "// property omits the class. A static initialiser decodes them once",
        "// into arrays sorted by range start, so a lookup binary-searches.",
        "//",
        "// GENERATED FILE - DO NOT EDIT. Regenerate with",
        "// tools/generate_grapheme_tables.py.",
        "final class GraphemeTables {",
        "  private GraphemeTables() {}",
        "",
        "  // How many data rows the pinned corpus carries, counted at",
        "  // generation. The corpus gate asserts the rows it reads against",
        "  // this, so a row lost between the file and the fold fails rather",
        "  // than quietly shrinking the denominator.",
        "  static final int PUBLISHED_ROW_COUNT = %d;" % published_rows,
        "",
        "  // The Grapheme_Cluster_Break values. OTHER is the value of every",
        "  // code point no range covers, so it has no table entry.",
        format_constants("GCB", GCB_VALUES, extra="OTHER"),
        "",
        format_names("GRAPHEME_CLUSTER_BREAK_VALUES", GCB_VALUES,
                     extra="Other"),
        "",
        "  // The Indic_Conjunct_Break values. NONE is the value of every code",
        "  // point no range covers, so it has no table entry.",
        format_constants("INCB", INCB_VALUES, extra="NONE"),
        "",
        format_names("INDIC_CONJUNCT_BREAK_VALUES", INCB_VALUES,
                     extra="None"),
        "",
        "  private static final String[] GCB_ENCODED = {",
        "    " + chunk_literals(encode_ranges(gcb_ranges, GCB_VALUES),
                               "    "),
        "  };",
        "",
        "  private static final String[] INCB_ENCODED = {",
        "    " + chunk_literals(encode_ranges(incb_ranges, INCB_VALUES),
                               "    "),
        "  };",
        "",
        "  private static final String[] EXT_PICT_ENCODED = {",
        "    " + chunk_literals(encode_flag_ranges(ext_pict_ranges), "    "),
        "  };",
        "",
        "  static final int[] GCB_START;",
        "  static final int[] GCB_END;",
        "  static final byte[] GCB_CLASS;",
        "  static final int[] INCB_START;",
        "  static final int[] INCB_END;",
        "  static final byte[] INCB_CLASS;",
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
        "    Decoded gcb = decodeClassed(GCB_ENCODED);",
        "    GCB_START = gcb.start();",
        "    GCB_END = gcb.end();",
        "    GCB_CLASS = gcb.cls();",
        "    Decoded incb = decodeClassed(INCB_ENCODED);",
        "    INCB_START = incb.start();",
        "    INCB_END = incb.end();",
        "    INCB_CLASS = incb.cls();",
        "    Decoded extPict = decodeFlagged(EXT_PICT_ENCODED);",
        "    EXT_PICT_START = extPict.start();",
        "    EXT_PICT_END = extPict.end();",
        "  }",
        "}",
        "",
    ]))

    os.makedirs(os.path.dirname(VENDORED_CORPUS), exist_ok=True)
    shutil.copyfile(GRAPHEME_BREAK_TEST_TXT, VENDORED_CORPUS)
    sys.stdout.write("wrote %s (%d published rows)\n" % (
        os.path.relpath(VENDORED_CORPUS, ROOT), published_rows))


if __name__ == "__main__":
    main()
