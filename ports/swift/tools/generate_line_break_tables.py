#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
#                      // tools // generate // line-break-tables
# ─────────────────────────────────────────────────────────────────────────────
#
# Emits the property tables the UAX #14 line breaker reads and vendors the
# published corpus it is judged against, from the pinned UCD files in the
# repository root:
#
#   Sources/UnicodeSecurity/Segmentation/LineBreakTables.swift
#       Three of the four properties the algorithm reads — Line_Break, a port
#       of `Unicode.Generated.LineBreakProperty`; General_Category, a port of
#       `Unicode.Generated.DerivedGeneralCategory`; and Extended_Pictographic,
#       a port of `Unicode.Generated.EmojiData` — plus the corpus row count.
#
#       Extended_Pictographic serves two rules, LB30b and GB11, from the one
#       table here.
#   ContractTests/Resources/testdata/LineBreakTest.txt
#       The published corpus, as a test-target resource the bundle carries.
#
# The fourth property, East_Asian_Width, is not emitted. The security layer of
# this same module already parses it from its digest-pinned EastAsianWidth.txt
# and resolves it through a binary search, and a Swift module is one namespace,
# so the line breaker calls that `eastAsianWidth` directly. Emitting a second
# copy would be a second answer to one question.
#
# The tables that are emitted are generated into source rather than parsed at
# load, so the segmentation algorithms take code points and need no data
# directory, and no new file enters the digest-pinned resource set.
#
# Each table is three parallel columns of primitives — the inclusive bounds and
# the raw class value — rather than one array of structures: an array literal
# of several thousand aggregates is a type-checking cost paid on every build,
# while a literal of `UInt32` and `UInt8` elements is laid down as static data.
# Each column is sorted by lower bound and coalesced, so the range covering a
# code point is unique and a binary search agrees with the linear first-match
# of the Lean reference.
#
#   python3 ports/swift/tools/generate_line_break_tables.py
#
# Run from anywhere. Writing the table file and the corpus is the whole effect.

import os
import re
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

UCD = os.path.join(ROOT, "Unicode", "Ucd")
LINE_BREAK_TXT = os.path.join(UCD, "LineBreak.txt")
LINE_BREAK_TEST_TXT = os.path.join(UCD, "LineBreakTest.txt")
UNICODE_DATA_TXT = os.path.join(UCD, "UnicodeData.txt")
EMOJI_DATA_TXT = os.path.join(UCD, "emoji-data.txt")

PORT = os.path.join(ROOT, "ports", "swift")
LINE_BREAK_TABLES_SWIFT = os.path.join(
    PORT, "Sources", "UnicodeSecurity", "Segmentation", "LineBreakTables.swift")
VENDORED_CORPUS = os.path.join(
    PORT, "ContractTests", "Resources", "testdata", "LineBreakTest.txt")

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

# Swift reserves these, and three Line_Break abbreviations collide with them.
# A case keeps the UCD abbreviation and wears backticks rather than taking an
# invented spelling, so a reader checking the emitted rules against UAX #14
# reads the same two letters the standard writes.
SWIFT_KEYWORDS = {
    "as", "in", "is", "do", "if", "for", "let", "var", "nil", "try", "case",
    "else", "enum", "func", "true", "false", "where", "while", "return",
    "struct", "switch", "default", "class", "protocol", "extension",
    "internal", "private", "public", "static", "self", "super", "init",
    "deinit", "subscript", "typealias", "import", "operator", "repeat",
    "guard", "defer", "throw", "throws", "rethrows", "catch", "break",
    "continue", "fallthrough", "associatedtype", "inout", "indirect", "some",
    "any", "await", "async",
}


def swift_case(value):
    """The Swift enum case for a UCD property value name.

    Swift writes a case in lower camel case. A UCD value names its words two
    ways and both have to be split, or a case comes out mis-spelled: with an
    underscore (`Regional_Indicator`) and by capitalisation alone
    (`SpacingMark`). An all-capitals segment is an abbreviation (`AL`, `B2`,
    `ZWJ`) and lowercases whole; any other segment is words. A result
    colliding with a reserved word is backticked, which preserves the
    abbreviation exactly.
    """
    words = []
    for segment in value.split("_"):
        if segment.isupper():
            words.append(segment)
        else:
            words.extend(re.findall(r"[A-Z][a-z0-9]*|[a-z0-9]+", segment))
    name = words[0].lower() + "".join(word.capitalize() for word in words[1:])
    if name in SWIFT_KEYWORDS:
        return "`%s`" % name
    return name


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
    if not rows:
        raise SystemExit(
            "%s names no %s range" % (os.path.basename(path), label))
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


def format_enum(doc, type_name, values, trailing_doc):
    """A `UInt8`-raw enum whose case order fixes each value's raw value.

    The lookup below reconstructs a class from the raw value the table holds,
    so the declaration order here and the index the table emits are one fact.
    """
    lines = ["/// %s" % doc]
    lines.append("///")
    for paragraph in trailing_doc:
        lines.append("/// %s" % paragraph)
    # Public because the contract tests are a separate module: a test naming
    # `LineBreakClass.cj` to pin LB1's tailoring cannot see an internal case.
    lines.append("public enum %s: UInt8 {" % type_name)
    for value in values:
        lines.append("    /// `%s`." % value)
        lines.append("    case %s" % swift_case(value))
    lines.append("}")
    return "\n".join(lines)


def format_column(name, values, formatter, last=False):
    """One column of a table, wrapped to a readable width.

    The final column of a call carries no trailing comma: a trailing comma in
    an argument list is accepted only from Swift 6.1, and this port builds
    under the 5.10 toolchain the flake pins.
    """
    lines = ["    %s: [" % name]
    row = "       "
    for value in values:
        token = " " + formatter(value) + ","
        if len(row) + len(token) > 78:
            lines.append(row)
            row = "       "
        row += token
    if row.strip():
        lines.append(row)
    lines.append("    ]" if last else "    ],")
    return "\n".join(lines)


def format_range_table(name, doc, ranges, values):
    index_of = {value: index for index, value in enumerate(values)}
    return "\n".join([
        "/// %s" % doc,
        "private let %s = RangeTable(" % name,
        format_column("lo", [row[0] for row in ranges], lambda v: "0x%04X" % v),
        format_column("hi", [row[1] for row in ranges], lambda v: "0x%04X" % v),
        format_column(
            "cls", [index_of[row[2]] for row in ranges], lambda v: "%d" % v,
            last=True),
        ")",
    ])


def format_flag_table(name, doc, ranges):
    return "\n".join([
        "/// %s" % doc,
        "private let %s = FlagTable(" % name,
        format_column("lo", [row[0] for row in ranges], lambda v: "0x%04X" % v),
        format_column(
            "hi", [row[1] for row in ranges], lambda v: "0x%04X" % v,
            last=True),
        ")",
    ])


def format_lookup(func, doc, table, type_name, default_case, default_doc):
    """A total lookup: the table's answer, else the property's own default.

    The enum and the table are emitted from one value list, so the raw value
    the table holds always names a case. The `??` arm is unreachable, and it
    carries the same default the file's `@missing` header declares, so a
    generator that ever disagreed with its enum would read as that default
    rather than as an arbitrary class.
    """
    lines = ["/// %s" % doc, "///"]
    lines.append(
        "/// The ranges are sorted by lower bound and disjoint, so the "
        "covering")
    lines.append("/// range is unique and a binary search finds it.")
    for paragraph in default_doc:
        lines.append("/// %s" % paragraph)
    # The default is written type-qualified. A property value spelled `none`
    # would otherwise read as `Optional.none` on the right of `??`, where the
    # left operand is already an optional.
    qualified = "%s.%s" % (type_name, default_case)
    lines.append("public func %s(_ cp: UInt32) -> %s {" % (func, type_name))
    lines.append("    guard let raw = rangeClass(%s, cp) else {" % table)
    lines.append("        return %s" % qualified)
    lines.append("    }")
    lines.append("    return %s(rawValue: raw) ?? %s" % (
        type_name, qualified))
    lines.append("}")
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

    write_file(LINE_BREAK_TABLES_SWIFT, "\n".join([
        "// Code generated by tools/generate_line_break_tables.py. "
        "DO NOT EDIT.",
        "",
        "// Property tables the UAX #14 line breaker reads, generated from the",
        "// pinned UCD 17.0.0 files — ports of",
        "// Unicode.Generated.{LineBreakProperty,DerivedGeneralCategory,"
        "EmojiData}.",
        "// Same ranges, same class values.",
        "//",
        "// Line_Break ranges: %d, General_Category ranges: %d,"
        % (len(lb_ranges), len(gc_ranges)),
        "// Extended_Pictographic ranges: %d." % len(ext_pict_ranges),
        "//",
        "// East_Asian_Width is absent by design: the security layer of this",
        "// module parses it from its digest-pinned EastAsianWidth.txt, and a",
        "// Swift module is one namespace, so the line breaker calls that",
        "// `eastAsianWidth` rather than carrying a second copy.",
        "",
        format_enum(
            "A UAX #14 Line_Break property value.",
            "LineBreakClass", LB_VALUES,
            [
                "These are raw, before UAX #14 LB1 tailors them;",
                "`resolvedLineBreakClass` applies LB1. The case order fixes "
                "each",
                "value's raw value, which is what the generated table stores.",
            ]),
        "",
        format_enum(
            "A UAX #44 section 5.7.1 General_Category value.",
            "GeneralCategory", GC_VALUES,
            [
                "UAX #14 reads this for LB1's SA resolution, the Pi/Pf quote",
                "refinement of LB15a and LB15b, and LB30b.",
            ]),
        "",
        format_range_table(
            "lineBreakRanges",
            "The Line_Break ranges, ascending and coalesced.",
            lb_ranges, LB_VALUES),
        "",
        format_range_table(
            "generalCategoryRanges",
            "The General_Category ranges, ascending and coalesced.",
            gc_ranges, GC_VALUES),
        "",
        format_flag_table(
            "extendedPictographicRanges",
            "The Extended_Pictographic ranges, ascending and coalesced.",
            ext_pict_ranges),
        "",
        format_lookup(
            "rawLineBreakClass",
            "The Line_Break class of `cp` before LB1.",
            "lineBreakRanges", "LineBreakClass", "xx",
            [
                "A code point no range covers is `XX`, the default",
                "LineBreak.txt's own `@missing: 0000..10FFFF; XX` header",
                "declares.",
            ]),
        "",
        format_lookup(
            "generalCategory",
            "The General_Category of `cp`.",
            "generalCategoryRanges", "GeneralCategory", "cn",
            [
                "A code point no range covers is `Cn`, the category",
                "UnicodeData.txt leaves unassigned code points in.",
            ]),
        "",
        "\n".join([
            "/// True iff `cp` has the Extended_Pictographic property, which "
            "LB30b",
            "/// and GB11 read.",
            "///",
            "/// The ranges are sorted by lower bound and disjoint, so a "
            "binary",
            "/// search decides membership.",
            "public func isExtendedPictographic(_ cp: UInt32) -> Bool {",
            "    flagCovers(extendedPictographicRanges, cp)",
            "}",
        ]),
        "",
        "\n".join([
            "/// How many data rows the pinned corpus carries, counted from "
            "the",
            "/// canonical LineBreakTest.txt at generation.",
            "///",
            "/// The corpus gate asserts the rows it reads from the vendored "
            "copy",
            "/// against this, so a row lost between the two fails rather "
            "than",
            "/// quietly shrinking the denominator.",
            "public let lineBreakPublishedRowCount = %d" % published_rows,
        ]),
        "",
    ]))

    os.makedirs(os.path.dirname(VENDORED_CORPUS), exist_ok=True)
    shutil.copyfile(LINE_BREAK_TEST_TXT, VENDORED_CORPUS)
    sys.stdout.write("wrote %s (%d published rows)\n" % (
        os.path.relpath(VENDORED_CORPUS, ROOT), published_rows))


if __name__ == "__main__":
    main()
