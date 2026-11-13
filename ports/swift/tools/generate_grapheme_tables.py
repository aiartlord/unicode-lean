#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
#                       // tools // generate // grapheme-tables
# ─────────────────────────────────────────────────────────────────────────────
#
# Emits the property tables the UAX #29 grapheme cluster breaker reads and
# vendors the published corpus it is judged against, from the pinned UCD files
# in the repository root:
#
#   Sources/UnicodeSecurity/Segmentation/GraphemeTables.swift
#       Two of the three properties the algorithm reads —
#       Grapheme_Cluster_Break, a port of
#       `Unicode.Generated.GraphemeBreakProperty`, and Indic_Conjunct_Break, a
#       port of `Unicode.Generated.IndicConjunctBreak` — plus the corpus row
#       count.
#
#       The third, Extended_Pictographic, is already in this module:
#       `isExtendedPictographic` in LineBreakTables.swift serves LB30b, and
#       GB11 reads the same property from the same table.
#   ContractTests/Resources/testdata/GraphemeBreakTest.txt
#       The published corpus, as a test-target resource the bundle carries.
#
# The tables are generated into source rather than parsed at load, so the
# segmentation algorithms take code points and need no data directory, and no
# new file enters the digest-pinned resource set.
#
# Each table is three parallel columns of primitives — the inclusive bounds and
# the raw class value — rather than one array of structures: an array literal
# of several thousand aggregates is a type-checking cost paid on every build,
# while a literal of `UInt32` and `UInt8` elements is laid down as static data.
# Each column is sorted by lower bound and coalesced. Coalescing rejects
# overlapping rows, which is what makes the binary search agree with the linear
# first-match of the Lean reference: with disjoint ranges the covering range is
# unique, so whichever one a search finds is the one a scan in file order would
# have found first.
#
#   python3 ports/swift/tools/generate_grapheme_tables.py
#
# Run from anywhere. Writing the table file and the corpus is the whole effect.

import os
import re
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

UCD = os.path.join(ROOT, "Unicode", "Ucd")
GRAPHEME_BREAK_PROPERTY_TXT = os.path.join(UCD, "GraphemeBreakProperty.txt")
DERIVED_CORE_PROPERTIES_TXT = os.path.join(UCD, "DerivedCoreProperties.txt")
GRAPHEME_BREAK_TEST_TXT = os.path.join(UCD, "GraphemeBreakTest.txt")

PORT = os.path.join(ROOT, "ports", "swift")
GRAPHEME_TABLES_SWIFT = os.path.join(
    PORT, "Sources", "UnicodeSecurity", "Segmentation", "GraphemeTables.swift")
VENDORED_CORPUS = os.path.join(
    PORT, "ContractTests", "Resources", "testdata", "GraphemeBreakTest.txt")

# The markers the published break corpora write at each boundary.
BREAK_MARKER = "÷"
NO_BREAK_MARKER = "×"

# The 14 Grapheme_Cluster_Break property values UAX #29 defines, as the UCD
# spells each one.
#
# Other leads the list so it is the raw value 0, which is what a code point no
# range covers carries: GraphemeBreakProperty.txt declares the default in its
# own `@missing: 0000..10FFFF; Other` header. The remaining order mirrors the
# Lean parseGCB?.
GCB_VALUES = [
    "Other",
    "CR",
    "LF",
    "Control",
    "Extend",
    "ZWJ",
    "Regional_Indicator",
    "Prepend",
    "SpacingMark",
    "L",
    "V",
    "T",
    "LV",
    "LVT",
]

# The four Indic_Conjunct_Break values, None leading for the same reason —
# DerivedCoreProperties.txt declares `@missing: 0000..10FFFF; InCB; None`.
INCB_VALUES = [
    "None",
    "Consonant",
    "Extend",
    "Linker",
]

# The literal that marks a DerivedCoreProperties.txt row as carrying the
# Indic_Conjunct_Break sub-property. Such a row has three fields — the range,
# this literal, and the value — where a row for any other property has two.
INCB_TAG = "InCB"

# Swift reserves these. A case colliding with one keeps the UCD spelling and
# wears backticks rather than taking an invented name.
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
    (`SpacingMark`). An all-capitals segment is an abbreviation (`CR`, `LVT`,
    `ZWJ`) and lowercases whole; any other segment is words. A result
    colliding with a reserved word is backticked.

    A case whose spelling is wrong is not a cosmetic defect. The standard
    library's `Unicode.GeneralCategory` carries `spacingMark`, `control` and
    `format` too, so a missing case on this type lets the comparison resolve
    against that one instead.
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


def read_grapheme_cluster_break_rows():
    """Explicit (lo, hi, value) rows of GraphemeBreakProperty.txt.

    A value the generator does not carry is a file naming a property value
    this port has no case for, so the emitted table would silently omit those
    code points. That aborts rather than writing a short table.
    """
    admitted = set(GCB_VALUES)
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
        raise SystemExit(
            "GraphemeBreakProperty.txt names no Grapheme_Cluster_Break range")
    return rows


def read_indic_conjunct_break_rows():
    """Explicit (lo, hi, value) InCB rows of DerivedCoreProperties.txt.

    The file carries many properties; a row belongs to this one when its
    second field is the InCB literal, and then its third field is the value.
    """
    admitted = set(INCB_VALUES)
    rows = []
    with open(DERIVED_CORE_PROPERTIES_TXT, "r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            body = strip_comment(line)
            if not body:
                continue
            fields = body.split(";")
            if len(fields) < 3 or fields[1].strip() != INCB_TAG:
                continue
            value = fields[2].strip()
            if value not in admitted:
                raise SystemExit(
                    "DerivedCoreProperties.txt line %d names an "
                    "Indic_Conjunct_Break value the generator does not carry: "
                    "%r" % (number, value))
            lo, hi = parse_range_field(fields[0])
            rows.append((lo, hi, value))
    if not rows:
        raise SystemExit(
            "DerivedCoreProperties.txt names no Indic_Conjunct_Break range")
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


def format_enum(doc, type_name, values, trailing_doc):
    """A `UInt8`-raw enum whose case order fixes each value's raw value.

    The lookup below reconstructs a class from the raw value the table holds,
    so the declaration order here and the index the table emits are one fact.
    """
    lines = ["/// %s" % doc, "///"]
    for paragraph in trailing_doc:
        lines.append("/// %s" % paragraph)
    # Public because the contract tests are a separate module: a test naming
    # `IndicConjunctBreak.linker` to pin GB9c cannot see an internal case.
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
    # The default is written type-qualified. `None` is a real property value
    # here, and `?? .none` on the right of an optional would read as
    # `Optional.none`.
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
    gcb_ranges = coalesce(read_grapheme_cluster_break_rows())
    incb_ranges = coalesce(read_indic_conjunct_break_rows())
    published_rows = count_break_test_rows()

    write_file(GRAPHEME_TABLES_SWIFT, "\n".join([
        "// Code generated by tools/generate_grapheme_tables.py. DO NOT EDIT.",
        "",
        "// Property tables the UAX #29 grapheme cluster breaker reads,",
        "// generated from the pinned UCD 17.0.0 files — ports of",
        "// Unicode.Generated.{GraphemeBreakProperty,IndicConjunctBreak}. Same",
        "// ranges, same class values.",
        "//",
        "// The third property the rules read, Extended_Pictographic, is the",
        "// one LB30b reads: GB11 calls `isExtendedPictographic` from",
        "// LineBreakTables.swift rather than carrying a second copy.",
        "//",
        "// Grapheme_Cluster_Break ranges: %d, Indic_Conjunct_Break ranges: %d."
        % (len(gcb_ranges), len(incb_ranges)),
        "",
        format_enum(
            "A UAX #29 Grapheme_Cluster_Break property value.",
            "GraphemeClusterBreak", GCB_VALUES,
            [
                "`other` is the raw value 0, so it is the class a code point",
                "outside every range carries. The case order fixes each "
                "value's",
                "raw value, which is what the generated table stores.",
            ]),
        "",
        format_enum(
            "A UAX #29 Indic_Conjunct_Break property value, the sub-property "
            "GB9c reads.",
            "IndicConjunctBreak", INCB_VALUES,
            [
                "`none` is the raw value 0, so it is the class a code point",
                "outside every range carries.",
            ]),
        "",
        format_range_table(
            "graphemeClusterBreakRanges",
            "The Grapheme_Cluster_Break ranges, ascending and coalesced.",
            gcb_ranges, GCB_VALUES),
        "",
        format_range_table(
            "indicConjunctBreakRanges",
            "The Indic_Conjunct_Break ranges, ascending and coalesced.",
            incb_ranges, INCB_VALUES),
        "",
        format_lookup(
            "graphemeClusterBreak",
            "The Grapheme_Cluster_Break class of `cp`.",
            "graphemeClusterBreakRanges", "GraphemeClusterBreak", "other",
            [
                "A code point no range covers is `Other`, the default",
                "GraphemeBreakProperty.txt's own `@missing: 0000..10FFFF; "
                "Other`",
                "header declares.",
            ]),
        "",
        format_lookup(
            "indicConjunctBreak",
            "The Indic_Conjunct_Break class of `cp`.",
            "indicConjunctBreakRanges", "IndicConjunctBreak", "none",
            [
                "A code point no range covers is `None`, the default",
                "DerivedCoreProperties.txt's own `@missing: 0000..10FFFF; "
                "InCB;",
                "None` header declares.",
            ]),
        "",
        "\n".join([
            "/// How many data rows the pinned corpus carries, counted from "
            "the",
            "/// canonical GraphemeBreakTest.txt at generation.",
            "///",
            "/// The corpus gate asserts the rows it reads from the vendored "
            "copy",
            "/// against this, so a row lost between the two fails rather "
            "than",
            "/// quietly shrinking the denominator.",
            "public let graphemePublishedRowCount = %d" % published_rows,
        ]),
        "",
    ]))

    os.makedirs(os.path.dirname(VENDORED_CORPUS), exist_ok=True)
    shutil.copyfile(GRAPHEME_BREAK_TEST_TXT, VENDORED_CORPUS)
    sys.stdout.write("wrote %s (%d published rows)\n" % (
        os.path.relpath(VENDORED_CORPUS, ROOT), published_rows))


if __name__ == "__main__":
    main()
