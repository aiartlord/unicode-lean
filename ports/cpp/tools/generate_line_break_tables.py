#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
#                      // tools // generate // line-break-tables
# ─────────────────────────────────────────────────────────────────────────────
#
# Emits the generated property headers the UAX #14 line breaker reads, plus the
# published corpus it is judged against, from the pinned UCD files in the
# repository root:
#
#   include/unicode_cpp/general_category_tables.hpp
#       General_Category ranges, a port of
#       `Unicode.Generated.DerivedGeneralCategory`.
#   include/unicode_cpp/east_asian_width_tables.hpp
#       East_Asian_Width ranges, a port of
#       `Unicode.Generated.EastAsianWidth`.
#   include/unicode_cpp/segmentation/line_break_tables.hpp
#       Line_Break ranges, a port of `Unicode.Generated.LineBreakProperty`.
#   test/line_break_corpus.hpp
#       Every row of the published line-break corpus.
#
# The tables are compiled into the headers rather than read at load, which is
# the route `segmentation/grapheme_tables.hpp` already takes: a segmentation
# header takes code points and nothing else, while the security layer loads its
# own tables from a data directory through `ucd::Tables::load_from_dir`. This
# follows that existing split rather than giving segmentation a runtime data
# dependency.
#
# Each table carries coalesced inclusive ranges sorted by lower bound, so a
# lookup binary-searches for the one range covering a code point; the ranges of
# each property partition the code space, so that range is unique and agrees
# with the linear first-match the Lean reference uses.
#
#   python3 ports/cpp/tools/generate_line_break_tables.py
#
# Run from the repository root. Writing the headers is the whole effect.

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

UCD = os.path.join(ROOT, "Unicode", "Ucd")
LINE_BREAK_TXT = os.path.join(UCD, "LineBreak.txt")
LINE_BREAK_TEST_TXT = os.path.join(UCD, "LineBreakTest.txt")
UNICODE_DATA_TXT = os.path.join(UCD, "UnicodeData.txt")
EAST_ASIAN_WIDTH_TXT = os.path.join(UCD, "EastAsianWidth.txt")

PORT = os.path.join(ROOT, "ports", "cpp")
INCLUDE = os.path.join(PORT, "include", "unicode_cpp")
GENERAL_CATEGORY_HPP = os.path.join(INCLUDE, "general_category_tables.hpp")
EAST_ASIAN_WIDTH_HPP = os.path.join(INCLUDE, "east_asian_width_tables.hpp")
LINE_BREAK_TABLES_HPP = os.path.join(
    INCLUDE, "segmentation", "line_break_tables.hpp")
LINE_BREAK_CORPUS_HPP = os.path.join(PORT, "test", "line_break_corpus.hpp")

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


def variant(value):
    """The C++ enumerator naming a UCD property value.

    A two-letter code is written as the port's other property enums write it —
    `Gcb::Lv`, `EastAsianWidth::Na` — so `AL` becomes `Al` and `ZWJ` `Zwj`.
    A code already in that case, such as `B2` or `Mn`, is unchanged.
    """
    return value.capitalize()


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


def read_break_test_rows():
    """The published rows of LineBreakTest.txt as (codepoints, flags).

    A row alternates boundary markers and code points, starting and ending
    with a marker, so it carries one more flag than code points.
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


def format_enum(doc, name, values):
    lines = ["// %s" % doc, "enum class %s : std::uint8_t {" % name]
    for value in values:
        lines.append("  %s,  // %s" % (variant(value), value))
    lines.append("};")
    return "\n".join(lines)


def format_range_struct(name, enum):
    return "\n".join([
        "// One inclusive range of the property, [lo, hi].",
        "struct %s {" % name,
        "  std::uint32_t lo;",
        "  std::uint32_t hi;",
        "  %s cls;" % enum,
        "};",
    ])


def format_table(array, struct, enum, ranges):
    lines = ["inline constexpr std::array<%s, %d> %s{{"
             % (struct, len(ranges), array)]
    for lo, hi, value in ranges:
        lines.append("    {0x%04X, 0x%04X, %s::%s},"
                     % (lo, hi, enum, variant(value)))
    lines.append("}};")
    return "\n".join(lines)


def format_lookup(func, doc, array, enum, default):
    return "\n".join([
        "// %s" % doc,
        "//",
        "// The ranges partition the code space and are sorted by lower bound,",
        "// so the covering range is unique and a binary search finds it.",
        "inline %s %s(std::uint32_t cp) {" % (enum, func),
        "  std::size_t lo = 0;",
        "  std::size_t hi = %s.size();" % array,
        "  while (lo < hi) {",
        "    const std::size_t mid = lo + (hi - lo) / 2;",
        "    const auto &r = %s[mid];" % array,
        "    if (cp < r.lo) {",
        "      hi = mid;",
        "    } else if (cp > r.hi) {",
        "      lo = mid + 1;",
        "    } else {",
        "      return r.cls;",
        "    }",
        "  }",
        "  return %s;" % default,
        "}",
    ])


def header(guard, doc, namespace, body):
    return "\n".join([
        doc,
        "",
        "#ifndef %s" % guard,
        "#define %s" % guard,
        "",
        "#include <array>",
        "#include <cstddef>",
        "#include <cstdint>",
        "",
        "namespace %s {" % namespace,
        "",
        body,
        "",
        "}  // namespace %s" % namespace,
        "",
        "#endif  // %s" % guard,
        "",
    ])


GENERATED_NOTE = (
    "// Generated by tools/generate_line_break_tables.py. Edit that script and\n"
    "// regenerate rather than editing this file.")


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
    test_rows = read_break_test_rows()

    write_file(GENERAL_CATEGORY_HPP, header(
        "UNICODE_CPP_GENERAL_CATEGORY_TABLES_HPP",
        "\n".join([
            "// General_Category ranges from UCD UnicodeData.txt.",
            "//",
            "// A port of Unicode.Generated.DerivedGeneralCategory: the same 30",
            "// property values, the same coalesced inclusive ranges, and the",
            "// same Cn default for a code point no range covers.",
            "//",
            "// This header sits above both the security and segmentation",
            "// layers so either can read the property, which is where the Lean",
            "// keeps it.",
            "//",
            GENERATED_NOTE,
        ]),
        "unicode_cpp",
        "\n\n".join([
            format_enum(
                "A UAX #44 section 5.7.1 General_Category value.",
                "GeneralCategory", GC_VALUES),
            format_range_struct("GeneralCategoryRange", "GeneralCategory"),
            "// General_Category of a code point no range covers, the default\n"
            "// UnicodeData.txt declares for unassigned code points.\n"
            "inline constexpr GeneralCategory kDefaultGeneralCategory =\n"
            "    GeneralCategory::Cn;",
            format_table("kGeneralCategoryRanges", "GeneralCategoryRange",
                         "GeneralCategory", gc_ranges),
            format_lookup(
                "general_category",
                "General_Category of cp, Cn when no range covers it.",
                "kGeneralCategoryRanges", "GeneralCategory",
                "kDefaultGeneralCategory"),
        ])))

    write_file(EAST_ASIAN_WIDTH_HPP, header(
        "UNICODE_CPP_EAST_ASIAN_WIDTH_TABLES_HPP",
        "\n".join([
            "// East_Asian_Width ranges from UCD EastAsianWidth.txt.",
            "//",
            "// A port of Unicode.Generated.EastAsianWidth: the six UAX #11",
            "// property values, coalesced inclusive ranges, and the N default",
            "// the file declares for every code point it does not list.",
            "//",
            "// The security layer reads the same property from its runtime",
            "// Tables; this header is the compile-time route a segmentation",
            "// header takes, so a line breaker needs no data directory.",
            "//",
            GENERATED_NOTE,
        ]),
        "unicode_cpp",
        "\n\n".join([
            format_enum(
                "A UAX #11 East_Asian_Width value.",
                "EastAsianWidthClass", EAW_VALUES),
            format_range_struct(
                "EastAsianWidthRange", "EastAsianWidthClass"),
            "// East_Asian_Width of a code point the file does not list.\n"
            "inline constexpr EastAsianWidthClass kDefaultEastAsianWidth =\n"
            "    EastAsianWidthClass::N;",
            format_table("kEastAsianWidthRanges", "EastAsianWidthRange",
                         "EastAsianWidthClass", eaw_ranges),
            format_lookup(
                "east_asian_width_class",
                "East_Asian_Width of cp, N when the file omits it.",
                "kEastAsianWidthRanges", "EastAsianWidthClass",
                "kDefaultEastAsianWidth"),
        ])))

    write_file(LINE_BREAK_TABLES_HPP, header(
        "UNICODE_CPP_SEGMENTATION_LINE_BREAK_TABLES_HPP",
        "\n".join([
            "// Line_Break ranges from UCD LineBreak.txt.",
            "//",
            "// A port of Unicode.Generated.LineBreakProperty: the same 49",
            "// property values, the same inclusive ranges, and the same XX",
            "// default for a code point no range covers, which the file's own",
            "// `@missing: 0000..10FFFF; XX` header declares.",
            "//",
            "// The classes here are raw, before UAX #14 LB1 tailors them;",
            "// line_break.hpp's resolved_class applies LB1.",
            "//",
            GENERATED_NOTE,
        ]),
        "unicode_cpp::segmentation",
        "\n\n".join([
            format_enum("A UAX #14 Line_Break property value.", "Lb",
                        LB_VALUES),
            format_range_struct("LbRange", "Lb"),
            "// Line_Break class of a code point no range covers.\n"
            "inline constexpr Lb kDefaultLb = Lb::Xx;",
            format_table("kLbRanges", "LbRange", "Lb", lb_ranges),
            format_lookup(
                "raw_class", "Raw Line_Break class of cp, before LB1.",
                "kLbRanges", "Lb", "kDefaultLb"),
        ])))

    # The corpus is emitted as three flat constexpr arrays rather than a
    # vector of per-row vectors. A `std::vector<Row>` of 19,338 rows, each
    # holding two brace-initialised vectors, is dynamic initialisation: the
    # compiler emits construction code per row and the translation unit takes
    # minutes rather than seconds. Flat arrays plus offsets are a constant
    # initialiser the compiler just lays down.
    points = []
    flags = []
    rows = []
    for codepoints, row_flags in test_rows:
        rows.append((len(points), len(codepoints), len(flags), len(row_flags)))
        points.extend(codepoints)
        flags.extend(row_flags)

    def wrapped(values, per_line, render):
        lines, current = [], []
        for value in values:
            current.append(render(value))
            if len(current) == per_line:
                lines.append("    " + ", ".join(current) + ",")
                current = []
        if current:
            lines.append("    " + ", ".join(current) + ",")
        return "\n".join(lines)

    write_file(LINE_BREAK_CORPUS_HPP, "\n".join([
        "// The published UAX #14 line-break corpus, LineBreakTest.txt.",
        "//",
        "// Hand-written vectors cannot establish a segmentation algorithm: its",
        "// rules read context on both sides of a boundary and the answer",
        "// depends on state carried from earlier in the sequence, so a wrong",
        "// rule survives any vector a person would pick. The Unicode",
        "// Consortium publishes a corpus per algorithm for that reason, and",
        "// this is it, as data.",
        "//",
        "// The rows are three flat arrays and a table of offsets, not a vector",
        "// of vectors: per-row containers would be dynamic initialisation and",
        "// cost minutes of compile time for this many rows, where a constant",
        "// initialiser costs none.",
        "//",
        GENERATED_NOTE,
        "",
        "#ifndef UNICODE_CPP_TEST_LINE_BREAK_CORPUS_HPP",
        "#define UNICODE_CPP_TEST_LINE_BREAK_CORPUS_HPP",
        "",
        "#include <array>",
        "#include <cstddef>",
        "#include <cstdint>",
        "#include <span>",
        "",
        "namespace unicode_cpp::test {",
        "",
        "// Where one published case sits in the flat arrays: its code points",
        "// at [cp_at, cp_at + cp_len) and its boundary flags at",
        "// [flag_at, flag_at + flag_len).",
        "struct CorpusRow {",
        "  std::size_t cp_at;",
        "  std::size_t cp_len;",
        "  std::size_t flag_at;",
        "  std::size_t flag_len;",
        "};",
        "",
        "// How many rows the pinned corpus carries, counted at generation. The",
        "// corpus gate asserts the emitted row count against this, so a row",
        "// lost between the file and the table fails rather than quietly",
        "// shrinking the denominator.",
        "inline constexpr std::size_t kPublishedCount = %d;" % len(test_rows),
        "",
        "inline constexpr std::array<std::uint32_t, %d> kCorpusCodepoints{{"
        % len(points),
        wrapped(points, 12, lambda cp: "0x%04X" % cp),
        "}};",
        "",
        "inline constexpr std::array<bool, %d> kCorpusFlags{{" % len(flags),
        wrapped(flags, 24, lambda f: "1" if f else "0"),
        "}};",
        "",
        "inline constexpr std::array<CorpusRow, %d> kPublishedRows{{"
        % len(rows),
        wrapped(rows, 4,
                lambda r: "{%d,%d,%d,%d}" % r),
        "}};",
        "",
        "// The code points of one row.",
        "inline std::span<const std::uint32_t> row_codepoints(",
        "    const CorpusRow &row) {",
        "  return std::span<const std::uint32_t>(",
        "      kCorpusCodepoints.data() + row.cp_at, row.cp_len);",
        "}",
        "",
        "// The published boundary flags of one row.",
        "inline std::span<const bool> row_flags(const CorpusRow &row) {",
        "  return std::span<const bool>(kCorpusFlags.data() + row.flag_at,",
        "                               row.flag_len);",
        "}",
        "",
        "}  // namespace unicode_cpp::test",
        "",
        "#endif  // UNICODE_CPP_TEST_LINE_BREAK_CORPUS_HPP",
        "",
    ]))


if __name__ == "__main__":
    main()
