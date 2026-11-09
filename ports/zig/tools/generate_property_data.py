#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
#                        // tools // generate // property-data
# ─────────────────────────────────────────────────────────────────────────────
#
# Emits src/property_data.zig: the UCD properties the security monitor reads
# per code point, as sorted disjoint range tables a lookup can bisect.
#
# The monitor's predicates each walked an embedded UCD text file from the top
# on every call, splitting fields and parsing hex per line. The properties
# below are read once per code point of every scanned input — some of them
# twice, since an identifier token is found by testing XID_Continue across the
# input and then again across the token — so a scan cost one full parse of a
# 1.1 MB table per property per code point. Measured on the port's own
# differential corpus: 182 ms per code point, which puts the 5,000-case corpus
# at about four hours. Bisection over these tables answers the same question
# in a handful of comparisons.
#
# Each table keeps the semantics of the scan it replaces:
#
#   grapheme_extend, xid_start, xid_continue
#       Rows of DerivedCoreProperties.txt whose value field is exactly the
#       property name.
#   identifier_status_allowed
#       Rows of IdentifierStatus.txt whose value is exactly Allowed. The
#       file's own `@missing: 0000..10FFFF; Restricted` default makes every
#       uncovered code point Restricted.
#   emoji, emoji_presentation, emoji_modifier_base
#       Rows of emoji-data.txt whose value field is exactly the property name.
#   script
#       The value of the first row of Scripts.txt covering the code point,
#       `Unknown` when none does.
#   joining_type
#       The value of the first row of DerivedJoiningType.txt covering the code
#       point, as its single letter, `U` when the value is not one of C D L R
#       T or no row covers it.
#   zwj_alphabet
#       Every code point other than U+200D appearing at any position of a
#       registered sequence in emoji-zwj-sequences.txt.
#   variation_pairs
#       Every (base, selector) pair listed in StandardizedVariants.txt or
#       emoji-variation-sequences.txt.
#
# Two checks run before anything is written, so a table that would answer
# differently from the scan it replaces fails here rather than changing a
# verdict. Ranges are coalesced and overlap is rejected, which is what makes
# sorting sound. Then every property is compared against a direct parse of its
# file across the whole code space, all 1,114,112 code points.
#
#   python3 ports/zig/tools/generate_property_data.py
#
# Run from anywhere. Writing the table module is the whole effect.

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

PORT = os.path.join(ROOT, "ports", "zig")
DATA = os.path.join(PORT, "src", "data")
OUT = os.path.join(PORT, "src", "property_data.zig")

DERIVED_CORE_PROPERTIES = os.path.join(DATA, "DerivedCoreProperties.txt")
IDENTIFIER_STATUS = os.path.join(DATA, "IdentifierStatus.txt")
EMOJI_DATA = os.path.join(DATA, "emoji-data.txt")
SCRIPTS = os.path.join(DATA, "Scripts.txt")
DERIVED_JOINING_TYPE = os.path.join(DATA, "DerivedJoiningType.txt")
EMOJI_ZWJ_SEQUENCES = os.path.join(DATA, "emoji-zwj-sequences.txt")
STANDARDIZED_VARIANTS = os.path.join(DATA, "StandardizedVariants.txt")
EMOJI_VARIATION_SEQUENCES = os.path.join(DATA, "emoji-variation-sequences.txt")
SCRIPT_EXTENSIONS = os.path.join(DATA, "ScriptExtensions.txt")
PROPERTY_VALUE_ALIASES = os.path.join(DATA, "PropertyValueAliases.txt")

# One past the last Unicode code point.
CODE_SPACE = 0x110000

# The joiner itself is never part of the alphabet that may flank it.
ZWJ = 0x200D

# How many code points one row of emoji-zwj-sequences.txt may carry before the
# monitor's own parser rejects the row. Mirrors its MAX_ROW_LEN.
MAX_ROW_LEN = 64

# How many entries go on one line of an emitted table.
PER_LINE = 6


def strip_comment(line):
    """The part of a line before its `#`, which is what the scans read."""
    return line.split("#", 1)[0]


def parse_range(text):
    """A `lo..hi` or single-value hex range field, or None when unparseable.

    `None` mirrors the scans, which skip a row whose range does not parse
    rather than failing.
    """
    text = text.strip()
    if ".." in text:
        lo_text, hi_text = text.split("..", 1)
        try:
            return int(lo_text.strip(), 16), int(hi_text.strip(), 16)
        except ValueError:
            return None
    try:
        point = int(text, 16)
    except ValueError:
        return None
    return point, point


def value_rows(path):
    """(lo, hi, value) of every data row of a `RANGE ; VALUE` table, in file
    order. Rows whose range or value field is missing are skipped, as the
    scans skip them."""
    rows = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            body = strip_comment(line).strip()
            if not body:
                continue
            fields = body.split(";")
            if len(fields) < 2:
                continue
            bounds = parse_range(fields[0])
            if bounds is None:
                continue
            rows.append((bounds[0], bounds[1], fields[1].strip()))
    return rows


def property_ranges(path, name):
    """The ranges of one named property of a `RANGE ; PROPERTY` table."""
    return [(lo, hi) for lo, hi, value in value_rows(path) if value == name]


def coalesce(ranges):
    """Sorted, coalesced ranges, rejecting any overlap.

    A table whose ranges overlap has no unique covering range, so bisection
    over it would be ill-defined; for a boolean property an overlap is
    harmless but still means the source was misread, so it fails here.
    """
    out = []
    for lo, hi in sorted(ranges):
        if lo > hi:
            raise SystemExit("inverted range U+%04X..U+%04X" % (lo, hi))
        if out:
            prev_lo, prev_hi = out[-1]
            if lo <= prev_hi:
                raise SystemExit(
                    "ranges overlap: U+%04X..U+%04X and U+%04X..U+%04X"
                    % (prev_lo, prev_hi, lo, hi))
            if lo == prev_hi + 1:
                out[-1] = (prev_lo, hi)
                continue
        out.append((lo, hi))
    return out


def first_covering_rows(path):
    """Sorted (lo, hi, value) ranges giving the FIRST covering row's value.

    The scans they replace return the value of the first row in file order
    that covers the code point, so a later row covering ground an earlier one
    already claimed is unreachable and is clipped away here rather than
    sorted ahead of it.
    """
    claimed = []
    out = []
    for lo, hi, value in value_rows(path):
        remaining = [(lo, hi)]
        for claimed_lo, claimed_hi in claimed:
            next_remaining = []
            for part_lo, part_hi in remaining:
                if part_hi < claimed_lo or part_lo > claimed_hi:
                    next_remaining.append((part_lo, part_hi))
                    continue
                if part_lo < claimed_lo:
                    next_remaining.append((part_lo, claimed_lo - 1))
                if part_hi > claimed_hi:
                    next_remaining.append((claimed_hi + 1, part_hi))
            remaining = next_remaining
        for part_lo, part_hi in remaining:
            out.append((part_lo, part_hi, value))
            claimed.append((part_lo, part_hi))
    out.sort()
    merged = []
    for lo, hi, value in out:
        if merged and merged[-1][2] == value and lo == merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], hi, value)
            continue
        merged.append((lo, hi, value))
    return merged


def joining_letters(rows):
    """Joining_Type rows reduced to the single letter the monitor keeps."""
    out = []
    for lo, hi, value in rows:
        token = value.strip()
        letter = token if len(token) == 1 and token in "CDLRT" else "U"
        out.append((lo, hi, letter))
    merged = []
    for lo, hi, letter in out:
        if merged and merged[-1][2] == letter and lo == merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], hi, letter)
            continue
        merged.append((lo, hi, letter))
    return merged


def zwj_sequence_rows():
    """Every registered ZWJ sequence, parsed as the monitor's parseRow does."""
    rows = []
    with open(EMOJI_ZWJ_SEQUENCES, "r", encoding="utf-8") as handle:
        for line in handle:
            body = strip_comment(line).strip()
            if not body:
                continue
            sequence_field = body.split(";")[0]
            points = []
            malformed = False
            for token in sequence_field.split():
                try:
                    points.append(int(token, 16))
                except ValueError:
                    malformed = True
                    break
                if len(points) > MAX_ROW_LEN:
                    malformed = True
                    break
            if malformed or not points:
                continue
            rows.append(points)
    if not rows:
        raise SystemExit("emoji-zwj-sequences.txt carries no sequence")
    return rows


def variation_pairs():
    """Every (base, selector) pair of the two variation-sequence tables.

    A row contributes a pair only when the field before its first `;` holds
    exactly two whitespace-separated hex tokens, which is the condition the
    scan applies.
    """
    pairs = set()
    for path in (STANDARDIZED_VARIANTS, EMOJI_VARIATION_SEQUENCES):
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                body = strip_comment(line)
                pair_field = body.split(";")[0].strip()
                if not pair_field:
                    continue
                tokens = pair_field.split()
                if len(tokens) != 2:
                    continue
                try:
                    base = int(tokens[0], 16)
                    selector = int(tokens[1], 16)
                except ValueError:
                    continue
                pairs.add((base, selector))
    if not pairs:
        raise SystemExit("the variation tables carry no pair")
    return sorted(pairs)


# ── parity: the table must answer as the scan it replaces does ──────────────


def paint_boolean(rows):
    """One byte per code point: 1 where any row covers it.

    Painting both sides and comparing the arrays is exhaustive over the whole
    code space, and it costs the total length of the ranges rather than a scan
    of every row for every code point.
    """
    painted = bytearray(CODE_SPACE)
    for lo, hi in rows:
        if lo >= CODE_SPACE:
            continue
        painted[lo:min(hi, CODE_SPACE - 1) + 1] = b"\x01" * (
            min(hi, CODE_SPACE - 1) - lo + 1)
    return painted


def check_boolean_parity(label, raw_rows, table):
    """Every code point: the table agrees with a direct parse of the file."""
    if paint_boolean(raw_rows) != paint_boolean(table):
        raise SystemExit("%s disagrees with its source" % label)


def paint_valued(rows, default, codes):
    """One byte per code point: the index of the FIRST covering row's value.

    Later rows do not repaint ground an earlier row already claimed, which is
    the first-match-wins rule the text scans applied.
    """
    painted = bytearray([codes[default]]) * CODE_SPACE
    claimed = bytearray(CODE_SPACE)
    for lo, hi, value in rows:
        code = codes[value]
        for cp in range(lo, min(hi, CODE_SPACE - 1) + 1):
            if not claimed[cp]:
                claimed[cp] = 1
                painted[cp] = code
    return painted


def check_valued_parity(label, raw_rows, table, default):
    values = {default} | {value for _lo, _hi, value in raw_rows} \
        | {value for _lo, _hi, value in table}
    if len(values) > 255:
        raise SystemExit("%s carries more distinct values than the parity "
                         "check can encode in a byte" % label)
    codes = {value: index for index, value in enumerate(sorted(values))}
    if paint_valued(raw_rows, default, codes) != \
            paint_valued(table, default, codes):
        raise SystemExit("%s disagrees with its source" % label)


# ── emitters ────────────────────────────────────────────────────────────────


def emit_range_table(name, doc, table):
    lines = ["/// %s" % doc, "pub const %s = [_]Range{" % name]
    for at in range(0, len(table), PER_LINE):
        batch = table[at:at + PER_LINE]
        lines.append("    " + " ".join(
            ".{ .start = 0x%04X, .end = 0x%04X }," % (lo, hi)
            for lo, hi in batch))
    lines.append("};")
    return "\n".join(lines)


def emit_valued_table(name, kind, doc, table, render_value):
    lines = ["/// %s" % doc, "pub const %s = [_]%s{" % (name, kind)]
    for lo, hi, value in table:
        lines.append("    .{ .start = 0x%04X, .end = 0x%04X, .value = %s },"
                     % (lo, hi, render_value(value)))
    lines.append("};")
    return "\n".join(lines)


def emit_point_table(name, doc, points):
    lines = ["/// %s" % doc, "pub const %s = [_]u32{" % name]
    for at in range(0, len(points), PER_LINE * 2):
        batch = points[at:at + PER_LINE * 2]
        lines.append("    " + " ".join("0x%04X," % cp for cp in batch))
    lines.append("};")
    return "\n".join(lines)


def emit_pair_table(name, doc, pairs):
    lines = ["/// %s" % doc, "pub const %s = [_]Pair{" % name]
    for at in range(0, len(pairs), PER_LINE // 2 or 1):
        batch = pairs[at:at + (PER_LINE // 2 or 1)]
        lines.append("    " + " ".join(
            ".{ .base = 0x%04X, .selector = 0x%04X }," % (base, selector)
            for base, selector in batch))
    lines.append("};")
    return "\n".join(lines)


def script_abbreviations():
    """The Script long-name to four-letter-abbreviation pairs, and the set of
    abbreviations ScriptExtensions.txt actually uses.

    The monitor resolves a code point's script set by looking up the long name
    in the `sc` rows of PropertyValueAliases.txt and then checking that the
    abbreviation occurs somewhere in ScriptExtensions.txt, which is the whole
    vocabulary its resolver admits.
    """
    pairs = {}
    with open(PROPERTY_VALUE_ALIASES, "r", encoding="utf-8") as handle:
        for line in handle:
            body = strip_comment(line)
            fields = body.split(";")
            if len(fields) < 3:
                continue
            if fields[0].strip() != "sc":
                continue
            abbrev = fields[1].strip()
            long_name = fields[2].strip()
            # The scan keeps the first row whose long name matches, so a later
            # duplicate never wins.
            pairs.setdefault(long_name, abbrev)
    if not pairs:
        raise SystemExit("PropertyValueAliases.txt carries no sc row")

    used = set()
    for _lo, _hi, value in value_rows(SCRIPT_EXTENSIONS):
        for tag in value.split():
            used.add(tag)
    if not used:
        raise SystemExit("ScriptExtensions.txt carries no script tag")
    return sorted(pairs.items()), sorted(used)


def main():
    booleans = []
    for name, path, prop, doc in (
        ("grapheme_extend", DERIVED_CORE_PROPERTIES, "Grapheme_Extend",
         "Grapheme_Extend ranges of DerivedCoreProperties.txt."),
        ("xid_start", DERIVED_CORE_PROPERTIES, "XID_Start",
         "XID_Start ranges of DerivedCoreProperties.txt."),
        ("xid_continue", DERIVED_CORE_PROPERTIES, "XID_Continue",
         "XID_Continue ranges of DerivedCoreProperties.txt."),
        ("identifier_status_allowed", IDENTIFIER_STATUS, "Allowed",
         "Identifier_Status = Allowed ranges of IdentifierStatus.txt. Every "
         "code point outside them is Restricted by the file's own default."),
        ("emoji", EMOJI_DATA, "Emoji",
         "Emoji ranges of emoji-data.txt."),
        ("emoji_presentation", EMOJI_DATA, "Emoji_Presentation",
         "Emoji_Presentation ranges of emoji-data.txt."),
        ("emoji_modifier_base", EMOJI_DATA, "Emoji_Modifier_Base",
         "Emoji_Modifier_Base ranges of emoji-data.txt."),
    ):
        raw = property_ranges(path, prop)
        if not raw:
            raise SystemExit("%s names no %s row" % (path, prop))
        table = coalesce(raw)
        check_boolean_parity(name, raw, table)
        booleans.append((name, doc, table))

    script_raw = value_rows(SCRIPTS)
    script_table = first_covering_rows(SCRIPTS)
    check_valued_parity("script", script_raw, script_table, "Unknown")

    joining_raw = joining_letters(value_rows(DERIVED_JOINING_TYPE))
    joining_table = joining_letters(first_covering_rows(DERIVED_JOINING_TYPE))
    check_valued_parity("joining_type", joining_raw, joining_table, "U")

    # The monitor tells "no row covers this code point" from "a row covers it"
    # before falling back to Scripts.txt, and it reads the covering row's value
    # as a whitespace-separated tag list. An empty value would make those two
    # cases indistinguishable through the empty-string fallback the lookup
    # uses, so it is refused here rather than silently conflated.
    script_ext_raw = value_rows(SCRIPT_EXTENSIONS)
    for lo, hi, value in script_ext_raw:
        if not value:
            raise SystemExit(
                "ScriptExtensions.txt row U+%04X..U+%04X has an empty value"
                % (lo, hi))
    script_ext_table = first_covering_rows(SCRIPT_EXTENSIONS)
    check_valued_parity("script_extensions", script_ext_raw, script_ext_table, "")

    alias_pairs, known_abbrevs = script_abbreviations()

    alphabet = sorted({cp for row in zwj_sequence_rows() for cp in row
                       if cp != ZWJ})
    pairs = variation_pairs()

    blocks = [
        "// Property tables the security monitor reads per code point, from the",
        "// pinned UCD 17.0.0 files bundled under src/data. Every table is",
        "// sorted by range start and its ranges are disjoint, so the covering",
        "// range is unique and a lookup bisects for it.",
        "//",
        "// Each table was checked against a direct parse of its own source",
        "// file across all %d code points at generation." % CODE_SPACE,
        "//",
        "// Do not edit by hand. Regenerate with",
        "// tools/generate_property_data.py.",
        "",
        "/// A closed code point range. Field for field the shape",
        "/// casing_data.Range carries, so one membership helper serves both.",
        "pub const Range = struct { start: u32, end: u32 };",
        "",
        "/// A closed range carrying a string value.",
        "pub const StringRange = struct { start: u32, end: u32, value: []const u8 };",
        "",
        "/// A closed range carrying a single-letter value.",
        "pub const ByteRange = struct { start: u32, end: u32, value: u8 };",
        "",
        "/// A registered (base, variation selector) pair.",
        "pub const Pair = struct { base: u32, selector: u32 };",
        "",
        "/// A Script long name and its four-letter abbreviation.",
        "pub const Alias = struct { long: []const u8, abbrev: []const u8 };",
        "",
    ]
    for name, doc, table in booleans:
        blocks.append(emit_range_table(name, doc, table))
        blocks.append("")
    blocks.append(emit_valued_table(
        "script", "StringRange",
        "Script ranges of Scripts.txt, each carrying the first covering row's "
        "value. A code point outside them is Unknown.",
        script_table, lambda value: '"%s"' % value))
    blocks.append("")
    blocks.append(emit_valued_table(
        "joining_type", "ByteRange",
        "Joining_Type ranges of DerivedJoiningType.txt as single letters. A "
        "code point outside them is U, Non_Joining.",
        joining_table, lambda value: "'%s'" % value))
    blocks.append("")
    blocks.append(emit_point_table(
        "zwj_alphabet",
        "Every code point other than U+200D appearing at any position of a "
        "registered sequence in emoji-zwj-sequences.txt -- what may flank a "
        "joiner.",
        alphabet))
    blocks.append("")
    blocks.append(emit_pair_table(
        "variation_pairs",
        "Every (base, selector) pair of StandardizedVariants.txt and "
        "emoji-variation-sequences.txt.",
        pairs))
    blocks.append("")
    blocks.append(emit_valued_table(
        "script_extensions", "StringRange",
        "Script_Extensions ranges of ScriptExtensions.txt, each carrying the "
        "first covering row's whitespace-separated tag list. No row carries an "
        "empty list, so the empty string means no row covers the code point.",
        script_ext_table, lambda value: '"%s"' % value))
    blocks.append("")
    lines = [
        "/// The Script long name to four-letter abbreviation pairs of the sc",
        "/// rows of PropertyValueAliases.txt, sorted by long name. Where the",
        "/// file lists a long name twice the first row wins, as the scan did.",
        "pub const script_aliases = [_]Alias{",
    ]
    for long_name, abbrev in alias_pairs:
        lines.append('    .{ .long = "%s", .abbrev = "%s" },'
                     % (long_name, abbrev))
    lines.append("};")
    blocks.append("\n".join(lines))
    blocks.append("")
    lines = [
        "/// Every script abbreviation appearing in a ScriptExtensions.txt tag",
        "/// list, sorted -- the whole vocabulary the script resolver admits.",
        "pub const known_script_abbrevs = [_][]const u8{",
    ]
    for at in range(0, len(known_abbrevs), PER_LINE):
        batch = known_abbrevs[at:at + PER_LINE]
        lines.append("    " + " ".join('"%s",' % tag for tag in batch))
    lines.append("};")
    blocks.append("\n".join(lines))
    blocks.append("")

    text = "\n".join(blocks)
    with open(OUT, "w", encoding="utf-8") as handle:
        handle.write(text)

    sys.stdout.write("wrote %s (%d lines)\n"
                     % (os.path.relpath(OUT, ROOT), text.count("\n")))
    for name, _doc, table in booleans:
        sys.stdout.write("  %-26s %5d ranges\n" % (name, len(table)))
    sys.stdout.write("  %-26s %5d ranges\n" % ("script", len(script_table)))
    sys.stdout.write("  %-26s %5d ranges\n"
                     % ("joining_type", len(joining_table)))
    sys.stdout.write("  %-26s %5d ranges\n"
                     % ("script_extensions", len(script_ext_table)))
    sys.stdout.write("  %-26s %5d code points\n"
                     % ("zwj_alphabet", len(alphabet)))
    sys.stdout.write("  %-26s %5d pairs\n"
                     % ("variation_pairs", len(pairs)))
    sys.stdout.write("  %-26s %5d pairs\n"
                     % ("script_aliases", len(alias_pairs)))
    sys.stdout.write("  %-26s %5d tags\n"
                     % ("known_script_abbrevs", len(known_abbrevs)))


if __name__ == "__main__":
    main()
