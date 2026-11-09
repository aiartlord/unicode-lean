#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
#                   // tools // generate // break-corpus-rows
# ─────────────────────────────────────────────────────────────────────────────
#
# Emits the published break corpora this port's specs are judged against, from
# the pinned UCD files in the repository root:
#
#   test/LineBreakTestRows.hs   Every row of LineBreakTest.txt.
#   test/GraphemeTestRows.hs    Every row of GraphemeBreakTest.txt. The
#                               grapheme spec had no corpus to judge against,
#                               so its only evidence was a handful of
#                               hand-written masks, while `BreakCorpus` had
#                               been written for every published corpus.
#
# The corpora are compiled in rather than read at run time: a spec owns its
# inputs, and a test that opens a file fails on where it was run from rather
# than on what it measures.
#
# The rows are emitted in chunks of a thousand, each its own top-level binding,
# because a single list literal of this length is one enormous expression for
# GHC to typecheck and simplify. `publishedRows` concatenates the chunks.
#
#   python3 ports/haskell/tools/generate_break_corpus_rows.py
#
# Run from anywhere. Writing the two modules is the whole effect.

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

UCD = os.path.join(ROOT, "Unicode", "Ucd")
LINE_BREAK_TEST_TXT = os.path.join(UCD, "LineBreakTest.txt")
GRAPHEME_BREAK_TEST_TXT = os.path.join(UCD, "GraphemeBreakTest.txt")

TEST_DIR = os.path.join(ROOT, "ports", "haskell", "test")

# The markers the published break corpora write at each boundary.
BREAK_MARKER = "÷"
NO_BREAK_MARKER = "×"

# How many rows share one top-level binding.
CHUNK = 1000


def strip_comment(line):
    return line.split("#", 1)[0].strip()


def read_break_test_rows(path):
    """The published rows of a UAX break corpus as (codepoints, flags).

    A row alternates boundary markers and code points, starting and ending
    with a marker, so it carries one more flag than code points. Every
    published break corpus writes that one format, so one reader serves them
    all.
    """
    name = os.path.basename(path)
    rows = []
    with open(path, "r", encoding="utf-8") as handle:
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
                            "%s line %d has two markers in a row"
                            % (name, number))
                    flags.append(token == BREAK_MARKER)
                    expecting_marker = False
                else:
                    if expecting_marker:
                        raise SystemExit(
                            "%s line %d has two code points in a row"
                            % (name, number))
                    codepoints.append(int(token, 16))
                    expecting_marker = True
            if expecting_marker:
                raise SystemExit(
                    "%s line %d ends at a code point rather than a boundary "
                    "marker" % (name, number))
            if len(flags) != len(codepoints) + 1:
                raise SystemExit(
                    "%s line %d carries %d flags for %d code points"
                    % (name, number, len(flags), len(codepoints)))
            rows.append((codepoints, flags))
    return rows


def format_row(codepoints, flags):
    """One row as the pair the spec compares: code points and break flags."""
    points = ", ".join("0x%04X" % cp for cp in codepoints)
    marks = ", ".join("True" if flag else "False" for flag in flags)
    return "([%s], [%s])" % (points, marks)


def format_chunks(rows):
    """The rows as chunked top-level bindings, plus the chunk names."""
    lines = []
    names = []
    for start in range(0, len(rows), CHUNK):
        batch = rows[start:start + CHUNK]
        name = "rowsChunk%d" % (start // CHUNK)
        names.append(name)
        lines.append("")
        lines.append("-- | Published rows %d through %d."
                     % (start, start + len(batch) - 1))
        lines.append("%s :: [([Int], [Bool])]" % name)
        lines.append("%s =" % name)
        for index, (codepoints, flags) in enumerate(batch):
            opener = "    [ " if index == 0 else "    , "
            lines.append(opener + format_row(codepoints, flags))
        lines.append("    ]")
    return lines, names


def format_module(module, banner, uax, corpus, rows):
    """A corpus rows module: the published rows of one break corpus, as data."""
    chunk_lines, names = format_chunks(rows)
    aggregate = ["    " + names[0]] + [
        "        ++ %s" % name for name in names[1:]]
    return "\n".join([
        "{-# LANGUAGE StrictData #-}",
        "",
        "-- SPDX-License-Identifier: LicenseRef-Allodial-Tiered",
        "",
        "-- " + "━" * 77,
        "--%s" % banner.rjust(77),
        "-- " + "━" * 77,
        "",
        "-- | @Unicode.Segmentation.%s@ — every row the pinned UCD" % module,
        "-- @%s@ (UCD 17.0.0) publishes, parsed into the codepoint" % corpus,
        "-- sequence and the break flags it asserts.",
        "--",
        "-- A row of @n@ codepoints carries @n + 1@ flags: flag @i@ is whether a",
        "-- UAX #%s break opportunity falls immediately before codepoint @i@," % uax,
        "-- and flag @n@ is the break at end of text. That is the shape the",
        "-- implementation returns, so a row is judged by comparing the two",
        "-- lists.",
        "--",
        "-- The corpus is compiled in rather than read at run time: a spec owns",
        "-- its inputs, and a test that opens a file fails on where it was run",
        "-- from rather than on what it measures.",
        "--",
        "-- GENERATED FILE — DO NOT EDIT. Regenerate with",
        "-- @ports/haskell/tools/generate_break_corpus_rows.py@.",
        "",
        "module %s" % module,
        "    ( publishedRows",
        "    , publishedCount",
        "    ) where",
        "\n".join(chunk_lines),
        "",
        "-- | Every published row, in file order.",
        "publishedRows :: [([Int], [Bool])]",
        "publishedRows =",
        "\n".join(aggregate),
        "",
        "-- | How many rows the pinned file publishes. A suite that judges fewer",
        "-- has lost rows between this module and its own fold, so the count is",
        "-- asserted rather than taken from the list it is checking.",
        "publishedCount :: Int",
        "publishedCount = %d" % len(rows),
        "",
    ])


def write_file(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    sys.stdout.write("wrote %s (%d lines)\n" % (
        os.path.relpath(path, ROOT), text.count("\n")))


def main():
    write_file(
        os.path.join(TEST_DIR, "LineBreakTestRows.hs"),
        format_module(
            "LineBreakTestRows",
            "// unicode // generated // line-break-test-rows",
            "14", "LineBreakTest.txt",
            read_break_test_rows(LINE_BREAK_TEST_TXT)))
    write_file(
        os.path.join(TEST_DIR, "GraphemeTestRows.hs"),
        format_module(
            "GraphemeTestRows",
            "// unicode // generated // grapheme-test-rows",
            "29", "GraphemeBreakTest.txt",
            read_break_test_rows(GRAPHEME_BREAK_TEST_TXT)))


if __name__ == "__main__":
    main()
