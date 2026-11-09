// UAX #14 default line breaking.
//
// Validates the port's line breaker against the official Unicode
// LineBreakTest.txt (bundled under testdata/ so the package stays
// self-contained), plus targeted vectors pinning the individual rules and the
// output shape the Lean lineBreaks_length theorem fixes. Every break
// opportunity (÷) and non-break (×) in the official file must be reproduced
// exactly.
//
// The corpus reader, the mask comparison and the fixture decoder are shared
// with the grapheme suite: both published corpora write the same alternating
// markers and codepoints.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  lineBreaks,
  lineRuns,
  rawClass,
  resolvedClass,
  eastAsianWidth,
  isExtendedPictographic,
  PUBLISHED_ROW_COUNT,
} from "../src/segmentation/line-break.js";

import {
  readCorpus,
  segmentationFixture,
  formatCodepoints,
  sameMask,
  disagreements,
  raggedRows,
} from "./segmentation-corpus.js";

const CORPUS_URL = new URL("../testdata/LineBreakTest.txt", import.meta.url);

const VECTORS_URL = new URL(
  "../testdata/fixtures/segmentation/line_break_vectors.json",
  import.meta.url,
);

function vectors() {
  return segmentationFixture(
    VECTORS_URL,
    "line_break_vectors.json",
    "uax14-line-break",
  );
}

// What the corpus must be before it can judge anything: every row carries one
// more flag than codepoints, and the vendored copy carries every row the
// canonical file did. Without the second check a row lost between the two would
// shrink the denominator instead of failing.
test("the line-break corpus is well formed", () => {
  const rows = readCorpus(CORPUS_URL);
  assert.equal(raggedRows(rows), 0, "every row carries one flag per boundary");
  assert.equal(
    rows.length,
    PUBLISHED_ROW_COUNT,
    "the vendored corpus carries every published row",
  );
});

// Hand-written vectors cannot establish a segmentation algorithm: its rules
// read context on both sides of a boundary and the answer depends on state
// carried from earlier in the sequence, so a wrong rule survives any vector a
// person would pick. Agreeing with all of them is also the evidence the two
// departures declared at line-break.js's head needed — undefined-yielding
// reads in place of the Lean's positional lits[i]!, and dropping its write-only
// spSinceNoSp snapshot field.
test("the line breaker agrees with every published row", () => {
  const rows = readCorpus(CORPUS_URL);
  const { count, report } = disagreements(rows, lineBreaks);
  assert.equal(count, 0, `${count} of ${rows.length} rows disagree; ${report}`);
});

// One case per UAX #14 rule, the same bytes every port replays, so no port can
// carry a weaker set of rule checks than another. The published corpus above is
// the authority; these name which rule each boundary exercises.
test("the shared line-break vectors replay", () => {
  for (const testCase of vectors().cases) {
    const produced = lineBreaks(testCase.input);
    assert.ok(
      sameMask(produced, testCase.breaks),
      `${testCase.rule}: ${testCase.name}` +
        `\n  codepoints: ${formatCodepoints(testCase.input)}`,
    );
  }
});

// Both gates count the same published file, so they cannot drift apart.
test("the corpus and the vectors agree on the row count", () => {
  assert.equal(vectors().published_row_count, PUBLISHED_ROW_COUNT);
});

test("the output carries one flag per boundary", () => {
  // The Lean lineBreaks_length theorem: cps.length + 1 flags.
  for (let length = 0; length < 8; length += 1) {
    const cps = [];
    for (let i = 0; i < length; i += 1) cps.push(0x61 + i);
    assert.equal(lineBreaks(cps).length, length + 1);
  }
});

test("a space opens the next run", () => {
  // LB18 breaks after a space, so the space stays with the word before it. The
  // run split is a shape the boundary masks do not state.
  const runs = lineRuns([0x61, 0x20, 0x62]);
  assert.equal(runs.length, 2);
  assert.deepEqual(runs[0], [0x61, 0x20]);
  assert.deepEqual(runs[1], [0x62]);
});

test("a numeric chain is one run", () => {
  // LB25: "1,000" is one run across its separator.
  assert.equal(lineRuns([0x31, 0x2c, 0x30, 0x30, 0x30]).length, 1);
});

test("LB1 resolves the tailorable classes", () => {
  // U+3041 HIRAGANA LETTER SMALL A is CJ, resolving to NS.
  assert.equal(rawClass(0x3041), "CJ");
  assert.equal(resolvedClass(0x3041), "NS");
  // U+00A7 SECTION SIGN is AI, resolving to AL.
  assert.equal(rawClass(0x00a7), "AI");
  assert.equal(resolvedClass(0x00a7), "AL");
  // A surrogate codepoint is SG, resolving to AL.
  assert.equal(rawClass(0xd800), "SG");
  assert.equal(resolvedClass(0xd800), "AL");
  // U+05EB lies in the Hebrew block's unassigned gap, which no range covers, so
  // it takes the @missing XX default and LB1 reads it as AL.
  assert.equal(rawClass(0x05eb), "XX");
  assert.equal(resolvedClass(0x05eb), "AL");
});

test("LB1 resolves SA by General_Category", () => {
  // U+0E31 THAI CHARACTER MAI HAN-AKAT is SA with General_Category Mn, so LB1
  // reads it as CM; U+0E01 THAI CHARACTER KO KAI is SA with category Lo, so LB1
  // reads it as AL.
  assert.equal(rawClass(0x0e31), "SA");
  assert.equal(resolvedClass(0x0e31), "CM");
  assert.equal(rawClass(0x0e01), "SA");
  assert.equal(resolvedClass(0x0e01), "AL");
});

test("the properties LB19a, LB25, LB30 and LB30b read", () => {
  // U+FF21 FULLWIDTH LATIN CAPITAL LETTER A is F and U+0041 is Na.
  assert.equal(eastAsianWidth(0xff21), "F");
  assert.equal(eastAsianWidth(0x0041), "Na");
  // LB30b reads Extended_Pictographic from the one table in this directory,
  // which GB11 reads as well.
  assert.equal(isExtendedPictographic(0x1f466), true);
  assert.equal(isExtendedPictographic(0x0061), false);
});
