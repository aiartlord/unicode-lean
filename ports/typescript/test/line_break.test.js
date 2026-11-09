// UAX #14 default line breaking.
//
// Validates the port's line breaker against the official Unicode
// LineBreakTest.txt (bundled under testdata/ so the package stays
// self-contained), plus targeted vectors pinning the individual rules and the
// output shape the Lean lineBreaks_length theorem fixes. Every break
// opportunity (÷) and non-break (×) in the official file must be reproduced
// exactly.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  lineBreaks,
  lineRuns,
  rawClass,
  resolvedClass,
  eastAsianWidth,
  isExtendedPictographic,
  PUBLISHED_ROW_COUNT,
} from "../src/segmentation/line-break.js";

// The markers the published break corpus writes at each boundary.
const BREAK = "÷"; // ÷ : break opportunity
const NO_BREAK = "×"; // × : no break

const CORPUS_URL = new URL("../testdata/LineBreakTest.txt", import.meta.url);

// The shared segmentation vector fixture: one case per UAX rule, the same bytes
// in every port, so each port's segmentation tests ask the same questions
// rather than a per-port selection of them.
function segmentationFixture(name, algorithm) {
  const url = new URL(`../testdata/fixtures/segmentation/${name}`, import.meta.url);
  const document = JSON.parse(readFileSync(url, "utf8"));
  assert.equal(document.schema, 1, `${name} schema`);
  assert.equal(document.algorithm, algorithm, `${name} algorithm`);
  assert.ok(document.cases.length > 0, `${name} carries no cases`);
  return document;
}

// Parse one data line into its codepoints and expected boundary mask.
//
// A line is a sequence of alternating boundary markers and hex codepoints,
// beginning and ending with a marker: e.g. "× 0061 ÷ 0062 ÷". The markers form
// the expected mask (÷ -> true, × -> false) of length codepoints.length + 1;
// the hex tokens are the codepoints.
function parseRow(body) {
  const codepoints = [];
  const expected = [];
  for (const token of body.split(/\s+/)) {
    if (token === "") continue;
    if (token === BREAK) {
      expected.push(true);
    } else if (token === NO_BREAK) {
      expected.push(false);
    } else {
      const cp = Number.parseInt(token, 16);
      assert.ok(
        Number.isInteger(cp),
        `unparseable codepoint token ${JSON.stringify(token)}`,
      );
      codepoints.push(cp);
    }
  }
  return { codepoints, expected };
}

// Every data row of the vendored corpus.
function readCorpus() {
  const text = readFileSync(CORPUS_URL, "utf8");
  const rows = [];
  const lines = text.split("\n");
  for (let index = 0; index < lines.length; index += 1) {
    const hash = lines[index].indexOf("#");
    const body = (hash >= 0 ? lines[index].slice(0, hash) : lines[index]).trim();
    if (body === "") continue;
    const { codepoints, expected } = parseRow(body);
    rows.push({ line: index + 1, codepoints, expected });
  }
  return rows;
}

function formatCodepoints(cps) {
  return cps.map((cp) => cp.toString(16).toUpperCase().padStart(4, "0"))
    .join(" ");
}

// What the corpus must be before it can judge anything: every row carries one
// more flag than codepoints, and the vendored copy carries every row the
// canonical file did. Without the second check a row lost between the two would
// shrink the denominator instead of failing.
test("the line-break corpus is well formed", () => {
  const rows = readCorpus();
  let ragged = 0;
  for (const row of rows) {
    if (row.expected.length !== row.codepoints.length + 1) ragged += 1;
  }
  assert.equal(ragged, 0, "every row carries one flag per boundary");
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
  const rows = readCorpus();
  let disagreements = 0;
  let firstLine = 0;
  let detail = "";
  for (const row of rows) {
    const produced = lineBreaks(row.codepoints);
    const agrees =
      produced.length === row.expected.length &&
      produced.every((flag, index) => flag === row.expected[index]);
    if (!agrees) {
      if (disagreements === 0) {
        firstLine = row.line;
        // A conformance red is only actionable if it says which row disagreed
        // and how.
        detail =
          `\n  codepoints: ${formatCodepoints(row.codepoints)}` +
          `\n  published:  ${row.expected.map((f) => (f ? "/" : "x")).join(" ")}` +
          `\n  produced:   ${produced.map((f) => (f ? "/" : "x")).join(" ")}`;
      }
      disagreements += 1;
    }
  }
  assert.equal(
    disagreements,
    0,
    `${disagreements} of ${rows.length} rows disagree; first at corpus line ` +
      `${firstLine}${detail}`,
  );
});

// One case per UAX #14 rule, the same bytes every port replays, so no port can
// carry a weaker set of rule checks than another. The published corpus above is
// the authority; these name which rule each boundary exercises.
test("the shared line-break vectors replay", () => {
  const document = segmentationFixture(
    "line_break_vectors.json",
    "uax14-line-break",
  );
  for (const testCase of document.cases) {
    const produced = lineBreaks(testCase.input);
    const label = `${testCase.rule}: ${testCase.name}`;
    assert.deepEqual(
      produced,
      testCase.breaks,
      `${label}\n  codepoints: ${formatCodepoints(testCase.input)}`,
    );
  }
});

// Both gates count the same published file, so they cannot drift apart.
test("the corpus and the vectors agree on the row count", () => {
  const document = segmentationFixture(
    "line_break_vectors.json",
    "uax14-line-break",
  );
  assert.equal(document.published_row_count, PUBLISHED_ROW_COUNT);
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
  // LB30b reads Extended_Pictographic, and this port carries no grapheme
  // clustering to borrow a table from.
  assert.equal(isExtendedPictographic(0x1f466), true);
  assert.equal(isExtendedPictographic(0x0061), false);
});
