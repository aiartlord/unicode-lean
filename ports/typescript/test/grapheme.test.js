// UAX #29 default extended grapheme cluster segmentation.
//
// Validates the port's cluster breaker against the official Unicode
// GraphemeBreakTest.txt (bundled under testdata/ so the package stays
// self-contained), plus the shared vector fixture every other port replays and
// targeted cases for shapes a boundary mask does not state.
//
// The two corpus gates are the ones the line-break suite runs: agree with every
// published row, and separately account for the whole file so a row lost
// between the file and the fold fails rather than shrinking the denominator.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  graphemeBreaks,
  graphemeClusters,
  graphemeClusterBreak,
  indicConjunctBreak,
  isExtendedPictographic,
  GRAPHEME_PUBLISHED_ROW_COUNT,
} from "../src/segmentation/grapheme.js";

import {
  readCorpus,
  segmentationFixture,
  formatCodepoints,
  sameMask,
  disagreements,
  raggedRows,
} from "./segmentation-corpus.js";

const CORPUS_URL = new URL("../testdata/GraphemeBreakTest.txt", import.meta.url);

const VECTORS_URL = new URL(
  "../testdata/fixtures/segmentation/grapheme_vectors.json",
  import.meta.url,
);

function vectors() {
  return segmentationFixture(
    VECTORS_URL,
    "grapheme_vectors.json",
    "uax29-grapheme-cluster",
  );
}

// What the corpus must be before it can judge anything: every row carries one
// more flag than codepoints, and the vendored copy carries every row the
// canonical file did. Without the second check a row lost between the two would
// shrink the denominator instead of failing.
test("the grapheme corpus is well formed", () => {
  const rows = readCorpus(CORPUS_URL);
  assert.equal(raggedRows(rows), 0, "every row carries one flag per boundary");
  assert.equal(
    rows.length,
    GRAPHEME_PUBLISHED_ROW_COUNT,
    "the vendored corpus carries every published row",
  );
});

// Hand-written vectors cannot establish a segmentation algorithm: its rules
// read context on both sides of a boundary and the answer depends on state
// carried from earlier in the sequence, so a wrong rule survives any vector a
// person would pick.
test("the cluster breaker agrees with every published row", () => {
  const rows = readCorpus(CORPUS_URL);
  const { count, report } = disagreements(rows, graphemeBreaks);
  assert.equal(count, 0, `${count} of ${rows.length} rows disagree; ${report}`);
});

// One case per UAX #29 rule, the same bytes every port replays, so no port can
// carry a weaker set of rule checks than another. The published corpus above is
// the authority; these name which rule each boundary exercises.
test("the shared grapheme vectors replay", () => {
  for (const testCase of vectors().cases) {
    const produced = graphemeBreaks(testCase.input);
    assert.ok(
      sameMask(produced, testCase.breaks),
      `${testCase.rule}: ${testCase.name}` +
        `\n  codepoints: ${formatCodepoints(testCase.input)}`,
    );
  }
});

// Both gates count the same published file, so they cannot drift apart.
test("the grapheme corpus and the vectors agree on the row count", () => {
  assert.equal(vectors().published_row_count, GRAPHEME_PUBLISHED_ROW_COUNT);
});

test("the output carries one flag per boundary", () => {
  for (let length = 0; length < 8; length += 1) {
    const cps = [];
    for (let i = 0; i < length; i += 1) cps.push(0x61 + i);
    const breaks = graphemeBreaks(cps);
    assert.equal(breaks.length, length + 1);
    assert.equal(breaks[breaks.length - 1], true, "GB2 breaks at end of text");
    if (length > 0) {
      assert.equal(breaks[0], true, "GB1 breaks at start of text");
    }
  }
});

// The cluster split is a shape the boundary masks do not state.
test("a sequence splits into its clusters", () => {
  // GB999 leaves each ASCII letter its own cluster.
  assert.deepEqual(graphemeClusters([0x61, 0x62, 0x63]), [[0x61], [0x62], [0x63]]);
  // GB9 keeps a combining mark with its base.
  assert.deepEqual(graphemeClusters([0x65, 0x0301]), [[0x65, 0x0301]]);
  // GB3 keeps CR LF together.
  assert.deepEqual(graphemeClusters([0x0d, 0x0a]), [[0x0d, 0x0a]]);
  // GB12 pairs regional indicators, and GB13 ends the pair so a second pair
  // opens its own cluster.
  assert.deepEqual(graphemeClusters([0x1f1ef, 0x1f1f5]), [[0x1f1ef, 0x1f1f5]]);
  assert.deepEqual(
    graphemeClusters([0x1f1ef, 0x1f1f5, 0x1f1fa, 0x1f1f8]),
    [[0x1f1ef, 0x1f1f5], [0x1f1fa, 0x1f1f8]],
  );
  // GB11 holds an emoji ZWJ sequence together.
  assert.deepEqual(
    graphemeClusters([0x1f468, 0x200d, 0x1f469, 0x200d, 0x1f467]),
    [[0x1f468, 0x200d, 0x1f469, 0x200d, 0x1f467]],
  );
  // A base with a mark, then a letter: two clusters, and the mark stays with
  // its base.
  assert.deepEqual(
    graphemeClusters([0x65, 0x0301, 0x61]),
    [[0x65, 0x0301], [0x61]],
  );
  // An empty sequence has one boundary and no cluster.
  assert.deepEqual(graphemeClusters([]), []);
});

test("the properties the rules read", () => {
  assert.equal(graphemeClusterBreak(0x000d), "CR");
  assert.equal(graphemeClusterBreak(0x000a), "LF");
  assert.equal(graphemeClusterBreak(0x0301), "Extend");
  assert.equal(graphemeClusterBreak(0x200d), "ZWJ");
  assert.equal(graphemeClusterBreak(0x1f1ef), "Regional_Indicator");
  assert.equal(graphemeClusterBreak(0x093e), "SpacingMark");
  assert.equal(graphemeClusterBreak(0x1100), "L");
  // A codepoint no range covers takes the @missing Other default.
  assert.equal(graphemeClusterBreak(0x0061), "Other");

  // GB9c reads Indic_Conjunct_Break: U+094D DEVANAGARI SIGN VIRAMA is the
  // Linker and U+0915 DEVANAGARI LETTER KA a Consonant.
  assert.equal(indicConjunctBreak(0x094d), "Linker");
  assert.equal(indicConjunctBreak(0x0915), "Consonant");
  assert.equal(indicConjunctBreak(0x0300), "Extend");
  assert.equal(indicConjunctBreak(0x0061), "None");

  // GB11 reads Extended_Pictographic from the table LB30b also reads.
  assert.equal(isExtendedPictographic(0x1f466), true);
  assert.equal(isExtendedPictographic(0x0061), false);
});
