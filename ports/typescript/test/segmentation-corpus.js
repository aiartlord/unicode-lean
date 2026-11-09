// Readers the segmentation suites share.
//
// Both published corpora — LineBreakTest.txt and GraphemeBreakTest.txt — write
// the same alternating boundary markers and hex codepoints, and both suites
// replay the same shared vector fixture shape, so the reading is here and each
// suite names the corpus and the fixture it is judged against.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

// The markers the published break corpora write at each boundary.
const BREAK = "÷"; // ÷ : break opportunity
const NO_BREAK = "×"; // × : no break

/**
 * Parse one data line into its codepoints and expected boundary mask.
 *
 * A line is a sequence of alternating boundary markers and hex codepoints,
 * beginning and ending with a marker: e.g. "× 0061 ÷ 0062 ÷". The markers form
 * the expected mask (÷ -> true, × -> false) of length codepoints.length + 1;
 * the hex tokens are the codepoints.
 *
 * @param {string} body
 */
export function parseRow(body) {
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

/**
 * Every data row of a vendored published corpus.
 *
 * @param {URL} url
 */
export function readCorpus(url) {
  const text = readFileSync(url, "utf8");
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

/**
 * The shared segmentation vector fixture: one case per UAX rule, the same bytes
 * in every port, so each port's segmentation tests ask the same questions
 * rather than a per-port selection of them.
 *
 * The algorithm is checked rather than assumed: a fixture of the wrong schema
 * or the wrong algorithm would otherwise yield cases that pass every assertion
 * over them.
 *
 * @param {URL} url
 * @param {string} name
 * @param {string} algorithm
 */
export function segmentationFixture(url, name, algorithm) {
  const document = JSON.parse(readFileSync(url, "utf8"));
  assert.equal(document.schema, 1, `${name} schema`);
  assert.equal(document.algorithm, algorithm, `${name} algorithm`);
  assert.ok(document.cases.length > 0, `${name} carries no cases`);
  return document;
}

/** Hex codepoints, space separated, for a failure message. */
export function formatCodepoints(cps) {
  return cps.map((cp) => cp.toString(16).toUpperCase().padStart(4, "0"))
    .join(" ");
}

/** A boundary mask as slashes and crosses, for a failure message. */
export function formatMask(flags) {
  return flags.map((flag) => (flag ? "/" : "x")).join(" ");
}

/**
 * Whether a produced mask equals a published one, length included.
 *
 * @param {ReadonlyArray<boolean>} produced
 * @param {ReadonlyArray<boolean>} published
 */
export function sameMask(produced, published) {
  return produced.length === published.length &&
    produced.every((flag, index) => flag === published[index]);
}

/**
 * How many rows of a corpus a breaker disagrees with, and a report naming the
 * first one. A conformance red is only actionable if it says which row
 * disagreed and how.
 *
 * @param {ReadonlyArray<{line: number, codepoints: number[], expected: boolean[]}>} rows
 * @param {(cps: number[]) => boolean[]} breaker
 */
export function disagreements(rows, breaker) {
  let count = 0;
  let report = "";
  for (const row of rows) {
    const produced = breaker(row.codepoints);
    if (sameMask(produced, row.expected)) continue;
    if (count === 0) {
      report =
        `first at corpus line ${row.line}` +
        `\n  codepoints: ${formatCodepoints(row.codepoints)}` +
        `\n  published:  ${formatMask(row.expected)}` +
        `\n  produced:   ${formatMask(produced)}`;
    }
    count += 1;
  }
  return { count, report };
}

/**
 * How many rows carry a flag count that is not one per boundary. Without this
 * the corpus could not judge anything.
 *
 * @param {ReadonlyArray<{codepoints: number[], expected: boolean[]}>} rows
 */
export function raggedRows(rows) {
  let ragged = 0;
  for (const row of rows) {
    if (row.expected.length !== row.codepoints.length + 1) ragged += 1;
  }
  return ragged;
}
