import assert from "node:assert/strict";
import test from "node:test";

import "../src/security.js"; // configures the verified data reader
import { bip39Canonical, bip39Detect } from "../src/security-core.js";

const ABANDON = [0x61, 0x62, 0x61, 0x6e, 0x64, 0x6f, 0x6e];
const ABOUT = [0x61, 0x62, 0x6f, 0x75, 0x74];

const tag = (cps) => bip39Detect(cps).classify.sub;

test("bip39 canonicalisation matches the Lean spot-checks", () => {
  assert.deepEqual(bip39Canonical([]), []);
  assert.deepEqual(bip39Canonical([0x61, 0x20, 0x20, 0x62]), [0x61, 0x20, 0x62]);
  assert.deepEqual(bip39Canonical([0x61, 0x20]), [0x61]);
  assert.deepEqual(bip39Canonical([0x20, 0x61]), [0x61]);
  assert.deepEqual(bip39Canonical([0x41]), [0x61]);
  assert.deepEqual(bip39Canonical([0x61, 0x3000, 0x62]), [0x61, 0x20, 0x62]);
});

test("bip39 detect hazard tags match the Lean vectors", () => {
  assert.equal(tag([...ABANDON, 0x20]), "TrailingWhitespace");
  assert.equal(tag([0x41, 0x62, 0x61, 0x6e, 0x64, 0x6f, 0x6e]), "MixedCase");
  assert.equal(tag([...ABANDON, 0x20, 0x20, ...ABOUT]), "WhitespaceAnomaly");
  assert.equal(tag([0x20, ...ABANDON]), "WhitespaceAnomaly");
  assert.equal(tag([0xfb00]), "NonNFKD"); // ﬀ ligature
  assert.equal(tag([0x61, 0x00a0, 0x62]), "NonNFKD"); // NBSP
  assert.equal(tag([0x71, 0x7a, 0x71, 0x7a]), "WordlistMismatch"); // "qzqz"
});

test("bip39 detect positions match the Lean vectors", () => {
  assert.deepEqual(bip39Detect([...ABANDON, 0x20]).classify.positions, [7]);
  assert.deepEqual(bip39Detect([0x41, 0x62, 0x61, 0x6e, 0x64, 0x6f, 0x6e]).classify.positions, [0]);
});

test("bip39 detect clear cases and word count", () => {
  const empty = bip39Detect([]);
  assert.equal(empty.classify.isClear, true);
  assert.equal(empty.classify.language, "english");

  let mnemonic = [];
  for (let i = 0; i < 11; i += 1) mnemonic = [...mnemonic, ...ABANDON, 0x20];
  mnemonic = [...mnemonic, ...ABOUT];
  const verdict = bip39Detect(mnemonic);
  assert.equal(verdict.classify.isClear, true);
  assert.equal(verdict.classify.language, "english");
  assert.equal(verdict.wordCount, 12);
});
