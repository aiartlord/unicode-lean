import assert from "node:assert/strict";
import test from "node:test";

import "../src/security.js"; // configures the verified data reader
import { localeCaseInversionDetect } from "../src/security-core.js";

// Ground truth: the detect_* spot-check theorems in
// Unicode/Security/Form/LocaleCaseInversion.lean.

const sub = (cps) => localeCaseInversionDetect(cps).sub;

test("locale-case-inversion detect tags match the Lean vectors", () => {
  assert.equal(sub([]), null);
  assert.equal(sub([0x48, 0x65, 0x6c, 0x6c, 0x6f]), null);
  assert.equal(sub([0x0049]), "TurkishCaseDivergence");
  assert.deepEqual(localeCaseInversionDetect([0x0049]).positions, [0]);
  assert.equal(sub([0x0130]), "TurkishCaseDivergence");
  assert.equal(sub([0x0049, 0x0300]), "TurkishCaseDivergence");
  assert.equal(sub([0x004a, 0x0300]), "LithuanianCaseDivergence");
});
