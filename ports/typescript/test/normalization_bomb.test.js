import assert from "node:assert/strict";
import test from "node:test";

import "../src/security.js"; // configures the verified data reader
import { normalizationBombDetect } from "../src/security-core.js";

// Ground truth: the detect_* spot-check theorems in
// Unicode/Security/Form/NormalizationBomb.lean, plus the two ratio-branch
// shapes the module docstring guarantees.

const sub = (cps) => normalizationBombDetect(cps).sub;

test("normalization-bomb detect tags match the Lean vectors", () => {
  assert.equal(sub([]), null);
  assert.equal(sub([0x48, 0x65, 0x6c, 0x6c, 0x6f]), null);
  assert.equal(sub([0xd55c]), null); // NFD ratio exactly 300, not > 300
  assert.equal(sub([0x2460]), null); // circled one, NFKD 1x
  assert.equal(sub([0xfdfa]), "SingleCpBlowup");
  assert.deepEqual(normalizationBombDetect([0xfdfa]).positions, [0]);
  assert.equal(sub([0xfdfb]), "NfkdHighExpansion");
  assert.equal(sub([0x1f82]), "NfdHighExpansion");
});
