import assert from "node:assert/strict";
import test from "node:test";

import "../src/security.js"; // configures the verified data reader
import { nfcIdempotenceWitnessDetect } from "../src/security-core.js";

// Ground truth: the detect_* theorems in
// Unicode/Security/Form/NfcIdempotenceWitness.lean.

const sub = (cps) => nfcIdempotenceWitnessDetect(cps).sub;

test("nfc-idempotence-witness detect tags match the Lean vectors", () => {
  assert.equal(sub([]), null);
  assert.equal(sub([0x48, 0x65, 0x6c, 0x6c, 0x6f]), null);
  assert.equal(sub([0x00e9]), null); // precomposed e-acute, already NFC/NFKC
  assert.equal(sub([0x0065, 0x0301]), "NonNfcForm"); // decomposed e-acute
  assert.deepEqual(nfcIdempotenceWitnessDetect([0x0065, 0x0301]).positions, [0]);
  assert.equal(sub([0xfb01]), "NonNfkcCompatForm"); // fi ligature
});
