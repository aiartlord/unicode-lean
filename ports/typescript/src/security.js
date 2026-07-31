import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

export * from "./security-core.js";
import { configureSecurityDataReader } from "./security-core.js";

// Pinned SHA-256 digests of the vendored UCD-derived tables, embedded as code
// constants so the code — not a co-located, swappable manifest — is the trust
// anchor. The reader below hashes each table's raw bytes at load and refuses to
// serve (throws) on any mismatch or unpinned table, so a rolled-back, corrupted,
// or tampered data file on a deployed node fails closed instead of silently
// mis-classifying. Keep in sync with the vendored src/data/SHA256SUMS manifest
// and the canonical repository data/SHA256SUMS; the runtime-data build gate
// enforces that sync.
const PINNED_TABLE_DIGESTS = new Map([
  ["CaseFolding.txt", "ff8d8fefbf123574205085d6714c36149eb946d717a0c585c27f0f4ef58c4183"],
  ["confusables.txt", "091c7f82fc39ef208faf8f94d29c244de99254675e09de163160c810d13ef22a"],
  ["KnownAttackTargets.txt", "47acf87f48e23c2e3ddfb5aed877965fbe29142e61f6f85c4ee7db90c0684947"],
  ["StandardizedVariants.txt", "f55100b2fb11d3d75a37b8c1ab752192dbd1c4b12328c5ec6b38e3807c0ca597"],
  ["emoji-variation-sequences.txt", "bb3d09ef03f206012c7532dd52dc0a21c9efddba0135ea4cf0d9201b8b9bba7e"],
  ["DerivedBidiClass.txt", "4867b4b7f0731ed1bfcd34cc6251211ff1542541fce0734b6fbda139ee80b3a4"],
  ["UnicodeData.txt", "2e1efc1dcb59c575eedf5ccae60f95229f706ee6d031835247d843c11d96470c"],
  ["CompositionExclusions.txt", "2f239196ef3b5b61db5cc476e9bd80f534d15aa1b74e1be1dea5d042a344c85f"],
]);

function readVerifiedTable(name) {
  const expected = PINNED_TABLE_DIGESTS.get(name);
  if (expected === undefined) {
    throw new Error(
      `unicode-security: refusing to load unpinned data table "${name}" (fail closed)`,
    );
  }
  const bytes = readFileSync(new URL(`./data/${name}`, import.meta.url));
  const actual = createHash("sha256").update(bytes).digest("hex");
  if (actual !== expected) {
    throw new Error(
      `unicode-security: data table "${name}" failed integrity check ` +
        `(expected ${expected}, got ${actual}); refusing to load (fail closed)`,
    );
  }
  return bytes.toString("utf8");
}

configureSecurityDataReader(readVerifiedTable);
