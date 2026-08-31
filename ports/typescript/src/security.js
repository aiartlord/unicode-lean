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
  ["DerivedJoiningType.txt", "f39ebe974825d6736aee15582250307aa532b2cfab3caf3f86bd23fddc9c5c4d"],
  ["EastAsianWidth.txt", "ea7ce50f3444a050333448dffef1cadd9325af55cbb764b4a2280faf52170a33"],
  ["UnicodeData.txt", "2e1efc1dcb59c575eedf5ccae60f95229f706ee6d031835247d843c11d96470c"],
  ["CompositionExclusions.txt", "2f239196ef3b5b61db5cc476e9bd80f534d15aa1b74e1be1dea5d042a344c85f"],
  ["DerivedCoreProperties.txt", "24c7fed1195c482faaefd5c1e7eb821c5ee1fb6de07ecdbaa64b56a99da22c08"],
  ["IdentifierStatus.txt", "617228a16da13850bf8af28b6cd08f5e9b6595d2eb60404fe6eee2c85b4e4a35"],
  ["Scripts.txt", "9f5e50d3abaee7d6ce09480f325c706f485ae3240912527e651954d2d6b035bf"],
  ["ScriptExtensions.txt", "ec2107e58825a1586acee8e0911ce18260394ac8b87e535ca325f1ccbeb06bc6"],
  ["PropertyValueAliases.txt", "64e9a5f76f7a1e8b5a47d6a1f9a26522a251208f5276bdfa1559dac7cf2e827a"],
  ["SpecialCasing.txt", "efc25faf19de21b92c1194c111c932e03d2a5eaf18194e33f1156e96de4c9588"],
  ["emoji-data.txt", "2cb2bb9455cda83e8481541ecf5b6dfda66a3bb89efa3fa7c5297eccf607b72b"],
  ["emoji-zwj-sequences.txt", "5b25441daed2322b068c5e70cda522946a4f0274df864445a1965a92e5fc5cad"],
  ["bip39/chinese_simplified.txt", "5c5942792bd8340cb8b27cd592f1015edf56a8c5b26276ee18a482428e7c5726"],
  ["bip39/chinese_traditional.txt", "417b26b3d8500a4ae3d59717d7011952db6fc2fb84b807f3f94ac734e89c1b5f"],
  ["bip39/czech.txt", "7e80e161c3e93d9554c2efb78d4e3cebf8fc727e9c52e03b83b94406bdcc95fc"],
  ["bip39/english.txt", "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"],
  ["bip39/french.txt", "ebc3959ab7801a1df6bac4fa7d970652f1df76b683cd2f4003c941c63d517e59"],
  ["bip39/italian.txt", "d392c49fdb700a24cd1fceb237c1f65dcc128f6b34a8aacb58b59384b5c648c2"],
  ["bip39/japanese.txt", "2eed0aef492291e061633d7ad8117f1a2b03eb80a29d0e4e3117ac2528d05ffd"],
  ["bip39/korean.txt", "9e95f86c167de88f450f0aaf89e87f6624a57f973c67b516e338e8e8b8897f60"],
  ["bip39/portuguese.txt", "2685e9c194c82ae67e10ba59d9ea5345a23dc093e92276fc5361f6667d79cd3f"],
  ["bip39/spanish.txt", "46846a5a0139d1e3cb77293e521c2865f7bcdb82c44e8d0a06a2cd0ecba48c0b"],
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
