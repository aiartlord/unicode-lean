# TypeScript / WASM Port

This is the dependency-free JavaScript package surface for the shared Unicode
security runtime contract. It is designed for TypeScript consumers, Node-based
gateways, edge workers, and the eventual WASM packaging path.

The package exports the shared product APIs:

```ts
scan(profile, mode, input)
scanUtf8(profile, mode, bytes)
scanUtf16BE(profile, mode, bytes)
scanUtf16LE(profile, mode, bytes)
scanUtf32BE(profile, mode, bytes)
scanUtf32LE(profile, mode, bytes)
verdictJson(verdict)
```

It implements all 27 detector families, byte-faithful to the Lean-proven Rust
reference, emitting the shared reason codes and verdicts. The detector reference
and coverage matrix are in [`../DETECTOR_COVERAGE.md`](../DETECTOR_COVERAGE.md).

Tests consume package-local copies of the shared contract fixtures under
`testdata/fixtures/security/`, so `node --test` works from a packaged module
copy as well as from this checkout.

Runtime data is vendored under `src/data/` and pinned by
`src/data/SHA256SUMS`: `CaseFolding.txt`, `confusables.txt`,
`KnownAttackTargets.txt`, `StandardizedVariants.txt`,
`emoji-variation-sequences.txt`, and `DerivedBidiClass.txt` (read for
`Bidi_Class` via the explicit-range → `@missing`-default → `L` lookup that
mirrors Lean).

## Segmentation

The `./segmentation/line-break` export implements UAX #14 default line breaking:

```js
import { lineBreaks, lineRuns } from "@unicode-security/runtime/segmentation/line-break";

lineBreaks([0x61, 0x20, 0x62]); // one flag per boundary: n codepoints -> n + 1
lineRuns([0x61, 0x20, 0x62]);   // the runs a renderer may place on separate lines
```

It is judged against the Unicode Consortium's published corpus, because a
segmentation rule reads context on both sides of a boundary and a wrong rule
survives any vector a person would pick.

The module is dependency-free and reads no files. Its four property tables —
Line_Break, General_Category, East_Asian_Width and Extended_Pictographic — are
generated into `src/segmentation/line-break-tables.js` by
`tools/generate_line_break_tables.py`, which also vendors the corpus to
`testdata/LineBreakTest.txt`. Both are generated; edit the script and
regenerate. The tables are code rather than entries under `src/data/` because
the package serves its data tables only through the digest-verifying reader
`security.js` installs: a segmentation module opening a data file itself would
be a second data path outside that gate. Being dependency-free is also what
lets this module run unchanged on the edge build.

UAX #29 grapheme clustering, which some other ports carry, is not in this port.

Run from the repository root:

```sh
scripts/test-runtime-ports.sh --typescript-only
```

Run from this directory:

```sh
npm test
node --test test/*.test.js
```

Verify vendored security data hashes:

```sh
scripts/check-data-hashes.sh
```

## Install / Consume

The TypeScript port is a package tree, not a standalone binary in this slice.
Consumers can use the module rooted at `ports/typescript`, or the
self-contained tree emitted under `dist/runtime/typescript/`:

```js
import { scanUtf8, verdictJson } from "@unicode-security/runtime";

const verdict = scanUtf8("gateway-header", "enforce", [72, 101, 108, 108, 111]);
console.log(verdictJson(verdict));
```

The `./wasm` export currently provides the same contract through an async
adapter so downstream code can depend on the WASM-facing shape before the
compiled core lands.

Browser and edge-worker consumers should import the Node-free `./edge` export
and call `instantiateSecurity` with injected data or a fetchable package data
URL:

```js
import { instantiateSecurity } from "@unicode-security/runtime/edge";

const security = await instantiateSecurity({
  data: {
    confusables,
    caseFolding,
    knownAttackTargets,
    standardizedVariants,
    emojiVariationSequences,
  },
});

const verdict = security.scanUtf8("gateway-header", "enforce", [72, 101]);
```

The `./edge` and `./wasm` exports do not import Node filesystem APIs.
