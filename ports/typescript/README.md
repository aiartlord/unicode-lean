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

The current implementation covers the same v0 detector slice as the other
runtime ports: tag-block payloads, variation-selector payloads, zero-width
payloads, bidi-control imbalance, noncharacter/control interchange hazards,
the data-backed `homoglyph-confusable` `TargetMatch` / `MathAlpha` /
`WidthClass` / `DecompositionSwap` slice, and `mixed-script-admissibility`
`CrossScriptMix`.

Tests consume package-local copies of the shared contract fixtures under
`testdata/fixtures/security/`, so `node --test` works from a packaged module
copy as well as from this checkout.

Runtime data is vendored under `src/data/` and pinned by
`src/data/SHA256SUMS`: `CaseFolding.txt`, `confusables.txt`,
`KnownAttackTargets.txt`, `StandardizedVariants.txt`,
`emoji-variation-sequences.txt`, and `DerivedBidiClass.txt` (read for
`Bidi_Class` via the explicit-range → `@missing`-default → `L` lookup that
mirrors Lean).

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
