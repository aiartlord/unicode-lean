# Haskell Port

This is the in-repo Haskell runtime port for the Unicode security layer.
It is a standalone Cabal package under `ports/haskell/`, but it is not a
separate project or sibling repository.

The package name is `unicode-haskell`. It exists so Haskell consumers can
depend on the runtime port without importing Lean build artifacts, while this
repository remains the source of truth for shared fixtures, policy contracts,
tooling, CI, and release evidence.

## Scope

Current shipped surface:

- strict UTF-8 validation, decoding, encoding, and roundtrip tests
- UTF-16 BE/LE and UTF-32 BE/LE codecs
- BOM detection
- noncharacter detection and enumeration
- strict-ASCII identifier predicate
- `ValidatedUtf8`, `Utf8Blob`, and `IdentifierUtf8` refinement types
- UCD-backed normalization lookup tables used by the current tests

Current security-policy surface:

- `Unicode.Security.Policy.scan`
- shared policy fixture support
- shared verdict JSON contract fixture support
- shared v0 detector fixture support for tag-block payloads,
  variation-selector payloads, zero-width payloads, bidi-control imbalance,
  noncharacter/control interchange hazards, and the data-backed
  `homoglyph-confusable` `TargetMatch` / `MathAlpha` / `WidthClass` /
  `DecompositionSwap` slice, plus `mixed-script-admissibility`
  `CrossScriptMix`

Next parity work:

- UAX #31 identifier table parity
- RFC 8264 / 8265 PRECIS parity
- `RestrictionLow` parity only if the product changes homoglyph priority order
  or ports full restriction-level semantics; the current Rust/Python
  reference-only audit is not part of the shared runtime fixture
- security detector families aligned with Rust, Python, and C++

## Build

From the repository root:

```sh
scripts/test-runtime-ports.sh --haskell-only
```

From this directory:

```sh
cabal build all --offline
cabal test all --offline
```

Build a source distribution or install the library into the local Cabal store:

```sh
cabal sdist --offline
cabal install --offline --lib unicode-haskell
```

The root dev shell provides GHC, Cabal, and the current test dependencies.
The Haskell tier is part of `scripts/test-runtime-ports.sh` by default.

## Contract

The port must use this repository's shared fixtures and policy contract. New
runtime behavior should be added to `fixtures/` first, then implemented across
Rust, Python, C++, and Haskell against the same expected verdicts.
