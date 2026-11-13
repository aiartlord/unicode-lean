# Swift Port

This is the Swift Package Manager surface for the shared Unicode security
runtime contract. It is dependency-free and vendors the security data needed by
the `homoglyph-confusable` detector under package resources. It implements all
27 detector families, byte-faithful to the Lean-proven Rust reference and
emitting the same reason codes and verdicts as every other port; the detector
reference and coverage matrix are in
[`../DETECTOR_COVERAGE.md`](../DETECTOR_COVERAGE.md).

Run the contract tests:

```bash
scripts/test.sh
```

From the repository root:

```bash
scripts/test-runtime-ports.sh --swift-only
```

The public API mirrors the shared contract:

```swift
let verdict = scan(profile: Profile.gatewayHeader, mode: Mode.enforce, input: [72, 101])
let json = verdictJson(verdict)
```

Raw-byte entry points are available for UTF-8, UTF-16BE/LE, and UTF-32BE/LE.

Runtime data is vendored under
`Sources/UnicodeSecurity/Resources/Data/`: `CaseFolding.txt`,
`confusables.txt`, `KnownAttackTargets.txt`, `StandardizedVariants.txt`,
`emoji-variation-sequences.txt`, and `DerivedBidiClass.txt` (read for
`Bidi_Class` via the explicit-range → `@missing`-default → `L` lookup that
mirrors Lean).

## Segmentation

Two algorithms under `Sources/UnicodeSecurity/Segmentation/`.
`LineBreak.swift` implements UAX #14 default line breaking — `lineBreaks`
returns one boundary flag per position, so a sequence of n code points yields
n + 1 flags, and `lineRuns` splits a sequence at every break opportunity.
`Grapheme.swift` implements UAX #29 default extended grapheme clustering —
`graphemeBreaks` returns the same one-flag-per-boundary shape, and
`graphemeClusters` splits a sequence into the clusters a renderer treats as
single user-perceived characters. All four take and return code points as
`UInt32`.

Both are judged against the Unicode Consortium's published corpora, because a
segmentation rule reads context on both sides of a boundary and a wrong rule
survives any vector a person would pick. The corpora are bundled as test
resources and read from the test bundle at run time.

Their property ranges are generated into source, so neither algorithm needs a
data directory and no new file enters the digest-pinned resource set — edit the
script and regenerate.

- `tools/generate_line_break_tables.py` writes
  `Sources/UnicodeSecurity/Segmentation/LineBreakTables.swift` — the
  Line_Break, General_Category and Extended_Pictographic ranges — and vendors
  `ContractTests/Resources/testdata/LineBreakTest.txt`. East_Asian_Width is not
  emitted: the security layer already parses it from its digest-pinned
  `EastAsianWidth.txt`, and a Swift module is one namespace, so LB19a, LB25 and
  LB30 call that `eastAsianWidth` directly.
- `tools/generate_grapheme_tables.py` writes
  `Sources/UnicodeSecurity/Segmentation/GraphemeTables.swift` — the
  Grapheme_Cluster_Break and Indic_Conjunct_Break ranges — and vendors
  `ContractTests/Resources/testdata/GraphemeBreakTest.txt`.
  Extended_Pictographic is not emitted either: GB11 reads the table LB30b
  already has.

Both read their tables through the one lookup in
`Sources/UnicodeSecurity/Segmentation/RangeTable.swift`.
