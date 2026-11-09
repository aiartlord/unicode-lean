# Zig Port

This is the in-repo Zig runtime port of the Unicode security layer.
It implements the shared product contract:

```text
scan(profile, mode, input) -> verdict
```

It implements all 27 detector families, byte-faithful to the Lean-proven Rust
reference, emitting the shared reason codes and verdicts; see
[`../DETECTOR_COVERAGE.md`](../DETECTOR_COVERAGE.md). The port vendors the UTS #39
data inputs under `src/data/`; `src/confusables_data.zig` is generated from
`src/data/confusables.txt` for fast allocation-free lookup, and
`src/case_folding_data.zig` is generated from `src/data/CaseFolding.txt` for
full default case-folding lookup. `src/normalization_data.zig` is generated from
`src/data/UnicodeData.txt` for the NFD bracket used by the homoglyph skeleton.

The port scans without an allocator, so every working buffer is fixed. A scan
accepts at most `MaxInputLen` (1024) codepoints, and a form it cannot build
within its buffers — an NFD/NFKD/NFC/NFKC expansion, a case mapping, a
confusable skeleton, or a decoded text longer than the caller's buffer — is
neither truncated nor read as clear. `scan` answers a refused verdict: no
findings, the mode's blocking action (`reject`; `observe` under observe and
warn), and `refusal = .capacity_exceeded`, which `writeVerdictJson` serialises
as `"refusal":"capacity-exceeded"`. The detector modules return
`error.CapacityExceeded` from a direct call in the same cases. This is the
port's one documented divergence from the unbounded reference; the contract is
in [`../../docs/reference/ports.md`](../../docs/reference/ports.md).

Tests consume port-local copies of the shared policy, verdict, and detector
fixtures under `testdata/fixtures/security/`.

## Segmentation

Two algorithms, each its own module, so a consumer that wants segmentation and
not the security monitor links only what it uses. `src/line_break.zig`
implements UAX #14 default line breaking — `lineBreaks` returns one boundary
flag per position, so a sequence of n code points yields n + 1 flags, and
`lineRuns` splits a sequence at every break opportunity. `src/grapheme.zig`
implements UAX #29 default extended grapheme clustering — `graphemeBreaks`
returns the same one-flag-per-boundary shape, and `graphemeClusters` splits a
sequence into the clusters a renderer treats as single user-perceived
characters. Both take an allocator and the caller owns what they return.

Both are judged against the Unicode Consortium's published corpora, because a
segmentation rule reads context on both sides of a boundary and a wrong rule
survives any vector a person would pick. The corpora are read from disk at run
time through a path the build bakes in, since baking a megabyte-plus corpus in
as a string literal would make the compiler materialise it whole.

Both modules take code points and need no data directory. Their property ranges
are generated into source, and both the tables and the corpora they vendor are
generated — edit the script and regenerate.

- `tools/generate_line_break_tables.py` writes `src/line_break_data.zig` — the
  Line_Break, General_Category and Extended_Pictographic ranges — and vendors
  `testdata/LineBreakTest.txt`. East_Asian_Width is not emitted:
  `src/east_asian_width_data.zig` already carries it.
- `tools/generate_grapheme_tables.py` writes `src/grapheme_data.zig` — the
  Grapheme_Cluster_Break and Indic_Conjunct_Break ranges — and vendors
  `testdata/GraphemeBreakTest.txt`. Extended_Pictographic is not emitted
  either: GB11 reads the table LB30b already has.

Both read their tables through the one lookup in `src/range_lookup.zig`.

Run from the repository root:

```sh
scripts/test-runtime-ports.sh --zig-only
```

Run from this directory:

```sh
zig build test
```

Regenerate the vendored confusables and normalization tables from the repository root:

```sh
nix develop -c python ports/zig/tools/generate_confusables_data.py
```

Verify the vendored security data hashes and generated table reproducibility:

```sh
scripts/check-data-hashes.sh
scripts/check-generated-confusables.sh
```

## Install / Consume

Install the Zig library artifact into a local prefix:

```sh
zig build install --prefix ../../dist/runtime/zig
```

Downstream Zig consumers import the modules `build.zig` exposes:
`unicode_security` for the scan contract, `unicode_line_break` for UAX #14, and
`unicode_grapheme` for UAX #29.
