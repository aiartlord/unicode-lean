# Go Port

This is the in-repo Go runtime port of the Unicode security layer.
It implements the shared product contract:

```text
scan(profile, mode, input) -> verdict
```

It implements all 27 detector families, byte-faithful to the Lean-proven Rust
reference, emitting the shared reason codes and verdicts. The detector reference
and coverage matrix are in [`../DETECTOR_COVERAGE.md`](../DETECTOR_COVERAGE.md).
The entry point is `security.Scan` and the byte-level `security.ScanUTF8`,
`security.ScanUTF16BE|LE`, `security.ScanUTF32BE|LE`; see
[`../../docs/how-to/integrate.md`](../../docs/how-to/integrate.md).

Tests consume a vendored copy of the shared policy, verdict, decode, and
detector fixtures under `security/testdata/fixtures/security/`, so `go test`
works from a packaged module copy as well as from this checkout.

Runtime data is vendored under `security/data/` and pinned by
`security/data/SHA256SUMS`: `CaseFolding.txt`, `confusables.txt`,
`KnownAttackTargets.txt`, `StandardizedVariants.txt`,
`emoji-variation-sequences.txt`, and `UnicodeData.txt`.

## Segmentation

The `segmentation` package implements UAX #14 default line breaking —
`segmentation.LineBreaks` returns one boundary flag per position, so a sequence
of n code points yields n + 1 flags, and `segmentation.LineRuns` splits a
sequence at every break opportunity. It is judged against the Unicode
Consortium's published corpus, because a segmentation rule reads context on both
sides of a boundary and a wrong rule survives any vector a person would pick.

The package takes code points and needs no data directory: its property ranges
are generated into source by `tools/generate_line_break_tables.py`, which writes
`segmentation/line_break_tables.go` — the Line_Break, General_Category,
East_Asian_Width and Extended_Pictographic ranges UAX #14 reads — and vendors
the corpus to `segmentation/testdata/LineBreakTest.txt`. Both are generated;
edit the script and regenerate. The security package's own East_Asian_Width
table is not reachable from here: it and its class type are unexported.

UAX #29 grapheme clustering, which the other ports carry, is not in this port.

Run from the repository root:

```sh
scripts/test-runtime-ports.sh --go-only
nix build .#unicode-go
```

Run from this directory:

```sh
go test ./...
```

Verify the vendored security data hashes:

```sh
scripts/check-data-hashes.sh
```

## Install / Consume

The Go port is a module package, not a standalone binary in this slice.
Consumers should depend on the module rooted at `ports/go`, or the
self-contained module tree emitted under `dist/runtime/go/`, and import:

```go
import "unicode.local/ports/go/security"
```

The tracked Nix output installs the same self-contained tree under:

```text
share/unicode-go/
```

Local package check:

```sh
go list ./...
go test ./...
```

Packaged-copy check:

```sh
UNICODE_RUNTIME_DIST=/tmp/unicode-runtime scripts/package-runtime.sh
cd /tmp/unicode-runtime/go
go test ./...
```
