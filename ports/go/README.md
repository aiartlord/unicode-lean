# Go Port

This is the in-repo Go runtime port scaffold for the Unicode security layer.
It starts at the shared product contract:

```text
scan(profile, mode, input) -> verdict
```

The current implementation covers only the detector families represented in
the shared v0 fixtures: tag-block payloads, variation-selector payloads,
zero-width payloads, bidi-control imbalance, noncharacter/control interchange
hazards, the data-backed `homoglyph-confusable` `TargetMatch` / `MathAlpha` /
`WidthClass` / `DecompositionSwap` slice, and `mixed-script-admissibility`
`CrossScriptMix`. It is intentionally not a full restriction-level detector
port yet.

Tests consume a vendored copy of the shared policy, verdict, decode, and
detector fixtures under `security/testdata/fixtures/security/`, so `go test`
works from a packaged module copy as well as from this checkout.

Runtime data is vendored under `security/data/` and pinned by
`security/data/SHA256SUMS`: `CaseFolding.txt`, `confusables.txt`,
`KnownAttackTargets.txt`, `StandardizedVariants.txt`,
`emoji-variation-sequences.txt`, and `UnicodeData.txt`.

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
