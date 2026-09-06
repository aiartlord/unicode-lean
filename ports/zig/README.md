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

Downstream Zig consumers should import the `unicode_security` module exposed by
`build.zig`.
