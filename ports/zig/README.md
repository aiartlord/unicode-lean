# Zig Port

This is the in-repo Zig runtime port scaffold for the Unicode security layer.
It starts at the shared product contract:

```text
scan(profile, mode, input) -> verdict
```

The current implementation covers only the detector families represented in
the shared v0 fixtures: tag-block payloads, variation-selector payloads,
zero-width payloads, bidi-control imbalance, noncharacter/control interchange
hazards, the `homoglyph-confusable` `TargetMatch` / `MathAlpha` /
`WidthClass` / `DecompositionSwap` contract slice, and
`mixed-script-admissibility` `CrossScriptMix`. The port vendors the UTS #39
data inputs under `src/data/`; `src/confusables_data.zig` is generated from
`src/data/confusables.txt` for fast allocation-free lookup, and
`src/normalization_data.zig` is generated from `src/data/UnicodeData.txt` for
the NFD bracket used by the homoglyph skeleton.
It is intentionally not a full restriction-level detector port yet.

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
