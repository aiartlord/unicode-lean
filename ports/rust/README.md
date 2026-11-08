# Rust Port

The in-repo Rust runtime port of the Unicode security layer — the production
systems/runtime crate and the `unicode-security` CLI. It implements the shared
product contract:

```text
scan(profile, mode, input) -> verdict
```

The crate mirrors the Lean-specified surfaces — UTF-8/16/32 validation, BOM and
noncharacter handling, identifier admissibility, segmentation, and all 27
security detector families, byte-faithful to the Lean-proven reference and
emitting the same reason codes and verdicts as every other port. Lean is the
specification and assurance source of truth; this port is a runtime surface
that must inhabit the same contract.

Runtime UCD tables are vendored under `data/` and `include_str!`d at compile time,
kept identical to the canonical `Unicode/Ucd/` bytes by
`scripts/sync-runtime-data.sh` (`--check`/`--apply`) and pinned by `data/SHA256SUMS`,
so the crate is a self-contained deployment surface.

The property tables the segmentation algorithms read are the other route:
ranges compiled into Rust source rather than parsed at load.
`src/segmentation/grapheme_tables.rs` carries the UAX #29 properties, and
`tools/generate_line_break_tables.py` writes `src/general_category.rs`,
`src/east_asian_width.rs`, `src/segmentation/line_break_tables.rs` and the
published corpus under `tests/corpus/` from the canonical `Unicode/Ucd/` files.
Those four are generated; edit the script and regenerate. `general_category.rs`
and `east_asian_width.rs` sit above both the security and segmentation layers so
each reads one table, which is where the Lean keeps its generated properties.

Segmentation covers UAX #29 extended grapheme clusters and UAX #14 default line
breaking. Each is judged against the Unicode Consortium's published corpus for
that algorithm, because a segmentation rule reads context on both sides of a
boundary and a wrong rule survives any vector a person would pick.

The CLI golden fixtures live under `testdata/fixtures/security/cli/`; the shared
cross-port contract fixtures are the repository's `fixtures/security/`. Run from the
repository root:

```sh
scripts/test-runtime-ports.sh --rust-only
```
