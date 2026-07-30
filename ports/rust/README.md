# Rust Port

The in-repo Rust runtime port of the Unicode security layer — the production
systems/runtime crate and the `unicode-security` CLI. It implements the shared
product contract:

```text
scan(profile, mode, input) -> verdict
```

The crate mirrors the Lean-specified surfaces — UTF-8/16/32 validation, BOM and
noncharacter handling, identifier admissibility, segmentation, and the security
detector suite (tag-block, variation-selector, and zero-width payloads;
bidi-control balance; homoglyph-confusable; mixed-script admissibility). Lean is
the specification and assurance source of truth; this port is a runtime surface
that must inhabit the same contract.

Runtime UCD tables are vendored under `data/` and `include_str!`d at compile time,
kept identical to the canonical `Unicode/Ucd/` bytes by
`scripts/sync-runtime-data.sh` (`--check`/`--apply`) and pinned by `data/SHA256SUMS`,
so the crate is a self-contained deployment surface.

The CLI golden fixtures live under `testdata/fixtures/security/cli/`; the shared
cross-port contract fixtures are the repository's `fixtures/security/`. Run from the
repository root:

```sh
scripts/test-runtime-ports.sh --rust-only
```
