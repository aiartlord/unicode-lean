# C++ Port

The in-repo C++ runtime port of the Unicode security layer — a header-only interface
library (`unicode_cpp`) for embedded, router, and native integration. It implements
the shared product contract:

```text
scan(profile, mode, input) -> verdict
```

The headers under `include/unicode_cpp/` mirror the Lean-specified surfaces —
UTF-8/16/32 validation, BOM and noncharacter handling, identifier admissibility,
segmentation, and the security detector suite (tag-block, variation-selector, and
zero-width payloads; bidi-control balance; homoglyph-confusable; mixed-script
admissibility). Lean is the specification and assurance source of truth; this port
is a runtime surface that must inhabit the same contract.

Runtime UCD tables are vendored under `data/` and installed to
`${CMAKE_INSTALL_DATADIR}/unicode_cpp/data`, kept identical to the canonical
`Unicode/Ucd/` bytes by `scripts/sync-runtime-data.sh` (`--check`/`--apply`) and
pinned by `data/SHA256SUMS`, so the package is a self-contained deployment surface.
Tests locate the tables via a depth-tolerant candidate search (`data`, `../data`,
`../../data`).

Build and test from the repository root:

```sh
scripts/test-runtime-ports.sh --cpp-only
```
