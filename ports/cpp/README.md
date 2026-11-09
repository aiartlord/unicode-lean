# C++ Port

The in-repo C++ runtime port of the Unicode security layer — a header-only interface
library (`unicode_cpp`) for embedded, router, and native integration. It implements
the shared product contract:

```text
scan(profile, mode, input) -> verdict
```

The headers under `include/unicode_cpp/` mirror the Lean-specified surfaces —
UTF-8/16/32 validation, BOM and noncharacter handling, identifier admissibility,
segmentation, and all 27 security detector families, byte-faithful to the
Lean-proven reference and emitting the same reason codes and verdicts as every
other port. Lean is the specification and assurance source of truth; this port
is a runtime surface that must inhabit the same contract.

Runtime UCD tables are vendored under `data/` and installed to
`${CMAKE_INSTALL_DATADIR}/unicode_cpp/data`, kept identical to the canonical
`Unicode/Ucd/` bytes by `scripts/sync-runtime-data.sh` (`--check`/`--apply`) and
pinned by `data/SHA256SUMS`, so the package is a self-contained deployment surface.
Tests locate the tables via a depth-tolerant candidate search (`data`, `../data`,
`../../data`).

The segmentation headers take the other route: their property ranges are
compiled in, so a segmentation header takes code points and needs no data
directory, while the security layer loads its own tables through
`ucd::Tables::load_from_dir`. `segmentation/grapheme_tables.hpp` carries the
UAX #29 properties, and `tools/generate_line_break_tables.py` writes
`general_category_tables.hpp`, `east_asian_width_tables.hpp`,
`segmentation/line_break_tables.hpp` and the published corpus under
`test/line_break_corpus.hpp` from the canonical UCD files. Those four are
generated; edit the script and regenerate. The corpus is three flat `constexpr`
arrays and a table of offsets rather than a container per row, because per-row
containers are dynamic initialisation and cost minutes of compile time at this
row count.

Segmentation covers UAX #29 extended grapheme clusters and UAX #14 default line
breaking. Each is judged against the Unicode Consortium's published corpus for
that algorithm, because a segmentation rule reads context on both sides of a
boundary and a wrong rule survives any vector a person would pick.

Build and test from the repository root:

```sh
scripts/test-runtime-ports.sh --cpp-only
```
