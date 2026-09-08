# Python Port

The in-repo Python runtime port of the Unicode security layer. It implements the
shared product contract:

```text
scan(profile, mode, input) -> verdict
```

The package `unicode_python` mirrors the Lean-specified surfaces —
UTF-8/16/32 validation, BOM and noncharacter handling, identifier admissibility,
segmentation, and all 27 security detector families, byte-faithful to the
Lean-proven reference and emitting the same reason codes and verdicts as every
other port. Lean is the specification and assurance source of truth; this port
is a runtime surface that must inhabit the same contract.

Runtime UCD tables are vendored under `src/unicode_python/data/` and kept identical
to the canonical `Unicode/Ucd/` bytes by `scripts/sync-runtime-data.sh`
(`--check`/`--apply`), so the package is a self-contained deployment surface.

Contract tests consume the shared cross-port fixtures under the repository's
`fixtures/security/`; run them from the repository root:

```sh
scripts/test-runtime-ports.sh --python-only
```
