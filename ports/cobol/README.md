# unicode-cobol

The COBOL runtime port of the Unicode security reference monitor — all 27
detector families, byte-faithful to the Lean-proven Rust reference, emitting the
same reason codes and verdicts as every other port. It is a standalone GnuCOBOL
program under `ports/cobol/`; this repository is the source of truth. The
detector reference and coverage matrix are in
[`../DETECTOR_COVERAGE.md`](../DETECTOR_COVERAGE.md); the architecture and threat
model are in [`../../docs/explanation/`](../../docs/explanation/). It suits
mainframe and banking batch/transaction integration.

## What it is

Unlike the other ports, this is a **program**, not a linkable library. The
source is a single GnuCOBOL program (`PROGRAM-ID. USEC`, `src/usec.cob`) that a
consumer invokes as a subprocess or a called program. Lookup copybooks are
generated from the vendored UCD data at build time by `tools/generate_tables.py`.

## Invoke it

The program dispatches on a command-line operation name, a profile, a mode, and a
whitespace-separated list of codepoints:

```
usec <op-name> <profile> <mode> <codepoint> [<codepoint> ...]
```

For a full policy scan the op-name is the policy scan; individual detector
op-names run a single family. The program writes the verdict and its reason codes
to standard output in the shared JSON verdict shape, so a batch job or
transaction step reads the action and findings from that output. `mode` is
`observe | warn | enforce | strict`, and each finding carries a stable reason
code `unicode.security.<layer>.<slug>.<SubThreat>` identical across every port.

A mainframe consumer runs this at the text-ingress step: feed the decoded
codepoints, read the verdict, and reject or quarantine on a non-`allow` action
before the text reaches any downstream job. The shared integration contract is in
[`../../docs/how-to/integrate.md`](../../docs/how-to/integrate.md).

The program works in fixed tables: at most 4096 values per scan (codepoints, or
bytes for the byte-stream operations), a 4096-wide confusable skeleton, a
16384-wide normalization scratch, a 1024-wide side list. A scan that does not
fit — one value past the input table, or a working form such as an NFKD
expansion that outgrows its scratch — is refused rather than scanned in part:
the output carries no `FINDING` line, the `ACTION` is the mode's blocking action
(`reject`; `observe` under observe and warn), and the line after `ACTION` reads
`REFUSAL capacity-exceeded`. A consumer that reads only the action fails
closed; one that reads the refusal can split the input or route it to an
unbounded port. This is the port's one documented divergence from the reference;
the contract is in [`../../docs/reference/ports.md`](../../docs/reference/ports.md).

## Build and test

From this directory, with GnuCOBOL available:

```sh
bash scripts/test.sh
```

Or the reproducible build, which compiles the program and runs the fixture suite
as part of the build:

```sh
nix build .#unicode-cobol
```

## Data and contract

Runtime data is vendored under `data/` and pinned by `data/SHA256SUMS`; the
generated lookup copybooks are built from it and never from a Lean root. The
program is checked against the shared fixtures under `fixtures/security/`, so its
verdicts match every other port for the same input. Refresh vendored data only
through `scripts/sync-runtime-data.sh`.
