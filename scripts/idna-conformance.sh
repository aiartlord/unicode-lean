#!/usr/bin/env bash
# Print a UTS #46 IDNA conformance summary for a chosen number of rows.
#
# Whether the implementation passes the published file is settled by the
# `#eval` gate in `Unicode.Conformance.IdnaTestV2`, which folds all 6391 rows
# across `toUnicode`, `toAsciiN` and `toAsciiT` and fails the build on a single
# disagreeing row. This script answers a different question: what the tallies
# look like part-way through, and which row index fails first. That is what a
# bounded run is for while changing the implementation, and it is why the
# summary carries a `skipped` column the gate has no use for.
#
# Usage: idna-conformance.sh [ROWS|all]
#
# The fold is evaluated by the interpreter, not compiled, and its cost
# tracks label length: `toAscii` on a hundred-codepoint label runs a few
# hundred milliseconds, so the published file's 6391 rows are tens of
# minutes while the first few hundred are immediate. ROWS bounds the run
# to the first N rows in file order and defaults to a few hundred so an
# ordinary invocation finishes; `all` folds the whole file. Either way the
# summary states how many rows it judged, so a bounded run is never
# mistaken for a complete one.

set -euo pipefail

cd "$(dirname "$0")/.."

rows="${1:-250}"
if [ "$rows" = "all" ]; then
  expression="Unicode.Conformance.IdnaTestV2.report"
elif printf '%s' "$rows" | grep -qE '^[0-9]+$'; then
  expression="Unicode.Conformance.IdnaTestV2.reportFirst $rows"
else
  echo "usage: $0 [ROWS|all]" >&2
  exit 2
fi

driver="$(mktemp --suffix=.lean)"
trap 'rm -f "$driver"' EXIT

cat >"$driver" <<LEAN
import Unicode.Conformance.IdnaTestV2
def main : IO Unit :=
  IO.println ($expression)
LEAN

# Build the module the driver imports. This is not cheap: elaborating it runs
# the module's own full-corpus gate, which is minutes. A cached build costs
# nothing, so the price is paid once after an edit rather than per invocation.
lake build Unicode.Conformance.IdnaTestV2 >/dev/null

LEAN_PATH="$(lake env printenv LEAN_PATH 2>/dev/null || true)"
if [ -z "$LEAN_PATH" ]; then
  LEAN_PATH=".lake/build/lib"
fi

LEAN_PATH="$LEAN_PATH" lake env lean --run "$driver"
