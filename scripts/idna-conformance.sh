#!/usr/bin/env bash
# Run the UTS #46 IDNA conformance summary against the current
# implementation. Compiles a one-line driver that prints a
# `Unicode.Conformance.IdnaTestV2` summary. Invokes lean directly,
# bypassing `lake build` so the cost lands in this script's
# runtime — not in every `lake build` cycle on CI.
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

# Ensure deps are built (cheap; the heavy fold is in `report` only).
lake build Unicode.Conformance.IdnaTestV2 >/dev/null

LEAN_PATH="$(lake env printenv LEAN_PATH 2>/dev/null || true)"
if [ -z "$LEAN_PATH" ]; then
  LEAN_PATH=".lake/build/lib"
fi

LEAN_PATH="$LEAN_PATH" lake env lean --run "$driver"
