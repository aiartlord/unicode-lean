#!/usr/bin/env bash
# Run the UTS #46 IDNA conformance summary against the current
# implementation. Compiles a one-line driver that prints
# `Unicode.Conformance.IdnaTestV2.report`. Invokes lean directly,
# bypassing `lake build` so the cost lands in this script's
# runtime — not in every `lake build` cycle on CI.

set -euo pipefail

cd "$(dirname "$0")/.."

driver="$(mktemp --suffix=.lean)"
trap 'rm -f "$driver"' EXIT

cat >"$driver" <<'LEAN'
import Unicode.Conformance.IdnaTestV2
def main : IO Unit :=
  IO.println Unicode.Conformance.IdnaTestV2.report
LEAN

# Ensure deps are built (cheap; the heavy fold is in `report` only).
lake build Unicode.Conformance.IdnaTestV2 >/dev/null

LEAN_PATH="$(lake env printenv LEAN_PATH 2>/dev/null || true)"
if [ -z "$LEAN_PATH" ]; then
  LEAN_PATH=".lake/build/lib"
fi

LEAN_PATH="$LEAN_PATH" lake env lean --run "$driver"
