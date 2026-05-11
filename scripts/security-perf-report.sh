#!/usr/bin/env bash
# Report per-family build wall-clock for the Security Conformance Layer
# harnesses.  Each `Unicode.Conformance.Security.<X>Test` module folds
# its fixture and closes `all_rows_pass` via `native_decide`, so the
# elapsed time is dominated by `native_decide` evaluation cost.
#
# The script does a clean rebuild of each harness in isolation so
# numbers are comparable across runs.  Output is two columns:
#   <wall_seconds>  <module>
# sorted by wall time descending, with a total line at the bottom.

set -euo pipefail

cd "$(dirname "$0")/.."

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

results="$tmpdir/results"
: > "$results"

# Discover every harness module name.
find Unicode/Conformance/Security -maxdepth 1 -name '*Test.lean' \
  | sed -e 's|.*/||' -e 's|\.lean$||' \
  | LC_ALL=C sort > "$tmpdir/harnesses"

while IFS= read -r base; do
  module="Unicode.Conformance.Security.${base}"

  # Remove the cached olean so the build is non-trivial.
  olean="${module//./\/}"
  rm -f ".lake/build/lib/lean/${olean}.olean" \
        ".lake/build/lib/lean/${olean}.ilean" \
        ".lake/build/ir/${olean}.c" 2>/dev/null || true

  start="$(date +%s.%N)"
  lake build "$module" > /dev/null 2>&1
  end="$(date +%s.%N)"

  elapsed="$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.2f", e - s}')"
  printf '%s  %s\n' "$elapsed" "$module" >> "$results"
done < "$tmpdir/harnesses"

# Sort by wall time descending.
LC_ALL=C sort -rn -k 1 "$results"

# Sum.
total="$(awk '{s += $1} END{printf "%.2f", s}' "$results")"
count="$(wc -l < "$results" | tr -d ' ')"
echo "----"
printf '%s  TOTAL (%s harnesses)\n' "$total" "$count"
