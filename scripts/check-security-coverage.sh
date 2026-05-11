#!/usr/bin/env bash
# Fail if any Security Conformance Layer detector module is missing a
# matching `*Test.lean` harness under `Unicode/Conformance/Security/`,
# or if any present harness lacks an `all_rows_pass` theorem.
#
# Every detector module under
#   Unicode/Security/{Covert,Identity,Display,Form,Boundary}/X.lean
# must have a paired
#   Unicode/Conformance/Security/XTest.lean
# whose body closes `theorem all_rows_pass : rows.all verifyRow = true`
# via `native_decide`.  This guard prevents shipping a detector with no
# fixture-driven verification.
#
# Portable to bash 3.x — no associative arrays, plain temp files.

set -euo pipefail

cd "$(dirname "$0")/.."

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

detectors="$tmpdir/detectors"
harnesses="$tmpdir/harnesses"
missing_harness="$tmpdir/missing_harness"
missing_theorem="$tmpdir/missing_theorem"

# List of every detector base name (e.g. `NormalizationBomb`).
find Unicode/Security/Covert Unicode/Security/Identity \
     Unicode/Security/Display Unicode/Security/Form \
     Unicode/Security/Boundary \
  -maxdepth 1 -name '*.lean' -type f 2>/dev/null \
  | sed -e 's|.*/||' -e 's|\.lean$||' \
  | LC_ALL=C sort -u > "$detectors"

# List of every harness base name (strip the trailing `Test`).
find Unicode/Conformance/Security \
  -maxdepth 1 -name '*Test.lean' -type f \
  | sed -e 's|.*/||' -e 's|Test\.lean$||' \
  | LC_ALL=C sort -u > "$harnesses"

# Detectors without a matching harness.
LC_ALL=C comm -23 "$detectors" "$harnesses" > "$missing_harness"

# Harnesses present but missing `all_rows_pass`.
: > "$missing_theorem"
while IFS= read -r base; do
  [ -n "$base" ] || continue
  path="Unicode/Conformance/Security/${base}Test.lean"
  [ -f "$path" ] || continue
  if ! grep -qE '^theorem all_rows_pass' "$path"; then
    echo "$base" >> "$missing_theorem"
  fi
done < "$harnesses"

rc=0

if [ -s "$missing_harness" ]; then
  echo "FATAL: detector modules with no matching *Test.lean harness:"
  sed 's/^/  /' "$missing_harness"
  rc=1
fi

if [ -s "$missing_theorem" ]; then
  echo "FATAL: harnesses without an \`all_rows_pass\` theorem:"
  sed 's/^/  /' "$missing_theorem"
  rc=1
fi

if [ "$rc" -eq 0 ]; then
  detector_count="$(wc -l < "$detectors" | tr -d ' ')"
  echo "clean: $detector_count detector modules each have a paired harness"
  echo "       with \`all_rows_pass\` under Unicode/Conformance/Security/"
fi

exit "$rc"
