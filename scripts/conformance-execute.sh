#!/usr/bin/env bash
# Fold the collation corpora through the implementation and record the result.
#
# `fixtures/conformance/executed-runs.json` names this script as the way its
# rows are produced. Every other suite in that file also closes a `#eval` gate
# over its whole corpus during the `UnicodeFullConformance` build, so its record
# is a convenience beside a check the build already makes. Collation is the one
# suite whose run is too slow to sit in a build — an NFD pass and a DUCET walk
# per pair over 437,928 pairs — so for collation this recorded run, digest-gated
# by `scripts/conformance-run.py`, is the evidence itself.
#
# Usage:  scripts/conformance-execute.sh

set -euo pipefail

cd "$(dirname "$0")/.."

driver="dist/conformance-execute.lean"
progress="dist/conformance-execute-progress.log"
chunk="${CHUNK:-5000}"
mkdir -p dist

cat > "$driver" <<LEAN
import Unicode.Conformance.CollationTestRun

def main : IO Unit :=
  Unicode.Conformance.CollationTestRun.executeReporting $chunk
LEAN

echo "building the collation run's dependencies"
LEAN_NUM_THREADS=1 nice -n 19 lake build Unicode.Conformance.CollationTestRun

# Interpreted, deliberately. Compiling this to a `lean_exe` was tried and
# abandoned: statically linking the generated-table closure this fold reaches
# needs more than 12 GB in `ld`, which is not a cost a conformance script may
# impose on the machine it runs on. The interpreter is slower and bounded.
#
# One core, at the lowest priority the scheduler offers. This machine is shared
# with other work, and a fold that runs for hours has no claim on it beyond
# what is otherwise idle.
echo "folding both collation corpora; progress lands in $progress"
set +e
nice -n 19 lake env lean --run "$driver" 2>&1 | tee "$progress"
lean_status="${PIPESTATUS[0]}"
set -e
if [ "$lean_status" -ne 0 ]; then
  echo "FATAL: the fold exited $lean_status; see $progress"
  exit "$lean_status"
fi

# The record lines are the only ones shaped `<suite> <n> <n> <n>`; every
# progress line above them is indented and carries a slash.
output="$(grep -E '^CollationTest_[A-Z_]+ [0-9]+ [0-9]+ [0-9]+$' "$progress")"
if [ -z "$output" ]; then
  echo "FATAL: the fold produced no record line; see $progress"
  exit 1
fi

echo "$output"

python3 - "$output" <<'PY'
import hashlib
import json
import pathlib
import sys

# This block arrives on stdin, so `__file__` is not a path into the tree; the
# script has already changed into the repository root, and that is ROOT.
ROOT = pathlib.Path.cwd()
UCD = ROOT / "Unicode" / "Ucd"
RUNS = ROOT / "fixtures" / "conformance" / "executed-runs.json"


def sha256_of(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


payload = json.loads(RUNS.read_text(encoding="utf-8"))
runs = [run for run in payload["runs"] if not str(run["suite"]).startswith("CollationTest")]

for line in sys.argv[1].splitlines():
    fields = line.split()
    if len(fields) != 4:
        continue
    suite, judged, passed, failed = fields[0], int(fields[1]), int(fields[2]), int(fields[3])
    corpus = UCD / f"{suite}.txt"
    if not corpus.is_file():
        raise SystemExit(f"FATAL: {corpus} is not on disk")
    if failed != 0:
        raise SystemExit(f"FATAL: {suite} reported {failed} out-of-order pair(s)")
    if passed != judged:
        raise SystemExit(
            f"FATAL: {suite} judged {judged} pair(s) but only {passed} are accounted for"
        )
    runs.append(
        {
            "suite": suite,
            "input_sha256": sha256_of(corpus),
            "rows_judged": judged,
            "passed": passed,
            "failed": failed,
            "columns": ["collation order"],
            "note": (
                "Adjacent pairs, not rows: a corpus of n lines publishes n-1 order "
                "assertions, each that the line's sort key does not exceed the next "
                "line's."
            ),
        }
    )

payload["runs"] = runs
RUNS.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
print(f"recorded {RUNS.relative_to(ROOT)}")
PY
