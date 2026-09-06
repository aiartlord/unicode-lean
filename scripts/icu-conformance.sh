#!/usr/bin/env bash
# The ICU comparison row: build and run `tools/icu-conformance/icu_conformance.cpp`
# over the pinned Unicode test files and record what ICU reproduces.
#
# The record lands in `fixtures/conformance/icu-runs.json` beside the executed
# runs, carrying the SHA-256 of every input the harness read, the ICU version
# and the Unicode version ICU carries, and per suite the rows judged, passed
# and failed. `scripts/conformance-run.py` prints the record next to the Lean
# result only while the input digests still match the pinned files, the same
# rule the executed runs follow, so a record cannot outlive its inputs.
#
# Usage: nix develop .#runtime -c scripts/icu-conformance.sh [--record]
#   without --record the JSON is printed and nothing is written.

set -euo pipefail

cd "$(dirname "$0")/.."

record=0
if [ "${1:-}" = "--record" ]; then
  record=1
fi

out_dir="dist/icu-conformance"
mkdir -p "$out_dir"
binary="$out_dir/icu_conformance"

# The runtime shell carries ICU's headers and libraries on the compiler
# wrapper's search paths; the libraries are named directly rather than through
# pkg-config so the build does not depend on a .pc search path being exported.
g++ -std=c++17 -O2 -Wall -Wextra \
  tools/icu-conformance/icu_conformance.cpp \
  -o "$binary" \
  -licuuc -licui18n -licudata

result="$out_dir/icu-run.json"
"$binary" Unicode/Ucd > "$result"

inputs="BidiTest.txt BidiCharacterTest.txt NormalizationTest.txt GraphemeBreakTest.txt \
WordBreakTest.txt SentenceBreakTest.txt LineBreakTest.txt IdnaTestV2.txt \
CollationTest_NON_IGNORABLE_SHORT.txt CollationTest_SHIFTED_SHORT.txt"

python3 - "$result" "$record" $inputs <<'PY'
import hashlib
import json
import sys
from pathlib import Path

result_path = Path(sys.argv[1])
record = sys.argv[2] == "1"
names = sys.argv[3:]
run = json.loads(result_path.read_text(encoding="utf-8"))
digests = {}
for name in names:
    path = Path("Unicode/Ucd") / name
    digests[name] = hashlib.sha256(path.read_bytes()).hexdigest()
run["inputs_sha256"] = digests
run["harness"] = "tools/icu-conformance/icu_conformance.cpp"
text = json.dumps(run, indent=2) + "\n"
print(text, end="")
if record:
    target = Path("fixtures/conformance/icu-runs.json")
    target.write_text(text, encoding="utf-8")
    print(f"recorded {target}", file=sys.stderr)
PY
