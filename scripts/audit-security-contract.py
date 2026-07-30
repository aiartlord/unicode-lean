#!/usr/bin/env python3
"""Audit the shared detector contract against Lean ground truth.

The cross-port contract under fixtures/security/detectors/ asserts, per family, the
reason codes each input MUST produce. For "backed by Lean" to be a fact rather than a
claim, every such assertion must be reproduced by the product's own
`Unicode.Security.Policy.scan`. This gate extracts every live contract case, emits a
Lean validator that recomputes the family-filtered findings via scan, and reports any
assertion Lean does not produce.

Usage:  scripts/audit-security-contract.py
Requires a Lean toolchain (lake). Source-only; does not build proof/conformance roots.
"""

import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
DETECTORS = ROOT / "fixtures" / "security" / "detectors"
OUT = ROOT / "dist" / "audit-security-contract.lean"


def lean_nat_list(xs):
    return "[" + ", ".join(str(x) for x in xs) + "]"


def lean_str_list(xs):
    return "[" + ", ".join('"' + s + '"' for s in xs) + "]"


def collect_cases():
    rows = []
    for path in sorted(DETECTORS.glob("*.json")):
        doc = json.load(path.open())
        slug = doc["family"]
        for case in doc["cases"]:
            required = [r for r in case.get("required_findings", []) if f".{slug}." in r]
            rows.append((slug, case["name"], case["input"], required))
    return rows


def emit_validator(rows):
    lines = [
        "import Unicode.Security.Policy",
        "open Unicode.Security.Policy",
        "private def containsInfix (s sub : String) : Bool := (s.splitOn sub).length > 1",
        "def famFindings (slug : String) (input : List Nat) : List String :=",
        "  (((scan Profile.chatMessage Mode.observe input).findings.map (·.code)).filter",
        '    (fun code => containsInfix code ("." ++ slug ++ "."))).eraseDups',
        "def cases : List (String × String × List Nat × List String) := [",
        ",\n".join(
            f'  ("{s}", "{n}", {lean_nat_list(i)}, {lean_str_list(r)})' for s, n, i, r in rows
        ),
        "]",
        "def main : IO Unit := do",
        "  let mut fails := 0",
        "  for (slug, name, input, required) in cases do",
        "    let actual := famFindings slug input",
        "    for r in required do",
        "      unless actual.contains r do",
        '        IO.println s!"DRIFT {slug}/{name}: contract requires {r}, Lean scan produces {actual}"',
        "        fails := fails + 1",
        "  if fails == 0 then",
        '    IO.println s!"clean: all {cases.length} live contract assertions are reproduced by Lean scan"',
        "  else",
        '    IO.println s!"FAIL: {fails} contract assertions are not backed by Lean"',
        "#eval main",
    ]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines))


def main():
    rows = collect_cases()
    emit_validator(rows)
    result = subprocess.run(
        ["lake", "env", "lean", str(OUT)],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    output = result.stdout + result.stderr
    sys.stdout.write(output)
    # Non-zero exit if Lean reported drift or the run itself failed.
    if result.returncode != 0 or "FAIL:" in output:
        sys.exit(1)


if __name__ == "__main__":
    main()
