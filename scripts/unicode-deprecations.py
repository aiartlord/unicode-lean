#!/usr/bin/env python3
"""Recompile every tracked Lean module and report the deprecation warnings.

The staged cache runner builds with `lean --json` and records only the pass/
fail status, so deprecation warnings never reach its logs, and the package sets
no `-Werror`, so a deprecated call still produces an `ok` olean. This tool is
the authoritative deprecation finder: it re-elaborates each module through the
pinned toolchain (`lake env lean <file>`, writing the olean to /dev/null so the
built cache is untouched) and prints every diagnostic line mentioning
"deprecated", flushed as it is found, followed by a per-module summary.

It reads and compiles only; it modifies no source. Run it from the repo root;
it is slow (a full re-elaboration) but surfaces the first hits within minutes.

Usage:
  scripts/unicode-deprecations.py [--under PREFIX]
"""

from __future__ import annotations

import argparse
import subprocess
import sys


def tracked_lean(prefix: str) -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", prefix],
        stdout=subprocess.PIPE,
        text=True,
        check=True,
    ).stdout.split()
    return sorted(f for f in out if f.endswith(".lean"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Report Lean deprecation warnings.")
    parser.add_argument("--under", default="Unicode")
    args = parser.parse_args()

    files = tracked_lean(args.under)
    print(f"recompiling {len(files)} modules for deprecation warnings", flush=True)
    # Lean cannot write an olean to /dev/null; a real reused scratch path lets
    # elaboration complete so every warning is emitted before the write.
    scratch = ".lake/uc-dep-scratch.olean"
    per_module: dict[str, int] = {}
    for path in files:
        proc = subprocess.run(
            ["lake", "env", "lean", path, "-o", scratch],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        dep = [ln for ln in proc.stdout.splitlines() if "deprecated" in ln.lower()]
        if dep:
            per_module[path] = len(dep)
            for ln in dep:
                print(f"DEPRECATED {path}: {ln.strip()[:160]}", flush=True)
        if proc.returncode != 0 and not dep:
            print(f"BUILDFAIL {path}: exit {proc.returncode}", flush=True)

    total = sum(per_module.values())
    print(f"SWEEP_DONE deprecations={total} modules={len(per_module)}", flush=True)
    for path in sorted(per_module, key=lambda k: -per_module[k]):
        print(f"  {per_module[path]:4}  {path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
