#!/usr/bin/env python3
"""Child-process fixture for Lean cache runner bookkeeping tests.

This helper does not invoke Lean and must never be treated as build evidence.
It exists only so `check-lean-cache-runner-selftest.py` can exercise runner
status, resume, report, and archive behavior with a controlled child process.
"""

from __future__ import annotations

import argparse
import time


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("module")
    parser.add_argument("--sleep-sec", type=float, default=0.01)
    args = parser.parse_args()

    print(f"runner child processed {args.module}")
    time.sleep(args.sleep_sec)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
