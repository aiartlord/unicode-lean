#!/usr/bin/env python3
"""Scan a source tree with the reference CLI and report throughput.

Whether the scanner is CI-viable is a product fact, so the figure is taken
the way CI would take it: every regular file under the root, sent to
`unicode-security scan --jsonl` in batches of `--batch` files, source-code
profile, observe mode, one verdict line per file. The report states the
files and bytes scanned, wall time, throughput, the peak resident set of the
scanner processes, and the reason codes that fired with their counts, so a
reader can see what the number was measured over and what an ordinary tree
sets off.

Batching bounds the scanner's memory to one batch of input and its verdicts.
`--jobs` runs that many scanner processes at once over independent batches,
the way a CI runner would shard a tree; the report states the job count,
the summed scanner CPU-seconds and the wall time separately, so the
single-core rate and the sharded rate are both readable.

Usage:
  scripts/throughput-scan.py --root DIR --binary CLI [--batch 2000] [--jobs N]
      [--profile source-code] [--mode observe] [--limit-bytes N] [--json PATH]
"""

from __future__ import annotations

import argparse
import json
import os
import resource
import subprocess
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


def iter_files(root: Path, limit_bytes: int | None):
    """Regular files under `root` in sorted order, up to `limit_bytes` total."""
    total = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if path.is_symlink() or not path.is_file():
                continue
            size = path.stat().st_size
            if limit_bytes is not None and total + size > limit_bytes:
                return
            total += size
            yield path, size


def record_for(path: Path, root: Path, profile: str, mode: str) -> str:
    """One JSONL record. UTF-8 text rides as `text`; anything else as bytes."""
    raw = path.read_bytes()
    rel = path.relative_to(root).as_posix()
    try:
        text = raw.decode("utf-8")
        payload = {"id": rel, "profile": profile, "mode": mode, "text": text}
    except UnicodeDecodeError:
        payload = {"id": rel, "profile": profile, "mode": mode, "bytes": list(raw)}
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)


def scan_batch(binary: Path, records: list[str]) -> tuple[bytes, float]:
    payload = ("\n".join(records) + "\n").encode("utf-8", "surrogatepass")
    started = time.monotonic()
    completed = subprocess.run(
        [str(binary), "scan", "--jsonl"],
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    elapsed = time.monotonic() - started
    if completed.returncode == 2:
        print(
            f"FATAL: scanner failed on a batch: {completed.stderr.decode('utf-8', 'replace')}",
            file=sys.stderr,
        )
        raise SystemExit(1)
    return completed.stdout, elapsed


def main() -> int:
    parser = argparse.ArgumentParser(description="Reference-scanner throughput over a tree.")
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--batch", type=int, default=2000)
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--profile", default="source-code")
    parser.add_argument("--mode", default="observe")
    parser.add_argument("--limit-bytes", type=int, default=None)
    parser.add_argument("--json", type=Path, default=None)
    args = parser.parse_args()

    root = args.root.resolve()
    files = 0
    total_bytes = 0
    scan_seconds = 0.0
    verdict_lines = 0
    codes: Counter[str] = Counter()
    actions: Counter[str] = Counter()
    files_with_findings = 0
    batch: list[str] = []
    wall_started = time.monotonic()
    pool = ThreadPoolExecutor(max_workers=max(1, args.jobs))
    pending = []

    def tally(stdout: bytes, elapsed: float) -> None:
        nonlocal scan_seconds, verdict_lines, files_with_findings
        scan_seconds += elapsed
        for line in stdout.splitlines():
            if not line.strip():
                continue
            verdict_lines += 1
            verdict = json.loads(line)
            actions[str(verdict.get("action"))] += 1
            findings = verdict.get("findings", [])
            if findings:
                files_with_findings += 1
            for finding in findings:
                codes[str(finding.get("code"))] += 1

    def drain(limit: int) -> None:
        while len(pending) > limit:
            stdout, elapsed = pending.pop(0).result()
            tally(stdout, elapsed)

    def flush() -> None:
        if not batch:
            return
        records = list(batch)
        batch.clear()
        pending.append(pool.submit(scan_batch, args.binary, records))
        drain(max(1, args.jobs))

    for path, size in iter_files(root, args.limit_bytes):
        files += 1
        total_bytes += size
        batch.append(record_for(path, root, args.profile, args.mode))
        if len(batch) >= args.batch:
            flush()
            print(f"  {files} files, {total_bytes / 1048576:.0f} MiB queued", file=sys.stderr)
    flush()
    drain(0)
    pool.shutdown()
    wall_seconds = time.monotonic() - wall_started

    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    peak_kb = usage.ru_maxrss
    report = {
        "root": str(root),
        "binary": str(args.binary),
        "profile": args.profile,
        "mode": args.mode,
        "batch": args.batch,
        "jobs": args.jobs,
        "files": files,
        "bytes": total_bytes,
        "verdicts": verdict_lines,
        "scanner_seconds": round(scan_seconds, 2),
        "wall_seconds": round(wall_seconds, 2),
        "scanner_mb_per_s": round(total_bytes / 1048576 / scan_seconds, 3) if scan_seconds else None,
        "wall_mb_per_s": round(total_bytes / 1048576 / wall_seconds, 3) if wall_seconds else None,
        "files_per_s": round(files / wall_seconds, 2) if wall_seconds else None,
        "scanner_peak_rss_kb": peak_kb,
        "files_with_findings": files_with_findings,
        "actions": dict(actions),
        "codes": dict(codes.most_common()),
    }
    print(json.dumps(report, indent=2))
    if args.json is not None:
        args.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if verdict_lines == files else 1


if __name__ == "__main__":
    raise SystemExit(main())
