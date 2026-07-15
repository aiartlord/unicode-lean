#!/usr/bin/env python3
"""Self-test Lean cache runner bookkeeping without invoking Lean or Lake.

This check validates runner status, resume, report, and archive behavior. It is
not Lean build evidence and must not be used to claim any module has compiled.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def run(command: list[str], env: dict[str, str] | None = None) -> str:
    completed = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
        check=False,
    )
    if completed.returncode != 0:
        print(completed.stdout, file=sys.stderr)
        raise RuntimeError(f"command failed: {' '.join(command)}")
    return completed.stdout


def main() -> int:
    repo = Path.cwd()
    with tempfile.TemporaryDirectory(prefix="unicode-lean-cache-selftest-") as tmp:
        out_dir = Path(tmp) / "stage"
        archive_dir = Path(tmp) / "archive"

        run(
            [
                "scripts/lean-cache-stages.py",
                "--preset",
                "product",
                "--stage",
                "stage-1-generated-base",
                "--explain-plan",
                "--out-dir",
                str(out_dir),
            ]
        )
        explain = json.loads((out_dir / "explain-plan.json").read_text(encoding="utf-8"))
        assert explain["modules"], "explain-plan must list modules"
        assert all("initial_reason" in row for row in explain["modules"])

        env = os.environ.copy()
        env["UNICODE_LEAN_CACHE_TEST_COMMAND"] = "1"
        run(
            [
                "scripts/lean-cache-stages.py",
                "--root",
                "default",
                "--stage",
                "stage-4-product-default",
                "--run",
                "--allow-dirty-source",
                "--allow-existing-cache",
                "--out-dir",
                str(out_dir),
                "--test-command-template",
                f"{sys.executable} scripts/internal/lean_cache_runner_child.py {{module}}",
            ],
            env=env,
        )
        status = json.loads((out_dir / "status.json").read_text(encoding="utf-8"))
        assert "plan_signature" in status
        unicode_status = status["modules"]["Unicode"]
        assert unicode_status["status"] == "ok"
        assert "peak_tree_rss_kb" in unicode_status

        run(
            [
                "scripts/lean-cache-stages.py",
                "--root",
                "default",
                "--stage",
                "stage-4-product-default",
                "--run",
                "--resume",
                "--allow-dirty-source",
                "--allow-existing-cache",
                "--out-dir",
                str(out_dir),
                "--test-command-template",
                f"{sys.executable} scripts/internal/lean_cache_runner_child.py {{module}}",
            ],
            env=env,
        )

        drift = subprocess.run(
            [
                "scripts/lean-cache-stages.py",
                "--preset",
                "product",
                "--stage",
                "stage-1-generated-base",
                "--only-module",
                "Unicode.Generated.UnicodeData",
                "--run",
                "--resume",
                "--allow-dirty-source",
                "--allow-existing-cache",
                "--out-dir",
                str(out_dir),
                "--test-command-template",
                f"{sys.executable} scripts/internal/lean_cache_runner_child.py {{module}}",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
            check=False,
        )
        assert drift.returncode != 0
        assert "plan signature does not match" in drift.stdout

        run(
            [
                "scripts/lean-cache-stages.py",
                "--root",
                "default",
                "--stage",
                "stage-4-product-default",
                "--report",
                "--bundle-evidence",
                str(Path(tmp) / "evidence.tar.gz"),
                "--out-dir",
                str(out_dir),
            ]
        )
        report = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
        assert report["completed_modules"] == 1
        assert (Path(tmp) / "evidence.tar.gz").exists()

        run(
            [
                "scripts/lean-cache-stages.py",
                "--root",
                "default",
                "--stage",
                "stage-4-product-default",
                "--archive-existing-out-dir",
                "--out-dir",
                str(out_dir),
                "--archive-dir",
                str(archive_dir),
            ]
        )
        assert archive_dir.exists()
        assert any(archive_dir.iterdir()), "archive dir must contain moved stage output"

        shutil.rmtree(tmp, ignore_errors=True)

    print("clean: lean-cache runner bookkeeping selftest passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
