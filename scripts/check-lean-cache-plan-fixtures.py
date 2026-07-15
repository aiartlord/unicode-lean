#!/usr/bin/env python3
"""Check graph-derived Lean cache plan summary fixtures without invoking Lean."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import sys


PRESETS = ("default", "product", "evidence")


def load_runner(repo: Path):
    path = repo / "scripts" / "lean-cache-stages.py"
    spec = importlib.util.spec_from_file_location("unicode_lean_cache_stages", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load runner module from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def summary_for(runner, repo: Path, preset: str) -> dict[str, object]:
    roots = runner.resolve_roots([], preset)
    rows, problems, modules = runner.build_plan(repo, roots)
    rows, _promotion_imports = runner.promote_stages(rows, modules)
    rows = runner.ordered_rows(rows)
    problems.extend(runner.validate_order(rows, modules))
    if problems:
        raise RuntimeError("; ".join(problems))

    stages = []
    for stage in runner.STAGE_ORDER:
        stage_rows = [row for row in rows if row.stage == stage]
        if not stage_rows:
            continue
        stages.append(
            {
                "stage": stage,
                "modules": len(stage_rows),
                "bytes": sum(row.size for row in stage_rows),
                "decide_kernel": sum(row.decide_kernel for row in stage_rows),
                "row_refs": sum(row.row_refs for row in stage_rows),
                "budget": runner.STAGE_BUDGETS[stage],
            }
        )

    return {
        "preset": preset,
        "roots": [{"label": label, "module": module} for label, module in roots],
        "module_steps": len(rows),
        "stages": stages,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check Lean cache plan summary fixtures."
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="Rewrite fixtures from the current import graph.",
    )
    parser.add_argument(
        "--fixture-dir",
        default="fixtures/lean-cache-plans",
        help="Directory containing *.summary.json fixtures.",
    )
    args = parser.parse_args()

    repo = Path.cwd()
    runner = load_runner(repo)
    fixture_dir = Path(args.fixture_dir)
    fixture_dir.mkdir(parents=True, exist_ok=True)

    failed = False
    for preset in PRESETS:
        actual = summary_for(runner, repo, preset)
        path = fixture_dir / f"{preset}.summary.json"
        rendered = json.dumps(actual, indent=2, sort_keys=True) + "\n"
        if args.write:
            path.write_text(rendered, encoding="utf-8")
            print(f"wrote {path}")
            continue

        if not path.exists():
            print(f"missing fixture: {path}", file=sys.stderr)
            failed = True
            continue
        expected = path.read_text(encoding="utf-8")
        if expected != rendered:
            print(f"fixture drift: {path}", file=sys.stderr)
            failed = True
        else:
            print(f"clean: {path}")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
