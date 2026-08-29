#!/usr/bin/env python3
"""
Plan and optionally execute Lean cache stages one module at a time.

Default mode is plan/dry-run only. Passing --run is required before this script
starts Lake or Lean.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import signal
import shlex
import subprocess
import sys
import tarfile
import time


ROOTS = {
    "default": "Unicode",
    "security": "Unicode.SecurityRoot",
    "idna": "Unicode.Idna",
    "uca": "Unicode.Uca",
    "unihan": "Unicode.UnihanRoot",
    "segmentation-specs": "Unicode.SegmentationSpecs",
    "assurance": "Unicode.Assurance",
    "full-conformance": "Unicode.FullConformance",
}

PRESETS = {
    "default": ["default"],
    "product": ["default", "security", "idna", "uca", "unihan", "segmentation-specs"],
    "assurance": ["assurance"],
    "evidence": ["assurance", "full-conformance"],
    "full": [
        "default",
        "security",
        "idna",
        "uca",
        "unihan",
        "segmentation-specs",
        "assurance",
        "full-conformance",
    ],
}

STAGE_ORDER = [
    "stage-1-generated-base",
    "stage-2-normalization-runtime",
    "stage-3-runtime-property-tables",
    "stage-4-product-default",
    "stage-5-product-domain",
    "stage-6-assurance-proof-chunk",
    "stage-7-assurance-aggregate",
    "stage-8-conformance-module",
    "stage-9-conformance-aggregate",
]

STAGE_BUDGETS = {
    "stage-1-generated-base": {"max_rss_gb": 40, "wall_time_sec": 0},
    "stage-2-normalization-runtime": {"max_rss_gb": 40, "wall_time_sec": 0},
    "stage-3-runtime-property-tables": {"max_rss_gb": 40, "wall_time_sec": 0},
    "stage-4-product-default": {"max_rss_gb": 40, "wall_time_sec": 0},
    "stage-5-product-domain": {"max_rss_gb": 40, "wall_time_sec": 0},
    "stage-6-assurance-proof-chunk": {"max_rss_gb": 40, "wall_time_sec": 0},
    "stage-7-assurance-aggregate": {"max_rss_gb": 40, "wall_time_sec": 0},
    "stage-8-conformance-module": {"max_rss_gb": 40, "wall_time_sec": 0},
    "stage-9-conformance-aggregate": {"max_rss_gb": 40, "wall_time_sec": 0},
}


@dataclass(frozen=True)
class PlanRow:
    index: int
    root_label: str
    root_module: str
    stage: str
    module: str
    path: Path
    category: str
    size: int
    decide_kernel: int
    row_refs: int


@dataclass(frozen=True)
class StageAssignment:
    module: str
    category: str
    initial_stage: str
    final_stage: str
    initial_reason: str
    promotion_imports: tuple[str, ...]


@dataclass(frozen=True)
class RunResult:
    exit_code: int
    elapsed_sec: float
    log_path: Path
    peak_tree_rss_kb: int
    rss_limit_exceeded: bool


def load_auditor(repo: Path):
    path = repo / "scripts" / "audit-lean-root-boundaries.py"
    spec = importlib.util.spec_from_file_location("unicode_lean_boundary_audit", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load auditor module from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def resolve_roots(labels: list[str], preset: str | None) -> list[tuple[str, str]]:
    if preset is not None:
        labels = PRESETS[preset] + labels
    if not labels:
        labels = PRESETS["default"]

    resolved: list[tuple[str, str]] = []
    seen: set[str] = set()
    for label in labels:
        if label in seen:
            continue
        seen.add(label)
        if label in ROOTS:
            resolved.append((label, ROOTS[label]))
        elif label.startswith("Unicode"):
            resolved.append((label, label))
        else:
            valid = ", ".join(sorted(ROOTS))
            raise ValueError(f"unknown root {label!r}; use one of: {valid}")
    return resolved


def stage_assignment_reason(
    module: str, category: str, root_label: str, root_module: str
) -> tuple[str, str]:
    if root_module == "Unicode.FullConformance":
        if module == root_module:
            return "stage-9-conformance-aggregate", "full-conformance aggregate root"
        if category == "conformance":
            return "stage-8-conformance-module", "conformance module under FullConformance"

    if root_module == "Unicode.Assurance":
        if module == root_module:
            return "stage-7-assurance-aggregate", "assurance aggregate root"
        if category in {"assurance-proof", "assurance-facts"}:
            return "stage-6-assurance-proof-chunk", f"{category} module"

    if root_label not in {"default", "assurance", "full-conformance"}:
        if module == root_module or category.startswith("optional-") or category == "security-runtime":
            return "stage-5-product-domain", f"optional product root/category {category}"

    if module == "Unicode":
        return "stage-4-product-default", "default product root"
    if module in {
        "Unicode.Invariants",
        "Unicode.Codec.Strict",
        "Unicode.Codec.Utf8",
        "Unicode.Precis.WidthMapping",
    }:
        return "stage-2-normalization-runtime", "normalization prerequisite"
    if module.startswith("Unicode.Normalization"):
        return "stage-2-normalization-runtime", "normalization module"
    if category == "generated-data":
        return "stage-1-generated-base", "generated data"
    if category == "generated-wrapper":
        if module.startswith("Unicode.Generated.Normalization"):
            return "stage-2-normalization-runtime", "normalization generated wrapper"
        return "stage-1-generated-base", "generated wrapper"
    if category == "runtime":
        return "stage-3-runtime-property-tables", "runtime module"
    if category == "spec-bridge":
        return "stage-5-product-domain", "spec bridge"
    return "stage-5-product-domain", f"fallback category {category}"


def stage_for(module: str, category: str, root_label: str, root_module: str) -> str:
    stage, _ = stage_assignment_reason(module, category, root_label, root_module)
    return stage


def build_plan(
    repo: Path, root_specs: list[tuple[str, str]]
) -> tuple[list[PlanRow], list[str], dict[str, object]]:
    audit = load_auditor(repo)
    modules = audit.read_modules(repo)

    rows: list[PlanRow] = []
    problems: list[str] = []
    seen_modules: set[str] = set()

    for root_label, root_module in root_specs:
        order, missing = audit.topo_order(modules, root_module)
        if missing:
            problems.append(f"{root_module}: missing imports: {', '.join(sorted(missing))}")

        for module in order:
            if module in seen_modules:
                continue
            seen_modules.add(module)
            info = modules[module]
            category = audit.category(module)
            rows.append(
                PlanRow(
                    index=len(rows) + 1,
                    root_label=root_label,
                    root_module=root_module,
                    stage=stage_for(module, category, root_label, root_module),
                    module=module,
                    path=info.path,
                    category=category,
                    size=info.size,
                    decide_kernel=info.decide_kernel,
                    row_refs=info.row_refs,
                )
            )

    return rows, problems, modules


def ordered_rows(rows: list[PlanRow]) -> list[PlanRow]:
    stage_rank = {stage: index for index, stage in enumerate(STAGE_ORDER)}
    return sorted(rows, key=lambda row: (stage_rank.get(row.stage, 999), row.index))


def promote_stages(
    rows: list[PlanRow], modules: dict[str, object]
) -> tuple[list[PlanRow], dict[str, tuple[str, ...]]]:
    stage_rank = {stage: index for index, stage in enumerate(STAGE_ORDER)}
    by_module = {row.module: row for row in rows}
    promotion_imports: dict[str, set[str]] = {row.module: set() for row in rows}

    changed = True
    while changed:
        changed = False
        for row in list(by_module.values()):
            info = modules[row.module]
            rank = stage_rank[row.stage]
            promoted_rank = rank
            for imported in info.imports:
                imported_row = by_module.get(imported)
                if imported_row is None:
                    continue
                imported_rank = stage_rank[imported_row.stage]
                if imported_rank > promoted_rank:
                    promoted_rank = imported_rank
                    promotion_imports[row.module].add(imported)
            if promoted_rank != rank:
                promoted_stage = STAGE_ORDER[promoted_rank]
                by_module[row.module] = replace(row, stage=promoted_stage)
                changed = True

    return (
        [by_module[row.module] for row in rows],
        {module: tuple(sorted(imports)) for module, imports in promotion_imports.items()},
    )


def validate_order(rows: list[PlanRow], modules: dict[str, object]) -> list[str]:
    planned = {row.module for row in rows}
    built: set[str] = set()
    problems: list[str] = []

    for row in rows:
        info = modules[row.module]
        for imported in info.imports:
            if imported in planned and imported not in built:
                problems.append(f"{row.module} is planned before import {imported}")
        built.add(row.module)
    return problems


def filter_rows(
    rows: list[PlanRow], only_modules: list[str], from_module: str | None
) -> tuple[list[PlanRow], list[str]]:
    problems: list[str] = []
    modules = [row.module for row in rows]

    if from_module is not None:
        if from_module not in modules:
            problems.append(f"--from-module not in plan: {from_module}")
        else:
            start = modules.index(from_module)
            rows = rows[start:]

    if only_modules:
        wanted = set(only_modules)
        available = {row.module for row in rows}
        missing = sorted(wanted.difference(available))
        if missing:
            problems.extend(f"--only-module not in plan: {module}" for module in missing)
        rows = [row for row in rows if row.module in wanted]

    return rows, problems


def plan_summary(rows: list[PlanRow], roots: list[tuple[str, str]], preset: str | None) -> dict[str, object]:
    stages = []
    for stage in STAGE_ORDER:
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
                "budget": STAGE_BUDGETS[stage],
            }
        )

    return {
        "preset": preset,
        "roots": [{"label": label, "module": module} for label, module in roots],
        "module_steps": len(rows),
        "stages": stages,
    }


def plan_signature(rows: list[PlanRow], roots: list[tuple[str, str]]) -> str:
    payload = {
        "roots": [{"label": label, "module": module} for label, module in roots],
        "modules": [
            {
                "module": row.module,
                "path": str(row.path),
                "stage": row.stage,
                "category": row.category,
                "size": row.size,
                "decide_kernel": row.decide_kernel,
                "row_refs": row.row_refs,
            }
            for row in rows
        ],
    }
    rendered = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(rendered).hexdigest()


def write_transcript(
    path: Path,
    rows: list[PlanRow],
    roots: list[tuple[str, str]],
    signature: str,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Lean Cache Stage Plan",
        "",
        f"plan_signature: `{signature}`",
        f"module_steps: `{len(rows)}`",
        "",
        "## Roots",
        "",
    ]
    for label, module in roots:
        lines.append(f"- `{label}`: `{module}`")

    lines.extend(["", "## Stages", ""])
    for stage in STAGE_ORDER:
        stage_rows = [row for row in rows if row.stage == stage]
        if not stage_rows:
            continue
        lines.append(
            f"- `{stage}`: {len(stage_rows)} modules, "
            f"{sum(row.size for row in stage_rows)} bytes, "
            f"decide+kernel={sum(row.decide_kernel for row in stage_rows)}, "
            f"row_refs={sum(row.row_refs for row in stage_rows)}, "
            f"max_rss_gb={STAGE_BUDGETS[stage]['max_rss_gb']}, "
            f"wall_time_sec={STAGE_BUDGETS[stage]['wall_time_sec']}"
        )

    lines.extend(["", "## Module Order", ""])
    for index, row in enumerate(rows, 1):
        lines.append(
            f"{index}. `{row.module}` - `{row.stage}` - `{row.category}` - `{row.path}`"
        )

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def check_plan_drift(
    rows: list[PlanRow],
    roots: list[tuple[str, str]],
    preset: str | None,
    fixture_dir: Path,
) -> list[str]:
    if preset is None:
        return ["--fail-if-plan-drift requires --preset"]
    path = fixture_dir / f"{preset}.summary.json"
    if not path.exists():
        return [f"missing plan fixture: {path}"]
    expected = path.read_text(encoding="utf-8")
    actual = json.dumps(plan_summary(rows, roots, preset), indent=2, sort_keys=True) + "\n"
    if expected != actual:
        return [f"plan fixture drift: {path}"]
    return []


def write_tsv(path: Path, rows: list[PlanRow]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        handle.write(
            "index\troot_label\troot_module\tstage\tmodule\tpath\tcategory\t"
            "size\tdecide_kernel\trow_refs\n"
        )
        for index, row in enumerate(rows, 1):
            handle.write(
                f"{index}\t{row.root_label}\t{row.root_module}\t{row.stage}\t"
                f"{row.module}\t{row.path}\t{row.category}\t{row.size}\t"
                f"{row.decide_kernel}\t{row.row_refs}\n"
            )


def write_json(path: Path, rows: list[PlanRow], roots: list[tuple[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "roots": [{"label": label, "module": module} for label, module in roots],
        "stages": STAGE_ORDER,
        "modules": [
            {
                "index": index,
                "root_label": row.root_label,
                "root_module": row.root_module,
                "stage": row.stage,
                "module": row.module,
                "path": str(row.path),
                "category": row.category,
                "size": row.size,
                "decide_kernel": row.decide_kernel,
                "row_refs": row.row_refs,
            }
            for index, row in enumerate(rows, 1)
        ],
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_explain_plan(
    path: Path,
    rows: list[PlanRow],
    roots: list[tuple[str, str]],
    promotion_imports: dict[str, tuple[str, ...]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    modules = []
    for index, row in enumerate(rows, 1):
        initial_stage, reason = stage_assignment_reason(
            row.module, row.category, row.root_label, row.root_module
        )
        modules.append(
            {
                "index": index,
                "module": row.module,
                "path": str(row.path),
                "root_label": row.root_label,
                "root_module": row.root_module,
                "category": row.category,
                "initial_stage": initial_stage,
                "final_stage": row.stage,
                "initial_reason": reason,
                "promotion_imports": list(promotion_imports.get(row.module, ())),
                "size": row.size,
                "decide_kernel": row.decide_kernel,
                "row_refs": row.row_refs,
            }
        )
    payload = {
        "roots": [{"label": label, "module": module} for label, module in roots],
        "stages": STAGE_ORDER,
        "modules": modules,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_text(command: list[str]) -> tuple[int, str]:
    completed = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    return completed.returncode, completed.stdout.strip()


def command_available(command: str) -> bool:
    path = os.environ.get("PATH", "")
    for directory in path.split(os.pathsep):
        candidate = Path(directory) / command
        if candidate.exists() and os.access(candidate, os.X_OK):
            return True
    return False


def cgroup_memory_info() -> dict[str, object]:
    info: dict[str, object] = {
        "available": False,
        "version": "unknown",
        "memory_max": None,
        "memory_current": None,
    }
    cgroup_root = Path("/sys/fs/cgroup")
    if not cgroup_root.exists():
        return info

    memory_max = cgroup_root / "memory.max"
    memory_current = cgroup_root / "memory.current"
    if memory_max.exists() and memory_current.exists():
        info["available"] = True
        info["version"] = "v2"
        info["memory_max"] = memory_max.read_text(errors="replace").strip()
        info["memory_current"] = memory_current.read_text(errors="replace").strip()
        return info

    memory_limit = cgroup_root / "memory" / "memory.limit_in_bytes"
    memory_usage = cgroup_root / "memory" / "memory.usage_in_bytes"
    if memory_limit.exists() and memory_usage.exists():
        info["available"] = True
        info["version"] = "v1"
        info["memory_max"] = memory_limit.read_text(errors="replace").strip()
        info["memory_current"] = memory_usage.read_text(errors="replace").strip()
    return info


def memory_backend_info() -> dict[str, object]:
    systemd_available = command_available("systemd-run")
    return {
        "process_tree": {"available": Path("/proc").exists(), "enforcing": True},
        "systemd": {"available": systemd_available, "enforcing": systemd_available},
        "cgroup": cgroup_memory_info(),
    }


def select_memory_backend(args: argparse.Namespace) -> str:
    info = memory_backend_info()
    if args.memory_backend == "auto":
        return "process-tree"
    if args.memory_backend == "process-tree":
        return "process-tree"
    if args.memory_backend == "systemd":
        if not info["systemd"]["available"]:
            raise RuntimeError("systemd-run is not available")
        return "systemd"
    if args.memory_backend == "cgroup":
        if not info["cgroup"]["available"]:
            raise RuntimeError("cgroup memory accounting is not available")
        raise RuntimeError("cgroup backend detection is available; direct cgroup enforcement is not implemented")
    raise RuntimeError(f"unknown memory backend: {args.memory_backend}")


def render_command(row: PlanRow, args: argparse.Namespace) -> list[str]:
    return build_command(row, args)


def git_text(args: list[str]) -> str:
    status, output = run_text(["git"] + args)
    if status != 0:
        return ""
    return output


def process_touches_repo(pid: int, args: str, repo: Path) -> bool:
    """True iff the process is building THIS repository.

    The guard exists to stop two builds writing one `.lake/build`, so it must
    be scoped to this checkout. A Lean build in a sibling directory shares the
    machine but not the cache, and blocking on it would couple this repository
    to unrelated work. Lake runs from the package root, so the working
    directory identifies the owner; an absolute path in the command line
    covers a `lean` invoked from elsewhere.
    """
    root = str(repo.resolve())
    try:
        cwd = os.readlink(f"/proc/{pid}/cwd")
    except OSError:
        cwd = ""
    if cwd == root or cwd.startswith(root + os.sep):
        return True
    return root in args


def active_lean_processes(repo: Path) -> list[str]:
    status, output = run_text(["ps", "-eo", "pid=,comm=,args="])
    if status != 0:
        return []

    current_pid = os.getpid()
    rows: list[str] = []
    for line in output.splitlines():
        fields = line.strip().split(maxsplit=2)
        if len(fields) < 2:
            continue
        try:
            pid = int(fields[0])
        except ValueError:
            continue
        if pid == current_pid:
            continue
        command_name = fields[1]
        args = fields[2] if len(fields) == 3 else ""
        if command_name in {"lean", "lake"} or args.startswith("lean ") or args.startswith("lake "):
            if process_touches_repo(pid, args, repo):
                rows.append(line.strip())
    return rows


def tracked_path(path: Path) -> bool:
    status, _ = run_text(["git", "ls-files", "--error-unmatch", "--", str(path)])
    return status == 0


def untracked_planned_modules(rows: list[PlanRow]) -> list[str]:
    missing: list[str] = []
    for row in rows:
        if not tracked_path(row.path):
            missing.append(f"{row.module} ({row.path})")
    return missing


def cache_state(repo: Path) -> dict[str, object]:
    build = repo / ".lake" / "build"
    if not build.exists():
        return {"exists": False, "path": str(build), "olean_count": 0, "ilean_count": 0}

    olean_count = sum(1 for _ in build.rglob("*.olean"))
    ilean_count = sum(1 for _ in build.rglob("*.ilean"))
    return {
        "exists": True,
        "path": str(build),
        "olean_count": olean_count,
        "ilean_count": ilean_count,
    }


def move_cache_aside(repo: Path, out_dir: Path, stamp: str) -> str | None:
    build = repo / ".lake" / "build"
    if not build.exists():
        return None
    archive_dir = out_dir / "cache-archive"
    archive_dir.mkdir(parents=True, exist_ok=True)
    target = archive_dir / f"build-{stamp}"
    suffix = 1
    while target.exists():
        suffix += 1
        target = archive_dir / f"build-{stamp}-{suffix}"
    build.rename(target)
    return str(target)


def tree_size_bytes(path: Path) -> int:
    if not path.exists():
        return 0
    if path.is_file():
        return path.stat().st_size
    total = 0
    for item in path.rglob("*"):
        try:
            if item.is_file():
                total += item.stat().st_size
        except OSError:
            continue
    return total


def archive_existing_out_dir(out_dir: Path, archive_dir: Path, stamp: str) -> str | None:
    if not out_dir.exists():
        return None
    out_resolved = out_dir.resolve()
    archive_resolved = archive_dir.resolve()
    if out_resolved == archive_resolved:
        raise RuntimeError("--archive-dir must differ from --out-dir")
    try:
        archive_resolved.relative_to(out_resolved)
        raise RuntimeError("--archive-dir must not be inside --out-dir")
    except ValueError:
        pass

    archive_dir.mkdir(parents=True, exist_ok=True)
    target = archive_dir / f"{out_dir.name}-{stamp}"
    suffix = 1
    while target.exists():
        suffix += 1
        target = archive_dir / f"{out_dir.name}-{stamp}-{suffix}"
    out_dir.rename(target)
    return str(target)


def write_cleanup_report(out_dir: Path, archive_dir: Path) -> Path:
    log_dir = out_dir / "logs"
    cache_archive = out_dir / "cache-archive"
    report = {
        "out_dir": str(out_dir),
        "out_dir_exists": out_dir.exists(),
        "out_dir_bytes": tree_size_bytes(out_dir),
        "log_dir": str(log_dir),
        "log_file_count": len(list(log_dir.glob("*.log"))) if log_dir.exists() else 0,
        "log_dir_bytes": tree_size_bytes(log_dir),
        "cache_archive": str(cache_archive),
        "cache_archive_entries": len(list(cache_archive.iterdir())) if cache_archive.exists() else 0,
        "cache_archive_bytes": tree_size_bytes(cache_archive),
        "status_json": str(out_dir / "status.json"),
        "status_json_exists": (out_dir / "status.json").exists(),
        "stage0_snapshot": str(out_dir / "stage0-snapshot.json"),
        "stage0_snapshot_exists": (out_dir / "stage0-snapshot.json").exists(),
        "archive_dir": str(archive_dir),
        "archive_dir_exists": archive_dir.exists(),
        "archive_dir_bytes": tree_size_bytes(archive_dir),
        "policy": "non-destructive: use --archive-existing-out-dir to move current --out-dir aside",
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "cleanup-report.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("Lean cache cleanup report")
    print(f"out_dir_bytes: {report['out_dir_bytes']}")
    print(f"log_file_count: {report['log_file_count']}")
    print(f"cache_archive_entries: {report['cache_archive_entries']}")
    print(f"archive_dir_bytes: {report['archive_dir_bytes']}")
    print(f"cleanup_report_json: {path}")
    return path


def write_evidence_bundle(out_dir: Path, bundle_path: Path) -> Path:
    bundle_path.parent.mkdir(parents=True, exist_ok=True)
    include_names = [
        "plan.tsv",
        "plan.json",
        "plan.md",
        "explain-plan.json",
        "stage0-snapshot.json",
        "status.json",
        "report.json",
        "cleanup-report.json",
        "failure-triage.json",
    ]
    files: list[Path] = []
    for name in include_names:
        path = out_dir / name
        if path.exists() and path.is_file():
            files.append(path)
    log_dir = out_dir / "logs"
    if log_dir.exists():
        files.extend(sorted(path for path in log_dir.rglob("*") if path.is_file()))

    manifest = {
        "out_dir": str(out_dir),
        "bundle_path": str(bundle_path),
        "files": [str(path.relative_to(out_dir)) for path in files],
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    manifest_path = out_dir / "evidence-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    files.append(manifest_path)

    with tarfile.open(bundle_path, "w:gz") as archive:
        for path in files:
            archive.add(path, arcname=str(path.relative_to(out_dir)))

    print(f"evidence_bundle: {bundle_path}")
    print(f"evidence_files: {len(files)}")
    return bundle_path


def write_stage0_snapshot(
    repo: Path,
    rows: list[PlanRow],
    roots: list[tuple[str, str]],
    args: argparse.Namespace,
    out_dir: Path,
) -> Path:
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    out_dir.mkdir(parents=True, exist_ok=True)
    active = active_lean_processes(repo)
    untracked = untracked_planned_modules(rows)
    tracked_status = git_text(["status", "--porcelain", "--untracked-files=no"])
    full_status = git_text(["status", "--porcelain", "--untracked-files=all"])
    before_cache = cache_state(repo)
    moved_to = None

    if active and not args.allow_active_lean:
        raise RuntimeError("active Lean/Lake process detected:\n" + "\n".join(active))
    if tracked_status and not args.allow_dirty_source:
        raise RuntimeError("tracked source tree is dirty; pass --allow-dirty-source to record it")
    if untracked and not args.allow_untracked_lean:
        raise RuntimeError(
            "planned Lean modules are untracked; pass --allow-untracked-lean to record them:\n"
            + "\n".join(untracked)
        )
    if before_cache["exists"] and not (
        args.resume or args.allow_existing_cache or args.move_cache_aside
    ):
        raise RuntimeError(
            ".lake/build exists; pass --resume, --allow-existing-cache, "
            "or --move-cache-aside"
        )
    if args.move_cache_aside:
        moved_to = move_cache_aside(repo, out_dir, stamp)

    snapshot = {
        "timestamp_utc": stamp,
        "git_commit": git_text(["rev-parse", "--verify", "HEAD"]) or "unknown",
        "git_tree_state": "dirty" if full_status else "clean",
        "tracked_tree_state": "dirty" if tracked_status else "clean",
        "tracked_status": tracked_status.splitlines(),
        "full_status": full_status.splitlines(),
        "roots": [{"label": label, "module": module} for label, module in roots],
        "planned_modules": len(rows),
        "stages": STAGE_ORDER,
        "active_lean_processes": active,
        "untracked_planned_modules": untracked,
        "cache_before": before_cache,
        "cache_moved_to": moved_to,
        "cache_after": cache_state(repo),
        "mem_available_gb": available_gb(),
        "memory_backend": args.memory_backend,
        "memory_backend_info": memory_backend_info(),
    }
    path = out_dir / "stage0-snapshot.json"
    path.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def read_status_payload(path: Path) -> dict[str, object]:
    if not path.exists():
        return {"modules": {}}
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise RuntimeError(f"invalid status file: {path}")
    if "modules" not in data:
        data["modules"] = {}
    if not isinstance(data["modules"], dict):
        raise RuntimeError(f"invalid status file: {path}")
    return data


def read_status(path: Path) -> dict[str, dict[str, object]]:
    data = read_status_payload(path)
    modules = data.get("modules", {})
    return modules


def write_status(
    path: Path,
    status: dict[str, dict[str, object]],
    metadata: dict[str, object] | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"modules": status}
    if metadata:
        payload.update(metadata)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def write_failure_triage(
    out_dir: Path,
    row: PlanRow,
    status: str,
    message: str,
    modules: dict[str, object],
    roots: list[tuple[str, str]],
) -> Path:
    info = modules.get(row.module)
    imports = list(info.imports) if info is not None else []
    payload = {
        "module": row.module,
        "path": str(row.path),
        "stage": row.stage,
        "category": row.category,
        "status": status,
        "message": message,
        "root_label": row.root_label,
        "root_module": row.root_module,
        "roots": [{"label": label, "module": module} for label, module in roots],
        "imports": imports,
        "risk": {
            "size": row.size,
            "decide_kernel": row.decide_kernel,
            "row_refs": row.row_refs,
        },
    }
    path = out_dir / "failure-triage.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def extract_peak_rss_kb(log_path: Path) -> int | None:
    if not log_path.exists():
        return None
    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "Maximum resident set size" in line:
            fields = line.rsplit(":", 1)
            if len(fields) != 2:
                continue
            try:
                return int(fields[1].strip())
            except ValueError:
                return None
    return None


def write_report(rows: list[PlanRow], out_dir: Path) -> Path:
    status_path = out_dir / "status.json"
    status = read_status(status_path) if status_path.exists() else {}
    row_by_module = {row.module: row for row in rows}
    counts: dict[str, int] = {}
    stage_counts: dict[str, dict[str, int]] = {}
    elapsed_total = 0.0
    peak_rss_kb = 0
    peak_rss_module = None

    for module, entry in status.items():
        state = str(entry.get("status", "unknown"))
        counts[state] = counts.get(state, 0) + 1
        stage = str(entry.get("stage", row_by_module.get(module, PlanRow(
            0, "", "", "unknown", module, Path(""), "", 0, 0, 0
        )).stage))
        stage_counts.setdefault(stage, {})
        stage_counts[stage][state] = stage_counts[stage].get(state, 0) + 1

        elapsed = entry.get("elapsed_sec")
        if isinstance(elapsed, (int, float)):
            elapsed_total += float(elapsed)

        status_peak = entry.get("peak_tree_rss_kb")
        if isinstance(status_peak, int) and status_peak > peak_rss_kb:
            peak_rss_kb = status_peak
            peak_rss_module = module

        log_value = entry.get("log")
        if (not isinstance(status_peak, int)) and isinstance(log_value, str):
            rss = extract_peak_rss_kb(Path(log_value))
            if rss is not None and rss > peak_rss_kb:
                peak_rss_kb = rss
                peak_rss_module = module

    planned = len(rows)
    completed = counts.get("ok", 0)
    pending = max(0, planned - len(status))
    report = {
        "planned_modules": planned,
        "status_file": str(status_path),
        "status_counts": counts,
        "pending_modules": pending,
        "completed_modules": completed,
        "elapsed_sec_total": round(elapsed_total, 3),
        "peak_rss_kb": peak_rss_kb if peak_rss_kb else None,
        "peak_rss_module": peak_rss_module,
        "stage_counts": stage_counts,
    }
    path = out_dir / "report.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print("Lean cache status report")
    print(f"planned_modules: {planned}")
    print(f"completed_modules: {completed}")
    print(f"pending_modules: {pending}")
    for state, count in sorted(counts.items()):
        print(f"{state}: {count}")
    print(f"elapsed_sec_total: {round(elapsed_total, 3)}")
    if peak_rss_kb:
        print(f"peak_rss_kb: {peak_rss_kb}")
        print(f"peak_rss_module: {peak_rss_module}")
    print(f"report_json: {path}")
    return path


def available_gb() -> int:
    meminfo = Path("/proc/meminfo")
    if not meminfo.exists():
        return 999
    for line in meminfo.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("MemAvailable:"):
            fields = line.split()
            return int(int(fields[1]) / 1024 / 1024)
    return 999


def proc_children(pid: int) -> list[int]:
    children: set[int] = set()
    task_dir = Path("/proc") / str(pid) / "task"
    if task_dir.exists():
        for task in task_dir.iterdir():
            children_file = task / "children"
            try:
                text = children_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for field in text.split():
                try:
                    children.add(int(field))
                except ValueError:
                    continue

    if children:
        return sorted(children)

    # Fallback for systems without /proc/<pid>/task/*/children.
    proc_dir = Path("/proc")
    for entry in (proc_dir.iterdir() if proc_dir.exists() else []):
        if not entry.name.isdigit():
            continue
        status_file = entry / "status"
        try:
            status = status_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in status.splitlines():
            if line.startswith("PPid:"):
                try:
                    if int(line.split()[1]) == pid:
                        children.add(int(entry.name))
                except (IndexError, ValueError):
                    pass
                break
    return sorted(children)


def process_tree_pids(root_pid: int) -> list[int]:
    seen: set[int] = set()
    stack = [root_pid]
    while stack:
        pid = stack.pop()
        if pid in seen:
            continue
        seen.add(pid)
        stack.extend(proc_children(pid))
    return sorted(seen)


def pid_rss_kb(pid: int) -> int:
    status_file = Path("/proc") / str(pid) / "status"
    try:
        text = status_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0
    for line in text.splitlines():
        if line.startswith("VmRSS:"):
            fields = line.split()
            if len(fields) >= 2:
                try:
                    return int(fields[1])
                except ValueError:
                    return 0
    return 0


def process_tree_rss_kb(root_pid: int) -> int:
    return sum(pid_rss_kb(pid) for pid in process_tree_pids(root_pid))


def terminate_process_group(root_pid: int) -> None:
    try:
        os.killpg(root_pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except PermissionError:
        return


def kill_process_group(root_pid: int) -> None:
    try:
        os.killpg(root_pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    except PermissionError:
        return


def time_command(command: list[str]) -> list[str]:
    time_bin = Path("/usr/bin/time")
    if time_bin.exists() and os.access(time_bin, os.X_OK):
        return [str(time_bin), "-v"] + command
    return command


def build_command(row: PlanRow, args: argparse.Namespace) -> list[str]:
    if args.test_command_template:
        if os.environ.get("UNICODE_LEAN_CACHE_TEST_COMMAND") != "1":
            raise RuntimeError(
                "--test-command-template requires UNICODE_LEAN_CACHE_TEST_COMMAND=1"
            )
        rendered = args.test_command_template.format(module=row.module, path=row.path)
        command = shlex.split(rendered)
    else:
        command = time_command(["lake", "build", row.module])

    if args.memory_backend == "systemd":
        memory_max = f"{args.max_rss_gb}G" if args.max_rss_gb > 0 else "infinity"
        return [
            "systemd-run",
            "--user",
            "--scope",
            "--quiet",
            "--same-dir",
            "--wait",
            "--collect",
            "-p",
            f"MemoryMax={memory_max}",
        ] + command
    return command


def run_module(row: PlanRow, args: argparse.Namespace, log_dir: Path) -> RunResult:
    log_dir.mkdir(parents=True, exist_ok=True)
    safe_module = row.module.replace(".", "_")
    log_path = log_dir / f"{row.index:04d}-{safe_module}.log"

    mem_now = available_gb()
    if mem_now < args.min_available_gb:
        raise RuntimeError(
            f"MemAvailable {mem_now}G is below required {args.min_available_gb}G"
        )

    command = build_command(row, args)
    env = os.environ.copy()
    env["LEAN_NUM_THREADS"] = "1"
    env["JOBS"] = "1"

    def prepare_child() -> None:
        os.setsid()
        if args.max_vmem_gb > 0:
            limit = args.max_vmem_gb * 1024 * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (limit, limit))

    started = time.time()
    peak_tree_rss_kb = 0
    rss_limit_exceeded = False
    rss_limit_kb = args.max_rss_gb * 1024 * 1024 if args.max_rss_gb > 0 else 0
    timeout_at = started + args.timeout_sec if args.timeout_sec > 0 else None

    with log_path.open("w", encoding="utf-8") as log:
        log.write(f"module: {row.module}\n")
        log.write(f"stage: {row.stage}\n")
        log.write(f"command: {' '.join(command)}\n")
        log.write(f"max_vmem_gb: {args.max_vmem_gb}\n")
        log.write(f"max_rss_gb: {args.max_rss_gb}\n")
        log.write(f"rss_poll_sec: {args.rss_poll_sec}\n")
        log.write(f"mem_available_gb: {mem_now}\n\n")
        log.flush()

        proc = subprocess.Popen(
            command,
            cwd=Path.cwd(),
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            preexec_fn=prepare_child,
        )

        while True:
            exit_code = proc.poll()
            current_rss = process_tree_rss_kb(proc.pid)
            peak_tree_rss_kb = max(peak_tree_rss_kb, current_rss)

            if exit_code is not None:
                break

            now = time.time()
            if rss_limit_kb and current_rss > rss_limit_kb:
                rss_limit_exceeded = True
                log.write(
                    "\nRSS_LIMIT_EXCEEDED "
                    f"current_kb={current_rss} limit_kb={rss_limit_kb}\n"
                )
                log.flush()
                terminate_process_group(proc.pid)
                deadline = time.time() + args.kill_grace_sec
                while proc.poll() is None and time.time() < deadline:
                    time.sleep(0.5)
                    current_rss = process_tree_rss_kb(proc.pid)
                    peak_tree_rss_kb = max(peak_tree_rss_kb, current_rss)
                if proc.poll() is None:
                    kill_process_group(proc.pid)
                exit_code = proc.wait()
                break

            if timeout_at is not None and now >= timeout_at:
                log.write(f"\nTIMEOUT_EXCEEDED timeout_sec={args.timeout_sec}\n")
                log.flush()
                terminate_process_group(proc.pid)
                deadline = time.time() + args.kill_grace_sec
                while proc.poll() is None and time.time() < deadline:
                    time.sleep(0.5)
                if proc.poll() is None:
                    kill_process_group(proc.pid)
                raise subprocess.TimeoutExpired(command, args.timeout_sec)

            time.sleep(args.rss_poll_sec)

        log.write(f"\npeak_tree_rss_kb: {peak_tree_rss_kb}\n")
        log.flush()

    elapsed = time.time() - started
    return RunResult(
        exit_code=exit_code,
        elapsed_sec=elapsed,
        log_path=log_path,
        peak_tree_rss_kb=peak_tree_rss_kb,
        rss_limit_exceeded=rss_limit_exceeded,
    )


def execute(
    rows: list[PlanRow],
    args: argparse.Namespace,
    modules: dict[str, object],
    roots: list[tuple[str, str]],
    signature: str,
) -> int:
    out_dir = Path(args.out_dir)
    status_path = out_dir / "status.json"
    log_dir = out_dir / "logs"
    status_payload = read_status_payload(status_path) if args.resume else {"modules": {}}
    if args.resume:
        existing_signature = status_payload.get("plan_signature")
        if existing_signature != signature and not args.allow_status_plan_drift:
            print(
                "resume blocked: status.json plan signature does not match current plan",
                file=sys.stderr,
            )
            return 3
    status = status_payload.get("modules", {})
    metadata = {
        "plan_signature": signature,
        "roots": [{"label": label, "module": module} for label, module in roots],
        "module_steps": len(rows),
        "updated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    for row in rows:
        existing = status.get(row.module)
        if args.resume and existing and existing.get("status") == "ok":
            print(f"skip ok {row.module}")
            continue

        print(f"run {row.index}/{len(rows)} {row.stage} {row.module}", flush=True)
        started_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        try:
            result = run_module(row, args, log_dir)
        except subprocess.TimeoutExpired as exc:
            status[row.module] = {
                "status": "timeout",
                "stage": row.stage,
                "started_utc": started_utc,
                "timeout_sec": args.timeout_sec,
                "log": str(log_dir / f"{row.index:04d}-{row.module.replace('.', '_')}.log"),
            }
            triage = write_failure_triage(
                out_dir, row, "timeout", str(exc), modules, roots
            )
            status[row.module]["failure_triage"] = str(triage)
            write_status(status_path, status, metadata)
            print(f"timeout {row.module}: {exc}", file=sys.stderr)
            return 124
        except RuntimeError as exc:
            status[row.module] = {
                "status": "blocked",
                "stage": row.stage,
                "started_utc": started_utc,
                "message": str(exc),
            }
            triage = write_failure_triage(
                out_dir, row, "blocked", str(exc), modules, roots
            )
            status[row.module]["failure_triage"] = str(triage)
            write_status(status_path, status, metadata)
            print(f"blocked {row.module}: {exc}", file=sys.stderr)
            return 3

        result_status = "ok" if result.exit_code == 0 else "failed"
        if result.rss_limit_exceeded:
            result_status = "rss_exceeded"
        status[row.module] = {
            "status": result_status,
            "stage": row.stage,
            "started_utc": started_utc,
            "elapsed_sec": round(result.elapsed_sec, 3),
            "exit_code": result.exit_code,
            "log": str(result.log_path),
            "peak_tree_rss_kb": result.peak_tree_rss_kb,
            "max_rss_gb": args.max_rss_gb,
        }
        if result.exit_code != 0:
            triage = write_failure_triage(
                out_dir,
                row,
                result_status,
                f"exit {result.exit_code}",
                modules,
                roots,
            )
            status[row.module]["failure_triage"] = str(triage)
        write_status(status_path, status, metadata)
        if result.exit_code != 0:
            print(
                f"{result_status} {row.module}: exit {result.exit_code}; log {result.log_path}",
                file=sys.stderr,
            )
            return result.exit_code

    print(f"complete: {len(rows)} module steps")
    return 0


def print_summary(rows: list[PlanRow], roots: list[tuple[str, str]], mode: str) -> None:
    print("Lean cache stage plan")
    print(f"mode: {mode}")
    print("roots:")
    for label, module in roots:
        print(f"  {label}: {module}")
    print(f"module_steps: {len(rows)}")

    for stage in STAGE_ORDER:
        stage_rows = [row for row in rows if row.stage == stage]
        if not stage_rows:
            continue
        size = sum(row.size for row in stage_rows)
        decide = sum(row.decide_kernel for row in stage_rows)
        row_refs = sum(row.row_refs for row in stage_rows)
        print(
            f"{stage}: modules={len(stage_rows)} bytes={size} "
            f"decide+kernel={decide} row_refs={row_refs}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Plan or run one-module-at-a-time Lean cache stages."
    )
    parser.add_argument(
        "--root",
        action="append",
        default=[],
        help="Root label or Lean module. Labels: " + ", ".join(sorted(ROOTS)),
    )
    parser.add_argument(
        "--preset",
        choices=sorted(PRESETS),
        help="Root preset. May be combined with --root for extra roots.",
    )
    parser.add_argument(
        "--list-roots",
        action="store_true",
        help="List known root labels and presets, then exit.",
    )
    parser.add_argument(
        "--list-stages",
        action="store_true",
        help="List stage names and budget expectations, then exit.",
    )
    parser.add_argument(
        "--list-memory-backends",
        action="store_true",
        help="List memory backend availability, then exit.",
    )
    parser.add_argument(
        "--validate-args-only",
        action="store_true",
        help="Parse arguments and exit before graph planning or execution.",
    )
    parser.add_argument(
        "--out-dir",
        default="dist/lean-cache-stages",
        help="Plan, status, and log directory.",
    )
    parser.add_argument("--plan-tsv", help="Write the ordered plan as TSV.")
    parser.add_argument("--plan-json", help="Write the ordered plan as JSON.")
    parser.add_argument(
        "--explain-plan",
        action="store_true",
        help="Write JSON explaining each module's stage assignment.",
    )
    parser.add_argument(
        "--explain-json",
        help="Path for --explain-plan output. Defaults to --out-dir/explain-plan.json.",
    )
    parser.add_argument(
        "--stage",
        action="append",
        default=[],
        help="Limit to a stage name. May be repeated.",
    )
    parser.add_argument(
        "--only-module",
        action="append",
        default=[],
        help="Limit to an exact module name. May be repeated.",
    )
    parser.add_argument(
        "--from-module",
        help="Start the selected plan at this exact module name.",
    )
    parser.add_argument(
        "--transcript",
        help="Write a human-readable plan transcript. Defaults to --out-dir/plan.md.",
    )
    parser.add_argument(
        "--fail-if-plan-drift",
        action="store_true",
        help="Fail if the selected preset summary differs from tracked fixtures.",
    )
    parser.add_argument(
        "--dry-run-command-lines",
        action="store_true",
        help="Print exact per-module command lines without execution.",
    )
    parser.add_argument(
        "--fixture-dir",
        default="fixtures/lean-cache-plans",
        help="Fixture directory used by --fail-if-plan-drift.",
    )
    parser.add_argument(
        "--run",
        action="store_true",
        help="Execute the planned module builds. Omitted means dry-run only.",
    )
    parser.add_argument(
        "--test-command-template",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--stage0",
        action="store_true",
        help="Write Stage 0 snapshot and safety checks, then exit unless --run is set.",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Summarize status.json and module logs, then exit unless --run is set.",
    )
    parser.add_argument(
        "--cleanup-report",
        action="store_true",
        help="Inventory logs/cache archives without deleting or moving anything.",
    )
    parser.add_argument(
        "--bundle-evidence",
        help="Write a tar.gz bundle of plan/snapshot/status/report/log evidence.",
    )
    parser.add_argument(
        "--archive-existing-out-dir",
        action="store_true",
        help="Move an existing --out-dir under --archive-dir before writing a fresh plan.",
    )
    parser.add_argument(
        "--archive-dir",
        default="dist/lean-cache-archive",
        help="Destination for archived stage output directories.",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Skip modules already marked ok in the status file.",
    )
    parser.add_argument(
        "--allow-status-plan-drift",
        action="store_true",
        help="Allow --resume even when status.json was written for a different plan.",
    )
    parser.add_argument(
        "--move-cache-aside",
        action="store_true",
        help="During Stage 0, move .lake/build under --out-dir/cache-archive.",
    )
    parser.add_argument(
        "--allow-existing-cache",
        action="store_true",
        help="Allow Stage 0 to proceed when .lake/build already exists.",
    )
    parser.add_argument(
        "--allow-dirty-source",
        action="store_true",
        help="Allow Stage 0 to record a dirty tracked source tree.",
    )
    parser.add_argument(
        "--allow-untracked-lean",
        action="store_true",
        help="Allow Stage 0 to include planned Lean modules that are not tracked by git.",
    )
    parser.add_argument(
        "--allow-active-lean",
        action="store_true",
        help="Allow Stage 0 to proceed when Lean/Lake processes are already active.",
    )
    parser.add_argument(
        "--max-vmem-gb",
        type=int,
        default=40,
        help="Address-space limit for each module process. Use 0 for no limit.",
    )
    parser.add_argument(
        "--max-rss-gb",
        type=int,
        default=40,
        help="Process-tree RSS limit for each module build. Use 0 for no limit.",
    )
    parser.add_argument(
        "--memory-backend",
        choices=["auto", "process-tree", "systemd", "cgroup"],
        default="process-tree",
        help="Memory enforcement backend. Default: process-tree.",
    )
    parser.add_argument(
        "--rss-poll-sec",
        type=float,
        default=5.0,
        help="Seconds between process-tree RSS checks during --run.",
    )
    parser.add_argument(
        "--kill-grace-sec",
        type=float,
        default=15.0,
        help="Seconds to wait after SIGTERM before SIGKILL on timeout/RSS cap.",
    )
    parser.add_argument(
        "--min-available-gb",
        type=int,
        default=8,
        help="Minimum MemAvailable before starting each module.",
    )
    parser.add_argument(
        "--timeout-sec",
        type=int,
        default=0,
        help="Per-module timeout. Default 0 means no timeout.",
    )
    args = parser.parse_args()

    if args.list_roots:
        print("Root labels:")
        for label, module in sorted(ROOTS.items()):
            print(f"  {label}: {module}")
        print("Presets:")
        for preset, labels in sorted(PRESETS.items()):
            print(f"  {preset}: {', '.join(labels)}")
        return 0

    if args.list_stages:
        print("Stages:")
        for stage in STAGE_ORDER:
            budget = STAGE_BUDGETS[stage]
            print(
                f"  {stage}: max_rss_gb={budget['max_rss_gb']} "
                f"wall_time_sec={budget['wall_time_sec']}"
            )
        return 0

    if args.list_memory_backends:
        print(json.dumps(memory_backend_info(), indent=2, sort_keys=True))
        return 0

    if args.validate_args_only:
        print("clean: arguments parsed")
        return 0

    if args.rss_poll_sec <= 0:
        print("--rss-poll-sec must be positive", file=sys.stderr)
        return 2
    if args.kill_grace_sec < 0:
        print("--kill-grace-sec must be non-negative", file=sys.stderr)
        return 2
    try:
        selected_memory_backend = select_memory_backend(args)
    except RuntimeError as exc:
        print(f"memory backend blocked: {exc}", file=sys.stderr)
        return 3

    repo = Path.cwd()
    roots = resolve_roots(args.root, args.preset)
    rows, problems, modules = build_plan(repo, roots)
    rows, promotion_imports = promote_stages(rows, modules)
    rows = ordered_rows(rows)
    order_problems = validate_order(rows, modules)
    problems.extend(order_problems)

    if args.stage:
        wanted = set(args.stage)
        unknown = wanted.difference(STAGE_ORDER)
        if unknown:
            print("unknown stage: " + ", ".join(sorted(unknown)), file=sys.stderr)
            return 2
        rows = [row for row in rows if row.stage in wanted]

    rows, filter_problems = filter_rows(rows, args.only_module, args.from_module)
    problems.extend(filter_problems)

    if args.fail_if_plan_drift:
        problems.extend(check_plan_drift(rows, roots, args.preset, Path(args.fixture_dir)))

    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1

    signature = plan_signature(rows, roots)
    out_dir = Path(args.out_dir)
    archive_dir = Path(args.archive_dir)
    if args.archive_existing_out_dir:
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        try:
            archived_to = archive_existing_out_dir(out_dir, archive_dir, stamp)
        except RuntimeError as exc:
            print(f"archive blocked: {exc}", file=sys.stderr)
            return 3
        if archived_to:
            print(f"archived_existing_out_dir: {archived_to}")

    plan_tsv = Path(args.plan_tsv) if args.plan_tsv else out_dir / "plan.tsv"
    plan_json = Path(args.plan_json) if args.plan_json else out_dir / "plan.json"
    transcript = Path(args.transcript) if args.transcript else out_dir / "plan.md"
    write_tsv(plan_tsv, rows)
    write_json(plan_json, rows, roots)
    write_transcript(transcript, rows, roots, signature)
    if args.explain_plan:
        explain_json = Path(args.explain_json) if args.explain_json else out_dir / "explain-plan.json"
        write_explain_plan(explain_json, rows, roots, promotion_imports)

    if args.run:
        mode = "run"
    elif args.stage0:
        mode = "stage0"
    elif args.report:
        mode = "report"
    elif args.cleanup_report:
        mode = "cleanup-report"
    else:
        mode = "dry-run"
    print_summary(rows, roots, mode)
    print(f"plan_signature: {signature}")
    print(f"memory_backend: {selected_memory_backend}")
    print(f"plan_tsv: {plan_tsv}")
    print(f"plan_json: {plan_json}")
    print(f"transcript: {transcript}")
    if args.explain_plan:
        explain_json = Path(args.explain_json) if args.explain_json else out_dir / "explain-plan.json"
        print(f"explain_json: {explain_json}")

    if args.cleanup_report:
        write_cleanup_report(out_dir, archive_dir)
        if not (args.stage0 or args.report or args.run):
            return 0

    if args.dry_run_command_lines:
        print("dry_run_command_lines:")
        for row in rows:
            command = " ".join(shlex.quote(part) for part in render_command(row, args))
            print(f"  {row.module}: {command}")

    if args.bundle_evidence:
        write_evidence_bundle(out_dir, Path(args.bundle_evidence))

    if args.report:
        write_report(rows, out_dir)
        if not args.run:
            return 0

    if args.stage0 or args.run:
        try:
            snapshot_path = write_stage0_snapshot(repo, rows, roots, args, out_dir)
        except RuntimeError as exc:
            print(f"stage0 blocked: {exc}", file=sys.stderr)
            return 3
        print(f"stage0_snapshot: {snapshot_path}")
        if args.stage0 and not args.run:
            return 0

    if not args.run:
        print("dry-run: no Lean or Lake command executed")
        return 0

    return execute(rows, args, modules, roots, signature)


if __name__ == "__main__":
    sys.exit(main())
