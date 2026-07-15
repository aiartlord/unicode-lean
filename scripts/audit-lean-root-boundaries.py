#!/usr/bin/env python3
"""
Audit Lean root import boundaries and derive one-module-at-a-time cache plans.

This script is intentionally read-only. It does not call Lean, Lake, git, or
touch `.lake`. Its source of truth is the current checkout's Lean import graph.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
import re
import sys

PROOF_GAP_A = "sor" + "ry"
PROOF_GAP_B = "ad" + "mit"


@dataclass(frozen=True)
class ModuleInfo:
    module: str
    path: Path
    imports: tuple[str, ...]
    size: int
    decide_kernel: int
    row_refs: int
    max_rec_depth: int
    native_decide: int
    proof_gap_a: int
    proof_gap_b: int


def module_name(path: Path) -> str:
    if path == Path("Unicode.lean"):
        return "Unicode"
    return ".".join(path.with_suffix("").parts)


def read_modules(repo: Path) -> dict[str, ModuleInfo]:
    paths = [Path("Unicode.lean")]
    paths.extend(sorted(Path("Unicode").rglob("*.lean")))
    modules: dict[str, ModuleInfo] = {}

    for rel in paths:
        full = repo / rel
        if not full.exists():
            continue
        text = full.read_text(errors="replace")
        code = strip_lean_comments(text)
        code_for_tokens = strip_lean_strings(code)
        imports: list[str] = []
        for line in code.splitlines():
            stripped = line.strip()
            if stripped.startswith("import "):
                fields = stripped.split()
                if len(fields) >= 2:
                    imports.append(fields[1])

        modules[module_name(rel)] = ModuleInfo(
            module=module_name(rel),
            path=rel,
            imports=tuple(imports),
            size=full.stat().st_size,
            decide_kernel=code_for_tokens.count("decide +kernel"),
            row_refs=(
                code_for_tokens.count("rowsList")
                + code_for_tokens.count("rowsChunk")
                + code_for_tokens.count("UnicodeData.rows")
                + code_for_tokens.count("verifyRow")
            ),
            max_rec_depth=code_for_tokens.count("set_option maxRecDepth"),
            native_decide=count_token(code_for_tokens, "native_decide"),
            proof_gap_a=count_token(code_for_tokens, PROOF_GAP_A),
            proof_gap_b=count_token(code_for_tokens, PROOF_GAP_B),
        )

    return modules


def strip_lean_comments(text: str) -> str:
    """Remove Lean line comments and nested block comments."""
    out: list[str] = []
    i = 0
    depth = 0
    while i < len(text):
        if depth == 0 and text.startswith("--", i):
            while i < len(text) and text[i] != "\n":
                i += 1
            if i < len(text):
                out.append("\n")
                i += 1
        elif text.startswith("/-", i):
            depth += 1
            i += 2
        elif depth > 0 and text.startswith("-/", i):
            depth -= 1
            i += 2
        elif depth > 0:
            if text[i] == "\n":
                out.append("\n")
            i += 1
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def count_token(text: str, token: str) -> int:
    return len(re.findall(rf"(?<![A-Za-z0-9_'.]){re.escape(token)}(?![A-Za-z0-9_'.])", text))


def strip_lean_strings(text: str) -> str:
    """Blank out ordinary Lean string literals, preserving newlines."""
    out: list[str] = []
    i = 0
    in_string = False
    while i < len(text):
        c = text[i]
        if not in_string:
            if c == '"':
                in_string = True
                out.append(" ")
            else:
                out.append(c)
            i += 1
        else:
            if c == "\\" and i + 1 < len(text):
                out.append(" ")
                out.append("\n" if text[i + 1] == "\n" else " ")
                i += 2
            elif c == '"':
                in_string = False
                out.append(" ")
                i += 1
            else:
                out.append("\n" if c == "\n" else " ")
                i += 1
    return "".join(out)


def closure(
    modules: dict[str, ModuleInfo], roots: list[str]
) -> tuple[set[str], set[str]]:
    seen: set[str] = set()
    missing: set[str] = set()
    stack = list(roots)

    while stack:
        module = stack.pop()
        if module in seen:
            continue
        seen.add(module)
        info = modules.get(module)
        if info is None:
            if module.startswith("Unicode"):
                missing.add(module)
            continue
        stack.extend(info.imports)

    return {m for m in seen if m in modules}, missing


def topo_order(
    modules: dict[str, ModuleInfo], root: str
) -> tuple[list[str], set[str]]:
    seen: set[str] = set()
    visiting: set[str] = set()
    order: list[str] = []
    missing: set[str] = set()
    cycles: list[str] = []

    def visit(module: str) -> None:
        if module in seen:
            return
        if module in visiting:
            cycles.append(module)
            return
        info = modules.get(module)
        if info is None:
            if module.startswith("Unicode"):
                missing.add(module)
            return

        visiting.add(module)
        for imported in info.imports:
            visit(imported)
        visiting.remove(module)
        seen.add(module)
        order.append(module)

    visit(root)
    if cycles:
        raise RuntimeError("cycle detected: " + ", ".join(sorted(set(cycles))))
    return order, missing


def reverse_imports(modules: dict[str, ModuleInfo]) -> dict[str, list[str]]:
    rev: dict[str, list[str]] = defaultdict(list)
    for module, info in modules.items():
        for imported in info.imports:
            rev[imported].append(module)
    return rev


def path_to_root(
    reverse: dict[str, list[str]], start: str, root: str
) -> list[str] | None:
    queue = deque([(start, [start])])
    seen = {start}
    while queue:
        module, path = queue.popleft()
        if module == root:
            return path
        for parent in sorted(reverse.get(module, [])):
            if parent not in seen:
                seen.add(parent)
                queue.append((parent, path + [parent]))
    return None


def category(module: str) -> str:
    if module in {"Unicode", "Unicode.Assurance", "Unicode.FullConformance"}:
        return "root"
    if module.startswith("Unicode.Conformance"):
        return "conformance"
    if module.startswith("Unicode.ConfusablesTableFacts"):
        return "assurance-facts"
    if module in {
        "Unicode.Normalization.QuickCheckFacts",
        "Unicode.Normalization.QuickCheckHangulFacts",
        "Unicode.Normalization.QuickCheckSingletonRankData",
    }:
        return "assurance-facts"
    if (
        module.startswith("Unicode.Normalization.ToNFDAppend")
        or module.startswith("Unicode.Normalization.ComposeInversion")
        or module.startswith("Unicode.Normalization.QuickCheckSoundness")
        or module in {
            "Unicode.CaseFoldCommutation",
            "Unicode.CaseFoldRoundtrip",
            "Unicode.Precis.Preparation",
            "Unicode.Precis.OpaqueString",
            "Unicode.Precis.ZsPreservation",
        }
    ):
        return "assurance-proof"
    if module == "Unicode.Generated.IdnaMapping" or module.startswith(
        "Unicode.Generated.IdnaMapping."
    ):
        return "optional-idna-data"
    if module in {"Unicode.Generated.IdnaMappingData"}:
        return "optional-idna-data"
    if module in {"Unicode.Generated.Allkeys", "Unicode.Generated.AllkeysData"}:
        return "optional-uca-data"
    if module == "Unicode.Generated.BIP39" or module.startswith("Unicode.Generated.BIP39."):
        return "optional-security-data"
    if module in {
        "Unicode.Generated.KnownAttackTargets",
        "Unicode.Generated.KnownAttackTargetsData",
        "Unicode.Generated.WatermarkSchemes",
        "Unicode.Generated.WatermarkSchemesData",
        "Unicode.Generated.GlitchTokens",
        "Unicode.Generated.GlitchTokensData",
        "Unicode.Generated.StandardizedVariants",
        "Unicode.Generated.EmojiVariationSequences",
        "Unicode.Generated.EmojiVariationSequencesData",
    }:
        return "optional-security-data"
    if module.startswith("Unicode.Generated"):
        if "Data" in module.split(".")[-1]:
            return "generated-data"
        return "generated-wrapper"
    if module.startswith("Unicode.Security"):
        return "security-runtime"
    if module.startswith("Unicode.Idna"):
        return "optional-idna"
    if module.startswith("Unicode.Uca"):
        return "optional-uca"
    if module == "Unicode.Unihan" or module.startswith("Unicode.Generated.Unihan"):
        return "optional-unihan"
    if module.endswith("Spec") or ".Spec" in module:
        return "spec-bridge"
    return "runtime"


def consumer_violation(module: str, info: ModuleInfo) -> str | None:
    cat = category(module)
    if cat in {
        "conformance",
        "assurance-facts",
        "assurance-proof",
        "optional-idna",
        "optional-idna-data",
        "optional-uca",
        "optional-uca-data",
        "optional-unihan",
        "security-runtime",
        "optional-security-data",
        "spec-bridge",
    }:
        return cat
    if info.native_decide:
        return "native_decide"
    if info.proof_gap_a or info.proof_gap_b:
        return "incomplete-proof"
    return None


def direct_root_import_violations(
    modules: dict[str, ModuleInfo], root: str
) -> list[tuple[str, str]]:
    info = modules.get(root)
    if info is None:
        return [(root, "missing-root")]

    violations: list[tuple[str, str]] = []
    for imported in info.imports:
        imported_info = modules.get(imported)
        if imported_info is None:
            if imported.startswith("Unicode"):
                violations.append((imported, "missing-import"))
            continue
        reason = consumer_violation(imported, imported_info)
        if reason:
            violations.append((imported, reason))
    return violations


def summarize_closure(modules: dict[str, ModuleInfo], root: str) -> tuple[set[str], set[str]]:
    module_set, missing = closure(modules, [root])
    size = sum(modules[m].size for m in module_set)
    categories = Counter(category(m) for m in module_set)
    decide = sum(modules[m].decide_kernel for m in module_set)
    row_refs = sum(modules[m].row_refs for m in module_set)

    print(
        f"{root}: modules={len(module_set)} bytes={size} "
        f"decide+kernel={decide} row_refs={row_refs}"
    )
    if missing:
        print("  missing imports: " + ", ".join(sorted(missing)))
    for cat, count in sorted(categories.items()):
        cat_bytes = sum(modules[m].size for m in module_set if category(m) == cat)
        print(f"  {cat:18s} modules={count:3d} bytes={cat_bytes}")
    return module_set, missing


def print_large_and_risky(modules: dict[str, ModuleInfo], module_set: set[str]) -> None:
    rows: list[tuple[int, str]] = []
    for module in module_set:
        info = modules[module]
        if (
            info.size >= 80_000
            or info.decide_kernel >= 10
            or info.row_refs
            or info.max_rec_depth
            or info.native_decide
            or info.proof_gap_a
            or info.proof_gap_b
        ):
            rows.append((info.size, module))

    for _, module in sorted(rows, reverse=True):
        info = modules[module]
        print(
            f"  {module:72s} cat={category(module):18s} "
            f"size={info.size:8d} decide={info.decide_kernel:3d} "
            f"row_refs={info.row_refs:3d} maxRec={info.max_rec_depth:2d} "
            f"native={info.native_decide} gapA={info.proof_gap_a} "
            f"gapB={info.proof_gap_b}"
        )


def write_plan(path: Path, order: list[str], modules: dict[str, ModuleInfo]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        handle.write("index\tmodule\tpath\tcategory\tsize\tdecide_kernel\trow_refs\n")
        for index, module in enumerate(order, 1):
            info = modules[module]
            handle.write(
                f"{index}\t{module}\t{info.path}\t{category(module)}\t"
                f"{info.size}\t{info.decide_kernel}\t{info.row_refs}\n"
            )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit Lean import roots and derive cache plans."
    )
    parser.add_argument(
        "--root",
        action="append",
        default=[],
        help="Root module to audit. May be repeated. Defaults to all library roots.",
    )
    parser.add_argument(
        "--consumer-root",
        default="Unicode",
        help="Root that must remain consumer-light for boundary checks.",
    )
    parser.add_argument(
        "--plan-out",
        type=Path,
        help="Write a TSV one-module-at-a-time cache plan for --consumer-root.",
    )
    parser.add_argument(
        "--fail-consumer-boundary",
        action="store_true",
        help="Exit nonzero if the consumer root imports disallowed module classes.",
    )
    parser.add_argument(
        "--fail-direct-root-imports",
        action="store_true",
        help="Exit nonzero if the consumer root directly imports disallowed modules.",
    )
    args = parser.parse_args()

    repo = Path.cwd()
    modules = read_modules(repo)
    roots = args.root or ["Unicode", "Unicode.Assurance", "Unicode.FullConformance"]

    print(f"lean_files={len(modules)}")
    print()

    closures: dict[str, set[str]] = {}
    any_missing = False
    for root in roots:
        module_set, missing = summarize_closure(modules, root)
        closures[root] = module_set
        any_missing = any_missing or bool(missing)
        print()

    consumer_set, consumer_missing = closure(modules, [args.consumer_root])
    reverse = reverse_imports(modules)
    violations: list[tuple[str, str]] = []
    for module in sorted(consumer_set):
        reason = consumer_violation(module, modules[module])
        if reason:
            violations.append((module, reason))

    print(f"consumer_root={args.consumer_root}")
    print(f"consumer_modules={len(consumer_set)}")
    print(f"consumer_missing={','.join(sorted(consumer_missing)) if consumer_missing else '-'}")
    print(f"consumer_boundary_violations={len(violations)}")
    for module, reason in violations:
        path = path_to_root(reverse, module, args.consumer_root)
        rendered_path = " <- ".join(path) if path else "(no path found)"
        print(f"  {reason:18s} {module} via {rendered_path}")
    print()

    direct_violations = direct_root_import_violations(modules, args.consumer_root)
    print(f"direct_root_import_violations={len(direct_violations)}")
    for module, reason in direct_violations:
        print(f"  {reason:18s} {args.consumer_root} imports {module}")
    print()

    print(f"large_or_risky_modules_in_{args.consumer_root}:")
    print_large_and_risky(modules, consumer_set)
    print()

    order, topo_missing = topo_order(modules, args.consumer_root)
    print(
        f"cache_plan root={args.consumer_root} modules={len(order)} "
        f"missing={','.join(sorted(topo_missing)) if topo_missing else '-'}"
    )
    if args.plan_out:
        write_plan(args.plan_out, order, modules)
        print(f"cache_plan_written={args.plan_out}")

    if args.fail_consumer_boundary and violations:
        return 2
    if args.fail_direct_root_imports and direct_violations:
        return 2
    if any_missing or consumer_missing or topo_missing:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
