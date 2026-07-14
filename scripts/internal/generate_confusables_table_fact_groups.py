#!/usr/bin/env python3
"""Generate hierarchical Lean combiners for confusables table facts."""

from __future__ import annotations

import argparse
from pathlib import Path


def render_joined_terms(prefix: str, indexes: list[int], indent: str) -> list[str]:
    if not indexes:
        return [f"{indent}[]"]
    lines = [f"{indent}{prefix}{indexes[0]}"]
    for index in indexes[1:]:
        lines.append(f"{indent}++ {prefix}{index}")
    return lines


def render_group(group: int, indexes: list[int]) -> str:
    first = indexes[0]
    last = indexes[-1]
    imports = "\n".join(f"import Unicode.ConfusablesTableFacts{index}" for index in indexes)
    chunk_terms = [f"Unicode.Generated.Confusables.mappingsChunk{index}" for index in indexes]
    chain_facts = ", ".join(f"mappingsChunk{index}_chain" for index in indexes)
    expansion_facts = ", ".join(f"mappingsChunk{index}_expansion" for index in indexes)
    all_append = "List.all_append"
    simp_chain = ", ".join([all_append, chain_facts, "Bool.true_and", "Bool.and_true"])
    simp_expansion = ", ".join([all_append, expansion_facts, "Bool.true_and", "Bool.and_true"])
    lines = [
        "/-",
        f"  Unicode.ConfusablesTableFactsGroup{group}",
        "",
        f"  Group facts for generated confusables chunks {first}-{last}.",
        "-/",
        "",
        imports,
        "",
        "namespace Unicode.Confusables",
        "",
        "open Unicode.Generated",
        "",
        "set_option maxRecDepth 1000000",
        "set_option maxHeartbeats 0",
        "",
        f"def mappingsFactGroup{group} : List (Nat × Array Nat) :=",
    ]
    lines.extend(render_joined_terms("", list(range(len(chunk_terms))), "  "))
    for local_index, term in enumerate(chunk_terms):
        lines[-len(chunk_terms) + local_index] = lines[-len(chunk_terms) + local_index].replace(
            str(local_index), term, 1
        )
    lines.extend(
        [
            "",
            f"theorem mappingsFactGroup{group}_chain :",
            f"    mappingsFactGroup{group}.all chainConvergesEntry = true := by",
            f"  unfold mappingsFactGroup{group}",
            f"  simp only [{simp_chain}]",
            "",
            f"theorem mappingsFactGroup{group}_expansion :",
            f"    mappingsFactGroup{group}.all (expansionEntryUnderBound 18) = true := by",
            f"  unfold mappingsFactGroup{group}",
            f"  simp only [{simp_expansion}]",
            "",
            "end Unicode.Confusables",
            "",
        ]
    )
    return "\n".join(lines)


def render_top(group_count: int) -> str:
    imports = "\n".join(f"import Unicode.ConfusablesTableFactsGroup{index}" for index in range(group_count))
    group_indexes = list(range(group_count))
    group_chain = ", ".join(f"mappingsFactGroup{index}_chain" for index in group_indexes)
    group_expansion = ", ".join(f"mappingsFactGroup{index}_expansion" for index in group_indexes)
    simp_chain = ", ".join(["List.all_append", group_chain, "Bool.true_and", "Bool.and_true"])
    simp_expansion = ", ".join(["List.all_append", group_expansion, "Bool.true_and", "Bool.and_true"])
    lines = [
        "/-",
        "  Unicode.ConfusablesTableFacts",
        "",
        "  Proof-heavy table-wide facts for `Unicode.Confusables`. These are kept out of",
        "  the runtime module so ordinary security detector builds do not reduce the",
        "  full confusables table.",
        "",
        "  The all-row chain theorem below certifies the raw UTS #39 substitution graph",
        "  used to justify `confusableChainBound`; it does not re-run the NFC/case-fold",
        "  wrappers from the product `skeleton` pipeline for every table row.",
        "-/",
        "",
        "import Unicode.ConfusablesTableFactsCore",
        imports,
        "",
        "namespace Unicode.Confusables",
        "",
        "open Unicode",
        "open Unicode.Generated",
        "",
        "set_option maxRecDepth 1000000",
        "set_option maxHeartbeats 0",
        "",
        "/-- Grouped mirror of the generated confusables table, in chunk order. -/",
        "def mappingsFactGroupsList : List (Nat × Array Nat) :=",
    ]
    lines.extend(render_joined_terms("mappingsFactGroup", group_indexes, "  "))
    lines.extend(
        [
            "",
            "/-- Every source row in the generated confusables table reaches a raw",
            "    UTS #39 substitution-graph fixed point within `confusableChainBound`",
            "    iterations after its first table edge. -/",
            "def chainConvergesUnderBound : Bool :=",
            "  mappingsFactGroupsList.all chainConvergesEntry",
            "",
            "/-- Whole-table substitution-graph convergence for the bundled UTS #39 data. -/",
            "theorem confusable_chain_within_bound :",
            "    chainConvergesUnderBound = true := by",
            "  unfold chainConvergesUnderBound mappingsFactGroupsList",
            f"  simp only [{simp_chain}]",
            "",
            "/-- Every target sequence in the generated table has length <= 18. -/",
            "theorem mappingsList_expansion_under_bound :",
            "    mappingsFactGroupsList.all (expansionEntryUnderBound 18) = true := by",
            "  unfold mappingsFactGroupsList",
            f"  simp only [{simp_expansion}]",
            "",
            "/-- The maximum target sequence length across the generated confusables table. -/",
            "def maxConfusableExpansion : Nat :=",
            "  mappingsFactGroupsList.foldl (fun m e => max m e.2.size) 0",
            "",
            "/-- Concrete expansion bound for the bundled UTS #39 data. -/",
            "theorem maxConfusableExpansion_concrete :",
            "    maxConfusableExpansion <= 18 := by",
            "  unfold maxConfusableExpansion",
            "  exact foldl_max_size_le_of_all 18 mappingsFactGroupsList 0",
            "    (Nat.zero_le 18) mappingsList_expansion_under_bound",
            "",
            "end Unicode.Confusables",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=Path("Unicode"))
    parser.add_argument("--chunk-count", type=int, default=103)
    parser.add_argument("--group-size", type=int, default=10)
    args = parser.parse_args()

    groups = [
        list(range(start, min(start + args.group_size, args.chunk_count)))
        for start in range(0, args.chunk_count, args.group_size)
    ]

    for group_index, indexes in enumerate(groups):
        (args.output_dir / f"ConfusablesTableFactsGroup{group_index}.lean").write_text(
            render_group(group_index, indexes),
            encoding="utf-8",
        )

    (args.output_dir / "ConfusablesTableFacts.lean").write_text(
        render_top(len(groups)),
        encoding="utf-8",
    )

if __name__ == "__main__":
    main()
