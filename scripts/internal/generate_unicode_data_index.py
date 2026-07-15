#!/usr/bin/env python3
"""Generate the low-byte UnicodeData lookup index used by Lean.

The checked-in `Unicode.Generated.UnicodeData` table remains the audit surface.
This companion index is derived from the same pinned UCD source and buckets rows
by `codepoint % 256`, keeping concrete lookup reduction over small collision
buckets instead of the full NFC-relevant table.
"""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
UCD = ROOT / "Unicode" / "Ucd" / "UnicodeData.txt"
OUT = ROOT / "Unicode" / "Generated" / "UnicodeDataIndex.lean"
FACT_GROUPS = 64


def parse_hex(text: str) -> int:
    return int(text, 16)


def parse_rows() -> list[tuple[int, int, tuple[int, ...]]]:
    rows: list[tuple[int, int, tuple[int, ...]]] = []
    for raw in UCD.read_text(encoding="utf-8").splitlines():
        if not raw or raw.startswith("#"):
            continue
        fields = raw.split(";")
        if len(fields) < 6:
            continue
        cp = parse_hex(fields[0])
        ccc = int(fields[3] or "0")
        decomp_raw = fields[5].strip()
        if decomp_raw and not decomp_raw.startswith("<"):
            decomp = tuple(parse_hex(part) for part in decomp_raw.split())
        else:
            decomp = ()
        if ccc != 0 or decomp:
            rows.append((cp, ccc, decomp))
    rows.sort(key=lambda row: row[0])
    return rows


def hex_nat(n: int) -> str:
    if n <= 0xFFFF:
        return f"0x{n:04X}"
    return f"0x{n:X}"


def row_literal(row: tuple[int, int, tuple[int, ...]]) -> str:
    cp, ccc, decomp = row
    mapping = ", ".join(hex_nat(x) for x in decomp)
    return f"⟨{hex_nat(cp)}, {ccc}, #[{mapping}]⟩"


def emit_bucket(name: str, rows: list[tuple[int, int, tuple[int, ...]]]) -> list[str]:
    out: list[str] = [f"def {name} : List UnicodeDataRow := ["]
    for row in rows:
        out.append(f"  {row_literal(row)},")
    out.append("]")
    return out


def emit_fact_file(group: int, lows: range) -> None:
    lines: list[str] = [
        "/-",
        f"  Unicode.Generated.UnicodeDataIndexFacts{group}",
        "",
        f"  Membership facts for low-byte buckets {lows.start:02X}..{lows.stop - 1:02X}.",
        "-/",
        "",
        "import Unicode.Generated.UnicodeDataIndex",
        "",
        f"namespace Unicode.Generated.UnicodeDataIndexFacts{group}",
        "",
        "open Unicode.Generated",
        "open Unicode.Generated.UnicodeData",
        "open Unicode.Generated.UnicodeDataIndex",
        "",
        "set_option maxRecDepth 100000",
        "set_option linter.unusedVariables false",
        "",
    ]
    for low in lows:
        name = f"rowsLowByte{low:02X}"
        lines.append(f"theorem {name}_all_supported_rowsList :")
        lines.append(f"    {name}.all (fun row =>")
        lines.append("      UnicodeData.rowsList.any (fun src =>")
        lines.append("        decide (src.codepoint = row.codepoint ∧")
        lines.append("          src.canonicalCombiningClass = row.canonicalCombiningClass ∧")
        lines.append("          src.canonicalDecomposition = row.canonicalDecomposition))) = true := by")
        lines.append("  decide +kernel")
        lines.append("")
        lines.append(f"theorem rowsList_all_codepoint_mem_{name} :")
        lines.append("    UnicodeData.rowsList.all (fun row =>")
        lines.append(f"      decide (row.codepoint % 256 = 0x{low:02X} →")
        lines.append(f"        {name}.any (fun indexed =>")
        lines.append("          decide (indexed.codepoint = row.codepoint)) = true)) = true := by")
        lines.append("  decide +kernel")
        lines.append("")
    lines.append(f"end Unicode.Generated.UnicodeDataIndexFacts{group}")
    lines.append("")
    path = ROOT / "Unicode" / "Generated" / f"UnicodeDataIndexFacts{group}.lean"
    path.write_text("\n".join(lines), encoding="utf-8")


def emit_fact_aggregator() -> None:
    lines: list[str] = [
        "/-",
        "  Unicode.Generated.UnicodeDataIndexFacts",
        "",
        "  Aggregated soundness/completeness facts for the low-byte UnicodeData index.",
        "-/",
        "",
    ]
    for group in range(FACT_GROUPS):
        lines.append(f"import Unicode.Generated.UnicodeDataIndexFacts{group}")
    lines.extend([
        "",
        "namespace Unicode.Generated.UnicodeDataIndex",
        "",
        "open Unicode.Generated",
        "open Unicode.Generated.UnicodeData",
    ])
    for group in range(FACT_GROUPS):
        lines.append(f"open Unicode.Generated.UnicodeDataIndexFacts{group}")
    lines.extend([
        "",
        "set_option maxRecDepth 100000",
        "",
        "theorem rowBucket_all_supported_rowsList : ∀ low : Nat,",
        "    (rowBucketByLowByte low).all (fun row =>",
        "      UnicodeData.rowsList.any (fun src =>",
        "        decide (src.codepoint = row.codepoint ∧",
        "          src.canonicalCombiningClass = row.canonicalCombiningClass ∧",
        "          src.canonicalDecomposition = row.canonicalDecomposition))) = true",
    ])
    for low in range(256):
        lines.append(f"  | 0x{low:02X} => rowsLowByte{low:02X}_all_supported_rowsList")
    lines.append("  | low + 256 => by rfl")
    lines.append("")
    lines.extend([
        "theorem rowsList_all_codepoint_mem_rowBucket : ∀ low : Nat,",
        "    UnicodeData.rowsList.all (fun row =>",
        "      decide (row.codepoint % 256 = low →",
        "        (rowBucketByLowByte low).any (fun indexed =>",
        "          decide (indexed.codepoint = row.codepoint)) = true)) = true",
    ])
    for low in range(256):
        lines.append(f"  | 0x{low:02X} => rowsList_all_codepoint_mem_rowsLowByte{low:02X}")
    lines.extend([
        "  | low + 256 => by",
        "      rw [List.all_eq_true]",
        "      intro row _hrow",
        "      apply decide_eq_true",
        "      intro hLow",
        "      have hMod : row.codepoint % 256 < 256 := Nat.mod_lt row.codepoint (by decide)",
        "      omega",
        "",
        "theorem lookupRow?_codepoint {cp : Nat} {row : UnicodeDataRow}",
        "    (h : lookupRow? cp = some row) : row.codepoint = cp := by",
        "  unfold lookupRow? at h",
        "  exact of_decide_eq_true",
        "    (List.find?_some",
        "      (p := fun (row : UnicodeDataRow) => decide (row.codepoint = cp)) h)",
        "",
        "theorem lookupRow?_supported_rowsList {cp : Nat} {row : UnicodeDataRow}",
        "    (h : lookupRow? cp = some row) :",
        "    ∃ src, src ∈ UnicodeData.rowsList ∧",
        "      src.codepoint = row.codepoint ∧",
        "      src.canonicalCombiningClass = row.canonicalCombiningClass ∧",
        "      src.canonicalDecomposition = row.canonicalDecomposition := by",
        "  unfold lookupRow? at h",
        "  have hMemBucket : row ∈ rowBucketByLowByte (cp % 256) :=",
        "    List.mem_of_find?_eq_some h",
        "  have hAll := rowBucket_all_supported_rowsList (cp % 256)",
        "  have hAny := List.all_eq_true.mp hAll row hMemBucket",
        "  rw [List.any_eq_true] at hAny",
        "  obtain ⟨src, hSrcMem, hSrcFieldsBool⟩ := hAny",
        "  exact ⟨src, hSrcMem, of_decide_eq_true hSrcFieldsBool⟩",
        "",
        "theorem rowsList_codepoint_mem_rowBucket {cp : Nat} {row : UnicodeDataRow}",
        "    (hMem : row ∈ UnicodeData.rowsList) (hCp : row.codepoint = cp) :",
        "    (rowBucketByLowByte (cp % 256)).any",
        "      (fun indexed => decide (indexed.codepoint = cp)) = true := by",
        "  have hAll := rowsList_all_codepoint_mem_rowBucket (cp % 256)",
        "  have hImp : row.codepoint % 256 = cp % 256 →",
        "      (rowBucketByLowByte (cp % 256)).any",
        "        (fun indexed => decide (indexed.codepoint = row.codepoint)) = true :=",
        "    of_decide_eq_true (List.all_eq_true.mp hAll row hMem)",
        "  have hAny := hImp (by rw [hCp])",
        "  simpa [hCp] using hAny",
        "",
        "theorem lookupRow?_none_no_rowsList_codepoint {cp : Nat} {row : UnicodeDataRow}",
        "    (h : lookupRow? cp = none) (hMem : row ∈ UnicodeData.rowsList) :",
        "    row.codepoint ≠ cp := by",
        "  intro hCp",
        "  unfold lookupRow? at h",
        "  rw [List.find?_eq_none] at h",
        "  have hAny := rowsList_codepoint_mem_rowBucket hMem hCp",
        "  rw [List.any_eq_true] at hAny",
        "  obtain ⟨indexed, hIndexedMem, hIndexedCpBool⟩ := hAny",
        "  have hFalse := h indexed hIndexedMem",
        "  exact hFalse hIndexedCpBool",
        "",
        "end Unicode.Generated.UnicodeDataIndex",
        "",
    ])
    path = ROOT / "Unicode" / "Generated" / "UnicodeDataIndexFacts.lean"
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    rows = parse_rows()
    buckets: list[list[tuple[int, int, tuple[int, ...]]]] = [[] for _ in range(256)]
    for row in rows:
        buckets[row[0] % 256].append(row)

    lines: list[str] = [
        "/-",
        "  Unicode.Generated.UnicodeDataIndex",
        "",
        "  Generated low-byte index for the NFC-relevant UnicodeData rows.",
        "  Source: Unicode/Ucd/UnicodeData.txt",
        "-/",
        "",
        "import Unicode.Generated.UnicodeData",
        "",
        "namespace Unicode.Generated.UnicodeDataIndex",
        "",
        "open Unicode.Generated.UnicodeData",
        "",
        "set_option maxRecDepth 100000",
        "set_option linter.unusedVariables false",
        "",
    ]

    for low, bucket in enumerate(buckets):
        lines.extend(emit_bucket(f"rowsLowByte{low:02X}", bucket))
        lines.append("")

    bucket_names = [f"rowsLowByte{low:02X}" for low in range(256)]
    lines.append("/-- Bucket for a low-byte value. Values `>= 256` are empty by totality. -/")
    lines.append("def rowBucketByLowByte : Nat → List UnicodeDataRow")
    for low, name in enumerate(bucket_names):
        lines.append(f"  | 0x{low:02X} => {name}")
    lines.append("  | low + 256 => []")
    lines.append("")
    lines.append("/-- Indexed row lookup. Concrete lookups scan one low-byte collision bucket. -/")
    lines.append("def lookupRow? (cp : Nat) : Option UnicodeDataRow :=")
    lines.append("  (rowBucketByLowByte (cp % 256)).find? (fun row => row.codepoint = cp)")
    lines.append("")
    lines.append("/-- Flattened generated index, used only by closed integrity gates. -/")
    lines.append("def rowsIndexedList : List UnicodeDataRow :=")
    lines.append("  []")
    for name in bucket_names:
        lines.append(f"  ++ {name}")
    lines.append("")
    lines.append("def rowEqBool (a b : UnicodeDataRow) : Bool :=")
    lines.append("  a.codepoint == b.codepoint &&")
    lines.append("  a.canonicalCombiningClass == b.canonicalCombiningClass &&")
    lines.append("  a.canonicalDecomposition == b.canonicalDecomposition")
    lines.append("")
    lines.append("def rowsEqBool : List UnicodeDataRow → List UnicodeDataRow → Bool")
    lines.append("  | [], [] => true")
    lines.append("  | a :: as, b :: bs => rowEqBool a b && rowsEqBool as bs")
    lines.append("  | _, _ => false")
    lines.append("")
    lines.append("#eval show IO Unit from do")
    lines.append("  unless rowsIndexedList.length == UnicodeData.rowsList.length do")
    lines.append("    throw (IO.userError \"UnicodeDataIndex drift: indexed row count differs from rowsList\")")
    lines.append("  for row in UnicodeData.rowsList do")
    lines.append("    match lookupRow? row.codepoint with")
    lines.append("    | some got =>")
    lines.append("        unless rowEqBool got row do")
    lines.append("          throw (IO.userError \"UnicodeDataIndex drift: lookup row differs from rowsList\")")
    lines.append("    | none =>")
    lines.append("        throw (IO.userError \"UnicodeDataIndex drift: rowsList row missing from index\")")
    lines.append("  for low in List.range 256 do")
    lines.append("    for row in rowBucketByLowByte low do")
    lines.append("      unless row.codepoint % 256 == low do")
    lines.append("        throw (IO.userError \"UnicodeDataIndex drift: row in wrong low-byte bucket\")")
    lines.append("")
    lines.append("end Unicode.Generated.UnicodeDataIndex")
    lines.append("")

    OUT.write_text("\n".join(lines), encoding="utf-8")
    group_size = 256 // FACT_GROUPS
    for group in range(FACT_GROUPS):
        start = group * group_size
        stop = start + group_size
        emit_fact_file(group, range(start, stop))
    emit_fact_aggregator()


if __name__ == "__main__":
    main()
