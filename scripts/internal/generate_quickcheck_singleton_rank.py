#!/usr/bin/env python3
"""Generate quick-check singleton decomposition-rank data for Lean.

The generated module is proof-layer data, not runtime data.  It records the
finite rank structure of QC=Y, CCC=0, non-Hangul UnicodeData rows with a
canonical decomposition.  The theorem layer uses this to replace monolithic
`toNFC #[row.codepoint]` table reduction with a bounded topological proof.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
UCD = ROOT / "Unicode" / "Ucd" / "UnicodeData.txt"
DNP = ROOT / "Unicode" / "Ucd" / "DerivedNormalizationProps.txt"
OUT = ROOT / "Unicode" / "Normalization" / "QuickCheckSingletonRankData.lean"


def parse_hex(text: str) -> int:
    return int(text, 16)


def hex_nat(n: int) -> str:
    if n <= 0xFFFF:
        return f"0x{n:04X}"
    return f"0x{n:X}"


def parse_codepoint_range(text: str) -> tuple[int, int]:
    if ".." in text:
        lo, hi = text.split("..", 1)
        return parse_hex(lo), parse_hex(hi)
    cp = parse_hex(text)
    return cp, cp


def parse_unicode_data() -> tuple[dict[int, int], dict[int, tuple[int, ...]]]:
    ccc: dict[int, int] = {}
    decomp: dict[int, tuple[int, ...]] = {}
    for raw in UCD.read_text(encoding="utf-8").splitlines():
        if not raw or raw.startswith("#"):
            continue
        fields = raw.split(";")
        if len(fields) < 6:
            continue
        cp = parse_hex(fields[0])
        cls = int(fields[3] or "0")
        dec_raw = fields[5].strip()
        dec: tuple[int, ...] = ()
        if dec_raw and not dec_raw.startswith("<"):
            dec = tuple(parse_hex(part) for part in dec_raw.split())
        if cls != 0 or dec:
            ccc[cp] = cls
            decomp[cp] = dec
    return ccc, decomp


def parse_nfc_qc_ranges() -> list[tuple[int, int, str]]:
    ranges: list[tuple[int, int, str]] = []
    for raw in DNP.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ";" not in line:
            continue
        parts = [part.strip() for part in line.split(";")]
        if len(parts) >= 3 and parts[1] == "NFC_QC":
            lo, hi = parse_codepoint_range(parts[0])
            ranges.append((lo, hi, parts[2]))
    return ranges


def nfc_qc(cp: int, ranges: list[tuple[int, int, str]]) -> str:
    for lo, hi, value in ranges:
        if lo <= cp <= hi:
            return value
    return "Y"


def is_hangul_syllable(cp: int) -> bool:
    return 0xAC00 <= cp < 0xAC00 + 11172


def main() -> None:
    ccc, decomp = parse_unicode_data()
    nfc_ranges = parse_nfc_qc_ranges()

    @lru_cache(maxsize=None)
    def rank(cp: int) -> int:
        dec = decomp.get(cp, ())
        if not dec:
            return 0
        return 1 + max(rank(part) for part in dec)

    relevant: list[tuple[int, int, int, int]] = []
    for cp in sorted(decomp):
        dec = decomp[cp]
        if (
            ccc.get(cp, 0) == 0
            and nfc_qc(cp, nfc_ranges) == "Y"
            and dec
            and not is_hangul_syllable(cp)
        ):
            if len(dec) != 2:
                raise SystemExit(f"non-binary relevant decomposition: {cp:04X} {dec}")
            left, right = dec
            if decomp.get(right, ()):
                raise SystemExit(f"non-terminal right component: {cp:04X} -> {right:04X}")
            r = rank(cp)
            if r < 1 or r > 3:
                raise SystemExit(f"unexpected rank {r} for {cp:04X}")
            if rank(left) >= r:
                raise SystemExit(f"left rank does not decrease: {cp:04X} -> {left:04X}")
            relevant.append((cp, r, left, right))

    by_rank: dict[int, list[tuple[int, int, int, int]]] = {
        r: [entry for entry in relevant if entry[1] == r] for r in (1, 2, 3)
    }

    def entry_literal(entry: tuple[int, int, int, int]) -> str:
        cp, r, left, right = entry
        return (
            f"  {{ codepoint := {hex_nat(cp)}, rank := {r}, "
            f"left := {hex_nat(left)}, right := {hex_nat(right)} }},"
        )

    lines: list[str] = [
        "/-",
        "  Unicode.Normalization.QuickCheckSingletonRankData",
        "",
        "  Generated canonical-decomposition rank data for QC=Y starter",
        "  singleton soundness. Source: Unicode/Ucd/*.txt.",
        "-/",
        "",
        "import Unicode.Normalization.NFC",
        "import Unicode.Normalization.Lookup",
        "import Unicode.Normalization.Hangul",
        "import Unicode.Generated.UnicodeData",
        "",
        "namespace Unicode.Normalization.QuickCheckSingletonRankData",
        "",
        "open Unicode.Normalization",
        "open Unicode.Normalization.NFC (nfcQCValue)",
        "open Unicode.Generated",
        "",
        "set_option maxRecDepth 100000",
        "",
        "structure SingletonRankRow where",
        "  codepoint : Nat",
        "  rank      : Nat",
        "  left      : Nat",
        "  right     : Nat",
        "  deriving Repr, Inhabited",
        "",
    ]

    for r in (1, 2, 3):
        lines.append(f"def rowsRank{r} : List SingletonRankRow := [")
        lines.extend(entry_literal(entry) for entry in by_rank[r])
        lines.append("]")
        lines.append("")

    lines.extend(
        [
            "def rows : List SingletonRankRow :=",
            "  rowsRank1 ++ rowsRank2 ++ rowsRank3",
            "",
            "def rowFieldsMatch (entry : SingletonRankRow) : Bool :=",
            "  UnicodeData.rowsList.any (fun row =>",
            "    decide (row.codepoint = entry.codepoint ∧",
            "      row.canonicalCombiningClass = 0 ∧",
            "      row.canonicalDecomposition = #[entry.left, entry.right]))",
            "",
            "def entryCommonValid (entry : SingletonRankRow) : Bool :=",
            "  rowFieldsMatch entry &&",
            "  decide (nfcQCValue entry.codepoint = .Y) &&",
            "  decide (Hangul.isHangulSyllable entry.codepoint = false) &&",
            "  decide (Lookup.canonicalCombiningClass entry.codepoint = 0) &&",
            "  decide (Lookup.canonicalDecomposition entry.codepoint = #[entry.left, entry.right]) &&",
            "  decide (Lookup.canonicalCombiningClass entry.left = 0) &&",
            "  decide (nfcQCValue entry.left = .Y) &&",
            "  decide (Hangul.isHangulSyllable entry.left = false) &&",
            "  decide (Lookup.canonicalDecomposition entry.right = #[]) &&",
            "  decide (Hangul.isHangulSyllable entry.right = false) &&",
            "  decide (Hangul.composePair? entry.left entry.right = none)",
            "",
            "def entryRankValid (entry : SingletonRankRow) : Bool :=",
            "  entryCommonValid entry &&",
            "  if entry.rank = 1 then",
            "    decide (Lookup.canonicalDecomposition entry.left = #[])",
            "  else if entry.rank = 2 then",
            "    rowsRank1.any (fun parent => decide (parent.codepoint = entry.left))",
            "  else if entry.rank = 3 then",
            "    rowsRank2.any (fun parent => decide (parent.codepoint = entry.left))",
            "  else false",
            "",
            "def parentRightOrderValid (parents : List SingletonRankRow) (entry : SingletonRankRow) : Bool :=",
            "  parents.any (fun parent =>",
            "    decide (parent.codepoint = entry.left ∧",
            "      (Lookup.canonicalCombiningClass entry.right = 0 ∨",
            "        Lookup.canonicalCombiningClass parent.right ≤",
            "          Lookup.canonicalCombiningClass entry.right)))",
            "",
        ]
    )

    for r in (1, 2, 3):
        lines.extend(
            [
                f"theorem rowsRank{r}_valid :",
                f"    rowsRank{r}.all entryRankValid = true := by",
                "  decide +kernel",
                "",
            ]
        )

    for r in (1, 2, 3):
        lines.extend(
            [
                f"theorem rowsRank{r}_rank :",
                f"    rowsRank{r}.all (fun entry => decide (entry.rank = {r})) = true := by",
                "  decide +kernel",
                "",
            ]
        )

    lines.extend(
        [
            "theorem rowsRank2_parentRightOrder_valid :",
            "    rowsRank2.all (parentRightOrderValid rowsRank1) = true := by",
            "  decide +kernel",
            "",
            "theorem rowsRank3_parentRightOrder_valid :",
            "    rowsRank3.all (parentRightOrderValid rowsRank2) = true := by",
            "  decide +kernel",
            "",
        ]
    )

    lines.extend(
        [
            "theorem relevant_rows_covered :",
            "    UnicodeData.rowsList.all (fun row =>",
            "      decide (row.canonicalCombiningClass ≠ 0) ||",
            "      decide (Hangul.isHangulSyllable row.codepoint = true) ||",
            "      decide (nfcQCValue row.codepoint ≠ .Y) ||",
            "      decide (row.canonicalDecomposition.size = 0) ||",
            "      rows.any (fun entry => decide (entry.codepoint = row.codepoint))) = true := by",
            "  decide +kernel",
            "",
            "theorem max_rank_three :",
            "    rows.all (fun entry => decide (1 ≤ entry.rank ∧ entry.rank ≤ 3)) = true := by",
            "  decide +kernel",
            "",
            "end Unicode.Normalization.QuickCheckSingletonRankData",
            "",
        ]
    )

    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} ({len(relevant)} rows; "
          f"rank1={len(by_rank[1])}, rank2={len(by_rank[2])}, rank3={len(by_rank[3])})")


if __name__ == "__main__":
    main()
