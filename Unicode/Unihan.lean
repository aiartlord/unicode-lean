/-
  Unicode.Unihan

  UAX #38 Unihan database surface for variant relationships and
  numeric values. The Unihan distribution carries a much wider
  field set (radicals, readings, source IDs, dictionary indices);
  this module exposes the two slices most directly used by
  application-layer text processing:

    * Variants     — `simplified`, `traditional`, `semantic`,
                     `specializedSemantic`, `spoofing`, `zVariant`
                     codepoint maps. The `simplified` /
                     `traditional` pair drives Simplified ↔
                     Traditional Chinese conversion at the
                     character level.

    * NumericValues — `primaryNumeric`, `accountingNumeric`, plus
                      four script-specific numeric tables. Lets
                      `一` resolve to `1`, `壹` to `1` (formal
                      banking form), `十` to `10`, etc.

  Both slices are pure lookups against the parsed
  `Unihan_Variants.txt` / `Unihan_NumericValues.txt` rows; no
  pipeline / no transformation. Higher-level conversion
  pipelines (T↔S document conversion, CJK number parsing) belong
  in their own modules.
-/

import Unicode.Generated.UnihanVariants
import Unicode.Generated.UnihanNumeric

namespace Unicode.Unihan

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 VARIANT LOOKUPS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The Simplified Chinese variant(s) of `cp`. Returns `[]` for
    codepoints with no `kSimplifiedVariant` row. -/
def simplifiedVariants (cp : Nat) : List Nat :=
  Unicode.Generated.UnihanVariants.lookup cp .SimplifiedVariant

/-- The Traditional Chinese variant(s) of `cp`. Returns `[]` for
    codepoints with no `kTraditionalVariant` row. -/
def traditionalVariants (cp : Nat) : List Nat :=
  Unicode.Generated.UnihanVariants.lookup cp .TraditionalVariant

/-- The semantic variant(s) of `cp` — characters with the same
    meaning but different graphical form. -/
def semanticVariants (cp : Nat) : List Nat :=
  Unicode.Generated.UnihanVariants.lookup cp .SemanticVariant

/-- The specialized-semantic variant(s) of `cp` — variants
    restricted to particular contexts. -/
def specializedSemanticVariants (cp : Nat) : List Nat :=
  Unicode.Generated.UnihanVariants.lookup cp .SpecializedSemanticVariant

/-- The spoofing variant(s) of `cp` — codepoints visually
    confusable with `cp` and explicitly flagged in the Unihan
    spoofing table. Useful for security-sensitive identifier
    comparison alongside `Unicode.Confusables`. -/
def spoofingVariants (cp : Nat) : List Nat :=
  Unicode.Generated.UnihanVariants.lookup cp .SpoofingVariant

/-- The Z-axis (graphical) variant(s) of `cp`. -/
def zVariants (cp : Nat) : List Nat :=
  Unicode.Generated.UnihanVariants.lookup cp .ZVariant

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 NUMERIC VALUE LOOKUPS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The canonical numeric value of `cp`, if any. Returns `none`
    for codepoints with no `kPrimaryNumeric` entry. -/
def primaryNumeric (cp : Nat) : Option Nat :=
  Unicode.Generated.UnihanNumeric.lookup cp .PrimaryNumeric

/-- The formal-banking-form numeric value of `cp` (e.g. 壹 → 1
    is the banking form of 一 → 1). -/
def accountingNumeric (cp : Nat) : Option Nat :=
  Unicode.Generated.UnihanNumeric.lookup cp .AccountingNumeric

/-- The non-canonical numeric meaning of `cp`, if any. -/
def otherNumeric (cp : Nat) : Option Nat :=
  Unicode.Generated.UnihanNumeric.lookup cp .OtherNumeric

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 TEST VECTORS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- 漢 (U+6F22, traditional) maps to 汉 (U+6C49, simplified). -/
theorem simplified_han :
    simplifiedVariants 0x6F22 = [0x6C49] := by
  simp [simplifiedVariants, Unicode.Generated.UnihanVariants.lookup_u6F22_simplified]

/-- 汉 (U+6C49, simplified) maps to 漢 (U+6F22, traditional). -/
theorem traditional_han :
    traditionalVariants 0x6C49 = [0x6F22] := by
  simp [traditionalVariants, Unicode.Generated.UnihanVariants.lookup_u6C49_traditional]

/-- 国 (U+56FD, simplified country) → 國 (U+570B, traditional). -/
theorem traditional_guo :
    traditionalVariants 0x56FD = [0x570B] := by
  simp [traditionalVariants, Unicode.Generated.UnihanVariants.lookup_u56FD_traditional]

/-- 一 (U+4E00) is the canonical CJK numeric 1. -/
theorem primary_yi : primaryNumeric 0x4E00 = some 1 := by
  simp [primaryNumeric, Unicode.Generated.UnihanNumeric.lookup_u4E00_primary]

/-- 二 (U+4E8C) is 2. -/
theorem primary_er : primaryNumeric 0x4E8C = some 2 := by
  simp [primaryNumeric, Unicode.Generated.UnihanNumeric.lookup_u4E8C_primary]

/-- 十 (U+5341) is 10. -/
theorem primary_shi : primaryNumeric 0x5341 = some 10 := by
  simp [primaryNumeric, Unicode.Generated.UnihanNumeric.lookup_u5341_primary]

/-- 百 (U+767E) is 100. -/
theorem primary_bai : primaryNumeric 0x767E = some 100 := by
  simp [primaryNumeric, Unicode.Generated.UnihanNumeric.lookup_u767E_primary]

/-- 壹 (U+58F9) is the banking form of 1. -/
theorem accounting_yi : accountingNumeric 0x58F9 = some 1 := by
  simp [accountingNumeric, Unicode.Generated.UnihanNumeric.lookup_u58F9_accounting]

/-- A character with no numeric meaning returns `none`. -/
theorem primary_letter_none : primaryNumeric 0x6F22 = none := by
  simp [primaryNumeric, Unicode.Generated.UnihanNumeric.lookup_u6F22_primary]

end Unicode.Unihan
