/-
  Unicode.Codec.Noncharacters

  Detection and enumeration of the 66 designated Unicode
  noncharacters per UAX #44 §5.6 / Unicode Standard 17.0 §23.7.

  Two categories:

    * BMP block:    U+FDD0 .. U+FDEF                (32 codepoints)
    * Plane ends:   U+nnFFFE / U+nnFFFF for n=0..16 (34 codepoints)

  Total: 66.

  Noncharacters are reserved for internal use; conformant Unicode
  text MUST NOT contain them in interchange. They are technically
  valid scalar codepoints (in the range and not surrogates), so
  `IsValidCodepoint` includes them; downstream consumers that
  reject noncharacters layer this predicate on top.
-/

import Unicode.Codec.Utf8Roundtrip

namespace Unicode.Codec.Noncharacters

open Unicode.Codec.Utf8Roundtrip (IsValidCodepoint)

/-- True iff `cp` is one of the 66 designated Unicode noncharacters. -/
def isNoncharacter (cp : Nat) : Bool :=
  (0xFDD0 ≤ cp && cp ≤ 0xFDEF) ||
  (cp ≤ 0x10FFFF && (cp &&& 0xFFFF == 0xFFFE || cp &&& 0xFFFF == 0xFFFF))

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 BMP BLOCK NONCHARACTERS  (FDD0..FDEF)
-- ═══════════════════════════════════════════════════════════════════════════════

theorem isNoncharacter_FDD0 : isNoncharacter 0xFDD0 = true := by native_decide
theorem isNoncharacter_FDEF : isNoncharacter 0xFDEF = true := by native_decide

/-- Every codepoint in the FDD0..FDEF block is a noncharacter. -/
theorem isNoncharacter_block_FDD0_FDEF :
    ∀ cp : Fin 0x20, isNoncharacter (0xFDD0 + cp.val) = true := by native_decide

/-- Codepoints just outside the FDD0..FDEF block are not (necessarily) noncharacters. -/
theorem isNoncharacter_FDCF : isNoncharacter 0xFDCF = false := by native_decide
theorem isNoncharacter_FDF0 : isNoncharacter 0xFDF0 = false := by native_decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 PLANE-END NONCHARACTERS  (nnFFFE / nnFFFF for n=0..16)
-- ═══════════════════════════════════════════════════════════════════════════════

theorem isNoncharacter_FFFE : isNoncharacter 0xFFFE = true := by native_decide
theorem isNoncharacter_FFFF : isNoncharacter 0xFFFF = true := by native_decide

theorem isNoncharacter_1FFFE : isNoncharacter 0x1FFFE = true := by native_decide
theorem isNoncharacter_1FFFF : isNoncharacter 0x1FFFF = true := by native_decide

theorem isNoncharacter_10FFFE : isNoncharacter 0x10FFFE = true := by native_decide
theorem isNoncharacter_10FFFF : isNoncharacter 0x10FFFF = true := by native_decide

/-- 0x110000 is beyond the codepoint range, so even though its low
    16 bits are 0x0000, it's not flagged. (And conversely, a
    hypothetical 0x110FFE would not be flagged because it exceeds
    the cp ≤ 0x10FFFF gate.) -/
theorem isNoncharacter_beyond_max : isNoncharacter 0x110000 = false := by native_decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 NEGATIVE CASES (regular codepoints)
-- ═══════════════════════════════════════════════════════════════════════════════

theorem isNoncharacter_A : isNoncharacter 0x0041 = false := by native_decide
theorem isNoncharacter_eacute : isNoncharacter 0x00E9 = false := by native_decide
theorem isNoncharacter_hiragana_a : isNoncharacter 0x3042 = false := by native_decide
theorem isNoncharacter_emoji : isNoncharacter 0x1F600 = false := by native_decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 ENUMERATION + COUNT
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Enumerate the 66 noncharacters as an Array. -/
def all : Array Nat :=
  -- 32 in BMP block
  let bmp := (Array.range 0x20).map (fun i => 0xFDD0 + i)
  -- 17 × 2 plane-ends
  let planes := (Array.range 17).foldl (fun acc n =>
    acc.push (n * 0x10000 + 0xFFFE) |>.push (n * 0x10000 + 0xFFFF)) #[]
  bmp ++ planes

/-- The enumeration has exactly 66 elements. -/
theorem count_noncharacters : all.size = 66 := by native_decide

/-- Every enumerated noncharacter satisfies `isNoncharacter`. -/
theorem all_are_noncharacters : all.all isNoncharacter = true := by native_decide

/-- Every enumerated noncharacter is in the valid scalar codepoint
    range (i.e. ≤ 0x10FFFF and not a surrogate). -/
theorem all_are_valid_codepoints : all.all (fun cp => decide (IsValidCodepoint cp)) = true := by
  native_decide

end Unicode.Codec.Noncharacters
