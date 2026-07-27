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

theorem isNoncharacter_FDD0 : isNoncharacter 0xFDD0 = true := by decide
theorem isNoncharacter_FDEF : isNoncharacter 0xFDEF = true := by decide

/-- Every codepoint in the FDD0..FDEF block is a noncharacter. -/
theorem isNoncharacter_block_FDD0_FDEF :
    ∀ cp : Fin 0x20, isNoncharacter (0xFDD0 + cp.val) = true := by decide

/-- Codepoints just outside the FDD0..FDEF block are not (necessarily) noncharacters. -/
theorem isNoncharacter_FDCF : isNoncharacter 0xFDCF = false := by decide
theorem isNoncharacter_FDF0 : isNoncharacter 0xFDF0 = false := by decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 PLANE-END NONCHARACTERS  (nnFFFE / nnFFFF for n=0..16)
-- ═══════════════════════════════════════════════════════════════════════════════

theorem isNoncharacter_FFFE : isNoncharacter 0xFFFE = true := by decide
theorem isNoncharacter_FFFF : isNoncharacter 0xFFFF = true := by decide

theorem isNoncharacter_1FFFE : isNoncharacter 0x1FFFE = true := by decide
theorem isNoncharacter_1FFFF : isNoncharacter 0x1FFFF = true := by decide

theorem isNoncharacter_10FFFE : isNoncharacter 0x10FFFE = true := by decide
theorem isNoncharacter_10FFFF : isNoncharacter 0x10FFFF = true := by decide

/-- 0x110000 is beyond the codepoint range, so even though its low
    16 bits are 0x0000, it's not flagged. (And conversely, a
    hypothetical 0x110FFE would not be flagged because it exceeds
    the cp ≤ 0x10FFFF gate.) -/
theorem isNoncharacter_beyond_max : isNoncharacter 0x110000 = false := by decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 NEGATIVE CASES (regular codepoints)
-- ═══════════════════════════════════════════════════════════════════════════════

theorem isNoncharacter_A : isNoncharacter 0x0041 = false := by decide
theorem isNoncharacter_eacute : isNoncharacter 0x00E9 = false := by decide
theorem isNoncharacter_hiragana_a : isNoncharacter 0x3042 = false := by decide
theorem isNoncharacter_emoji : isNoncharacter 0x1F600 = false := by decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 ENUMERATION + COUNT
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Enumerate the 66 noncharacters as an Array. -/
def all : List Nat := [
  0xFDD0,
  0xFDD1,
  0xFDD2,
  0xFDD3,
  0xFDD4,
  0xFDD5,
  0xFDD6,
  0xFDD7,
  0xFDD8,
  0xFDD9,
  0xFDDA,
  0xFDDB,
  0xFDDC,
  0xFDDD,
  0xFDDE,
  0xFDDF,
  0xFDE0,
  0xFDE1,
  0xFDE2,
  0xFDE3,
  0xFDE4,
  0xFDE5,
  0xFDE6,
  0xFDE7,
  0xFDE8,
  0xFDE9,
  0xFDEA,
  0xFDEB,
  0xFDEC,
  0xFDED,
  0xFDEE,
  0xFDEF,
  0xFFFE,
  0xFFFF,
  0x01FFFE,
  0x01FFFF,
  0x02FFFE,
  0x02FFFF,
  0x03FFFE,
  0x03FFFF,
  0x04FFFE,
  0x04FFFF,
  0x05FFFE,
  0x05FFFF,
  0x06FFFE,
  0x06FFFF,
  0x07FFFE,
  0x07FFFF,
  0x08FFFE,
  0x08FFFF,
  0x09FFFE,
  0x09FFFF,
  0x0AFFFE,
  0x0AFFFF,
  0x0BFFFE,
  0x0BFFFF,
  0x0CFFFE,
  0x0CFFFF,
  0x0DFFFE,
  0x0DFFFF,
  0x0EFFFE,
  0x0EFFFF,
  0x0FFFFE,
  0x0FFFFF,
  0x10FFFE,
  0x10FFFF
]

/-- The enumeration has exactly 66 elements. -/
theorem count_noncharacters : all.length = 66 := by
  simp [all]

/-- Every enumerated noncharacter satisfies `isNoncharacter`. -/
theorem all_are_noncharacters : all.all isNoncharacter = true := by
  simp [all, isNoncharacter]

/-- Every enumerated noncharacter is in the valid scalar codepoint
    range (i.e. ≤ 0x10FFFF and not a surrogate). -/
theorem all_are_valid_codepoints : all.all (fun cp => decide (IsValidCodepoint cp)) = true := by
  simp [all, IsValidCodepoint]

end Unicode.Codec.Noncharacters
