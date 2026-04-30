/-
  Unicode.Codec.Bom

  Byte-Order-Mark detection across the five Unicode encodings:

    UTF-8    : EF BB BF              (3 bytes)
    UTF-16BE : FE FF                 (2 bytes)
    UTF-16LE : FF FE                 (2 bytes)
    UTF-32BE : 00 00 FE FF           (4 bytes)
    UTF-32LE : FF FE 00 00           (4 bytes)

  Order matters: UTF-32 BOMs share their leading bytes with UTF-16
  BOMs, so the 4-byte UTF-32 patterns must be checked BEFORE the
  2-byte UTF-16 patterns. Specifically, `FF FE 00 00` is a UTF-32LE
  BOM, not a UTF-16LE BOM followed by two NUL bytes.
-/

namespace Unicode.Codec.Bom

/-- The five Unicode encoding kinds distinguishable by their BOM. -/
inductive BomKind where
  | utf8
  | utf16BE
  | utf16LE
  | utf32BE
  | utf32LE
  deriving Repr, DecidableEq, Inhabited

/-- The byte length of each BOM. -/
def BomKind.length : BomKind → Nat
  | .utf8    => 3
  | .utf16BE => 2
  | .utf16LE => 2
  | .utf32BE => 4
  | .utf32LE => 4

/-- Detect a leading BOM, returning the encoding kind and the number
    of BOM bytes to skip. The 4-byte UTF-32 BOMs are tested before
    the 2-byte UTF-16 BOMs because `FF FE 00 00` is UTF-32LE, not
    UTF-16LE followed by U+0000. Returns `none` if the input does
    not begin with any recognised BOM. -/
def detect (bs : ByteArray) : Option (BomKind × Nat) :=
  if h4 : bs.size ≥ 4 then
    let b0 := (bs[0]'(by omega)).toNat
    let b1 := (bs[1]'(by omega)).toNat
    let b2 := (bs[2]'(by omega)).toNat
    let b3 := (bs[3]'(by omega)).toNat
    -- UTF-32 BE: 00 00 FE FF
    if b0 = 0x00 ∧ b1 = 0x00 ∧ b2 = 0xFE ∧ b3 = 0xFF then
      some (.utf32BE, 4)
    -- UTF-32 LE: FF FE 00 00 (must precede UTF-16 LE check)
    else if b0 = 0xFF ∧ b1 = 0xFE ∧ b2 = 0x00 ∧ b3 = 0x00 then
      some (.utf32LE, 4)
    -- UTF-8: EF BB BF
    else if b0 = 0xEF ∧ b1 = 0xBB ∧ b2 = 0xBF then
      some (.utf8, 3)
    -- UTF-16 BE: FE FF
    else if b0 = 0xFE ∧ b1 = 0xFF then
      some (.utf16BE, 2)
    -- UTF-16 LE: FF FE
    else if b0 = 0xFF ∧ b1 = 0xFE then
      some (.utf16LE, 2)
    else none
  else if h3 : bs.size ≥ 3 then
    let b0 := (bs[0]'(by omega)).toNat
    let b1 := (bs[1]'(by omega)).toNat
    let b2 := (bs[2]'(by omega)).toNat
    if b0 = 0xEF ∧ b1 = 0xBB ∧ b2 = 0xBF then
      some (.utf8, 3)
    else if b0 = 0xFE ∧ b1 = 0xFF then
      some (.utf16BE, 2)
    else if b0 = 0xFF ∧ b1 = 0xFE then
      some (.utf16LE, 2)
    else none
  else if h2 : bs.size ≥ 2 then
    let b0 := (bs[0]'(by omega)).toNat
    let b1 := (bs[1]'(by omega)).toNat
    if b0 = 0xFE ∧ b1 = 0xFF then
      some (.utf16BE, 2)
    else if b0 = 0xFF ∧ b1 = 0xFE then
      some (.utf16LE, 2)
    else none
  else none

/-- Strip the BOM from `bs` if one is present, returning the
    remaining content and the detected encoding. Returns
    `(none, bs)` (no BOM stripped) if the input does not begin with
    a recognised BOM. -/
def strip (bs : ByteArray) : Option BomKind × ByteArray :=
  match detect bs with
  | some (kind, n) => (some kind, bs.extract n bs.size)
  | none           => (none, bs)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 CONCRETE BOM DETECTION
-- ═══════════════════════════════════════════════════════════════════════════════

theorem detect_utf8_bom :
    detect (ByteArray.mk #[0xEF, 0xBB, 0xBF]) = some (.utf8, 3) := by native_decide

theorem detect_utf8_bom_with_content :
    detect (ByteArray.mk #[0xEF, 0xBB, 0xBF, 0x41]) = some (.utf8, 3) := by native_decide

theorem detect_utf16_be_bom :
    detect (ByteArray.mk #[0xFE, 0xFF]) = some (.utf16BE, 2) := by native_decide

theorem detect_utf16_le_bom :
    detect (ByteArray.mk #[0xFF, 0xFE]) = some (.utf16LE, 2) := by native_decide

theorem detect_utf32_be_bom :
    detect (ByteArray.mk #[0x00, 0x00, 0xFE, 0xFF]) = some (.utf32BE, 4) := by native_decide

theorem detect_utf32_le_bom :
    detect (ByteArray.mk #[0xFF, 0xFE, 0x00, 0x00]) = some (.utf32LE, 4) := by native_decide

/-- Critical: UTF-32LE BOM (FF FE 00 00) is detected as UTF-32LE,
    not as UTF-16LE followed by two NUL bytes. -/
theorem detect_prefers_utf32_over_utf16 :
    detect (ByteArray.mk #[0xFF, 0xFE, 0x00, 0x00]) = some (.utf32LE, 4) := by
  native_decide

/-- Empty input has no BOM. -/
theorem detect_empty :
    detect ByteArray.empty = none := by native_decide

/-- Non-BOM content returns none. -/
theorem detect_ascii :
    detect (ByteArray.mk #[0x48, 0x65, 0x6C, 0x6C, 0x6F]) = none := by native_decide

end Unicode.Codec.Bom
