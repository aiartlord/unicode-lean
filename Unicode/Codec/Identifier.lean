/-
  Unicode.Codec.Identifier

  Strict ASCII identifier predicate: ASCII letter or low-line first,
  followed by ASCII letters, decimal digits, or low-line.

    * First byte MUST be in 0x41..0x5A (A–Z), 0x61..0x7A (a–z), or 0x5F.
    * Subsequent bytes MUST be in the first-byte set OR 0x30..0x39 (0–9).
    * Empty byte arrays are REJECTED.

  This codec stays strict ASCII permanently. Callers needing Unicode
  identifiers use a separate `PrecisIdentifier` codec per RFC 8264/8265,
  providing defense-in-depth: ASCII belt + PRECIS suspenders.

  Three layers, mirroring `Unicode.Codec.OpaqueBlob`:
    * `isIdentifierStartByte` / `isIdentifierContinueByte` — byte-class
                                          predicates for the first and
                                          continuation positions.
    * `firstInvalidIdentifierContinueFrom` — walker returning the first
                                          continuation byte that fails.
    * `isValidIdentifierBytes`             — Boolean aggregate predicate.
    * `IdentifierUtf8 maxBytes`            — refinement type carrying the
                                          bytes plus the validity proof
                                          and a size bound.
    * `IdentifierUtf8.ofBytes?`            — smart constructor.

  Strict-cohesion (StrictBox + RejectReason) and any wire-format framing
  are downstream concerns; this module owns only the specification-level
  predicate, the refinement type, and the constructor.
-/

namespace Unicode.Codec.Identifier

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 BYTE-CLASS PREDICATES
-- ═══════════════════════════════════════════════════════════════════════════════

/-- A byte starts an ASCII identifier when it is `A..Z`, `a..z`, or low-line. -/
def isIdentifierStartByte (b : UInt8) : Bool :=
  decide (
    (0x41 ≤ b.toNat ∧ b.toNat ≤ 0x5A)
    ∨ (0x61 ≤ b.toNat ∧ b.toNat ≤ 0x7A)
    ∨ b.toNat = 0x5F
  )

/-- A byte continues an ASCII identifier when it is in the start-byte
    set or `0..9`. -/
def isIdentifierContinueByte (b : UInt8) : Bool :=
  decide (
    (0x41 ≤ b.toNat ∧ b.toNat ≤ 0x5A)
    ∨ (0x61 ≤ b.toNat ∧ b.toNat ≤ 0x7A)
    ∨ b.toNat = 0x5F
    ∨ (0x30 ≤ b.toNat ∧ b.toNat ≤ 0x39)
  )

theorem isStart_A : isIdentifierStartByte 0x41 = true := by decide
theorem isStart_z : isIdentifierStartByte 0x7A = true := by decide
theorem isStart_underscore : isIdentifierStartByte 0x5F = true := by decide
theorem isStart_digit : isIdentifierStartByte 0x39 = false := by decide
theorem isStart_space : isIdentifierStartByte 0x20 = false := by decide

theorem isContinue_digit : isIdentifierContinueByte 0x39 = true := by decide
theorem isContinue_space : isIdentifierContinueByte 0x20 = false := by decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 CONTINUE-BYTE WALKER
-- ═══════════════════════════════════════════════════════════════════════════════

def firstInvalidIdentifierContinueList :
    Nat → List UInt8 → Option (Nat × UInt8)
  | offset, bytes =>
    match bytes with
    | [] => none
    | b :: rest =>
      if isIdentifierContinueByte b then
        firstInvalidIdentifierContinueList (offset + 1) rest
      else
        some (offset, b)

/-- Walk the continuation positions of `bs` starting at `i`, returning
    the offset and value of the first byte that fails
    `isIdentifierContinueByte`. Returns `none` when every position from
    `i` onward is a valid continuation byte. -/
def firstInvalidIdentifierContinueFrom (bs : List UInt8) (i : Nat) :
    Option (Nat × UInt8) :=
  firstInvalidIdentifierContinueList i (bs.drop i)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 AGGREGATE PREDICATE
-- ═══════════════════════════════════════════════════════════════════════════════

/-- ASCII-identifier predicate: non-empty, valid start byte at position
    zero, and every subsequent byte a valid continuation byte. -/
def isValidIdentifierBytes (bs : List UInt8) : Bool :=
  if h : 0 < bs.length then
    isIdentifierStartByte (bs[0]'h)
      && (firstInvalidIdentifierContinueFrom bs 1).isNone
  else
    false

theorem hello_is_identifier :
    isValidIdentifierBytes ([0x68, 0x65, 0x6C, 0x6C, 0x6F]) = true := by
  rfl
theorem var_1_is_identifier :
    isValidIdentifierBytes ([0x76, 0x61, 0x72, 0x5F, 0x31]) = true := by
  rfl
theorem underscore_start :
    isValidIdentifierBytes ([0x5F]) = true := by
  rfl
theorem empty_not_identifier :
    isValidIdentifierBytes ([] : List UInt8) = false := by
  rfl
theorem leading_digit_not :
    isValidIdentifierBytes ([0x31, 0x76, 0x61, 0x72]) = false := by
  rfl
theorem embedded_space_not :
    isValidIdentifierBytes ([0x61, 0x20, 0x62]) = false := by
  rfl
theorem high_bit_not :
    isValidIdentifierBytes ([0x41, 0xFF]) = false := by
  rfl

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 REFINEMENT TYPE
-- ═══════════════════════════════════════════════════════════════════════════════

/-- A byte sequence carrying its size bound and identifier-validity
    proof. -/
structure IdentifierUtf8 (maxBytes : Nat) where
  bytes   : List UInt8
  sizeOk  : bytes.length ≤ maxBytes
  validId : isValidIdentifierBytes bytes = true

instance (maxBytes : Nat) : DecidableEq (IdentifierUtf8 maxBytes) := fun a b =>
  if h : a.bytes = b.bytes then
    isTrue (by cases a; cases b; simp only [IdentifierUtf8.mk.injEq]; exact h)
  else
    isFalse (fun heq => h (by rw [heq]))

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 CONSTRUCTION
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Build an `IdentifierUtf8` value from a `List UInt8`, returning `none`
    when either the size bound or identifier validity is violated. -/
def IdentifierUtf8.ofBytes? (maxBytes : Nat) (bs : List UInt8) :
    Option (IdentifierUtf8 maxBytes) :=
  if hSize : bs.length ≤ maxBytes then
    if hValid : isValidIdentifierBytes bs = true then
      some ⟨bs, hSize, hValid⟩
    else none
  else none

/-- An `IdentifierUtf8` constructed from its own bytes resolves to itself. -/
theorem IdentifierUtf8.ofBytes?_self {maxBytes : Nat} (r : IdentifierUtf8 maxBytes) :
    IdentifierUtf8.ofBytes? maxBytes r.bytes = some r := by
  cases r with
  | mk bytes sizeOk validId =>
    unfold ofBytes?
    simp [sizeOk, validId]

end Unicode.Codec.Identifier
