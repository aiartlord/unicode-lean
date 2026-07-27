/-
  Unicode.Codec.OpaqueBlob

  Opaque text predicate: structurally valid UTF-8, size-bounded.
  No character-class or codepoint filtering beyond UTF-8 validity.

  Intended for callers who apply their own text hardening downstream.
  Direct use in security-sensitive contexts is a gap to escalate —
  hardened identifier and printable profiles layer on top of this
  predicate (RFC 8264 IdentifierClass; the printable-string profile)
  and are exposed as separate modules.

  Three layers:
    * `isUtf8Blob`            — Boolean validity predicate.
    * `Utf8Blob maxBytes`     — refinement type carrying the bytes
                                 plus the validity proof and a size
                                 bound.
    * `Utf8Blob.ofBytes?`     — smart constructor.

  Strict-cohesion (StrictBox + RejectReason) and any wire-format
  framing are downstream concerns; this module owns only the
  specification-level predicate, the refinement type, and the
  constructor.
-/

import Unicode.Codec.Utf8

namespace Unicode.Codec.OpaqueBlob

open Unicode.Codec.Utf8 (firstInvalidUtf8Offset)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 PREDICATE
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Opaque-blob predicate: structurally valid UTF-8.

    Defined via `firstInvalidUtf8Offset.isNone` so any downstream
    offset-tracking variant remains by-definition consistent with
    this Boolean form. -/
def isUtf8Blob (bs : List UInt8) : Bool :=
  (firstInvalidUtf8Offset bs).isNone

theorem empty_is_blob : isUtf8Blob ([] : List UInt8) = true := by decide

/-- The UTF-8 bytes of "hello" form a valid blob. -/
theorem hello_is_blob :
    isUtf8Blob ([0x68, 0x65, 0x6C, 0x6C, 0x6F] : List UInt8) = true := by decide

/-- The UTF-8 bytes of "héllo" (é = U+00E9 → 0xC3 0xA9) form a valid blob. -/
theorem accented_is_blob :
    isUtf8Blob ([0x68, 0xC3, 0xA9, 0x6C, 0x6C, 0x6F] : List UInt8) = true := by decide

/-- The UTF-8 bytes of "日本" (日 = 0xE6 0x97 0xA5, 本 = 0xE6 0x9C 0xAC) form a valid blob. -/
theorem cjk_is_blob :
    isUtf8Blob ([0xE6, 0x97, 0xA5, 0xE6, 0x9C, 0xAC] : List UInt8) = true := by decide

/-- The opaque blob predicate accepts content the printable profile
    rejects (e.g. bidi-override controls). Hardened callers must
    therefore use the printable profile instead of this predicate. -/
theorem bidi_override_is_blob :
    isUtf8Blob ([0xE2, 0x80, 0xAE]) = true := by decide

theorem invalid_start_not_blob :
    isUtf8Blob ([0x80]) = false := by decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 REFINEMENT TYPE
-- ═══════════════════════════════════════════════════════════════════════════════

/-- A byte sequence carrying its size bound and UTF-8 validity proof. -/
structure Utf8Blob (maxBytes : Nat) where
  bytes     : List UInt8
  sizeOk    : bytes.length ≤ maxBytes
  validUtf8 : isUtf8Blob bytes = true

instance (maxBytes : Nat) : DecidableEq (Utf8Blob maxBytes) := fun a b =>
  if h : a.bytes = b.bytes then
    isTrue (by cases a; cases b; simp only [Utf8Blob.mk.injEq]; exact h)
  else
    isFalse (fun heq => h (by rw [heq]))

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 CONSTRUCTION
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Build a `Utf8Blob` value from a `List UInt8`, returning `none` when
    either the size bound or UTF-8 validity is violated. -/
def Utf8Blob.ofBytes? (maxBytes : Nat) (bs : List UInt8) :
    Option (Utf8Blob maxBytes) :=
  if hSize : bs.length ≤ maxBytes then
    if hValid : isUtf8Blob bs = true then
      some ⟨bs, hSize, hValid⟩
    else none
  else none

/-- A `Utf8Blob` constructed from its own bytes resolves to itself. -/
theorem Utf8Blob.ofBytes?_self {maxBytes : Nat} (r : Utf8Blob maxBytes) :
    Utf8Blob.ofBytes? maxBytes r.bytes = some r := by
  cases r with
  | mk bytes sizeOk validUtf8 =>
    unfold ofBytes?
    simp [sizeOk, validUtf8]

end Unicode.Codec.OpaqueBlob
