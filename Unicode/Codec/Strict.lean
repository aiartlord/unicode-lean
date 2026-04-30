/-
  Unicode.Codec.Strict

  Shared types and strict primitives for the tiered text codecs under
  `Unicode.Codec.*`. Defines:

    * RejectReason — structured rejection-cause ADT with byte offsets
    * StrictParseResult α — ok | rejected | incomplete
    * StrictBox α — bidirectional codec shape with `roundtrip` /
      `consumption` constraints over StrictParseResult
    * Utf8RejectKind, PrecisSubReason, ForbiddenCategory enum types
      consumed by the text codecs in this directory
    * TextCodecFamilyRegistryEntry — registry shape for variable-width
      dual-API codecs

  Offset convention: every `offset : Nat` in a RejectReason is a byte
  index into the codec's CONTENT (post-length-prefix), not into the
  outer input buffer.

  `.incomplete (needed : Nat)` follows the streaming semantics used by
  multi-frame codecs. File-ingestion callers treat `.incomplete` as a
  reject with "buffer exhausted relative to declared length"
  interpretation; `finalize` coerces.
-/

namespace Unicode.Codec.Strict

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 FORBIDDEN CATEGORIES (for the printable-UTF-8 codepoint blocklist)
-- ═══════════════════════════════════════════════════════════════════════════════

inductive ForbiddenCategory where
  | bidiOverride
  | bidiIsolate
  | zeroWidth
  | bom
  | tagCharacter
  | variationSelector
  | hangulFiller
  | softHyphen
  | interlinearAnnotation
  | mongolianVowelSeparator
  deriving Repr, DecidableEq, Inhabited

theorem bidiOverride_ne_bom : ForbiddenCategory.bidiOverride ≠ ForbiddenCategory.bom := by
  decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 UTF-8 REJECT KIND (populated by Unicode.Codec.Utf8)
-- ═══════════════════════════════════════════════════════════════════════════════

inductive Utf8RejectKind where
  | invalidStartByte
  | truncatedSequence
  | overlongEncoding
  | surrogateCodepoint
  | codepointBeyondMax
  | invalidContinuationByte
  deriving Repr, DecidableEq, Inhabited

theorem overlong_ne_surrogate :
    Utf8RejectKind.overlongEncoding ≠ Utf8RejectKind.surrogateCodepoint := by decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 PRECIS SUB-REASON (populated by the PRECIS codecs)
-- ═══════════════════════════════════════════════════════════════════════════════

inductive PrecisSubReason where
  | disallowedCategory
  | disallowedBidiClass
  | nfkcMismatch
  | unassignedCodepoint
  | contextualRuleFailed
  deriving Repr, DecidableEq, Inhabited

theorem nfkc_ne_unassigned :
    PrecisSubReason.nfkcMismatch ≠ PrecisSubReason.unassignedCodepoint := by decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 REJECT REASON
-- Every variant that takes `offset : Nat` uses byte offset INTO THE CODEC'S
-- CONTENT (post-length-prefix), not into the outer input buffer.
-- ═══════════════════════════════════════════════════════════════════════════════

inductive RejectReason where
  -- framing
  | sizeExceeded                (actual : Nat) (limit : Nat)
  -- UTF-8 structural (sub-categorised by Utf8RejectKind)
  | utf8InvalidStartByte        (offset : Nat) (byte : UInt8)
  | utf8TruncatedSequence       (offset : Nat)
  | utf8OverlongEncoding        (offset : Nat)
  | utf8Surrogate               (offset : Nat) (cp : Nat)
  | utf8BeyondMaxCodepoint      (offset : Nat) (cp : Nat)
  | utf8InvalidContinuation     (offset : Nat) (byte : UInt8)
  -- ASCII / identifier byte-class rejections
  | nonAsciiByte                (offset : Nat) (byte : UInt8)
  | nonPrintableAsciiByte       (offset : Nat) (byte : UInt8)
  | nonIdentifierStartByte      (offset : Nat) (byte : UInt8)
  | nonIdentifierContinueByte   (offset : Nat) (byte : UInt8)
  | identifierEmpty
  -- Unicode codepoint blocklist
  | forbiddenCodepoint          (offset : Nat) (cp : Nat) (category : ForbiddenCategory)
  -- Unicode semantic gates
  | defaultIgnorable            (offset : Nat) (cp : Nat)
  | notNfcNormalized            (offset : Nat)
  -- PRECIS
  | precisDisallowed            (offset : Nat) (reason : PrecisSubReason)
  -- Numeric refinement violations
  | numericNotPositive          (offset : Nat)
  | numericNotNegative          (offset : Nat)
  | numericIsZero               (offset : Nat)
  | numericOutOfInterval        (offset : Nat)
  | numericNotFinite            (offset : Nat)
  -- Container violations
  | containerLengthMismatch     (offset : Nat) (declared : Nat) (actual : Nat)
  | containerElementRejected    (offset : Nat) (innerReason : RejectReason)
  deriving Repr, DecidableEq, Inhabited

theorem rejectReason_sizeExceeded_concrete :
    RejectReason.sizeExceeded 17 16 = RejectReason.sizeExceeded 17 16 := rfl

theorem rejectReason_forbidden_different_categories_ne :
    RejectReason.forbiddenCodepoint 0 0x202E .bidiOverride
      ≠ RejectReason.forbiddenCodepoint 0 0x202E .bidiIsolate := by decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 STRICT PARSE RESULT
-- ═══════════════════════════════════════════════════════════════════════════════

inductive StrictParseResult (α : Type) where
  | ok         : α → ByteArray → StrictParseResult α
  | rejected   : RejectReason → StrictParseResult α
  | incomplete : (needed : Nat) → StrictParseResult α
  deriving DecidableEq

namespace StrictParseResult

def map {α β : Type} (f : α → β) : StrictParseResult α → StrictParseResult β
  | ok a rest    => ok (f a) rest
  | rejected r   => rejected r
  | incomplete n => incomplete n

def bind {α β : Type} (r : StrictParseResult α)
    (f : α → ByteArray → StrictParseResult β) : StrictParseResult β :=
  match r with
  | ok a rest    => f a rest
  | rejected r'  => rejected r'
  | incomplete n => incomplete n

@[simp] theorem map_ok {α β : Type} (f : α → β) (a : α) (rest : ByteArray) :
    map f (ok a rest) = ok (f a) rest := rfl
@[simp] theorem map_rejected {α β : Type} (f : α → β) (r : RejectReason) :
    map f (rejected r : StrictParseResult α) = (rejected r : StrictParseResult β) := rfl
@[simp] theorem map_incomplete {α β : Type} (f : α → β) (n : Nat) :
    map f (incomplete n : StrictParseResult α) = (incomplete n : StrictParseResult β) := rfl
@[simp] theorem bind_ok {α β : Type} (a : α) (rest : ByteArray)
    (f : α → ByteArray → StrictParseResult β) :
    bind (ok a rest) f = f a rest := rfl
@[simp] theorem bind_rejected {α β : Type} (r : RejectReason)
    (f : α → ByteArray → StrictParseResult β) :
    bind (rejected r : StrictParseResult α) f = (rejected r : StrictParseResult β) := rfl
@[simp] theorem bind_incomplete {α β : Type} (n : Nat)
    (f : α → ByteArray → StrictParseResult β) :
    bind (incomplete n : StrictParseResult α) f = (incomplete n : StrictParseResult β) := rfl

/-- Coerce `.incomplete` to `.rejected` for file-ingestion callers who know
    their input is complete. Loses the "needed N bytes" detail — callers who
    want that detail pattern-match on StrictParseResult directly. -/
def finalize {α : Type} : StrictParseResult α → Sum RejectReason (α × ByteArray)
  | ok a rest    => .inr (a, rest)
  | rejected r   => .inl r
  | incomplete n => .inl (RejectReason.sizeExceeded 0 n)

end StrictParseResult

theorem map_id_strictParseResult {α : Type} (r : StrictParseResult α) :
    StrictParseResult.map (fun x => x) r = r := by
  cases r <;> rfl

theorem bind_rejected_irrespective {α β : Type} (r : RejectReason)
    (f : α → ByteArray → StrictParseResult β) :
    StrictParseResult.bind (StrictParseResult.rejected r) f
      = StrictParseResult.rejected r := rfl

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 STRICT BOX
-- Bidirectional codec shape over StrictParseResult; roundtrip / consumption
-- constrain only the .ok path.
-- ═══════════════════════════════════════════════════════════════════════════════

structure StrictBox (α : Type) where
  parse       : ByteArray → StrictParseResult α
  serialize   : α → ByteArray
  roundtrip   : ∀ a, parse (serialize a) = StrictParseResult.ok a ByteArray.empty
  consumption : ∀ a extra, parse (serialize a ++ extra) = StrictParseResult.ok a extra

-- ═══════════════════════════════════════════════════════════════════════════════
-- §7 REGISTRY (variable-width dual-API shape)
-- ═══════════════════════════════════════════════════════════════════════════════

structure TextCodecFamilyRegistryEntry where
  name            : String
  owner           : String
  basis           : List String
  boxName         : String
  strictBoxName   : String
  wireFormat      : String
  deriving Repr

private def sampleRegistry : TextCodecFamilyRegistryEntry where
  name := "sample"
  owner := "Unicode.Codec"
  basis := ["Unicode.Codec.Strict.StrictBox"]
  boxName := "Unicode.Codec.Sample.sample"
  strictBoxName := "Unicode.Codec.Sample.sampleStrict"
  wireFormat := "u64le-prefix + variable content"

theorem sampleRegistry_name : sampleRegistry.name = "sample" := rfl

end Unicode.Codec.Strict
