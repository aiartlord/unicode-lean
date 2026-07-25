/-
  Unicode.Security.Covert.SurrogateReassembly

  C4 — Detection of byte-level UTF-8 anomalies: surrogate
  reassembly (CESU-8 / Java modified UTF-8), overlong encoding,
  truncated sequences, and codepoint-beyond-max attacks.

  Threat model.  Tier A₁ to A₂ (local injector / pipeline
  injector).  Adversary crafts a byte stream that survives
  a downstream decoder either by exploiting a non-strict
  decoder's permissiveness (CESU-8 surrogate pairs, overlong
  encoding) or by relying on inconsistent error-recovery
  across pipeline stages (truncated sequences).

  The Unicode Standard (RFC 3629 §3) defines strict UTF-8 by
  rejecting six categories of byte sequence.  This module reuses
  the existing `Unicode.Codec.Utf8.firstInvalidUtf8Offset` walk
  to surface the *first* invalid offset and its rejection
  category, then projects the category onto a security verdict.

  Sub-threat alignment with `Utf8RejectKind`:

    Utf8RejectKind             →  SubThreat
    ────────────────────────────────────────────────────────────
    .overlongEncoding          →  .overlong
    .surrogateCodepoint        →  .cesu8                (CESU-8
                                                         / Java
                                                         modified
                                                         UTF-8
                                                         indicator)
    .truncatedSequence         →  .truncated
    .invalidStartByte          →  .invalidStartByte
    .invalidContinuationByte   →  .invalidContinuation
    .codepointBeyondMax        →  .codepointBeyondMax

  Input convention.  C4 acts on a *byte stream*, but to keep the
  shared `Unicode.Security.Fixture` row format usable the
  detector accepts `Array Nat` where every value must fit in
  `UInt8`.  Values outside `[0, 255]` are clamped to `255`, a
  byte the strict decoder always rejects, so out-of-range values
  produce a malformed-stream verdict rather than being silently
  dropped.
-/

import Unicode.Security.Calculus
import Unicode.Codec.Utf8
import Unicode.Codec.Strict

namespace Unicode.Security.Covert.SurrogateReassembly

open Unicode.Security.Calculus
open Unicode.Codec.Strict (Utf8RejectKind)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Types
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Sub-threat enumeration for C4.  Each variant carries the
    byte offset at which the malformation was first detected. -/
inductive SubThreat where
  | overlong            (offset : Nat)
  | cesu8               (offset : Nat)   -- surrogate codepoint in UTF-8 stream
  | truncated           (offset : Nat)
  | invalidStartByte    (offset : Nat)
  | invalidContinuation (offset : Nat)
  | codepointBeyondMax  (offset : Nat)
  deriving DecidableEq, Repr, Inhabited

/-- Top-level classification for C4. -/
inductive Classification where
  | clear
  | hazard (sub : SubThreat) (positions : List Nat) (decoded : ByteArray)
  deriving Inhabited

/-- C4 verdict — the structured output of `detect`. -/
structure Verdict where
  input               : List Nat
  classify            : Classification
  byteCount           : Nat
  firstInvalidOffset  : Option Nat
  deriving Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Byte-stream conversion
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Convert a `List Nat` to a `ByteArray`.  Values outside the
    byte range `[0, 255]` are clamped to `255`, which is never a
    valid UTF-8 start byte, so any out-of-range input reaches the
    malformed-stream branch of the decoder. -/
def toByteArray (input : List Nat) : ByteArray :=
  (input.map (fun n => if n > 255 then 255 else UInt8.ofNat n)).toByteArray

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Reject-kind → sub-threat projection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Project a `Utf8RejectKind` to the corresponding `SubThreat`. -/
def subThreatOfRejectKind (offset : Nat) : Utf8RejectKind → SubThreat
  | .overlongEncoding         => .overlong offset
  | .surrogateCodepoint       => .cesu8 offset
  | .truncatedSequence        => .truncated offset
  | .invalidStartByte         => .invalidStartByte offset
  | .invalidContinuationByte  => .invalidContinuation offset
  | .codepointBeyondMax       => .codepointBeyondMax offset

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Top-level detection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The C4 detection function.  Treats `input` as a byte stream
    (one byte per entry, clamped to `0xFF`) and produces a
    structured verdict over the first detected UTF-8 violation. -/
def detect (input : List Nat) : Verdict :=
  let bytes := toByteArray input
  match Unicode.Codec.Utf8.firstInvalidUtf8Offset bytes with
  | none =>
    { input := input,
      classify := .clear,
      byteCount := bytes.size,
      firstInvalidOffset := none }
  | some (offset, kind) =>
    let sub := subThreatOfRejectKind offset kind
    { input := input,
      classify := .hazard sub [offset] bytes,
      byteCount := bytes.size,
      firstInvalidOffset := some offset }

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 Projection helpers
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Fixture-row tag string for each `SubThreat` constructor. -/
def SubThreat.tag : SubThreat → String
  | .overlong            offset => Function.const Nat "Overlong"            offset
  | .cesu8               offset => Function.const Nat "Cesu8"               offset
  | .truncated           offset => Function.const Nat "Truncated"           offset
  | .invalidStartByte    offset => Function.const Nat "InvalidStartByte"    offset
  | .invalidContinuation offset => Function.const Nat "InvalidContinuation" offset
  | .codepointBeyondMax  offset => Function.const Nat "CodepointBeyondMax"  offset

/-- True iff the classification is `.clear`. -/
def Classification.isClear : Classification → Bool
  | .clear                     => true
  | .hazard sub positions decoded =>
      Function.const (SubThreat × List Nat × ByteArray) false
        (sub, positions, decoded)

/-- Tag string of a classification (`none` for `.clear`). -/
def Classification.tag : Classification → Option String
  | .clear                     => none
  | .hazard sub positions decoded =>
      Function.const (List Nat × ByteArray) (some sub.tag) (positions, decoded)

/-- Positions list of a classification (empty for `.clear`). -/
def Classification.positions : Classification → List Nat
  | .clear                     => []
  | .hazard sub positions decoded =>
      Function.const (SubThreat × ByteArray) positions (sub, decoded)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 Spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Empty byte stream is clear. -/
theorem detect_empty_clear : (detect []).classify.isClear = true := by
  decide

/-- Pure ASCII (one byte per char) is valid UTF-8 → clear. -/
theorem detect_ascii_clear :
    (detect [0x48, 0x65, 0x6C, 0x6C, 0x6F]).classify.isClear = true := by
  decide

/-- The standard UTF-8 encoding of `é` (U+00E9 = `0xC3 0xA9`)
    is valid → clear. -/
theorem detect_e_acute_clear :
    (detect [0xC3, 0xA9]).classify.isClear = true := by decide

/-- The standard UTF-8 encoding of `中` (U+4E2D = `0xE4 0xB8 0xAD`)
    is valid → clear. -/
theorem detect_han_clear :
    (detect [0xE4, 0xB8, 0xAD]).classify.isClear = true := by decide

/-- The standard UTF-8 encoding of `😀` (U+1F600 = `0xF0 0x9F 0x98 0x80`)
    is valid → clear. -/
theorem detect_emoji_clear :
    (detect [0xF0, 0x9F, 0x98, 0x80]).classify.isClear = true := by
  decide

/-- The 2-byte sequence `0xC0 0x80` (Java modified-UTF-8 NUL)
    is rejected at the start byte — RFC 3629 §4 forbids
    `0xC0`/`0xC1` outright, before the overlong check can fire. -/
theorem detect_modified_utf8_null :
    (detect [0xC0, 0x80]).classify.tag = some "InvalidStartByte" := by
  decide

/-- The 2-byte sequence `0xC0 0xAF` (overlong slash, 2-byte form)
    is similarly rejected at the start byte. -/
theorem detect_modified_utf8_slash :
    (detect [0xC0, 0xAF]).classify.tag = some "InvalidStartByte" := by
  decide

/-- The 3-byte overlong encoding of `/` (U+002F) as
    `0xE0 0x80 0xAF` — `0xE0` is a valid start byte but the
    encoded value is overlong. -/
theorem detect_overlong_slash_3byte :
    (detect [0xE0, 0x80, 0xAF]).classify.tag = some "Overlong" := by
  decide

/-- The 4-byte overlong encoding of `/` as `0xF0 0x80 0x80 0xAF`. -/
theorem detect_overlong_slash_4byte :
    (detect [0xF0, 0x80, 0x80, 0xAF]).classify.tag = some "Overlong" := by
  decide

/-- Surrogate codepoint U+D800 encoded as `0xED 0xA0 0x80` —
    CESU-8 / Java-modified-UTF-8 indicator. -/
theorem detect_cesu8_surrogate :
    (detect [0xED, 0xA0, 0x80]).classify.tag = some "Cesu8" := by
  decide

/-- High surrogate U+DBFF encoded as `0xED 0xAF 0xBF`. -/
theorem detect_cesu8_surrogate_high :
    (detect [0xED, 0xAF, 0xBF]).classify.tag = some "Cesu8" := by
  decide

/-- Truncated 2-byte sequence (leading `0xC3` with no continuation). -/
theorem detect_truncated_2byte :
    (detect [0xC3]).classify.tag = some "Truncated" := by decide

/-- Truncated 4-byte sequence (leading `0xF0` with only two
    continuation bytes). -/
theorem detect_truncated_4byte :
    (detect [0xF0, 0x9F, 0x98]).classify.tag = some "Truncated" := by
  decide

/-- Invalid start byte `0xFE`. -/
theorem detect_invalid_start :
    (detect [0xFE]).classify.tag = some "InvalidStartByte" := by
  decide

/-- Lone continuation byte `0x80` — `.invalidStartByte`. -/
theorem detect_lone_continuation :
    (detect [0x80]).classify.tag = some "InvalidStartByte" := by
  decide

/-- A `0xFF` byte never appears in valid UTF-8. -/
theorem detect_byte_ff :
    (detect [0xFF]).classify.tag = some "InvalidStartByte" := by
  decide

end Unicode.Security.Covert.SurrogateReassembly
