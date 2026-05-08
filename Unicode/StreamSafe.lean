/-
  Unicode.StreamSafe

  UAX #15 § 13 Stream-Safe Text Format. Caps any "combining-mark
  run" — a maximal subsequence of codepoints with non-zero
  Canonical_Combining_Class (CCC) — at 30 characters. Production
  text never approaches this bound; an adversary feeding `a +
  10000 × U+0301` to an unbounded `toNFC` allocates a 10001-codepoint
  result. Stream-Safe enforcement at the input boundary keeps the
  normalization buffer bounded by `O(input.size)` plus a fixed
  constant, eliminating that DoS vector.

  Two operations:

    * `isStreamSafe` — predicate: is `cps` already Stream-Safe?
    * `toStreamSafe` — transformation: insert U+034F COMBINING
                       GRAPHEME JOINER after every 30 consecutive
                       non-zero-CCC codepoints. The result is
                       Stream-Safe and decodes equivalently for
                       most rendering pipelines (CGJ has no visible
                       effect, just resets the combining-mark counter).

  The 30-codepoint limit comes from UAX #15 § 13: "The maximum
  number of non-starters allowed in a row before being broken by
  the insertion of a CGJ is 30." We expose the limit as
  `streamSafeLimit` so it is queryable.
-/

import Unicode.Normalization.Lookup

namespace Unicode.StreamSafe

open Unicode.Normalization.Lookup (canonicalCombiningClass)

/-- UAX #15 § 13 limit: the maximum number of non-starter
    codepoints that may appear in a row before a stream-safe
    breaker (U+034F COMBINING GRAPHEME JOINER) must be inserted. -/
def streamSafeLimit : Nat := 30

/-- U+034F COMBINING GRAPHEME JOINER — the codepoint Stream-Safe
    Text Format inserts to break long combining-mark runs. -/
def cgj : Nat := 0x034F

/-- True iff `cp` is a "non-starter" — a codepoint with non-zero
    Canonical_Combining_Class (UAX #15 D49). Starters have CCC = 0. -/
def isNonStarter (cp : Nat) : Bool :=
  ! decide (canonicalCombiningClass cp = 0)

/-- True iff `cps` contains no run of more than `streamSafeLimit`
    consecutive non-starters. Implemented as a fuel-bounded scan
    that resets the counter on each starter. -/
def isStreamSafeGo (cps : Array Nat) (i : Nat) (run : Nat) (fuel : Nat) : Bool :=
  match fuel with
  | 0           => true
  | fuel' + 1 =>
    if h : i < cps.size then
      let cp := cps[i]
      if isNonStarter cp then
        let run' := run + 1
        if Nat.ble run' streamSafeLimit
          then isStreamSafeGo cps (i + 1) run' fuel'
          else false
      else
        isStreamSafeGo cps (i + 1) 0 fuel'
    else
      true

/-- True iff `cps` is already in Stream-Safe Text Format. -/
def isStreamSafe (cps : Array Nat) : Bool :=
  isStreamSafeGo cps 0 0 cps.size

/-- Build a Stream-Safe Text representation of `cps` by inserting
    U+034F COMBINING GRAPHEME JOINER after every `streamSafeLimit`
    consecutive non-starters. The CGJ acts as a starter, so the
    counter resets to zero immediately after insertion. -/
def toStreamSafeGo (cps : Array Nat) (i : Nat) (run : Nat)
    (acc : Array Nat) (fuel : Nat) : Array Nat :=
  match fuel with
  | 0           => acc
  | fuel' + 1 =>
    if h : i < cps.size then
      let cp := cps[i]
      if isNonStarter cp then
        if Nat.ble streamSafeLimit run then
          toStreamSafeGo cps i 0 (acc.push cgj) fuel'
        else
          toStreamSafeGo cps (i + 1) (run + 1) (acc.push cp) fuel'
      else
        toStreamSafeGo cps (i + 1) 0 (acc.push cp) fuel'
    else
      acc

/-- Transform `cps` into Stream-Safe Text Format by inserting CGJs
    where needed. A starter passes through unchanged; a non-starter
    triggers CGJ insertion when the consecutive non-starter run
    has reached the limit. -/
def toStreamSafe (cps : Array Nat) : Array Nat :=
  toStreamSafeGo cps 0 0 #[] (cps.size * 2 + 1)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 BASIC TEST VECTORS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- ASCII letters are starters; the empty array is trivially Stream-Safe. -/
theorem isStreamSafe_empty : isStreamSafe #[] = true := by native_decide

theorem isStreamSafe_ascii :
    isStreamSafe #[0x61, 0x62, 0x63] = true := by native_decide

/-- A single combining mark following a starter is Stream-Safe. -/
theorem isStreamSafe_one_combine :
    isStreamSafe #[0x61, 0x0301] = true := by native_decide

/-- Thirty combining marks in a row are still Stream-Safe (boundary case). -/
theorem isStreamSafe_thirty_marks :
    isStreamSafe #[0x61,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301] = true := by
  native_decide

/-- Thirty-one combining marks in a row are NOT Stream-Safe. -/
theorem isStreamSafe_thirtyone_marks :
    isStreamSafe #[0x61,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x0301] = false := by
  native_decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 toStreamSafe IS A FIXPOINT FOR ALREADY-STREAM-SAFE INPUT
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The transformation is a no-op on ASCII text. -/
theorem toStreamSafe_ascii :
    toStreamSafe #[0x61, 0x62, 0x63] = #[0x61, 0x62, 0x63] := by native_decide

/-- The transformation is a no-op on a single combining mark. -/
theorem toStreamSafe_one_combine :
    toStreamSafe #[0x61, 0x0301] = #[0x61, 0x0301] := by native_decide

/-- The transformation inserts a CGJ after the 30th non-starter
    in a 31-run, splitting the run. -/
theorem toStreamSafe_thirtyone_marks :
    let input := #[0x61,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x0301]
    let expected := #[0x61,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x034F,
      0x0301]
    toStreamSafe input = expected := by native_decide

/-- A run of 31 marks transforms into a Stream-Safe form. -/
theorem toStreamSafe_makes_safe :
    isStreamSafe (toStreamSafe #[0x61,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x0301, 0x0301, 0x0301, 0x0301, 0x0301,
      0x0301]) = true := by native_decide

end Unicode.StreamSafe
