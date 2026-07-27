/-
  Unicode.Normalization.ToNFDAppendMirror

  The reducer-friendly mirror of canonical decomposition used to discharge the
  UCD-row starter-head invariant. `fullCanonicalDecompose` and this mirror both
  use the generated low-byte UnicodeData index, so concrete lookups scan a small
  collision bucket instead of the whole 3045-row table.

  This module holds only the DEFINITIONS.  The per-chunk `rowP_c*` facts live
  in `ToNFDAppendRows0..3` (split across files so each `decide +kernel` batch is
  garbage-collected between compilations, bounding peak memory), and the
  equivalence theorems tying the mirror back to `Lookup`/`Decompose` live in
  `ToNFDAppend`.
-/

import Unicode.Generated.UnicodeData
import Unicode.Generated.UnicodeDataIndex
import Unicode.Normalization.Hangul
import Unicode.Normalization.Decompose

namespace Unicode.Normalization.ToNFDAppend

open Unicode.Normalization Unicode.Generated

/-- Tibetan vowel signs whose canonical decomposition begins with a non-starter
    (U+0F71, CCC = 129) — the complete UCD-17.0 anomaly set. -/
def anomalousStarters : List Nat := [0x0F73, 0x0F75, 0x0F81]

def isAnomalousStarter (cp : Nat) : Bool :=
  anomalousStarters.contains cp

/-- Row lookup through the generated low-byte UnicodeData index. -/
def lookupRowL (cp : Nat) : Option UnicodeData.UnicodeDataRow :=
  UnicodeDataIndex.lookupRow? cp

def canonicalDecompositionL (cp : Nat) : List Nat :=
  match lookupRowL cp with
  | some row => row.canonicalDecomposition
  | none => []

def fcdFuelL : Nat → Nat → List Nat
  | 0,        _cp => []
  | fuel + 1, cp =>
    match Hangul.decomposeSyllable? cp with
    | some jamo => jamo
    | none =>
      let step := canonicalDecompositionL cp
      if step.isEmpty then [cp]
      else step.foldl (fun acc cp' => acc ++ fcdFuelL fuel cp') []

def canonicalCombiningClassL (cp : Nat) : Nat :=
  match lookupRowL cp with
  | some row => row.canonicalCombiningClass
  | none => 0

def starterHeadBoolL (arr : List Nat) : Bool :=
  if h : 0 < arr.length then decide (canonicalCombiningClassL (arr[0]'h) = 0) else false

/-- Per-row invariant over the List mirror: the row is anomalous, a non-starter,
    or its full canonical decomposition is starter-headed. -/
def rowP (row : UnicodeData.UnicodeDataRow) : Bool :=
  isAnomalousStarter row.codepoint
  || decide (canonicalCombiningClassL row.codepoint ≠ 0)
  || starterHeadBoolL (fcdFuelL Decompose.maxDepth row.codepoint)

end Unicode.Normalization.ToNFDAppend
