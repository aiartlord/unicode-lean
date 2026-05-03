/-
  Unicode.Uca.Lookup

  Greedy longest-match DUCET lookup, plus the implicit-weight
  fallback for codepoints absent from the explicit table.

  Per UTS #10 §10.1, codepoints not covered by DUCET get a synthetic
  pair of collation elements computed algorithmically:

      AAAA = base + (cp >>> 15)
      BBBB = (cp & 0x7FFF) | 0x8000

  where `base` depends on which range the codepoint falls in:

      Tangut + Tangut Components / Supplement   → FB00
      Nushu                                     → FB01
      Khitan Small Script                       → FB02
      CJK Unified Ideographs / CJK Compat       → FB40 / FB80
      Other unassigned Han                      → FB80
      Everything else                           → FBC0

  This module implements both the explicit-table greedy match and
  the algorithmic fallback; the next layer (`Unicode.Uca.SortKey`)
  consumes its output to build the sort key.
-/

import Std.Data.HashMap
import Unicode.Generated.Allkeys
import Unicode.Generated.PropListUca16
import Unicode.Normalization.Lookup

namespace Unicode.Uca.Lookup

open Unicode.Generated.Allkeys

/-- DUCET index from "first codepoint of key" → list of entries
    sharing that first codepoint. Built once at module load so every
    subsequent lookup is O(k) where k is the small bucket size,
    instead of O(39 407) over the full table. -/
def ducetIndex : Std.HashMap Nat (Array DucetEntry) := Id.run do
  let mut acc : Std.HashMap Nat (Array DucetEntry) :=
    Std.HashMap.emptyWithCapacity 4096
  for entry in ducetEntries do
    if h : 0 < entry.key.size then
      let cp := entry.key[0]
      let bucket := acc.getD cp #[]
      acc := acc.insert cp (bucket.push entry)
  return acc

/-- Bucket of DUCET entries whose key starts with `cp`. Empty when
    no explicit entry begins with `cp` — the caller falls back to
    the implicit-weight branch. -/
def bucketFor (cp : Nat) : Array DucetEntry := ducetIndex.getD cp #[]

/-- True iff `cps[start..start+key.size]` equals `key` exactly. -/
def matchesAt (cps : Array Nat) (start : Nat) (key : Array Nat) : Bool := Id.run do
  if start + key.size > cps.size then return false
  for h : i in [0:key.size] do
    let kVal := key[i]
    match cps[start + i]? with
    | none      => return false
    | some cVal => if kVal ≠ cVal then return false
  return true

/-- Find the longest DUCET entry whose key prefixes `cps[start..]`.
    Lookup is bucketed by the first codepoint, so the inner scan is
    over a handful of contraction candidates rather than the entire
    table. -/
def longestMatchAt (cps : Array Nat) (start : Nat) : Option (DucetEntry × Nat) := Id.run do
  match cps[start]? with
  | none    => return none
  | some cp =>
    let bucket := bucketFor cp
    let mut best : Option (DucetEntry × Nat) := none
    for entry in bucket do
      if matchesAt cps start entry.key then
        let len := entry.key.size
        match best with
        | none             => best := some (entry, len)
        | some (oldEntry, oldLen) =>
          if len > oldLen then
            best := some (entry, len)
          else
            best := some (oldEntry, oldLen)
    return best

/-- True iff `cp` falls inside the given `@implicitweights` block. -/
def inImplicitBlock (cp : Nat) (b : ImplicitBlock) : Bool :=
  decide (b.min ≤ cp ∧ cp ≤ b.max)

/-- True iff `cp` lies in the CJK Unified Ideographs block
    (U+4E00..U+9FFF) or the CJK Compatibility Ideographs block
    (U+F900..U+FAFF). Used to split the Han Core tier from the
    Han Other tier in `implicitBaseFor`. -/
def inHanCoreBlock (cp : Nat) : Bool :=
  decide ((0x4E00 ≤ cp ∧ cp ≤ 0x9FFF) ∨ (0xF900 ≤ cp ∧ cp ≤ 0xFAFF))

/-- Implicit-weight base AAAA for `cp`, per UTS #10 §10.1.3 / Table 16.
    Four cases, evaluated in order:

      * `@implicitweights` blocks (Tangut, Nushu, Khitan, Jurchen,
        Seal in 16.0) — explicit directives in `allkeys.txt`.
      * Han Core (FB40): `Unified_Ideograph = Yes` AND in CJK
        Unified Ideographs OR CJK Compatibility Ideographs blocks.
      * Han Other (FB80): `Unified_Ideograph = Yes` AND NOT in those
        blocks (CJK Extensions A..I, restricted to assigned
        ideographs only).
      * Everything else (FBC0): unassigned codepoints, including
        the reserved gaps between consecutive CJK extension blocks. -/
def implicitBaseFor (cp : Nat) : Nat :=
  match implicitBlocks.findSome? (fun b =>
    if inImplicitBlock cp b then some b.base else none) with
  | some base => base
  | none =>
    if Unicode.Generated.PropListUca16.isUnifiedIdeograph cp then
      if inHanCoreBlock cp then 0xFB40 else 0xFB80
    else
      0xFBC0

/-- Implicit collation elements for `cp`, returned as a pair of
    elements per UTS #10 §10.1. -/
def implicitElements (cp : Nat) : Array CollationElement :=
  let base := implicitBaseFor cp
  let aaaa := base + (cp >>> 15)
  let bbbb := (cp &&& 0x7FFF) ||| 0x8000
  #[⟨aaaa, 0x0020, 0x0002, false⟩,
    ⟨bbbb, 0x0000, 0x0000, false⟩]

/-- Synthesize a default DUCET entry for `cp` when no explicit
    table entry covers it. -/
def implicitEntry (cp : Nat) : DucetEntry :=
  ⟨#[cp], implicitElements cp⟩

/-- Resolve the next collation step at `cps[start..]`. Returns
    the matched entry and the number of input codepoints consumed.
    Falls back to an implicit-weight entry for codepoints absent
    from the explicit DUCET. -/
def resolveAt (cps : Array Nat) (start : Nat) : DucetEntry × Nat :=
  match longestMatchAt cps start with
  | some (entry, len) => (entry, len)
  | none =>
    match cps[start]? with
    | some cp => (implicitEntry cp, 1)
    | none    => (implicitEntry 0, 0)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §X DISCONTIGUOUS MATCHING  (UTS #10 §6.1 / S2.1)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- One step's match result: the collation elements to emit, plus the
    sorted ascending list of input positions consumed by this step.
    Position `start` is always in `consumed`; additional positions
    appear when a discontiguous contraction match has skipped over
    blocked-class non-starters to find a longer key. -/
structure MatchStep where
  ces      : Array CollationElement
  consumed : Array Nat
  deriving Inhabited

/-- Look up a DUCET entry whose key exactly equals `target` within a
    bucket already filtered on the first codepoint. -/
def findInBucket (bucket : Array DucetEntry) (target : Array Nat) :
    Option DucetEntry :=
  bucket.findSome? (fun e => if e.key = target then some e else none)

/-- One walk step. Find the longest contiguous DUCET entry starting
    at `start`, then attempt to extend it discontiguously by
    appending unblocked non-starters that lie further along the
    input. Per UTS #10 §S2.1, a non-starter `c` at position `j` can
    be appended only when no unconsumed non-starter between the
    current end of the matched key and `j` has CCC ≥ CCC(c) — after
    NFD reordering, this is equivalent to requiring that the
    most-recently-skipped non-starter has strictly lower CCC than
    `c`. Successful extensions reset the skipped-CCC tracker. -/
def matchAt (cps : Array Nat) (consumed : Array Bool) (start : Nat) :
    MatchStep := Id.run do
  match cps[start]? with
  | none    => return ⟨#[], #[start]⟩
  | some cp =>
    let bucket := bucketFor cp
    -- Phase 1: longest contiguous prefix match. The `gotMatch` flag
    -- distinguishes "no DUCET hit so use implicit fallback" from
    -- "single-cp DUCET hit", since both have key length 1.
    let mut bestEntry : DucetEntry := implicitEntry cp
    let mut bestKey   : Array Nat   := #[cp]
    let mut bestLen   : Nat         := 1
    let mut gotMatch  : Bool        := false
    for entry in bucket do
      if matchesAt cps start entry.key then
        if !gotMatch ∨ entry.key.size > bestLen then
          bestEntry := entry
          bestKey   := entry.key
          bestLen   := entry.key.size
          gotMatch  := true
    let mut consumedHere : Array Nat :=
      (Array.range bestLen).map (fun k => start + k)
    -- Phase 2: discontiguous extension per UTS #10 §7.2 S2.1.1–S2.1.3.
    -- Walk forward from the end of the contiguous match. For each
    -- non-starter C at position j: if C is unblocked w.r.t. S
    -- (`CCC(C) > maxSkippedCCC`), try `bestKey ++ #[C]` against the
    -- bucket; on success extend the match and reset `maxSkippedCCC`,
    -- on failure record C as skipped (`maxSkippedCCC := max …`). If C
    -- is blocked (`CCC(C) ≤ maxSkippedCCC`), advance past C without
    -- trying to extend; C's CCC is already covered by the running max.
    -- The scan terminates on a starter (CCC = 0) or end of input.
    -- Bound the loop by `cps.size` so totality is structural.
    let mut j              : Nat := start + bestLen
    let mut maxSkippedCCC  : Nat := 0
    let n := cps.size
    for _step in [0:n] do
      if j ≥ n then break
      if (consumed[j]?.getD true) then
        j := j + 1
      else
        let c := cps[j]!
        let cCCC := Unicode.Normalization.Lookup.canonicalCombiningClass c
        if cCCC = 0 then
          break
        if cCCC > maxSkippedCCC then
          let candidateKey := bestKey.push c
          match findInBucket bucket candidateKey with
          | some entry =>
            bestEntry     := entry
            bestKey       := candidateKey
            consumedHere  := consumedHere.push j
            maxSkippedCCC := 0
          | none =>
            maxSkippedCCC := cCCC
        j := j + 1
    return ⟨bestEntry.ces, consumedHere⟩

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 SPOT CHECKS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- "abc" — three single-codepoint lookups, no contraction. -/
theorem resolveAt_abc_at_0 :
    (resolveAt #[0x0061, 0x0062, 0x0063] 0).snd = 1 := by native_decide

/-- 006C 00B7 (LATIN SMALL LETTER L + MIDDLE DOT) is a contraction —
    a two-codepoint match wins over the single-cp 'l' lookup. -/
theorem resolveAt_l_middledot :
    (resolveAt #[0x006C, 0x00B7, 0x0061] 0).snd = 2 := by native_decide

/-- A codepoint outside DUCET (U+E0000 in PUA-A) falls back to an
    implicit entry with two synthetic elements. -/
theorem resolveAt_pua :
    (resolveAt #[0xE0000] 0).fst.ces.size = 2 := by native_decide

/-- A CJK Unified Ideograph (U+4E2D 中) lands in the 0xFB40 implicit
    range and produces an implicit entry. -/
theorem resolveAt_cjk :
    (resolveAt #[0x4E2D] 0).fst.ces.size = 2 := by native_decide

end Unicode.Uca.Lookup
