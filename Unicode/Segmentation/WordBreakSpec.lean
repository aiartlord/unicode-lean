/-
  Unicode.Segmentation.WordBreakSpec

  Correctness scaffolding for the UAX #29 word-break algorithm
  (`Unicode.Segmentation.WordBreak.wordBreaks`), following the method proven on
  grapheme break in `GraphemeBreakSpec`: characterise the algorithm's state
  against declarative patterns over the raw prefix, then compose.

  Word break differs from grapheme break structurally: instead of threading one
  bounded `State`, it precomputes three arrays over the class sequence —
  `buildEffPrev` (the effective previous and prev-previous class, WB4 skipping
  Extend/Format/ZWJ), `buildEffNext` (the effective next class, via a reverse
  scan, for the WB6/WB7b/WB12 lookahead), and `buildEffRiRun` (the WB15/WB16
  Regional_Indicator run) — then `shouldBreakBefore` indexes them per position.

  So the first obligation is to characterise each precomputed array: element `i`
  is a pure function of the prefix `lits[0..i-1]`. This file begins with the
  common shape — every builder is a left fold that pushes one entry per input,
  so the output length matches the input and entry `i` is the fold's carry after
  the first `i` inputs.
-/

import Unicode.Segmentation.WordBreak
import Unicode.Segmentation.PrefixScan

namespace Unicode.Segmentation.WordBreak

open Unicode.Generated.WordBreakProperty (WBClass lookupWB)
open Unicode.Generated.EmojiData (isExtendedPictographic)

-- The precompute builders are `Array.foldl (push carry; update carry)`. The
-- following bridges each to `List.foldl` over `lits.toList`, so the entry at a
-- position can be reasoned about as the fold's carry over the prefix.

set_option maxRecDepth 100000

/-- The `buildEffRiRun` fold body over `(output, carry)`, structurally identical
    to the algorithm's inline step so the two folds are definitionally equal. -/
def riStep : Array Nat × Nat → WBClass → Array Nat × Nat :=
  fun (out, cur) c =>
    let out' := out.push cur
    if isAbsorbable c then (out', cur)
    else if c == WBClass.Regional_Indicator then (out', cur + 1)
    else (out', 0)

theorem buildEffRiRun_eq_foldl (lits : Array WBClass) :
    buildEffRiRun lits = (lits.toList.foldl riStep (#[], 0)).fst := by
  rw [Array.foldl_toList]
  rfl

/-- Every `riStep` pushes the current carry onto the output, regardless of which
    rule branch it takes. -/
theorem riStep_fst (acc : Array Nat × Nat) (c : WBClass) :
    (riStep acc c).fst = acc.fst.push acc.snd := by
  obtain ⟨out, cur⟩ := acc
  unfold riStep
  by_cases h1 : isAbsorbable c <;>
    by_cases h2 : c == WBClass.Regional_Indicator <;>
    simp [h1, h2]

/-- The output array of a `riStep` fold has one entry per consumed input. -/
theorem riStep_fst_length (l : List WBClass) (acc : Array Nat × Nat) :
    (l.foldl riStep acc).fst.toList.length = acc.fst.toList.length + l.length := by
  induction l generalizing acc with
  | nil => simp
  | cons x xs ih =>
    rw [List.foldl_cons, ih, riStep_fst]
    simp [Array.toList_push]
    omega

/-- `buildEffRiRun lits` has exactly one entry per class in `lits`. -/
theorem buildEffRiRun_size (lits : Array WBClass) :
    (buildEffRiRun lits).size = lits.size := by
  rw [buildEffRiRun_eq_foldl, ← Array.length_toList, riStep_fst_length]
  simp

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 WB15/WB16 CONTEXT — the Regional_Indicator carry equals a declarative pattern
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The carry update `riStep` performs on the running count. -/
def riUpdate (k : Nat) (c : WBClass) : Nat :=
  if isAbsorbable c then k
  else if c == WBClass.Regional_Indicator then k + 1
  else 0

/-- The carry after folding the update over a class list from `k` — the pure
    accumulator `buildEffRiRun` stores at each position. -/
def riCarry : Nat → List WBClass → Nat
  | k, []        => k
  | k, (c :: cs) => riCarry (riUpdate k c) cs

/-- `riCarry` is the left fold of `riUpdate`. -/
theorem riCarry_eq_foldl (c : Nat) (l : List WBClass) : riCarry c l = l.foldl riUpdate c := by
  induction l generalizing c with
  | nil => rfl
  | cons x xs ih => rw [riCarry, List.foldl_cons, ih]

/-- The WB4-effective subsequence: the classes not absorbed by WB4. -/
def effSeq (l : List WBClass) : List WBClass :=
  l.filter (fun c => ! isAbsorbable c)

/-- **WB4 skip-invariance.** The Regional_Indicator carry is unchanged by
    absorbable (Extend / Format / ZWJ) classes: it depends only on the
    WB4-effective subsequence. This is the core of the effective-neighbour
    mechanism — genuine content, not a restatement of the fold. -/
theorem riCarry_effSeq (l : List WBClass) (k : Nat) :
    riCarry k l = riCarry k (effSeq l) := by
  rw [riCarry_eq_foldl, riCarry_eq_foldl, effSeq]
  exact PrefixScan.foldl_filter riUpdate (fun c => ! isAbsorbable c)
    (fun c x hx => by rw [riUpdate, if_pos (by simpa using hx)]) l k

/-- A class of the effective sequence is a Regional_Indicator. -/
def isRI (c : WBClass) : Bool := c == WBClass.Regional_Indicator

/-- Trailing Regional_Indicator count of a class list. -/
def trailRI (m : List WBClass) : Nat := (m.reverse.takeWhile isRI).length

/-- Declarative WB15/WB16 context: the trailing Regional_Indicator count of the
    WB4-effective subsequence of `l`. -/
def effTrailingRI (l : List WBClass) : Nat := trailRI (effSeq l)

/-- `trailRI` peels its last element cleanly: a trailing RI extends the run by
    one, anything else resets it to zero. -/
theorem trailRI_snoc (m : List WBClass) (c : WBClass) :
    trailRI (m ++ [c]) = if isRI c then trailRI m + 1 else 0 := by
  unfold trailRI
  rw [List.reverse_append, List.reverse_cons, List.reverse_nil, List.nil_append,
      List.singleton_append, List.takeWhile_cons]
  by_cases h : isRI c
  · simp [h, List.length_cons]
  · simp [h]

/-- `riCarry` peels its last element as one `riUpdate`. -/
theorem riCarry_snoc (k : Nat) (m : List WBClass) (c : WBClass) :
    riCarry k (m ++ [c]) = riUpdate (riCarry k m) c := by
  induction m generalizing k with
  | nil => rfl
  | cons y ys ih => rw [List.cons_append, riCarry, riCarry, ih]

/-- Every class of `effSeq l` is non-absorbable (it is `filter`ed on that). -/
theorem effSeq_nonAbsorbable (l : List WBClass) :
    (effSeq l).all (fun c => ! isAbsorbable c) = true := by
  unfold effSeq
  rw [List.all_eq_true]
  intro x hx
  exact (List.mem_filter.mp hx).2

/-- On an absorbable-free list, the carry from zero is exactly the trailing RI
    count — the WB4 branch of `riUpdate` never fires. -/
theorem riCarry_zero_eq_trailRI_of_nonAbs (m : List WBClass)
    (hm : m.all (fun c => ! isAbsorbable c) = true) :
    riCarry 0 m = trailRI m := by
  induction m using PrefixScan.list_snoc_induction with
  | hnil => rfl
  | hsnoc init c ih =>
    rw [List.all_append, List.all_cons, List.all_nil, Bool.and_true, Bool.and_eq_true] at hm
    obtain ⟨hinit, hc⟩ := hm
    have hcAbs : isAbsorbable c = false := by simpa using hc
    rw [riCarry_snoc, ih hinit, trailRI_snoc, riUpdate]
    simp [hcAbs, isRI]

/-- **WB15/WB16 context.** The Regional_Indicator carry from the initial state
    equals `effTrailingRI` — the trailing Regional_Indicator count of the
    WB4-effective subsequence, the value WB15/WB16 test via `% 2`. -/
theorem riCarry_zero_eq_effTrailingRI (l : List WBClass) :
    riCarry 0 l = effTrailingRI l := by
  rw [riCarry_effSeq, effTrailingRI]
  exact riCarry_zero_eq_trailRI_of_nonAbs (effSeq l) (effSeq_nonAbsorbable l)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 WB5-WB13 CONTEXT — the effective previous / prev-previous class pair
-- ═══════════════════════════════════════════════════════════════════════════════

/-- `effSeq` peels its first element: absorbable classes vanish, others stay. -/
theorem effSeq_cons (c : WBClass) (cs : List WBClass) :
    effSeq (c :: cs) = if isAbsorbable c then effSeq cs else c :: effSeq cs := by
  unfold effSeq
  rw [List.filter_cons]
  by_cases h : isAbsorbable c
  · simp [h]
  · simp [h]

/-- The `buildEffPrev` carry update: an absorbable class leaves the pair
    unchanged (WB4), any other class becomes the new effective-prev and shifts
    the old one to effective-prev-prev. -/
def effPrevUpdate (acc : Option WBClass × Option WBClass) (c : WBClass) :
    Option WBClass × Option WBClass :=
  if isAbsorbable c then acc else (some c, acc.fst)

/-- The `(effPrev, effPrevPrev)` pair after folding the update over a class list —
    the pure accumulator `buildEffPrev` stores at each position. -/
def effPrevCarry : (Option WBClass × Option WBClass) → List WBClass
    → Option WBClass × Option WBClass
  | acc, []        => acc
  | acc, (c :: cs) => effPrevCarry (effPrevUpdate acc c) cs

/-- `effPrevCarry` is the left fold of `effPrevUpdate`. -/
theorem effPrevCarry_eq_foldl (acc : Option WBClass × Option WBClass) (l : List WBClass) :
    effPrevCarry acc l = l.foldl effPrevUpdate acc := by
  induction l generalizing acc with
  | nil => rfl
  | cons x xs ih => rw [effPrevCarry, List.foldl_cons, ih]

/-- **WB4 skip-invariance for the prev pair.** The effective-prev/prev-prev pair
    is unchanged by absorbable classes: it depends only on the WB4-effective
    subsequence. -/
theorem effPrevCarry_effSeq (l : List WBClass) (acc : Option WBClass × Option WBClass) :
    effPrevCarry acc l = effPrevCarry acc (effSeq l) := by
  rw [effPrevCarry_eq_foldl, effPrevCarry_eq_foldl, effSeq]
  exact PrefixScan.foldl_filter effPrevUpdate (fun c => ! isAbsorbable c)
    (fun c x hx => by rw [effPrevUpdate, if_pos (by simpa using hx)]) l acc

/-- `effPrevCarry` peels its last element as one `effPrevUpdate`. -/
theorem effPrevCarry_snoc (acc : Option WBClass × Option WBClass)
    (m : List WBClass) (c : WBClass) :
    effPrevCarry acc (m ++ [c]) = effPrevUpdate (effPrevCarry acc m) c := by
  induction m generalizing acc with
  | nil => rfl
  | cons y ys ih => rw [List.cons_append, effPrevCarry, effPrevCarry, ih]

/-- On an absorbable-free list, the pair from `(none, none)` is exactly the last
    and second-to-last classes — the effective-prev / prev-prev the WB5-WB13
    rules test. -/
theorem effPrevCarry_of_nonAbs (m : List WBClass)
    (hm : m.all (fun c => ! isAbsorbable c) = true) :
    effPrevCarry (none, none) m = (m.getLast?, m.dropLast.getLast?) := by
  induction m using PrefixScan.list_snoc_induction with
  | hnil => rfl
  | hsnoc init c ih =>
    rw [List.all_append, List.all_cons, List.all_nil, Bool.and_true, Bool.and_eq_true] at hm
    obtain ⟨hinit, hc⟩ := hm
    have hcAbs : isAbsorbable c = false := by simpa using hc
    rw [effPrevCarry_snoc, ih hinit, effPrevUpdate, if_neg (by simp [hcAbs]),
        List.getLast?_concat, List.dropLast_concat]

/-- **WB5-WB13 context.** The effective-prev/prev-prev pair after scanning `l`
    from the initial state is the last and second-to-last classes of the
    WB4-effective subsequence — the neighbours the WB5-WB13 rules test. -/
theorem effPrevCarry_zero (l : List WBClass) :
    effPrevCarry (none, none) l = ((effSeq l).getLast?, (effSeq l).dropLast.getLast?) := by
  rw [effPrevCarry_effSeq]
  exact effPrevCarry_of_nonAbs (effSeq l) (effSeq_nonAbsorbable l)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 WB6/WB7b/WB12 LOOKAHEAD — the effective next class (a reverse scan)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The `buildEffNext` reversed-scan update: an absorbable class leaves the
    running effective class unchanged (WB4), any other class becomes it. -/
def nextUpdate (acc : Option WBClass) (c : WBClass) : Option WBClass :=
  if isAbsorbable c then acc else some c

/-- The single-value carry the reversed scan of `buildEffNext` accumulates: the
    most-recent non-absorbable class. -/
def nextCarry : Option WBClass → List WBClass → Option WBClass
  | acc, []        => acc
  | acc, (c :: cs) => nextCarry (nextUpdate acc c) cs

/-- `nextCarry` is the left fold of `nextUpdate`. -/
theorem nextCarry_eq_foldl (acc : Option WBClass) (l : List WBClass) :
    nextCarry acc l = l.foldl nextUpdate acc := by
  induction l generalizing acc with
  | nil => rfl
  | cons x xs ih => rw [nextCarry, List.foldl_cons, ih]

/-- **WB4 skip-invariance for the effective class.** Absorbable classes leave
    the running effective class unchanged. -/
theorem nextCarry_effSeq (l : List WBClass) (acc : Option WBClass) :
    nextCarry acc l = nextCarry acc (effSeq l) := by
  rw [nextCarry_eq_foldl, nextCarry_eq_foldl, effSeq]
  exact PrefixScan.foldl_filter nextUpdate (fun c => ! isAbsorbable c)
    (fun c x hx => by rw [nextUpdate, if_pos (by simpa using hx)]) l acc

/-- `nextCarry` peels its last element as one `nextUpdate`. -/
theorem nextCarry_snoc (acc : Option WBClass) (m : List WBClass) (c : WBClass) :
    nextCarry acc (m ++ [c]) = nextUpdate (nextCarry acc m) c := by
  induction m generalizing acc with
  | nil => rfl
  | cons y ys ih => rw [List.cons_append, nextCarry, nextCarry, ih]

/-- On an absorbable-free list, the carry from `none` is the last class. -/
theorem nextCarry_of_nonAbs (m : List WBClass)
    (hm : m.all (fun c => ! isAbsorbable c) = true) :
    nextCarry none m = m.getLast? := by
  induction m using PrefixScan.list_snoc_induction with
  | hnil => rfl
  | hsnoc init c ih =>
    rw [List.all_append, List.all_cons, List.all_nil, Bool.and_true, Bool.and_eq_true] at hm
    obtain ⟨hinit, hc⟩ := hm
    have hcAbs : isAbsorbable c = false := by simpa using hc
    rw [nextCarry_snoc, ih hinit, nextUpdate, if_neg (by simp [hcAbs]), List.getLast?_concat]

/-- **WB6/WB7b/WB12 effective class.** The reversed scan's carry from the initial
    state is the last class of the WB4-effective subsequence. Applied to the
    reversed suffix, this is the effective NEXT class the lookahead rules test. -/
theorem nextCarry_zero (l : List WBClass) :
    nextCarry none l = (effSeq l).getLast? := by
  rw [nextCarry_effSeq]
  exact nextCarry_of_nonAbs (effSeq l) (effSeq_nonAbsorbable l)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 ARRAY-INDEX BRIDGE — the value the algorithm reads at riR[i]! is the carry
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The carry `riStep` carries forward is exactly `riUpdate`, so `riStep` is a
    push-carry step in the sense of `PrefixScan`. -/
theorem riStep_snd (acc : Array Nat × Nat) (c : WBClass) :
    (riStep acc c).snd = riUpdate acc.snd c := by
  obtain ⟨out, cur⟩ := acc
  unfold riStep riUpdate
  by_cases h1 : isAbsorbable c <;> by_cases h2 : c == WBClass.Regional_Indicator <;>
    simp [h1, h2]

/-- **RI array-index bridge.** The value the algorithm reads at `riR[i]!` is the
    RI carry over the first `i` classes — hence, via `riCarry_zero_eq_effTrailingRI`,
    `effTrailingRI (lits.take i)`. An instance of the push-carry scan bridge with
    update `riUpdate`. -/
theorem buildEffRiRun_getElem! (lits : Array WBClass) (i : Nat) (h : i < lits.size) :
    (buildEffRiRun lits)[i]! = riCarry 0 (lits.toList.take i) := by
  rw [riCarry_eq_foldl]
  exact PrefixScan.build_getElem! riStep riUpdate riStep_fst riStep_snd 0 lits
    (buildEffRiRun lits) (buildEffRiRun_eq_foldl lits) i h

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 ARRAY-INDEX BRIDGE for the prev pair — effP[i]! is the effective-prev pair
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The `buildEffPrev` fold body. The accumulator `(out, cur, prev)` is
    right-associated as `(out, (cur, prev))`, so the pair is the carry and the
    RI-bridge template applies directly. -/
def effPrevStep :
    Array (Option WBClass × Option WBClass) × Option WBClass × Option WBClass → WBClass
    → Array (Option WBClass × Option WBClass) × Option WBClass × Option WBClass :=
  fun (out, cur, prev) c =>
    let out' := out.push (cur, prev)
    if isAbsorbable c then (out', cur, prev)
    else (out', some c, cur)

theorem buildEffPrev_eq_foldl (lits : Array WBClass) :
    buildEffPrev lits = (lits.toList.foldl effPrevStep (#[], none, none)).fst := by
  rw [Array.foldl_toList]
  rfl

/-- Each `effPrevStep` pushes the current carry pair onto the output. -/
theorem effPrevStep_fst (acc : Array (Option WBClass × Option WBClass) × Option WBClass × Option WBClass)
    (c : WBClass) : (effPrevStep acc c).fst = acc.fst.push acc.snd := by
  obtain ⟨out, cur, prev⟩ := acc
  unfold effPrevStep
  by_cases h : isAbsorbable c <;> simp [h]

/-- The carry `effPrevStep` carries forward is exactly `effPrevUpdate`. -/
theorem effPrevStep_snd (acc : Array (Option WBClass × Option WBClass) × Option WBClass × Option WBClass)
    (c : WBClass) : (effPrevStep acc c).snd = effPrevUpdate acc.snd c := by
  obtain ⟨out, cur, prev⟩ := acc
  unfold effPrevStep effPrevUpdate
  by_cases h : isAbsorbable c <;> simp [h]

/-- **Prev-pair array-index bridge.** The value the algorithm reads at `effP[i]!`
    is the effective-prev/prev-prev pair over the first `i` classes — hence, via
    `effPrevCarry_zero`, the last two classes of `effSeq (lits.take i)`. An
    instance of the push-carry scan bridge with update `effPrevUpdate`. -/
theorem buildEffPrev_getElem! (lits : Array WBClass) (i : Nat) (h : i < lits.size) :
    (buildEffPrev lits)[i]! = effPrevCarry (none, none) (lits.toList.take i) := by
  rw [effPrevCarry_eq_foldl]
  exact PrefixScan.build_getElem! effPrevStep effPrevUpdate effPrevStep_fst effPrevStep_snd
    (none, none) lits (buildEffPrev lits) (buildEffPrev_eq_foldl lits) i h

-- ═══════════════════════════════════════════════════════════════════════════════
-- §7 ARRAY-INDEX BRIDGE for the effective next — a reverse scan then array reverse
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The `buildEffNext` reversed-scan fold body. -/
def nextStep : Array (Option WBClass) × Option WBClass → WBClass
    → Array (Option WBClass) × Option WBClass :=
  fun (out, cur) c =>
    let out' := out.push cur
    if isAbsorbable c then (out', cur)
    else (out', some c)

theorem buildEffNext_eq_foldl (lits : Array WBClass) :
    buildEffNext lits = ((lits.toList.reverse.foldl nextStep (#[], none)).fst).reverse := by
  unfold buildEffNext
  rw [Array.foldl_toList, ← Array.toList_reverse]
  rfl

/-- Each `nextStep` pushes the current carry. -/
theorem nextStep_fst (acc : Array (Option WBClass) × Option WBClass) (c : WBClass) :
    (nextStep acc c).fst = acc.fst.push acc.snd := by
  obtain ⟨out, cur⟩ := acc
  unfold nextStep
  by_cases h : isAbsorbable c <;> simp [h]

/-- The carry `nextStep` carries forward is exactly `nextUpdate`. -/
theorem nextStep_snd (acc : Array (Option WBClass) × Option WBClass) (c : WBClass) :
    (nextStep acc c).snd = nextUpdate acc.snd c := by
  obtain ⟨out, cur⟩ := acc
  unfold nextStep nextUpdate
  by_cases h : isAbsorbable c <;> simp [h]

/-- The reversed scan of `buildEffNext`, as a list, is the prefix carries of the
    reversed class sequence — then reversed back to forward order. -/
theorem buildEffNext_toList (lits : Array WBClass) :
    (buildEffNext lits).toList =
      (PrefixScan.carries nextUpdate none lits.toList.reverse).reverse := by
  rw [buildEffNext_eq_foldl, Array.toList_reverse,
      PrefixScan.foldl_toList nextStep nextUpdate nextStep_fst nextStep_snd]
  simp

/-- `effSeq` commutes with `reverse` (both are element-local). -/
theorem effSeq_reverse (l : List WBClass) : effSeq l.reverse = (effSeq l).reverse := by
  unfold effSeq
  rw [List.filter_reverse]

/-- The class array is `cps` mapped through `lookupWB`, so `lits[i]!` is the
    class of the `i`-th code point. -/
theorem lits_getElem! (cps : Array Nat) (i : Nat) (h : i < cps.size) :
    (cps.map lookupWB)[i]! = lookupWB (cps[i]!) := by
  have hs : i < (cps.map lookupWB).size := by rw [Array.size_map]; exact h
  rw [getElem!_pos (cps.map lookupWB) i hs, Array.getElem_map, getElem!_pos cps i h]

/-- The Extended_Pictographic array is `cps` mapped through
    `isExtendedPictographic`, so `eps[i]!` is that predicate on the `i`-th code
    point (the WB3c input). -/
theorem eps_getElem! (cps : Array Nat) (i : Nat) (h : i < cps.size) :
    (cps.map isExtendedPictographic)[i]! = isExtendedPictographic (cps[i]!) := by
  have hs : i < (cps.map isExtendedPictographic).size := by rw [Array.size_map]; exact h
  rw [getElem!_pos (cps.map isExtendedPictographic) i hs, Array.getElem_map,
      getElem!_pos cps i h]

/-- **Effective-next array-index bridge.** The value the algorithm reads at
    `effN[i]!` is the first non-absorbable class strictly after position `i` —
    `head?` of the WB4-effective subsequence of the suffix `lits.drop (i+1)`, the
    effective NEXT class the WB6/WB7b/WB12 lookahead rules test. -/
theorem buildEffNext_getElem! (lits : Array WBClass) (i : Nat) (h : i < lits.size) :
    (buildEffNext lits)[i]! = (effSeq (lits.toList.drop (i + 1))).head? := by
  have hrev : (PrefixScan.carries nextUpdate none lits.toList.reverse).length = lits.size := by
    rw [PrefixScan.carries_length, List.length_reverse, Array.length_toList]
  have hi_rev : i < (PrefixScan.carries nextUpdate none lits.toList.reverse).length := by
    rw [hrev]; exact h
  have hsize : i < (buildEffNext lits).size := by
    rw [← Array.length_toList, buildEffNext_toList, List.length_reverse]; exact hi_rev
  have hidx : (PrefixScan.carries nextUpdate none lits.toList.reverse).length - 1 - i
      < lits.toList.reverse.length := by
    rw [hrev, List.length_reverse, Array.length_toList]; omega
  have harith : lits.toList.length
      - ((PrefixScan.carries nextUpdate none lits.toList.reverse).length - 1 - i) = i + 1 := by
    rw [hrev, Array.length_toList]; omega
  have hq : (buildEffNext lits)[i]? = some ((effSeq (lits.toList.drop (i + 1))).head?) := by
    rw [← Array.getElem?_toList, buildEffNext_toList, List.getElem?_reverse hi_rev]
    have hqi := PrefixScan.carries_getElem? nextUpdate none lits.toList.reverse
      ((PrefixScan.carries nextUpdate none lits.toList.reverse).length - 1 - i)
    simp only [hidx, if_pos] at hqi
    rw [hqi, ← nextCarry_eq_foldl, nextCarry_zero, List.take_reverse, harith, effSeq_reverse,
        List.getLast?_reverse]
  rw [getElem!_pos (buildEffNext lits) i hsize]
  have hsome : (buildEffNext lits)[i]? = some (buildEffNext lits)[i] :=
    (Array.getElem?_eq_some_getElem_iff (buildEffNext lits) i hsize).mpr trivial
  rw [hsome] at hq
  exact Option.some_inj.mp hq

-- ═══════════════════════════════════════════════════════════════════════════════
-- §8 PER-POSITION EXTRACTION — wordBreaks is shouldBreakBefore mapped over positions
-- ═══════════════════════════════════════════════════════════════════════════════

/-- **Per-position structure.** `wordBreaks cps`, as a list, is
    `shouldBreakBefore` evaluated at each position `0 .. n-1`, followed by the
    WB2 end-of-text break. The `wordBreaks` boundary at `i` is therefore exactly
    the per-position decision, whose inputs are the bridged declarative
    patterns. -/
theorem wordBreaks_toList (cps : Array Nat) :
    (wordBreaks cps).toList =
      (List.range cps.size).map
        (fun i => shouldBreakBefore cps (cps.map lookupWB) (cps.map isExtendedPictographic)
          (buildEffPrev (cps.map lookupWB)) (buildEffNext (cps.map lookupWB))
          (buildEffRiRun (cps.map lookupWB)) i)
      ++ [true] := by
  unfold wordBreaks
  rw [Array.toList_push, PrefixScan.foldl_push_map_toList]
  simp

-- ═══════════════════════════════════════════════════════════════════════════════
-- §9 RULE EQUIVALENCE — shouldBreakBefore equals the declarative WB1-WB999 decision
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The UAX #29 WB3-WB999 decision over abstract inputs, factored verbatim from
    `shouldBreakBefore`'s body: the previous and current class, whether the
    current class is Extended_Pictographic (WB3c), the effective prev / prev-prev
    pair (WB5-WB13), the effective next class (WB6/WB7b/WB12), and the
    Regional_Indicator run parity (WB15/WB16). -/
def wbRuleDecision (lp lc : WBClass) (isEPCurr : Bool)
    (effPP : Option WBClass × Option WBClass) (effNext : Option WBClass) (prevRi : Nat) : Bool :=
  if lp == .CR && lc == .LF then false
  else if lp == .Newline || lp == .CR || lp == .LF then true
  else if lc == .Newline || lc == .CR || lc == .LF then true
  else if lp == .ZWJ && isEPCurr then false
  else if lp == .WSegSpace && lc == .WSegSpace then false
  else if isAbsorbable lc then false
  else
    let (effPrev, effPrevPrev) := effPP
    match effPrev with
    | none => true
    | some ep =>
      let isAH := fun (c : WBClass) => c == .ALetter || c == .Hebrew_Letter
      let isMid := fun (c : WBClass) =>
        c == .MidLetter || c == .MidNumLet || c == .Single_Quote
      let isMidNum := fun (c : WBClass) =>
        c == .MidNum || c == .MidNumLet || c == .Single_Quote
      let nextIsAH : Bool :=
        match effNext with | some n => isAH n | none => false
      let nextIsHL : Bool :=
        match effNext with | some n => n == .Hebrew_Letter | none => false
      let nextIsNum : Bool :=
        match effNext with | some n => n == .Numeric | none => false
      let prevPrevIsAH : Bool :=
        match effPrevPrev with | some pp => isAH pp | none => false
      let prevPrevIsHL : Bool :=
        match effPrevPrev with | some pp => pp == .Hebrew_Letter | none => false
      let prevPrevIsNum : Bool :=
        match effPrevPrev with | some pp => pp == .Numeric | none => false
      if isAH ep && isAH lc then false
      else if isAH ep && isMid lc && nextIsAH then false
      else if isMid ep && isAH lc && prevPrevIsAH then false
      else if ep == .Hebrew_Letter && lc == .Single_Quote then false
      else if ep == .Hebrew_Letter && lc == .Double_Quote && nextIsHL then false
      else if ep == .Double_Quote && lc == .Hebrew_Letter && prevPrevIsHL then false
      else if ep == .Numeric && lc == .Numeric then false
      else if isAH ep && lc == .Numeric then false
      else if ep == .Numeric && isAH lc then false
      else if isMidNum ep && lc == .Numeric && prevPrevIsNum then false
      else if ep == .Numeric && isMidNum lc && nextIsNum then false
      else if ep == .Katakana && lc == .Katakana then false
      else if (isAH ep || ep == .Numeric || ep == .Katakana || ep == .ExtendNumLet) &&
              lc == .ExtendNumLet then false
      else if ep == .ExtendNumLet &&
              (isAH lc || lc == .Numeric || lc == .Katakana) then false
      else if lc == .Regional_Indicator && prevRi % 2 == 1 then false
      else true

/-- `shouldBreakBefore` is `wbRuleDecision` applied to the values it reads from
    its arrays, once the WB1/WB2 boundary guards are discharged. -/
theorem shouldBreakBefore_decision (cps : Array Nat) (lits : Array WBClass) (eps : Array Bool)
    (effP : Array (Option WBClass × Option WBClass)) (effN : Array (Option WBClass))
    (riR : Array Nat) (i : Nat) (h0 : i ≠ 0) (hn : ¬ i ≥ cps.size) :
    shouldBreakBefore cps lits eps effP effN riR i =
      wbRuleDecision lits[i-1]! lits[i]! eps[i]! effP[i]! effN[i]! riR[i]! := by
  unfold shouldBreakBefore wbRuleDecision
  rw [if_neg h0, if_neg hn]
  rfl

/-- The declarative UAX #29 word-boundary decision at position `i`: WB1 (start),
    WB2 (end), else `wbRuleDecision` over the neighbours defined declaratively
    from the raw code points — the effective prev/prev-prev/next and the RI run
    over the WB4-effective subsequence of the class sequence. -/
def wbBreakSpecAt (cps : Array Nat) (i : Nat) : Bool :=
  if i = 0 then true
  else if i ≥ cps.size then true
  else
    let classes := (cps.map lookupWB).toList
    wbRuleDecision (lookupWB cps[i-1]!) (lookupWB cps[i]!) (isExtendedPictographic cps[i]!)
      ((effSeq (classes.take i)).getLast?, (effSeq (classes.take i)).dropLast.getLast?)
      ((effSeq (classes.drop (i + 1))).head?) (effTrailingRI (classes.take i))

/-- **Per-position rule equivalence.** The algorithm's boundary decision at `i`
    equals the declarative UAX #29 decision `wbBreakSpecAt`, obtained by
    substituting every array-index bridge into `shouldBreakBefore`. -/
theorem shouldBreakBefore_eq_spec (cps : Array Nat) (i : Nat) :
    shouldBreakBefore cps (cps.map lookupWB) (cps.map isExtendedPictographic)
      (buildEffPrev (cps.map lookupWB)) (buildEffNext (cps.map lookupWB))
      (buildEffRiRun (cps.map lookupWB)) i = wbBreakSpecAt cps i := by
  by_cases h0 : i = 0
  · simp [shouldBreakBefore, wbBreakSpecAt, h0]
  · by_cases hn : i ≥ cps.size
    · simp [shouldBreakBefore, wbBreakSpecAt, h0, hn]
    · have hi : i < cps.size := Nat.lt_of_not_ge hn
      have hi1 : i - 1 < cps.size := by omega
      have hmap : i < (cps.map lookupWB).size := by rw [Array.size_map]; exact hi
      rw [shouldBreakBefore_decision cps (cps.map lookupWB) (cps.map isExtendedPictographic)
            (buildEffPrev (cps.map lookupWB)) (buildEffNext (cps.map lookupWB))
            (buildEffRiRun (cps.map lookupWB)) i h0 hn,
          lits_getElem! cps i hi, lits_getElem! cps (i - 1) hi1, eps_getElem! cps i hi,
          buildEffPrev_getElem! (cps.map lookupWB) i hmap, effPrevCarry_zero,
          buildEffNext_getElem! (cps.map lookupWB) i hmap,
          buildEffRiRun_getElem! (cps.map lookupWB) i hmap, riCarry_zero_eq_effTrailingRI]
      unfold wbBreakSpecAt
      rw [if_neg h0, if_neg hn]

/-- **Word break equals its declarative UAX #29 specification.** `wordBreaks cps`
    is, position by position, the declarative WB1-WB999 decision over the raw
    code points, followed by the WB2 end-of-text break. Correctness for all input
    without brute force — the analog of `graphemeBreaks_eq_spec`. -/
theorem wordBreaks_eq_spec (cps : Array Nat) :
    (wordBreaks cps).toList = (List.range cps.size).map (wbBreakSpecAt cps) ++ [true] := by
  rw [wordBreaks_toList]
  have hfun : (fun i => shouldBreakBefore cps (cps.map lookupWB) (cps.map isExtendedPictographic)
      (buildEffPrev (cps.map lookupWB)) (buildEffNext (cps.map lookupWB))
      (buildEffRiRun (cps.map lookupWB)) i) = wbBreakSpecAt cps := by
    funext i
    exact shouldBreakBefore_eq_spec cps i
  rw [hfun]

end Unicode.Segmentation.WordBreak
