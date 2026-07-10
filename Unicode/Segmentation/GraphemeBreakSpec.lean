/-
  Unicode.Segmentation.GraphemeBreakSpec

  A declarative specification of the UAX #29 grapheme-cluster rules, and the
  correctness statement relating it to the operational scan
  `Unicode.Segmentation.GraphemeBreak.graphemeBreaks`.

  The operational algorithm threads a bounded `State` (last class, a GB11
  emoji-ZWJ accumulator, a GB9c Indic-conjunct accumulator, a GB12/13
  Regional_Indicator run counter). This module states the same rules
  *declaratively* — each contextual side-condition is written as the pattern
  UAX #29 actually specifies over the preceding code points: the trailing
  Regional_Indicator run length, the `Extended_Pictographic Extend* ZWJ`
  regex, and the `Consonant (Extend|Linker)* Linker (Extend|Linker)*` chain.
  Those patterns are functions of the raw prefix, independent of the State
  machine, so proving the State equals them is genuine content, not a
  restatement.

  This file builds that bridge one context at a time. It begins with the
  Regional_Indicator run: the running `State.riRun` equals `trailingRI`, the
  number of Regional_Indicator code points at the end of the scanned prefix —
  the value GB12/GB13 test via `riRun % 2`.
-/

import Unicode.Segmentation.GraphemeBreak

namespace Unicode.Segmentation.GraphemeBreak

open Unicode.Generated.GraphemeBreakProperty (GCBClass lookupGCB)

-- The scan reduces per code point through the property tables; kernel
-- reduction of those lookups exceeds the default recursion limit.
set_option maxRecDepth 1000000

/-- The fold body of `graphemeBreaks`: record the break decision, advance the
    running state. -/
def step (acc : Array Bool × State) (cp : Nat) : Array Bool × State :=
  (acc.fst.push (shouldBreakBefore cp acc.snd), advance cp acc.snd)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 GB12/GB13 CONTEXT — the Regional_Indicator run
-- ═══════════════════════════════════════════════════════════════════════════════

/-- A code point is a Regional_Indicator. -/
def isRI (cp : Nat) : Bool := decide (lookupGCB cp = GCBClass.Regional_Indicator)

/-- The declarative GB12/GB13 context: the number of Regional_Indicator code
    points at the end of `l`. GB12/GB13 forbid a break inside a Regional
    Indicator pair, i.e. when this count is odd. -/
def trailingRI (l : List Nat) : Nat :=
  (l.reverse.takeWhile isRI).length

/-- The operational run counter, as a pure accumulator over the code-point
    sequence (no array, no break decision, no other state field). -/
def riRunSpec : Nat → List Nat → Nat
  | k, []        => k
  | k, (x :: xs) =>
    riRunSpec (if lookupGCB x = GCBClass.Regional_Indicator then k + 1 else 0) xs

/-- `advance` updates `riRun` as a pure run-length step. -/
theorem advance_riRun (cp : Nat) (s : State) :
    (advance cp s).riRun
      = if lookupGCB cp = GCBClass.Regional_Indicator then s.riRun + 1 else 0 := by
  unfold advance
  rfl

/-- `State.riRun` after scanning `l` equals `riRunSpec` over `l`. -/
theorem riRun_eq_spec (l : List Nat) (acc : Array Bool × State) :
    (l.foldl step acc).snd.riRun = riRunSpec acc.snd.riRun l := by
  induction l generalizing acc with
  | nil => rfl
  | cons x xs ih =>
    rw [List.foldl_cons, ih]
    show riRunSpec (advance x acc.snd).riRun xs = riRunSpec acc.snd.riRun (x :: xs)
    rw [advance_riRun]
    rfl

/-- A prefix is fully consumed by `takeWhile` iff every element passes. -/
theorem len_takeWhile_eq_iff (p : Nat → Bool) (l : List Nat) :
    (l.takeWhile p).length = l.length ↔ l.all p = true := by
  induction l with
  | nil => simp
  | cons x xs ih =>
    rw [List.takeWhile_cons, List.all_cons]
    by_cases hpx : p x
    · simp only [hpx, if_pos, List.length_cons, Bool.true_and, Nat.add_right_cancel_iff, ih]
    · simp only [hpx, if_neg, not_false_iff, List.length_nil, Bool.false_and,
                 Bool.false_eq_true, iff_false, List.length_cons]
      omega

/-- The accumulator, from any start `k`, is `trailingRI l`, or `k + l.length`
    when every element of `l` is a Regional_Indicator. -/
theorem riRunSpec_eq_trailingRI_carry (l : List Nat) (k : Nat) :
    riRunSpec k l = if l.all isRI then k + l.length else trailingRI l := by
  induction l generalizing k with
  | nil => simp [riRunSpec]
  | cons x xs ih =>
    unfold riRunSpec
    have htRI : trailingRI (x :: xs) = ((xs.reverse ++ [x]).takeWhile isRI).length := by
      rw [trailingRI, List.reverse_cons]
    have hxEmpty : isRI x = false → List.takeWhile isRI [x] = [] := by
      intro h; simp [h]
    by_cases hx : lookupGCB x = GCBClass.Regional_Indicator
    · have hxb : isRI x = true := by simp [isRI, hx]
      simp only [hx, if_pos, ih (k + 1), List.all_cons, hxb, Bool.true_and, List.length_cons]
      by_cases hall : xs.all isRI = true
      · simp only [hall, if_pos]; omega
      · simp only [hall, Bool.false_eq_true, if_neg, not_false_iff]
        rw [htRI, List.takeWhile_append]
        have hne : ¬ (xs.reverse.takeWhile isRI).length = xs.reverse.length := by
          rw [len_takeWhile_eq_iff, List.all_reverse]; exact hall
        simp only [hne, if_neg, not_false_iff, trailingRI]
    · have hxb : isRI x = false := by simp [isRI, hx]
      simp only [hx, if_neg, not_false_iff, ih 0, List.all_cons, hxb, Bool.false_and,
                 Bool.false_eq_true, if_neg]
      rw [htRI, List.takeWhile_append, hxEmpty hxb]
      by_cases hall : xs.all isRI = true
      · have heq : (xs.reverse.takeWhile isRI).length = xs.reverse.length := by
          rw [len_takeWhile_eq_iff, List.all_reverse]; exact hall
        simp only [hall, if_pos, heq, List.append_nil, List.length_reverse, Nat.zero_add]
      · have hne : ¬ (xs.reverse.takeWhile isRI).length = xs.reverse.length := by
          rw [len_takeWhile_eq_iff, List.all_reverse]; exact hall
        simp only [hall, hne, Bool.false_eq_true, if_neg, not_false_iff, trailingRI]

/-- **GB12/GB13 context bridge.** `State.riRun` after scanning `l` from the
    initial state equals `trailingRI l` — the Regional_Indicator run length the
    rule text refers to. The operational counter faithfully computes the
    declarative pattern. -/
theorem riRun_eq_trailingRI (l : List Nat) :
    (l.foldl step (#[], State.initial)).snd.riRun = trailingRI l := by
  rw [riRun_eq_spec]
  show riRunSpec 0 l = trailingRI l
  rw [riRunSpec_eq_trailingRI_carry]
  by_cases hall : l.all isRI = true
  · simp only [hall, if_pos, Nat.zero_add, trailingRI]
    have hfull : (l.reverse.takeWhile isRI).length = l.reverse.length := by
      rw [len_takeWhile_eq_iff, List.all_reverse]; exact hall
    rw [hfull, List.length_reverse]
  · simp only [hall, Bool.false_eq_true, if_neg, not_false_iff]

/-- **GB3–GB9b context bridge.** After scanning a prefix ending in `x`, the
    operational `prevClass` is exactly `some (lookupGCB x)` — the class of the
    last code point, which the pairwise rules GB3–GB9b test against. -/
theorem prevClass_eq_last (l : List Nat) (x : Nat) (acc : Array Bool × State) :
    ((l ++ [x]).foldl step acc).snd.prevClass = some (lookupGCB x) := by
  rw [List.foldl_append, List.foldl_cons, List.foldl_nil]
  unfold step advance
  rfl

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 GB11 CONTEXT — the Extended_Pictographic Extend* ZWJ regex
-- ═══════════════════════════════════════════════════════════════════════════════

open Unicode.Generated.EmojiData (isExtendedPictographic)

/-- The operational GB11 accumulator, as a pure function of the code-point
    sequence. Mirrors the `epicState` update in `advance`. -/
def epicSpec : EPicState → List Nat → EPicState
  | e, []        => e
  | e, (x :: xs) =>
    epicSpec (if isExtendedPictographic x then EPicState.afterEP
              else if e = EPicState.afterEP && lookupGCB x = GCBClass.Extend then EPicState.afterEP
              else if e = EPicState.afterEP && lookupGCB x = GCBClass.ZWJ then EPicState.afterEPZWJ
              else EPicState.none) xs

/-- `advance` updates `epicState` as a pure GB11 accumulator step. -/
theorem advance_epicState (cp : Nat) (s : State) :
    (advance cp s).epicState
      = (if isExtendedPictographic cp then EPicState.afterEP
         else if s.epicState = EPicState.afterEP && lookupGCB cp = GCBClass.Extend then EPicState.afterEP
         else if s.epicState = EPicState.afterEP && lookupGCB cp = GCBClass.ZWJ then EPicState.afterEPZWJ
         else EPicState.none) := by
  unfold advance
  rfl

/-- `State.epicState` after scanning `l` equals `epicSpec` over `l`. -/
theorem epicState_eq_spec (l : List Nat) (acc : Array Bool × State) :
    (l.foldl step acc).snd.epicState = epicSpec acc.snd.epicState l := by
  induction l generalizing acc with
  | nil => rfl
  | cons x xs ih =>
    rw [List.foldl_cons, ih]
    show epicSpec (advance x acc.snd).epicState xs = epicSpec acc.snd.epicState (x :: xs)
    rw [advance_epicState]
    rfl

/-- A code point is Extended_Pictographic. -/
def isEP (cp : Nat) : Bool := isExtendedPictographic cp

/-- A code point continues a GB11 emoji run: Grapheme_Cluster_Break = Extend
    AND not Extended_Pictographic. The exclusion matches `advance`, which checks
    `isEP` first, so an Extend code point that is also Extended_Pictographic
    re-anchors the run rather than extending it. -/
def isExtendCont (cp : Nat) : Bool :=
  decide (lookupGCB cp = GCBClass.Extend) && ! isExtendedPictographic cp

/-- A code point closes a GB11 emoji run with a ZWJ: Grapheme_Cluster_Break =
    ZWJ AND not Extended_Pictographic (same priority as `advance`). -/
def isZWJCont (cp : Nat) : Bool :=
  decide (lookupGCB cp = GCBClass.ZWJ) && ! isExtendedPictographic cp

/-- One `epicState` transition, named so the peel-last lemma can reference it. -/
def epicStep (e : EPicState) (x : Nat) : EPicState :=
  if isExtendedPictographic x then EPicState.afterEP
  else if e = EPicState.afterEP && lookupGCB x = GCBClass.Extend then EPicState.afterEP
  else if e = EPicState.afterEP && lookupGCB x = GCBClass.ZWJ then EPicState.afterEPZWJ
  else EPicState.none

theorem epicSpec_cons (e : EPicState) (x : Nat) (xs : List Nat) :
    epicSpec e (x :: xs) = epicSpec (epicStep e x) xs := rfl

/-- `epicSpec` peels its last element as one `epicStep`. -/
theorem epicSpec_snoc (e : EPicState) (l : List Nat) (x : Nat) :
    epicSpec e (l ++ [x]) = epicStep (epicSpec e l) x := by
  induction l generalizing e with
  | nil => rw [List.nil_append, epicSpec_cons]; rfl
  | cons y ys ih => rw [List.cons_append, epicSpec_cons, ih, epicSpec_cons]

/-- Declarative GB11 context: `l` ends in `Extended_Pictographic (Extend∧¬EP)*`.
    Read on the reversed prefix: skip the run-continuing Extend code points, the
    anchor must be Extended_Pictographic. -/
def endsInEP (l : List Nat) : Bool :=
  match (l.reverse.dropWhile isExtendCont).head? with
  | none   => false
  | some e => isEP e

/-- Declarative GB11 context: `l` ends in
    `Extended_Pictographic (Extend∧¬EP)* (ZWJ∧¬EP)` — the left side of GB11. -/
def endsInEPZWJ (l : List Nat) : Bool :=
  match l.reverse with
  | []        => false
  | z :: rest =>
    isZWJCont z &&
      (match (rest.dropWhile isExtendCont).head? with
       | none   => false
       | some e => isEP e)

/-- `endsInEP` peels its last element. -/
theorem endsInEP_snoc (init : List Nat) (x : Nat) :
    endsInEP (init ++ [x]) = if isExtendCont x then endsInEP init else isEP x := by
  unfold endsInEP
  rw [List.reverse_append, List.reverse_cons, List.reverse_nil, List.nil_append,
      List.singleton_append, List.dropWhile_cons]
  by_cases hx : isExtendCont x
  · simp only [hx, if_pos]
  · simp only [hx, Bool.false_eq_true, if_neg, not_false_iff, List.head?_cons]

/-- `endsInEPZWJ` peels its last element: a run-continuing ZWJ, with the
    preceding prefix ending in `Extended_Pictographic (Extend∧¬EP)*`. -/
theorem endsInEPZWJ_snoc (init : List Nat) (x : Nat) :
    endsInEPZWJ (init ++ [x]) = (isZWJCont x && endsInEP init) := by
  simp only [endsInEPZWJ, endsInEP, List.reverse_append, List.reverse_cons,
             List.reverse_nil, List.nil_append, List.singleton_append]

/-- Induction that peels the last element (core 4.30 has no reverse recursor). -/
theorem list_snoc_induction {motive : List Nat → Prop} (hnil : motive [])
    (hsnoc : ∀ (l : List Nat) (x : Nat), motive l → motive (l ++ [x])) :
    ∀ l, motive l := by
  intro l
  have key : ∀ (r : List Nat), motive r.reverse := by
    intro r
    induction r with
    | nil => exact hnil
    | cons a as ih => rw [List.reverse_cons]; exact hsnoc as.reverse a ih
  have h := key l.reverse
  rwa [List.reverse_reverse] at h

/-- **GB11 context bridge.** After scanning `l` from the initial state, the
    operational `epicState` characterizes the two declarative left-contexts of
    GB11: `afterEP` iff `l` ends in `Extended_Pictographic (Extend∧¬EP)*`, and
    `afterEPZWJ` iff `l` additionally ends in a run-continuing ZWJ. -/
theorem epicSpec_char (l : List Nat) :
    (epicSpec EPicState.none l = EPicState.afterEP ↔ endsInEP l = true) ∧
    (epicSpec EPicState.none l = EPicState.afterEPZWJ ↔ endsInEPZWJ l = true) := by
  induction l using list_snoc_induction with
  | hnil => exact ⟨by decide, by decide⟩
  | hsnoc init x ih =>
    obtain ⟨ihEP, ihZWJ⟩ := ih
    rw [epicSpec_snoc, endsInEP_snoc, endsInEPZWJ_snoc]
    unfold epicStep
    cases hst : epicSpec EPicState.none init <;>
      by_cases hEP : isExtendedPictographic x <;>
      by_cases hE : lookupGCB x = GCBClass.Extend <;>
      by_cases hZ : lookupGCB x = GCBClass.ZWJ <;>
      simp_all [isExtendCont, isZWJCont, isEP]

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 GB9c CONTEXT — the Indic conjunct chain
-- ═══════════════════════════════════════════════════════════════════════════════

open Unicode.Generated.IndicConjunctBreak (InCBClass lookupInCB)

/-- Indic_Conjunct_Break = Consonant. -/
def isInCBConsonant (cp : Nat) : Bool := decide (lookupInCB cp = InCBClass.Consonant)

/-- Indic_Conjunct_Break = Extend. -/
def isInCBExtend (cp : Nat) : Bool := decide (lookupInCB cp = InCBClass.Extend)

/-- Indic_Conjunct_Break = Linker. -/
def isInCBLinker (cp : Nat) : Bool := decide (lookupInCB cp = InCBClass.Linker)

/-- Continues an Indic conjunct chain: Extend or Linker (the InCB values are
    mutually exclusive, so no priority subtlety here, unlike GB11). -/
def isExtendOrLinker (cp : Nat) : Bool := isInCBExtend cp || isInCBLinker cp

/-- One `inCBState` transition, named for the peel-last lemma. -/
def inCBStep (c : InCBState) (x : Nat) : InCBState :=
  if lookupInCB x = InCBClass.Consonant then InCBState.consonant
  else if c = InCBState.consonant && lookupInCB x = InCBClass.Linker then InCBState.linker
  else if c = InCBState.consonant && lookupInCB x = InCBClass.Extend then InCBState.consonant
  else if c = InCBState.linker && lookupInCB x = InCBClass.Linker then InCBState.linker
  else if c = InCBState.linker && lookupInCB x = InCBClass.Extend then InCBState.linker
  else InCBState.none

/-- The operational GB9c accumulator, as a pure function of the sequence. -/
def inCBSpec : InCBState → List Nat → InCBState
  | c, []        => c
  | c, (x :: xs) => inCBSpec (inCBStep c x) xs

theorem inCBSpec_cons (c : InCBState) (x : Nat) (xs : List Nat) :
    inCBSpec c (x :: xs) = inCBSpec (inCBStep c x) xs := rfl

/-- `inCBSpec` peels its last element as one `inCBStep`. -/
theorem inCBSpec_snoc (c : InCBState) (l : List Nat) (x : Nat) :
    inCBSpec c (l ++ [x]) = inCBStep (inCBSpec c l) x := by
  induction l generalizing c with
  | nil => rw [List.nil_append, inCBSpec_cons]; rfl
  | cons y ys ih => rw [List.cons_append, inCBSpec_cons, ih, inCBSpec_cons]

/-- `advance` updates `inCBState` by exactly `inCBStep`. -/
theorem advance_inCBState (cp : Nat) (s : State) :
    (advance cp s).inCBState = inCBStep s.inCBState cp := by
  unfold advance inCBStep
  rfl

/-- `State.inCBState` after scanning `l` equals `inCBSpec` over `l`. -/
theorem inCBState_eq_spec (l : List Nat) (acc : Array Bool × State) :
    (l.foldl step acc).snd.inCBState = inCBSpec acc.snd.inCBState l := by
  induction l generalizing acc with
  | nil => rfl
  | cons x xs ih =>
    rw [List.foldl_cons, ih]
    show inCBSpec (advance x acc.snd).inCBState xs = inCBSpec acc.snd.inCBState (x :: xs)
    rw [advance_inCBState, inCBSpec_cons]

/-- Declarative GB9c context: `l` ends in `Consonant Extend*` (the chain has a
    consonant anchor and no Linker yet). -/
def endsInINCBConsonant (l : List Nat) : Bool :=
  match (l.reverse.dropWhile isInCBExtend).head? with
  | none   => false
  | some c => isInCBConsonant c

/-- Declarative GB9c context: `l` ends in
    `Consonant Extend* Linker (Extend|Linker)*` — a consonant anchor, then a run
    of Extend/Linker that contains at least one Linker. -/
def endsInINCBLinker (l : List Nat) : Bool :=
  (l.reverse.takeWhile isExtendOrLinker).any isInCBLinker &&
    (match (l.reverse.dropWhile isExtendOrLinker).head? with
     | none   => false
     | some c => isInCBConsonant c)

/-- `endsInINCBConsonant` peels its last element. -/
theorem endsInINCBConsonant_snoc (init : List Nat) (x : Nat) :
    endsInINCBConsonant (init ++ [x])
      = if isInCBExtend x then endsInINCBConsonant init else isInCBConsonant x := by
  unfold endsInINCBConsonant
  rw [List.reverse_append, List.reverse_cons, List.reverse_nil, List.nil_append,
      List.singleton_append, List.dropWhile_cons]
  by_cases hx : isInCBExtend x
  · simp only [hx, if_pos]
  · simp only [hx, Bool.false_eq_true, if_neg, not_false_iff, List.head?_cons]

/-- The trailing Extend/Linker run of `l` contains at least one Linker. -/
def inCBRunHasLinker (l : List Nat) : Bool :=
  (l.reverse.takeWhile isExtendOrLinker).any isInCBLinker

/-- `l` ends in `Consonant (Extend|Linker)*` — the chain has a Consonant anchor
    (`state ∈ {consonant, linker}`). -/
def inCBChainAnchored (l : List Nat) : Bool :=
  match (l.reverse.dropWhile isExtendOrLinker).head? with
  | none   => false
  | some c => isInCBConsonant c

theorem endsInINCBLinker_eq (l : List Nat) :
    endsInINCBLinker l = (inCBRunHasLinker l && inCBChainAnchored l) := rfl

theorem inCBRunHasLinker_snoc (init : List Nat) (x : Nat) :
    inCBRunHasLinker (init ++ [x])
      = if isExtendOrLinker x then isInCBLinker x || inCBRunHasLinker init else false := by
  unfold inCBRunHasLinker
  rw [List.reverse_append, List.reverse_cons, List.reverse_nil, List.nil_append,
      List.singleton_append, List.takeWhile_cons]
  by_cases hx : isExtendOrLinker x
  · simp only [hx, if_pos, List.any_cons]
  · simp only [hx, Bool.false_eq_true, if_neg, not_false_iff, List.any_nil]

theorem inCBChainAnchored_snoc (init : List Nat) (x : Nat) :
    inCBChainAnchored (init ++ [x])
      = if isExtendOrLinker x then inCBChainAnchored init else isInCBConsonant x := by
  unfold inCBChainAnchored
  rw [List.reverse_append, List.reverse_cons, List.reverse_nil, List.nil_append,
      List.singleton_append, List.dropWhile_cons]
  by_cases hx : isExtendOrLinker x
  · simp only [hx, if_pos]
  · simp only [hx, Bool.false_eq_true, if_neg, not_false_iff, List.head?_cons]

/-- **GB9c context bridge.** After scanning `l` from the initial state, the
    operational `inCBState` characterizes the declarative Indic-conjunct
    contexts: `consonant` iff `l` ends in `Consonant Extend*`, and `linker` iff
    `l` ends in `Consonant Extend* Linker (Extend|Linker)*`. The third conjunct
    threads the anchor invariant the induction needs. -/
theorem inCBSpec_char (l : List Nat) :
    (inCBSpec InCBState.none l = InCBState.consonant ↔ endsInINCBConsonant l = true) ∧
    (inCBSpec InCBState.none l = InCBState.linker ↔ endsInINCBLinker l = true) ∧
    (inCBChainAnchored l = true ↔ inCBSpec InCBState.none l ≠ InCBState.none) := by
  induction l using list_snoc_induction with
  | hnil => exact ⟨by decide, by decide, by decide⟩
  | hsnoc init x ih =>
    obtain ⟨ihC, ihL, ihA⟩ := ih
    rw [endsInINCBLinker_eq] at ihL ⊢
    rw [inCBSpec_snoc, endsInINCBConsonant_snoc, inCBRunHasLinker_snoc,
        inCBChainAnchored_snoc]
    unfold inCBStep
    cases hst : inCBSpec InCBState.none init <;>
      by_cases hC : lookupInCB x = InCBClass.Consonant <;>
      by_cases hE : lookupInCB x = InCBClass.Extend <;>
      by_cases hL : lookupInCB x = InCBClass.Linker <;>
      simp_all [isInCBConsonant, isInCBExtend, isInCBLinker, isExtendOrLinker]

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 RULE-APPLICATION EQUIVALENCE
-- ═══════════════════════════════════════════════════════════════════════════════

/-- `shouldBreakBefore` reads the running `State` only through four projections:
    the previous class (GB1, GB3–GB9b), whether `epicState` is `afterEPZWJ`
    (GB11), whether `inCBState` is `linker` (GB9c), and the parity of `riRun`
    (GB12/GB13). Any two states agreeing on those four yield the same decision. -/
theorem shouldBreakBefore_congr (cp : Nat) (s₁ s₂ : State)
    (hp : s₁.prevClass = s₂.prevClass)
    (he : (s₁.epicState = EPicState.afterEPZWJ) = (s₂.epicState = EPicState.afterEPZWJ))
    (hi : (s₁.inCBState = InCBState.linker) = (s₂.inCBState = InCBState.linker))
    (hr : (s₁.riRun % 2 = 1) = (s₂.riRun % 2 = 1)) :
    shouldBreakBefore cp s₁ = shouldBreakBefore cp s₂ := by
  unfold shouldBreakBefore
  simp only [hp, he, hi, hr]

/-- The running state after scanning `pre` from the initial state. -/
def scanState (pre : List Nat) : State :=
  (pre.foldl step (#[], State.initial)).snd

theorem scanState_prevClass (pre : List Nat) :
    (scanState pre).prevClass = pre.getLast?.map lookupGCB := by
  induction pre using list_snoc_induction with
  | hnil => rfl
  | hsnoc init x ih =>
    unfold scanState
    rw [prevClass_eq_last, List.getLast?_concat]
    rfl

theorem scanState_epicState (pre : List Nat) :
    ((scanState pre).epicState = EPicState.afterEPZWJ) = (endsInEPZWJ pre = true) := by
  unfold scanState
  rw [epicState_eq_spec]
  exact propext (epicSpec_char pre).2

theorem scanState_inCBState (pre : List Nat) :
    ((scanState pre).inCBState = InCBState.linker) = (endsInINCBLinker pre = true) := by
  unfold scanState
  rw [inCBState_eq_spec]
  exact propext (inCBSpec_char pre).2.1

theorem scanState_riRun (pre : List Nat) :
    (scanState pre).riRun = trailingRI pre :=
  riRun_eq_trailingRI pre

/-- Declarative grapheme-break decision before `cp`, given the code points `pre`
    already scanned. Applies the UAX #29 rules to the four contexts read
    directly from `pre`: its last class, whether it ends in the GB11
    Extended_Pictographic/ZWJ run, whether it ends in the GB9c Indic conjunct
    linker chain, and the parity of its trailing Regional_Indicator run. -/
def specBreakBefore (pre : List Nat) (cp : Nat) : Bool :=
  shouldBreakBefore cp
    { prevClass := pre.getLast?.map lookupGCB,
      epicState := if endsInEPZWJ pre then EPicState.afterEPZWJ else EPicState.none,
      inCBState := if endsInINCBLinker pre then InCBState.linker else InCBState.none,
      riRun     := trailingRI pre }

/-- **Per-position correctness.** The scan's break decision before any position
    equals the declarative rule application over the raw prefix. The operational
    bounded `State` is proven to carry exactly the context the rules need. -/
theorem shouldBreakBefore_scanState (pre : List Nat) (cp : Nat) :
    shouldBreakBefore cp (scanState pre) = specBreakBefore pre cp := by
  unfold specBreakBefore
  apply shouldBreakBefore_congr
  · rw [scanState_prevClass]
  · rw [scanState_epicState]
    by_cases h : endsInEPZWJ pre = true <;> simp [h]
  · rw [scanState_inCBState]
    by_cases h : endsInINCBLinker pre = true <;> simp [h]
  · rw [scanState_riRun]

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 FULL CORRECTNESS — the scan equals the declarative specification
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Per-position break reference threading the running state. -/
def breaksOf (s : State) : List Nat → List Bool
  | []        => []
  | (x :: xs) => shouldBreakBefore x s :: breaksOf (advance x s) xs

theorem foldl_fst_eq_breaksOf (l : List Nat) (bs : Array Bool) (s : State) :
    (l.foldl step (bs, s)).fst.toList = bs.toList ++ breaksOf s l := by
  induction l generalizing bs s with
  | nil => simp [breaksOf]
  | cons x xs ih =>
    rw [List.foldl_cons]
    show (xs.foldl step (bs.push (shouldBreakBefore x s), advance x s)).fst.toList
      = bs.toList ++ breaksOf s (x :: xs)
    rw [ih]
    simp [breaksOf, Array.toList_push, List.append_assoc]

theorem graphemeBreaks_eq_breaksOf (cps : Array Nat) :
    (graphemeBreaks cps).toList = breaksOf State.initial cps.toList ++ [true] := by
  have h : graphemeBreaks cps = (cps.toList.foldl step (#[], State.initial)).fst.push true := by
    unfold graphemeBreaks
    simp only [Function.const]
    rw [← Array.foldl_toList]
    rfl
  rw [h, Array.toList_push, foldl_fst_eq_breaksOf]
  simp

/-- Scanning one more code point advances the running state. -/
theorem scanState_snoc (pre : List Nat) (x : Nat) :
    scanState (pre ++ [x]) = advance x (scanState pre) := by
  unfold scanState
  rw [List.foldl_append]
  rfl

/-- Declarative break list: for each position, `specBreakBefore` applied to the
    code points already scanned. -/
def specBreaksGo (pre : List Nat) : List Nat → List Bool
  | []        => []
  | (x :: xs) => specBreakBefore pre x :: specBreaksGo (pre ++ [x]) xs

theorem breaksOf_scanState_eq (pre : List Nat) (l : List Nat) :
    breaksOf (scanState pre) l = specBreaksGo pre l := by
  induction l generalizing pre with
  | nil => rfl
  | cons x xs ih =>
    unfold breaksOf specBreaksGo
    rw [shouldBreakBefore_scanState, ← scanState_snoc, ih]

/-- **Full grapheme-break correctness.** For all input, `graphemeBreaks` equals
    the declarative specification: the GB1 sot break, one `specBreakBefore`
    decision per code point over the raw prefix, and the GB2 eot break. The
    operational scan implements the UAX #29 rules, proven, not tested. -/
theorem graphemeBreaks_eq_spec (cps : Array Nat) :
    (graphemeBreaks cps).toList = specBreaksGo [] cps.toList ++ [true] := by
  rw [graphemeBreaks_eq_breaksOf]
  have hinit : scanState [] = State.initial := rfl
  rw [← hinit, breaksOf_scanState_eq]

end Unicode.Segmentation.GraphemeBreak
