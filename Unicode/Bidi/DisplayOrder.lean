/-
  Unicode.Bidi.DisplayOrder

  Display order equals logical order on left-to-right text.

  The Trojan Source property (Boucher–Anderson, CVE-2021-42574) is that a
  source line reaches the reviewer's eye in the order the compiler reads it.
  UAX #9 permutes a line only through rule L2, and L2 reverses only runs at an
  odd embedding level. This module proves, for every input, that a paragraph
  whose codepoints carry no explicit-formatting class and no right-to-left or
  Arabic-number class resolves every position to an even level, so the visual
  order `reorderedInputIndices` computes is the identity on the retained
  positions. `Unicode.TrojanSource` turns that into the scanner's soundness
  statement: on such text a display/logical divergence cannot exist, so a
  divergence that does exist is caused by a codepoint the scanner names.

  Every theorem here is quantified over the input. Nothing is enumerated and
  nothing is sampled; the proofs walk the rule definitions in
  `Unicode.Bidi.Algorithm` by induction on the record array.
-/

import Unicode.Bidi.Algorithm

namespace Unicode.Bidi.Algorithm

open Unicode.Generated.DerivedBidiClass (BidiClass)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 THE CLASS SETS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- A Bidi class that neither opens or closes an explicit-formatting scope nor
    carries right-to-left or Arabic-number weight. These are the classes of
    ordinary left-to-right source text: letters, European digits and their
    separators and terminators, combining marks, boundary neutrals, the
    separators and whitespace, and other neutrals. -/
def isLtrSafe (bc : BidiClass) : Bool :=
  match bc with
  | .L | .EN | .ES | .ET | .CS | .NSM | .BN | .B | .S | .WS | .ON => true
  | .R | .AL | .AN | .LRE | .LRO | .RLE | .RLO | .PDF
  | .LRI | .RLI | .FSI | .PDI => false

/-- `isLtrSafe` without EN. Under a left-to-right sos the weak rules turn every
    European number into L (W7), so this is the class set the neutral rules
    receive; it contains no class the N-rules or I-rules read as right-to-left. -/
def isLtrResolved (bc : BidiClass) : Bool :=
  match bc with
  | .L | .ES | .ET | .CS | .NSM | .BN | .B | .S | .WS | .ON => true
  | .EN | .R | .AL | .AN | .LRE | .LRO | .RLE | .RLO | .PDF
  | .LRI | .RLI | .FSI | .PDI => false

/-- The whole input is left-to-right text: every codepoint's Bidi class is
    `isLtrSafe`. -/
def leftToRightOnly (cps : List Nat) : Bool :=
  cps.all (fun cp => isLtrSafe (lookupBidiClass cp))

theorem isLtrSafe_of_isLtrResolved (bc : BidiClass)
    (h : isLtrResolved bc = true) : isLtrSafe bc = true := by
  cases bc <;> first | rfl | exact absurd h (by decide)

/-- The record invariant carried through the X-rules and every isolating run
    sequence: embedding level zero and a left-to-right-safe resolved class. -/
abbrev LtrRecord (r : CharRecord) : Prop :=
  r.level = 0 ∧ isLtrSafe r.resolvedClass = true

/-- The invariant after the weak rules: level zero and no European number. -/
abbrev ResolvedRecord (r : CharRecord) : Prop :=
  r.level = 0 ∧ isLtrResolved r.resolvedClass = true

theorem LtrRecord_of_ResolvedRecord (r : CharRecord) (h : ResolvedRecord r) :
    LtrRecord r :=
  ⟨h.1, isLtrSafe_of_isLtrResolved r.resolvedClass h.2⟩

/-- The `Inhabited` record the `!` accessors fall back to: level zero, class L. -/
theorem default_LtrRecord : LtrRecord (default : CharRecord) := ⟨rfl, rfl⟩

theorem default_ResolvedRecord : ResolvedRecord (default : CharRecord) := ⟨rfl, rfl⟩

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 LIST HELPERS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- An element of `l.set i a` is `a` or an element of `l`. -/
theorem mem_of_mem_set {α : Type} {l : List α} {i : Nat} {a x : α}
    (h : x ∈ l.set i a) : x = a ∨ x ∈ l := by
  induction l generalizing i with
  | nil => simp at h
  | cons b bs ih =>
      cases i with
      | zero =>
          rw [List.set_cons_zero, List.mem_cons] at h
          rcases h with h | h
          · exact Or.inl h
          · exact Or.inr (List.mem_cons_of_mem b h)
      | succ n =>
          rw [List.set_cons_succ, List.mem_cons] at h
          rcases h with h | h
          · exact Or.inr (h ▸ List.mem_cons_self)
          · rcases ih h with hEq | hMem
            · exact Or.inl hEq
            · exact Or.inr (List.mem_cons_of_mem b hMem)

/-- A `!` read is an element of the list or the `Inhabited` default. -/
theorem getElem!_mem_or_default {α : Type} [Inhabited α] (l : List α) (i : Nat) :
    l[i]! ∈ l ∨ l[i]! = default := by
  rw [List.getElem!_eq_getElem?_getD]
  cases h : l[i]? with
  | none => exact Or.inr rfl
  | some a => exact Or.inl (List.mem_of_getElem? h)

/-- A property that holds of every element and of the default holds of every
    `!` read. -/
theorem getElem!_prop {α : Type} [Inhabited α] (P : α → Prop) (l : List α) (i : Nat)
    (hAll : ∀ x ∈ l, P x) (hDefault : P default) : P l[i]! := by
  rcases getElem!_mem_or_default l i with hMem | hDef
  · exact hAll l[i]! hMem
  · rw [hDef]; exact hDefault

/-- A fold that appends one element per step, threading a state: every output
    element is `f st a` for a state satisfying the invariant `I` and an input
    element satisfying `Q`, so it satisfies `P`. -/
theorem foldl_append_mem {α β σ : Type} (f : σ → α → β) (g : σ → α → σ)
    (I : σ → Prop) (Q : α → Prop) (P : β → Prop)
    (hI : ∀ st a, I st → Q a → I (g st a))
    (hP : ∀ st a, I st → Q a → P (f st a)) :
    ∀ (l : List α) (out : List β) (st : σ), I st → (∀ a ∈ l, Q a) →
      (∀ x ∈ out, P x) →
      ∀ x ∈ (l.foldl (fun acc a => (acc.1 ++ [f acc.2 a], g acc.2 a)) (out, st)).1,
        P x := by
  intro l
  induction l with
  | nil => intro out st hSt hQ hOut x hx; exact hOut x hx
  | cons a rest ih =>
      intro out st hSt hQ hOut x hx
      rw [List.foldl_cons] at hx
      have hQa : Q a := hQ a List.mem_cons_self
      have hOut' : ∀ y ∈ out ++ [f st a], P y := by
        intro y hy
        rcases List.mem_append.mp hy with hyOut | hySingle
        · exact hOut y hyOut
        · rw [List.mem_singleton.mp hySingle]; exact hP st a hSt hQa
      exact ih (out ++ [f st a]) (g st a) (hI st a hSt hQa)
        (fun b hb => hQ b (List.mem_cons_of_mem a hb)) hOut' x hx

/-- A fold preserves an invariant its step preserves on the elements folded. -/
theorem foldl_invariant {α σ : Type} (F : σ → α → σ) (I : σ → Prop) :
    ∀ (l : List α) (init : σ), I init → (∀ st a, a ∈ l → I st → I (F st a)) →
      I (l.foldl F init) := by
  intro l
  induction l with
  | nil => intro init hInit hStep; exact hInit
  | cons a rest ih =>
      intro init hInit hStep
      rw [List.foldl_cons]
      exact ih (F init a) (hStep init a List.mem_cons_self hInit)
        (fun st b hb hst => hStep st b (List.mem_cons_of_mem a hb) hst)

/-- `mapIdx` with a function that fixes every element of the list is the
    identity. -/
theorem mapIdx_id_of_fixed {α : Type} :
    ∀ (l : List α) (f : Nat → α → α), (∀ a ∈ l, ∀ i, f i a = a) → List.mapIdx f l = l := by
  intro l
  induction l with
  | nil => intro f hf; rfl
  | cons a rest ih =>
      intro f hf
      rw [List.mapIdx_cons, hf a List.mem_cons_self 0]
      rw [ih (fun i => f (i + 1)) (fun b hb i => hf b (List.mem_cons_of_mem a hb) (i + 1))]

/-- Every element of `mapIdx f l` is `f i x` for an element `x` of `l`. -/
theorem mapIdx_mem_prop {α β : Type} (f : Nat → α → β) (l : List α) (P : β → Prop)
    (h : ∀ i x, x ∈ l → P (f i x)) : ∀ y ∈ List.mapIdx f l, P y := by
  intro y hy
  rcases List.mem_mapIdx.mp hy with ⟨i, hi, hEq⟩
  rw [← hEq]
  exact h i l[i] (List.getElem_mem hi)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 P2/P3 — THE PARAGRAPH LEVEL IS ZERO
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The first-strong scan over left-to-right text finds nothing or L. -/
theorem firstStrong_ltr (cps : List Nat)
    (h : ∀ cp ∈ cps, isLtrSafe (lookupBidiClass cp) = true) :
    firstStrongIgnoringIsolates cps = none ∨ firstStrongIgnoringIsolates cps = some .L := by
  unfold firstStrongIgnoringIsolates
  generalize hinit : ((none : Option BidiClass), (0 : Nat)) = init
  have hI : init.1 = none ∨ init.1 = some .L := by rw [← hinit]; exact Or.inl rfl
  clear hinit
  induction cps generalizing init with
  | nil => exact hI
  | cons cp rest ih =>
      rw [List.foldl_cons]
      apply ih (fun c hc => h c (List.mem_cons_of_mem cp hc))
      have hSafe := h cp List.mem_cons_self
      rcases init with ⟨found, depth⟩
      cases found with
      | some c => exact hI
      | none =>
          dsimp only
          generalize hbc : lookupBidiClass cp = bc at hSafe ⊢
          cases bc <;> simp [isLtrSafe, isStrong] at hSafe ⊢ <;> (try split) <;> simp

/-- **Left-to-right text has paragraph level zero.** P2 finds no strong
    character or an L, and P3 assigns level 1 only to R or AL. -/
theorem paragraphLevel_ltr (cps : List Nat)
    (h : ∀ cp ∈ cps, isLtrSafe (lookupBidiClass cp) = true) :
    paragraphLevel cps = 0 := by
  unfold paragraphLevel
  rcases firstStrong_ltr cps h with hf | hf <;> rw [hf]

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 X5c — NO FSI TO RESOLVE
-- ═══════════════════════════════════════════════════════════════════════════════

theorem resolveFSIAt_id (cps : List Nat) (i cp : Nat)
    (h : lookupBidiClass cp ≠ .FSI) : resolveFSIAt cps i cp = cp := by
  unfold resolveFSIAt
  rw [ite_eq_right h]

/-- **X5c is the identity on left-to-right text**: there is no FSI to rewrite. -/
theorem resolveFSI_ltr (cps : List Nat)
    (h : ∀ cp ∈ cps, isLtrSafe (lookupBidiClass cp) = true) :
    resolveFSI cps = cps := by
  unfold resolveFSI
  apply mapIdx_id_of_fixed
  intro cp hcp i
  apply resolveFSIAt_id
  intro hf
  have hSafe := h cp hcp
  rw [hf] at hSafe
  exact absurd hSafe (by decide)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 X1–X10 — EVERY RECORD AT LEVEL ZERO, CLASS UNCHANGED
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The record the X-rules emit for one codepoint of left-to-right text at
    paragraph level zero, or nothing when X9 removes it. -/
def plainRecord (cp : Nat) : Option CharRecord :=
  let bc := lookupBidiClass cp
  if isX9Removed bc then none
  else some { codepoint := cp, origClass := bc, level := 0, resolvedClass := bc }

/-- The X-rules state at paragraph level zero: one stack frame, no overflow,
    no open isolate, and the record list `acc`. -/
def ltrState (acc : List CharRecord) : XState :=
  { stack            := [{ level := 0, override := none, isolate := false }],
    overflowEmbed    := 0,
    overflowIsolate  := 0,
    validIsolates    := 0,
    records          := acc }

/-- **One X-rules step on a left-to-right-safe codepoint** leaves the stack and
    the overflow counters alone and appends the plain record, if any. -/
theorem xStep_ltr (cp : Nat) (acc : List CharRecord)
    (h : isLtrSafe (lookupBidiClass cp) = true) :
    xStep 0 cp (ltrState acc) = ltrState (acc ++ (plainRecord cp).toList) := by
  unfold xStep plainRecord ltrState
  cases hbc : lookupBidiClass cp <;> simp [hbc, isLtrSafe] at h ⊢ <;>
    simp [topEntry, applyOverride, isX9Removed]

/-- The X-rules fold over left-to-right text, from any record prefix. -/
theorem xFold_ltr :
    ∀ (cps : List Nat) (acc : List CharRecord),
      (∀ cp ∈ cps, isLtrSafe (lookupBidiClass cp) = true) →
      cps.foldl (fun s cp => xStep 0 cp s) (ltrState acc)
        = ltrState (acc ++ cps.filterMap plainRecord) := by
  intro cps
  induction cps with
  | nil => intro acc hAll; simp
  | cons cp rest ih =>
      intro acc h
      rw [List.foldl_cons, xStep_ltr cp acc (h cp List.mem_cons_self),
        ih (acc ++ (plainRecord cp).toList)
          (fun c hc => h c (List.mem_cons_of_mem cp hc)),
        List.filterMap_cons]
      cases plainRecord cp <;> simp

/-- **The X-rules on left-to-right text emit exactly the plain records.** -/
theorem assignLevelsAt_ltr (cps : List Nat)
    (h : ∀ cp ∈ cps, isLtrSafe (lookupBidiClass cp) = true) :
    assignLevelsAt cps 0 = cps.filterMap plainRecord := by
  unfold assignLevelsAt
  simp only []
  rw [resolveFSI_ltr cps h]
  have hFold := xFold_ltr cps [] h
  unfold ltrState at hFold
  rw [hFold]
  simp

theorem plainRecord_LtrRecord (cp : Nat) (r : CharRecord)
    (h : isLtrSafe (lookupBidiClass cp) = true) (hr : plainRecord cp = some r) :
    LtrRecord r := by
  unfold plainRecord at hr
  generalize hbc : lookupBidiClass cp = bc at h hr
  simp only [] at hr
  split at hr
  · cases hr
  · cases hr
    exact ⟨rfl, h⟩

/-- **Every X-rules record on left-to-right text is at level zero with a safe
    class.** -/
theorem assignLevelsAt_ltr_records (cps : List Nat)
    (h : ∀ cp ∈ cps, isLtrSafe (lookupBidiClass cp) = true) :
    ∀ r ∈ assignLevelsAt cps 0, LtrRecord r := by
  rw [assignLevelsAt_ltr cps h]
  intro r hr
  rcases List.mem_filterMap.mp hr with ⟨cp, hcp, hpr⟩
  exact plainRecord_LtrRecord cp r (h cp hcp) hpr

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 W1–W7 — THE WEAK RULES KEEP THE CLASS SET AND REMOVE EN
--
-- Each rule is a fold or a pointwise map over the record array. The step
-- functions are restated here so the fold lemma can name them; every proof
-- checks the restatement against the rule by definitional unfolding.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The class W1 assigns: an NSM takes its predecessor's class (ON after an
    isolate initiator or PDI); every other class is kept. -/
def w1Class (prev : BidiClass) (r : CharRecord) : BidiClass :=
  match r.resolvedClass with
  | .NSM =>
    match prev with
    | .LRI | .RLI | .FSI | .PDI => .ON
    | .L | .R | .AL | .EN | .ES | .ET | .AN | .CS | .NSM | .BN
    | .B | .S | .WS | .ON | .LRE | .LRO | .RLE | .RLO | .PDF => prev
  | .L | .R | .AL | .EN | .ES | .ET | .AN | .CS | .BN
  | .B | .S | .WS | .ON | .LRE | .LRO | .RLE | .RLO | .PDF
  | .LRI | .RLI | .FSI | .PDI => r.resolvedClass

theorem w1Class_safe (prev : BidiClass) (r : CharRecord)
    (hp : isLtrSafe prev = true) (hr : isLtrSafe r.resolvedClass = true) :
    isLtrSafe (w1Class prev r) = true := by
  unfold w1Class
  generalize r.resolvedClass = cls at hr ⊢
  cases cls <;> simp [isLtrSafe] at hr ⊢ <;> cases prev <;> simp [isLtrSafe] at hp ⊢

theorem applyW1_ltr (records : List CharRecord) (hAll : ∀ r ∈ records, LtrRecord r) :
    ∀ r ∈ applyW1 .L records, LtrRecord r := by
  unfold applyW1
  exact foldl_append_mem
    (fun prev r => { r with resolvedClass := w1Class prev r })
    (fun prev r => w1Class prev r)
    (fun prev => isLtrSafe prev = true) LtrRecord LtrRecord
    (fun st r hst hr => w1Class_safe st r hst hr.2)
    (fun st r hst hr => ⟨hr.1, w1Class_safe st r hst hr.2⟩)
    records [] .L rfl hAll (fun x hx => absurd hx List.not_mem_nil)

/-- The class W2 assigns: EN after an AL becomes AN. -/
def w2Class (lastStrong : BidiClass) (r : CharRecord) : BidiClass :=
  match r.resolvedClass with
  | .EN => if lastStrong = .AL then .AN else .EN
  | .L | .R | .AL | .ES | .ET | .AN | .CS | .NSM | .BN
  | .B | .S | .WS | .ON | .LRE | .LRO | .RLE | .RLO | .PDF
  | .LRI | .RLI | .FSI | .PDI => r.resolvedClass

/-- The strong class W2 carries forward. -/
def w2Strong (lastStrong : BidiClass) (r : CharRecord) : BidiClass :=
  match r.resolvedClass with
  | .L | .R | .AL => r.resolvedClass
  | .EN | .ES | .ET | .AN | .CS | .NSM | .BN
  | .B | .S | .WS | .ON | .LRE | .LRO | .RLE | .RLO | .PDF
  | .LRI | .RLI | .FSI | .PDI => lastStrong

theorem w2Class_safe (lastStrong : BidiClass) (r : CharRecord)
    (hs : lastStrong = .L) (hr : isLtrSafe r.resolvedClass = true) :
    isLtrSafe (w2Class lastStrong r) = true := by
  unfold w2Class
  subst hs
  generalize r.resolvedClass = cls at hr ⊢
  cases cls <;> simp [isLtrSafe] at hr ⊢

theorem w2Strong_L (lastStrong : BidiClass) (r : CharRecord)
    (hs : lastStrong = .L) (hr : isLtrSafe r.resolvedClass = true) :
    w2Strong lastStrong r = .L := by
  unfold w2Strong
  subst hs
  generalize r.resolvedClass = cls at hr ⊢
  cases cls <;> simp [isLtrSafe] at hr ⊢

theorem applyW2_ltr (records : List CharRecord) (hAll : ∀ r ∈ records, LtrRecord r) :
    ∀ r ∈ applyW2 .L records, LtrRecord r := by
  unfold applyW2
  exact foldl_append_mem
    (fun lastStrong r => { r with resolvedClass := w2Class lastStrong r })
    (fun lastStrong r => w2Strong lastStrong r)
    (fun lastStrong => lastStrong = .L) LtrRecord LtrRecord
    (fun st r hst hr => w2Strong_L st r hst hr.2)
    (fun st r hst hr => ⟨hr.1, w2Class_safe st r hst hr.2⟩)
    records [] .L rfl hAll (fun x hx => absurd hx List.not_mem_nil)

theorem applyW3_ltr (records : List CharRecord) (hAll : ∀ r ∈ records, LtrRecord r) :
    ∀ r ∈ applyW3 records, LtrRecord r := by
  unfold applyW3
  intro y hy
  rcases List.mem_map.mp hy with ⟨r, hr, hEq⟩
  rw [← hEq]
  obtain ⟨hlvl, hsafe⟩ := hAll r hr
  have hNotAL : ¬ r.resolvedClass = .AL := by
    intro hAL
    rw [hAL] at hsafe
    exact absurd hsafe (by decide)
  rw [ite_eq_right hNotAL]
  exact ⟨hlvl, hsafe⟩

theorem applyW4_ltr (records : List CharRecord) (hAll : ∀ r ∈ records, LtrRecord r) :
    ∀ r ∈ applyW4 records, LtrRecord r := by
  unfold applyW4
  apply mapIdx_mem_prop
  intro i x hx
  obtain ⟨hlvl, hsafe⟩ := hAll x hx
  try dsimp only
  split
  · have hNoAN : ∀ j : Nat, ¬ (records[j]! : CharRecord).resolvedClass = BidiClass.AN := by
      intro j hj
      have hj' := (getElem!_prop LtrRecord records j hAll default_LtrRecord).2
      rw [hj] at hj'
      exact absurd hj' (by decide)
    simp only [hNoAN, false_and, ite_false]
    cases hc : x.resolvedClass <;> simp only <;> (try split) <;>
      first
      | exact ⟨hlvl, rfl⟩
      | exact ⟨hlvl, hsafe⟩
  · exact ⟨hlvl, hsafe⟩

theorem applyW5_ltr (records : List CharRecord) (hAll : ∀ r ∈ records, LtrRecord r) :
    ∀ r ∈ applyW5 records, LtrRecord r := by
  unfold applyW5
  apply mapIdx_mem_prop
  intro i x hx
  obtain ⟨hlvl, hsafe⟩ := hAll x hx
  try dsimp only
  split
  · exact ⟨hlvl, rfl⟩
  · exact ⟨hlvl, hsafe⟩

theorem applyW6_ltr (records : List CharRecord) (hAll : ∀ r ∈ records, LtrRecord r) :
    ∀ r ∈ applyW6 records, LtrRecord r := by
  unfold applyW6
  intro y hy
  rcases List.mem_map.mp hy with ⟨r, hr, hEq⟩
  rw [← hEq]
  obtain ⟨hlvl, hsafe⟩ := hAll r hr
  cases hc : r.resolvedClass <;> simp only <;>
    first
    | exact ⟨hlvl, rfl⟩
    | exact ⟨hlvl, hsafe⟩

/-- The class W7 assigns: EN after an L (or a left sos) becomes L. -/
def w7Class (lastStrong : BidiClass) (r : CharRecord) : BidiClass :=
  match r.resolvedClass with
  | .EN => if lastStrong = .L then .L else .EN
  | .L | .R | .AL | .ES | .ET | .AN | .CS | .NSM | .BN
  | .B | .S | .WS | .ON | .LRE | .LRO | .RLE | .RLO | .PDF
  | .LRI | .RLI | .FSI | .PDI => r.resolvedClass

/-- The strong class W7 carries forward. -/
def w7Strong (lastStrong : BidiClass) (r : CharRecord) : BidiClass :=
  match r.resolvedClass with
  | .L | .R => r.resolvedClass
  | .AL | .EN | .ES | .ET | .AN | .CS | .NSM | .BN
  | .B | .S | .WS | .ON | .LRE | .LRO | .RLE | .RLO | .PDF
  | .LRI | .RLI | .FSI | .PDI => lastStrong

theorem w7Class_resolved (lastStrong : BidiClass) (r : CharRecord)
    (hs : lastStrong = .L) (hr : isLtrSafe r.resolvedClass = true) :
    isLtrResolved (w7Class lastStrong r) = true := by
  unfold w7Class
  subst hs
  generalize r.resolvedClass = cls at hr ⊢
  cases cls <;> simp [isLtrSafe, isLtrResolved] at hr ⊢

theorem w7Strong_L (lastStrong : BidiClass) (r : CharRecord)
    (hs : lastStrong = .L) (hr : isLtrSafe r.resolvedClass = true) :
    w7Strong lastStrong r = .L := by
  unfold w7Strong
  subst hs
  generalize r.resolvedClass = cls at hr ⊢
  cases cls <;> simp [isLtrSafe] at hr ⊢

/-- **W7 under a left sos leaves no European number**: every EN's nearest
    preceding strong class is L (the sos itself when nothing precedes), so
    every EN becomes L. -/
theorem applyW7_ltr (records : List CharRecord) (hAll : ∀ r ∈ records, LtrRecord r) :
    ∀ r ∈ applyW7 .L records, ResolvedRecord r := by
  unfold applyW7
  exact foldl_append_mem
    (fun lastStrong r => { r with resolvedClass := w7Class lastStrong r })
    (fun lastStrong r => w7Strong lastStrong r)
    (fun lastStrong => lastStrong = .L) LtrRecord ResolvedRecord
    (fun st r hst hr => w7Strong_L st r hst hr.2)
    (fun st r hst hr => ⟨hr.1, w7Class_resolved st r hst hr.2⟩)
    records [] .L rfl hAll (fun x hx => absurd hx List.not_mem_nil)

/-- **The weak rules under a left sos** keep every record at level zero and
    leave a class set with no R, AL, AN or EN. -/
theorem applyWeakRules_ltr (records : List CharRecord)
    (hAll : ∀ r ∈ records, LtrRecord r) :
    ∀ r ∈ applyWeakRules .L records, ResolvedRecord r := by
  unfold applyWeakRules
  exact applyW7_ltr
    (applyW6 (applyW5 (applyW4 (applyW3 (applyW2 .L (applyW1 .L records))))))
    (applyW6_ltr (applyW5 (applyW4 (applyW3 (applyW2 .L (applyW1 .L records)))))
      (applyW5_ltr (applyW4 (applyW3 (applyW2 .L (applyW1 .L records))))
        (applyW4_ltr (applyW3 (applyW2 .L (applyW1 .L records)))
          (applyW3_ltr (applyW2 .L (applyW1 .L records))
            (applyW2_ltr (applyW1 .L records)
              (applyW1_ltr records hAll))))))

-- ═══════════════════════════════════════════════════════════════════════════════
-- §7 N0–N2 — THE NEUTRAL RULES RESOLVE EVERYTHING TO L
-- ═══════════════════════════════════════════════════════════════════════════════

theorem asNDir_resolved (bc : BidiClass) (h : isLtrResolved bc = true) :
    asNDir bc = none ∨ asNDir bc = some .LTR := by
  cases bc <;> simp [isLtrResolved] at h ⊢ <;> simp [asNDir]

/-- The direction carried past one record by the N1/N2 scans. -/
def nDirStep (prev : Direction) (r : CharRecord) : Direction :=
  match asNDir r.resolvedClass with
  | some d => d
  | none => prev

theorem nDirStep_LTR (prev : Direction) (r : CharRecord)
    (hp : prev = .LTR) (hr : ResolvedRecord r) : nDirStep prev r = .LTR := by
  unfold nDirStep
  rcases asNDir_resolved r.resolvedClass hr.2 with hNone | hSome
  · rw [hNone]; exact hp
  · rw [hSome]

theorem leftStrongDir_ltr (records : List CharRecord)
    (hAll : ∀ r ∈ records, ResolvedRecord r) :
    ∀ d ∈ leftStrongDir .LTR records, d = .LTR := by
  unfold leftStrongDir
  exact foldl_append_mem
    (fun prev r => prev)
    (fun prev r => nDirStep prev r)
    (fun prev => prev = .LTR) ResolvedRecord (fun d => d = .LTR)
    (fun st r hst hr => nDirStep_LTR st r hst hr)
    (fun st r hst hr => hst)
    records [] .LTR rfl hAll (fun x hx => absurd hx List.not_mem_nil)

theorem rightStrongDir_ltr (records : List CharRecord)
    (hAll : ∀ r ∈ records, ResolvedRecord r) :
    ∀ d ∈ rightStrongDir .LTR records, d = .LTR := by
  unfold rightStrongDir
  intro d hd
  rw [List.mem_reverse] at hd
  exact foldl_append_mem
    (fun prev r => prev)
    (fun prev r => nDirStep prev r)
    (fun prev => prev = .LTR) ResolvedRecord (fun d => d = .LTR)
    (fun st r hst hr => nDirStep_LTR st r hst hr)
    (fun st r hst hr => hst)
    records.reverse [] .LTR rfl
    (fun r hr => hAll r (List.mem_reverse.mp hr))
    (fun x hx => absurd hx List.not_mem_nil) d hd

theorem getD_LTR (dirs : List Direction) (i : Nat) (h : ∀ d ∈ dirs, d = .LTR) :
    dirs[i]?.getD .LTR = .LTR := by
  cases hd : dirs[i]? with
  | none => rfl
  | some d => exact h d (List.mem_of_getElem? hd)

theorem embeddingDirection_zero : embeddingDirection 0 = .LTR := by decide

/-- A direction-valued fold stays left when it starts left and every step
    keeps left. Stated over the step function so a rewrite keyed on
    `List.foldl` can find the fold inside a rule without restating its step. -/
theorem foldl_dir_LTR (F : Direction → CharRecord → Direction) (l : List CharRecord)
    (init : Direction) (hInit : init = .LTR)
    (hF : ∀ st r, r ∈ l → st = .LTR → F st r = .LTR) :
    l.foldl F init = .LTR :=
  foldl_invariant F (fun d => d = .LTR) l init hInit (fun st r hr hst => hF st r hr hst)

/-- **N1/N2 at level zero between left boundaries** set every neutral to L. -/
theorem applyN1N2_ltr (records : List CharRecord)
    (hAll : ∀ r ∈ records, ResolvedRecord r) :
    ∀ r ∈ applyN1N2 .LTR .LTR 0 records, ResolvedRecord r := by
  unfold applyN1N2
  try dsimp only
  apply mapIdx_mem_prop
  intro i x hx
  obtain ⟨hlvl, hres⟩ := hAll x hx
  try dsimp only
  split
  · have hl := getD_LTR (leftStrongDir .LTR records) i (leftStrongDir_ltr records hAll)
    have hr := getD_LTR (rightStrongDir .LTR records) i (rightStrongDir_ltr records hAll)
    simp only [hl, hr, embeddingDirection_zero, ite_true]
    exact ⟨hlvl, rfl⟩
  · exact ⟨hlvl, hres⟩

/-- Setting one record's class to L keeps the invariant. -/
theorem set_L_resolved (l : List CharRecord) (i : Nat)
    (hAll : ∀ r ∈ l, ResolvedRecord r) :
    ∀ r ∈ l.set i { l[i]! with resolvedClass := .L }, ResolvedRecord r := by
  intro r hr
  rcases mem_of_mem_set hr with hEq | hMem
  · rw [hEq]
    exact ⟨(getElem!_prop ResolvedRecord l i hAll default_ResolvedRecord).1, rfl⟩
  · exact hAll r hMem

/-- The guarded form N0 uses: set the class to L when the index is in range. -/
theorem set_L_if_resolved (l : List CharRecord) (i : Nat)
    (hAll : ∀ r ∈ l, ResolvedRecord r) :
    ∀ r ∈ (if i < l.length then l.set i { l[i]! with resolvedClass := .L } else l),
      ResolvedRecord r := by
  split
  · exact set_L_resolved l i hAll
  · exact hAll

theorem setBoth_L_resolved (records : List CharRecord) (openIdx closeIdx : Nat)
    (hAll : ∀ r ∈ records, ResolvedRecord r) :
    ∀ r ∈ (let withOpen :=
              if openIdx < records.length then
                records.set openIdx { records[openIdx]! with resolvedClass := .L }
              else records
            if closeIdx < withOpen.length then
              withOpen.set closeIdx { withOpen[closeIdx]! with resolvedClass := .L }
            else withOpen),
      ResolvedRecord r := by
  intro r hr
  exact set_L_if_resolved
    (if openIdx < records.length then
      records.set openIdx { records[openIdx]! with resolvedClass := .L } else records)
    closeIdx (set_L_if_resolved records openIdx hAll) r hr

/-- **N0 at level zero** resolves a bracket pair to L or leaves it alone. The
    N0(c) scan for the strong class before the opening bracket reads only
    resolved classes, so it stays left and the pair takes the embedding
    direction. -/
theorem resolveBracketPair_ltr (records : List CharRecord) (openIdx closeIdx : Nat)
    (hAll : ∀ r ∈ records, ResolvedRecord r) :
    ∀ r ∈ resolveBracketPair records 0 openIdx closeIdx, ResolvedRecord r := by
  unfold resolveBracketPair
  try dsimp only
  -- The N0(c) scan for the strong class before the opening bracket is the
  -- only direction-valued fold here; keyed on `List.foldl`, the rewrite finds
  -- it without restating its step. It reads only resolved classes, so it
  -- answers left, and every branch then sets brackets to L or keeps the
  -- records.
  rw [foldl_dir_LTR]
  · simp only [embeddingDirection_zero, ite_true]
    try dsimp only
    repeat' split
    all_goals first
      | exact hAll
      | (apply set_L_resolved; first | exact hAll | (apply set_L_resolved; exact hAll))
      | (rename_i hne; exact absurd rfl hne)
  · exact embeddingDirection_zero
  · intro st r hr hst
    subst hst
    have hres := (hAll r (List.mem_of_mem_take hr)).2
    generalize r.resolvedClass = cls at hres ⊢
    cases cls <;> simp [isLtrResolved] at hres ⊢

theorem applyN0_ltr (records : List CharRecord)
    (hAll : ∀ r ∈ records, ResolvedRecord r) :
    ∀ r ∈ applyN0 records 0, ResolvedRecord r := by
  unfold applyN0
  apply foldl_invariant (I := fun acc => ∀ r ∈ acc, ResolvedRecord r)
  · exact hAll
  · intro st i hi hst
    split
    · rename_i c hc
      exact resolveBracketPair_ltr st i c hst
    · exact hst
    · exact hst

/-- **The neutral rules at level zero between left boundaries** keep every
    record at level zero with no right-to-left class. -/
theorem applyNeutralRules_ltr (records : List CharRecord)
    (hAll : ∀ r ∈ records, ResolvedRecord r) :
    ∀ r ∈ applyNeutralRules .LTR .LTR 0 records, ResolvedRecord r := by
  unfold applyNeutralRules
  exact applyN1N2_ltr (applyN0 records 0) (applyN0_ltr records hAll)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §8 ONE ISOLATING RUN SEQUENCE AT LEVEL ZERO
-- ═══════════════════════════════════════════════════════════════════════════════

theorem level_getElem!_zero (records : List CharRecord)
    (hAll : ∀ r ∈ records, r.level = 0) (i : Nat) :
    (records[i]! : CharRecord).level = 0 :=
  getElem!_prop (fun r => r.level = 0) records i hAll rfl

/-- **Both boundaries of a run at level zero in a level-zero paragraph are
    left-to-right.** Every level the boundary rule reads is zero. -/
theorem computeIRSBoundaries_zero (records : List CharRecord) (irs : List Nat)
    (hAll : ∀ r ∈ records, r.level = 0) :
    computeIRSBoundaries records 0 irs = (.LTR, .LTR) := by
  unfold computeIRSBoundaries
  have hz : ∀ i : Nat, (records[i]?.getD default : CharRecord).level = 0 := by
    intro i
    rw [← List.getElem!_eq_getElem?_getD]
    exact level_getElem!_zero records hAll i
  split
  · simp [embeddingDirection]
  · simp [hz, embeddingDirection]

/-- The merge of a resolved run back into the record array keeps the
    invariant: every written record is a resolved one. -/
theorem mergeFold_ltr (irs : List Nat) (neutral records : List CharRecord)
    (hN : ∀ r ∈ neutral, LtrRecord r) (hR : ∀ r ∈ records, LtrRecord r) :
    ∀ r ∈ (irs.foldl
      (fun (acc : List CharRecord × Nat) recIdx =>
        let (out, j) := acc
        if hj : j < neutral.length then
          if recIdx < out.length then
            (out.set recIdx (neutral[j]'hj), j + 1)
          else (out, j + 1)
        else (out, j + 1))
      (records, 0)).1, LtrRecord r := by
  apply foldl_invariant (I := fun (acc : List CharRecord × Nat) => ∀ r ∈ acc.1, LtrRecord r)
  · exact hR
  · intro st recIdx hIdx hst
    rcases st with ⟨out, j⟩
    try dsimp only
    split
    · rename_i hj
      split
      · intro r hr
        rcases mem_of_mem_set hr with hEq | hMem
        · rw [hEq]; exact hN neutral[j] (List.getElem_mem hj)
        · exact hst r hMem
      · exact hst
    · exact hst

/-- **One isolating run sequence at level zero keeps every record at level
    zero with a left-to-right-safe class.** The run's boundaries are left, the
    weak rules leave no European number, the neutral rules resolve to L, and
    the merge writes only those records. -/
theorem applyWAndNToIRS_ltr (records : List CharRecord) (irs : List Nat)
    (hAll : ∀ r ∈ records, LtrRecord r) :
    ∀ r ∈ applyWAndNToIRS 0 records irs, LtrRecord r := by
  unfold applyWAndNToIRS
  by_cases hE : irs.isEmpty = true
  · rw [ite_eq_left hE]; exact hAll
  · rw [ite_eq_right hE]
    have hB := computeIRSBoundaries_zero records irs (fun r hr => (hAll r hr).1)
    have hz : ∀ i : Nat, (records[i]! : CharRecord).level = 0 :=
      level_getElem!_zero records (fun r hr => (hAll r hr).1)
    rw [hB]
    try dsimp only
    rw [hz irs[0]!]
    have hIrs : ∀ r ∈ irs.map (fun i => records[i]!), LtrRecord r := by
      intro r hr
      rcases List.mem_map.mp hr with ⟨i, hi, hEq⟩
      rw [← hEq]
      exact getElem!_prop LtrRecord records i hAll default_LtrRecord
    exact mergeFold_ltr irs
      (applyNeutralRules .LTR .LTR 0 (applyWeakRules .L (irs.map (fun i => records[i]!))))
      records
      (fun r hr => LtrRecord_of_ResolvedRecord r
        (applyNeutralRules_ltr (applyWeakRules .L (irs.map (fun i => records[i]!)))
          (applyWeakRules_ltr (irs.map (fun i => records[i]!)) hIrs) r hr))
      hAll

theorem irsFold_ltr (irses : List (List Nat)) (records : List CharRecord)
    (hAll : ∀ r ∈ records, LtrRecord r) :
    ∀ r ∈ irses.foldl (fun acc irs => applyWAndNToIRS 0 acc irs) records, LtrRecord r := by
  apply foldl_invariant (I := fun acc => ∀ r ∈ acc, LtrRecord r)
  · exact hAll
  · intro st irs hirs hst
    exact applyWAndNToIRS_ltr st irs hst

-- ═══════════════════════════════════════════════════════════════════════════════
-- §9 I1/I2 AND L1 KEEP EVERY LEVEL EVEN
-- ═══════════════════════════════════════════════════════════════════════════════

/-- **The implicit rules never produce an odd level from a safe class.** At an
    even level only R raises by one; AN and EN raise by two. -/
theorem applyImplicitLevels_even (records : List CharRecord)
    (hAll : ∀ r ∈ records, LtrRecord r) :
    ∀ r ∈ applyImplicitLevels records, r.level % 2 = 0 := by
  unfold applyImplicitLevels
  intro y hy
  rcases List.mem_map.mp hy with ⟨r, hr, hEq⟩
  rw [← hEq]
  obtain ⟨hlvl, hsafe⟩ := hAll r hr
  try dsimp only
  rw [hlvl]
  generalize hc : r.resolvedClass = cls at hsafe ⊢
  cases cls <;> simp [isLtrSafe] at hsafe ⊢

/-- **L1 at paragraph level zero keeps every level even.** -/
theorem applyL1_even (records : List CharRecord)
    (hAll : ∀ r ∈ records, r.level % 2 = 0) :
    ∀ r ∈ applyL1 0 records, r.level % 2 = 0 := by
  unfold applyL1
  try dsimp only
  apply mapIdx_mem_prop
  intro i x hx
  try dsimp only
  split
  · exact rfl
  · exact hAll x hx

/-- **Every record of a left-to-right paragraph resolves to an even level.** -/
theorem bidiParagraph_ltr_even (cps : List Nat)
    (h : ∀ cp ∈ cps, isLtrSafe (lookupBidiClass cp) = true) :
    ∀ r ∈ (bidiParagraph cps).records, r.level % 2 = 0 := by
  unfold bidiParagraph bidiParagraphAt
  rw [paragraphLevel_ltr cps h]
  try dsimp only
  exact applyL1_even
    (applyImplicitLevels
      ((computeIRSes (assignLevelsAt cps 0)).foldl
        (fun acc irs => applyWAndNToIRS 0 acc irs) (assignLevelsAt cps 0)))
    (applyImplicitLevels_even
      ((computeIRSes (assignLevelsAt cps 0)).foldl
        (fun acc irs => applyWAndNToIRS 0 acc irs) (assignLevelsAt cps 0))
      (irsFold_ltr (computeIRSes (assignLevelsAt cps 0)) (assignLevelsAt cps 0)
        (assignLevelsAt_ltr_records cps h)))

theorem bidiParagraph_ltr_level (cps : List Nat)
    (h : ∀ cp ∈ cps, isLtrSafe (lookupBidiClass cp) = true) :
    (bidiParagraph cps).paragraphLevel = 0 := by
  unfold bidiParagraph bidiParagraphAt
  try dsimp only
  exact paragraphLevel_ltr cps h

-- ═══════════════════════════════════════════════════════════════════════════════
-- §10 LENGTH BOOKKEEPING
--
-- The reorder reads the retained input positions by record index, so the
-- record array and the retained-position list must have the same length.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The merge of a run back into the record array writes in place, so the
    array keeps its length whatever the run holds. -/
theorem mergeFold_length (irs : List Nat) (neutral records : List CharRecord) :
    ((irs.foldl
      (fun (acc : List CharRecord × Nat) recIdx =>
        let (out, j) := acc
        if hj : j < neutral.length then
          if recIdx < out.length then
            (out.set recIdx (neutral[j]'hj), j + 1)
          else (out, j + 1)
        else (out, j + 1))
      (records, 0)).1).length = records.length := by
  apply foldl_invariant
    (I := fun (acc : List CharRecord × Nat) => acc.1.length = records.length)
  · rfl
  · intro st recIdx hIdx hst
    rcases st with ⟨out, j⟩
    try dsimp only
    by_cases hj : j < neutral.length
    · rw [dite_eq_left hj]
      by_cases hr : recIdx < out.length
      · rw [ite_eq_left hr]
        try dsimp only
        rw [List.length_set]
        exact hst
      · rw [ite_eq_right hr]
        exact hst
    · rw [dite_eq_right hj]
      exact hst

theorem applyWAndNToIRS_length (records : List CharRecord) (irs : List Nat) :
    (applyWAndNToIRS 0 records irs).length = records.length := by
  unfold applyWAndNToIRS
  by_cases hE : irs.isEmpty = true
  · rw [ite_eq_left hE]
  · rw [ite_eq_right hE]
    rcases hB : computeIRSBoundaries records 0 irs with ⟨sos, eos⟩
    try dsimp only
    apply mergeFold_length

theorem irsFold_length (irses : List (List Nat)) (records : List CharRecord) :
    (irses.foldl (fun acc irs => applyWAndNToIRS 0 acc irs) records).length
      = records.length := by
  apply foldl_invariant (I := fun (acc : List CharRecord) => acc.length = records.length)
  · rfl
  · intro st irs hirs hst
    rw [applyWAndNToIRS_length]
    exact hst

/-- The step of `originalInputIndices`, named so the fold can be reasoned about. -/
def retainedIndexStep (acc : List Nat × Nat) (cp : Nat) : List Nat × Nat :=
  let (out, idx) := acc
  let bc := lookupBidiClass cp
  if isX9Removed bc then (out, idx + 1)
  else (out ++ [idx], idx + 1)

theorem originalInputIndices_eq (cps : List Nat) :
    originalInputIndices cps = (cps.foldl retainedIndexStep ([], 0)).1 := rfl

theorem retainedIndexStep_eq (out : List Nat) (idx cp : Nat) :
    retainedIndexStep (out, idx) cp
      = (if isX9Removed (lookupBidiClass cp) then (out, idx + 1)
         else (out ++ [idx], idx + 1)) := rfl

theorem plainRecord_eq (cp : Nat) :
    plainRecord cp
      = (if isX9Removed (lookupBidiClass cp) then none
         else some { codepoint := cp, origClass := lookupBidiClass cp, level := 0,
                     resolvedClass := lookupBidiClass cp }) := rfl

/-- **The retained positions and the plain records count the same
    codepoints**: both drop exactly the X9-removed classes. -/
theorem retainedIndexFold_length :
    ∀ (cps : List Nat) (out : List Nat) (idx : Nat),
      ((cps.foldl retainedIndexStep (out, idx)).1).length
        = out.length + (cps.filterMap plainRecord).length := by
  intro cps
  induction cps with
  | nil => intro out idx; simp
  | cons cp rest ih =>
      intro out idx
      rw [List.foldl_cons, retainedIndexStep_eq]
      split
      · rename_i hrem
        rw [ih, List.filterMap_cons_none (by rw [plainRecord_eq, ite_eq_left hrem])]
      · rename_i hkeep
        rw [ih, List.filterMap_cons_some (by rw [plainRecord_eq, ite_eq_right hkeep])]
        rw [List.length_append, List.length_singleton, List.length_cons]
        omega

theorem originalInputIndices_length (cps : List Nat) :
    (originalInputIndices cps).length = (cps.filterMap plainRecord).length := by
  rw [originalInputIndices_eq, retainedIndexFold_length, List.length_nil, Nat.zero_add]

theorem bidiParagraph_ltr_length (cps : List Nat)
    (h : ∀ cp ∈ cps, isLtrSafe (lookupBidiClass cp) = true) :
    (bidiParagraph cps).records.length = (originalInputIndices cps).length := by
  rw [originalInputIndices_length]
  unfold bidiParagraph bidiParagraphAt
  rw [paragraphLevel_ltr cps h]
  try dsimp only
  rw [applyL1_length]
  unfold applyImplicitLevels
  rw [List.length_map, irsFold_length, assignLevelsAt_ltr cps h]

-- ═══════════════════════════════════════════════════════════════════════════════
-- §11 THE REORDER IS THE IDENTITY
-- ═══════════════════════════════════════════════════════════════════════════════

/-- L1 rewrites levels only; the codepoint sequence is unchanged. -/
theorem applyL1_map_codepoint (p : Level) (l : List CharRecord) :
    (applyL1 p l).map (fun r => r.codepoint) = l.map (fun r => r.codepoint) := by
  apply List.ext_getElem?
  intro i
  unfold applyL1
  try dsimp only
  rw [List.getElem?_map, List.getElem?_map, List.getElem?_mapIdx]
  cases l[i]? with
  | none => rfl
  | some r =>
      try dsimp only
      split <;> rfl

/-- Reading the retained positions by record index returns the positions
    themselves once the two lists have the same length. -/
theorem mapIdx_codepoint_eq :
    ∀ (records : List CharRecord) (idx : List Nat) (k : Nat),
      records.length + k = idx.length →
      (List.mapIdx (fun i r => { r with codepoint := idx[i + k]?.getD 0 }) records).map
          (fun r => r.codepoint)
        = idx.drop k := by
  intro records
  induction records with
  | nil =>
      intro idx k hlen
      rw [List.mapIdx_nil, List.map_nil]
      symm
      apply List.drop_of_length_le
      rw [← hlen, List.length_nil, Nat.zero_add]
      exact Nat.le_refl k
  | cons r rest ih =>
      intro idx k hlen
      have hk : k < idx.length := by
        rw [← hlen, List.length_cons]
        omega
      have hshift :
          (fun i (r : CharRecord) => { r with codepoint := idx[i + 1 + k]?.getD 0 })
            = (fun i (r : CharRecord) => { r with codepoint := idx[i + (k + 1)]?.getD 0 }) := by
        funext i r
        rw [Nat.add_right_comm i 1 k]
        rfl
      rw [List.mapIdx_cons, List.map_cons, List.drop_eq_getElem_cons hk]
      rw [hshift, ih idx (k + 1) (by rw [← hlen, List.length_cons]; omega)]
      rw [Nat.zero_add, List.getElem?_eq_getElem hk]
      rfl

/-- **Display order equals logical order on left-to-right text.** The visual
    order of the retained input positions is the identity: no position moves. -/
theorem reorderedInputIndices_ltr (cps : List Nat)
    (h : ∀ cp ∈ cps, isLtrSafe (lookupBidiClass cp) = true) :
    reorderedInputIndices cps (bidiParagraph cps) = originalInputIndices cps := by
  have hEven := bidiParagraph_ltr_even cps h
  have hLen := bidiParagraph_ltr_length cps h
  unfold reorderedInputIndices
  try dsimp only
  rw [bidiParagraph_ltr_level cps h]
  -- Name the two lists so the rewrites below match small terms rather than
  -- unfolding the pipeline while searching.
  generalize hI : originalInputIndices cps = idx at hLen ⊢
  generalize hR : (bidiParagraph cps).records = recs at hEven hLen ⊢
  have hIdxEven :
      ∀ r ∈ List.mapIdx (fun i r => { r with codepoint := idx[i]?.getD 0 }) recs,
        r.level % 2 = 0 := by
    apply mapIdx_mem_prop
    intro i x hx
    exact hEven x hx
  rw [applyL2_id_of_all_even
    (applyL1 0 (List.mapIdx (fun i r => { r with codepoint := idx[i]?.getD 0 }) recs))
    (applyL1_even (List.mapIdx (fun i r => { r with codepoint := idx[i]?.getD 0 }) recs)
      hIdxEven)]
  rw [applyL1_map_codepoint]
  exact mapIdx_codepoint_eq recs idx 0 (by rw [Nat.add_zero]; exact hLen)

/-- **The whole line renders in logical order.** `reorderLine` over the full
    record array returns the codepoints as read. -/
theorem reorderLine_ltr (cps : List Nat)
    (h : ∀ cp ∈ cps, isLtrSafe (lookupBidiClass cp) = true) :
    reorderLine (bidiParagraph cps) 0 (bidiParagraph cps).records.length
      = (bidiParagraph cps).records.map (fun r => r.codepoint) := by
  have hEven := bidiParagraph_ltr_even cps h
  unfold reorderLine
  try dsimp only
  rw [List.take_length, List.drop_zero, bidiParagraph_ltr_level cps h]
  generalize hR : (bidiParagraph cps).records = recs at hEven ⊢
  rw [applyL2_id_of_all_even (applyL1 0 recs) (applyL1_even recs hEven)]
  exact applyL1_map_codepoint 0 recs

/-- The same statement under the Boolean predicate a scanner evaluates. -/
theorem displayOrder_of_leftToRightOnly (cps : List Nat)
    (h : leftToRightOnly cps = true) :
    reorderedInputIndices cps (bidiParagraph cps) = originalInputIndices cps :=
  reorderedInputIndices_ltr cps (List.all_eq_true.mp h)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §12 THE CLASS TABLE — WHAT IS NOT LEFT-TO-RIGHT-SAFE
--
-- A codepoint fails `isLtrSafe` for exactly two reasons: an explicit-formatting
-- class, or right-to-left weight. The pinned `DerivedBidiClass` table carries
-- an explicit-formatting class only on a bidi format control
-- (`U+202A..U+202E`, `U+2066..U+2069`), so the first reason is a codepoint
-- `Unicode.TrojanSource.containsBidiFormatControl` reports.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The explicit-formatting classes (UAX #9 §3.3.2). -/
def isExplicitFormatting (bc : BidiClass) : Bool :=
  match bc with
  | .LRE | .LRO | .RLE | .RLO | .PDF | .LRI | .RLI | .FSI | .PDI => true
  | .L | .R | .AL | .EN | .ES | .ET | .AN | .CS | .NSM | .BN | .B | .S | .WS | .ON => false

/-- The classes with right-to-left or Arabic-number weight (R, AL, AN). -/
def isRtlWeight (bc : BidiClass) : Bool :=
  match bc with
  | .R | .AL | .AN => true
  | .L | .EN | .ES | .ET | .CS | .NSM | .BN | .B | .S | .WS | .ON
  | .LRE | .LRO | .RLE | .RLO | .PDF | .LRI | .RLI | .FSI | .PDI => false

theorem isLtrSafe_of_not (bc : BidiClass)
    (hf : isExplicitFormatting bc = false) (hr : isRtlWeight bc = false) :
    isLtrSafe bc = true := by
  cases bc <;> simp [isExplicitFormatting, isRtlWeight, isLtrSafe] at hf hr ⊢

/-- The binary search answers only from a row it read, or from the
    `Inhabited` row (class L) past the end of the table. -/
theorem binarySearchRange_sound (arr : List (Nat × Nat × BidiClass)) (cp : Nat) :
    ∀ (left right fuel : Nat) (cls : BidiClass),
      Unicode.Generated.DerivedBidiClass.binarySearchRange arr cp left right fuel = some cls →
      cls = .L ∨ ∃ row ∈ arr, row.1 ≤ cp ∧ cp ≤ row.2.1 ∧ row.2.2 = cls := by
  intro left right fuel
  induction fuel generalizing left right with
  | zero =>
      intro cls h
      unfold Unicode.Generated.DerivedBidiClass.binarySearchRange at h
      cases h
  | succ fuelNext ih =>
      intro cls h
      unfold Unicode.Generated.DerivedBidiClass.binarySearchRange at h
      try dsimp only at h
      split at h
      · rcases getElem!_mem_or_default arr ((left + right) / 2) with hMem | hDef
        · split at h
          · exact ih left ((left + right) / 2) cls h
          · split at h
            · exact ih ((left + right) / 2 + 1) right cls h
            · rename_i hlo hhi
              cases h
              exact Or.inr ⟨arr[(left + right) / 2]!, hMem,
                Nat.le_of_not_lt hlo, Nat.le_of_not_lt hhi, rfl⟩
        · split at h
          · exact ih left ((left + right) / 2) cls h
          · split at h
            · exact ih ((left + right) / 2 + 1) right cls h
            · cases h
              rw [hDef]
              exact Or.inl rfl
      · cases h

/-- The default-range scan answers only from a row it read. -/
theorem lookupDefault_sound (cp : Nat) (cls : BidiClass)
    (h : Unicode.Generated.DerivedBidiClass.lookupDefault cp = some cls) :
    ∃ row ∈ Unicode.Generated.DerivedBidiClass.defaultRanges,
      row.1 ≤ cp ∧ cp ≤ row.2.1 ∧ row.2.2 = cls := by
  have key :
      Unicode.Generated.DerivedBidiClass.lookupDefault cp = none
        ∨ ∃ row ∈ Unicode.Generated.DerivedBidiClass.defaultRanges,
            row.1 ≤ cp ∧ cp ≤ row.2.1
              ∧ Unicode.Generated.DerivedBidiClass.lookupDefault cp = some row.2.2 := by
    unfold Unicode.Generated.DerivedBidiClass.lookupDefault
    apply foldl_invariant
      (I := fun (acc : Option BidiClass) =>
        acc = none ∨ ∃ row ∈ Unicode.Generated.DerivedBidiClass.defaultRanges,
          row.1 ≤ cp ∧ cp ≤ row.2.1 ∧ acc = some row.2.2)
    · exact Or.inl rfl
    · intro st row hrow hst
      split
      · rename_i hc
        have hp := of_decide_eq_true hc
        exact Or.inr ⟨row, hrow, hp.1, hp.2, rfl⟩
      · exact hst
  rw [h] at key
  rcases key with hNone | ⟨row, hrow, hlo, hhi, hEq⟩
  · cases hNone
  · exact ⟨row, hrow, hlo, hhi, (Option.some.inj hEq).symm⟩

/-- **Table fact.** Every explicit row carrying an explicit-formatting class
    is a single codepoint inside `U+202A..U+202E` or `U+2066..U+2069`. -/
theorem explicitRanges_formatting_rows :
    Unicode.Generated.DerivedBidiClass.explicitRanges.all (fun row =>
      !isExplicitFormatting row.2.2
        || (row.1 == row.2.1
            && ((Nat.ble 0x202A row.1 && Nat.ble row.1 0x202E)
                || (Nat.ble 0x2066 row.1 && Nat.ble row.1 0x2069)))) = true := by
  decide +kernel

/-- **Table fact.** No default range carries an explicit-formatting class. -/
theorem defaultRanges_no_formatting :
    Unicode.Generated.DerivedBidiClass.defaultRanges.all
      (fun row => !isExplicitFormatting row.2.2) = true := by
  decide +kernel

/-- **A codepoint whose class is explicit-formatting is a bidi format
    control**: it lies in `U+202A..U+202E` or `U+2066..U+2069`. -/
theorem formatting_class_range (cp : Nat)
    (h : isExplicitFormatting (lookupBidiClass cp) = true) :
    (0x202A ≤ cp ∧ cp ≤ 0x202E) ∨ (0x2066 ≤ cp ∧ cp ≤ 0x2069) := by
  unfold lookupBidiClass Unicode.Generated.DerivedBidiClass.lookup at h
  cases hE : Unicode.Generated.DerivedBidiClass.lookupExplicitBinary cp with
  | some cls =>
      rw [hE] at h
      try dsimp only at h
      unfold Unicode.Generated.DerivedBidiClass.lookupExplicitBinary at hE
      rcases binarySearchRange_sound Unicode.Generated.DerivedBidiClass.explicitRanges cp
          0 Unicode.Generated.DerivedBidiClass.explicitRanges.length
          (Unicode.Generated.DerivedBidiClass.explicitRanges.length + 1) cls hE
        with hL | ⟨row, hrow, hlo, hhi, hcls⟩
      · rw [hL] at h
        exact absurd h (by decide)
      · have hfact := List.all_eq_true.mp explicitRanges_formatting_rows row hrow
        rw [hcls, h] at hfact
        simp only [Bool.not_true, Bool.false_or, Bool.and_eq_true, Bool.or_eq_true,
          beq_iff_eq, Nat.ble_eq] at hfact
        obtain ⟨hsingle, hrange⟩ := hfact
        have hcp : cp = row.1 := Nat.le_antisymm (hsingle ▸ hhi) hlo
        rw [hcp]
        exact hrange
  | none =>
      rw [hE] at h
      try dsimp only at h
      cases hD : Unicode.Generated.DerivedBidiClass.lookupDefault cp with
      | some cls =>
          rw [hD] at h
          try dsimp only at h
          rcases lookupDefault_sound cp cls hD with ⟨row, hrow, hlo, hhi, hcls⟩
          have hfact := List.all_eq_true.mp defaultRanges_no_formatting row hrow
          rw [hcls, h] at hfact
          exact absurd hfact (by decide)
      | none =>
          rw [hD] at h
          exact absurd h (by decide)

end Unicode.Bidi.Algorithm
