/-
  Unicode.Segmentation.LineBreakSpec

  Correctness scaffolding for the UAX #14 line-break algorithm
  (`Unicode.Segmentation.LineBreak.lineBreaks`), following the method proven on
  word break: characterise the algorithm's precomputed state against declarative
  patterns over the raw prefix, then compose.

  Line break has a single precompute pass, `buildSnapshots`, a left-to-right fold
  that pushes an `EffSnapshot` carry at every position and updates it from the
  current class — the push-carry scan of `Unicode.Segmentation.PrefixScan`. So the
  snapshot the decision reads at position `i` is the carry over the first `i`
  inputs, and the per-field characterisations (effective previous class, the
  Regional_Indicator run, the numeric chain, the Pi-quote window) follow from that
  fold, exactly as the word-break contexts did.
-/

import Unicode.Segmentation.LineBreak
import Unicode.Segmentation.PrefixScan

namespace Unicode.Segmentation.LineBreak

open Unicode.Generated.LineBreakProperty (LBClass lookupResolved)

set_option maxRecDepth 100000

/-- The carry update `buildSnapshots` performs at each position: the snapshot
    logic of the algorithm's fold with the output-push removed. Identical in
    structure to the inline step so the two folds agree. -/
def snapUpdate (cps : Array Nat) (s : EffSnapshot) : Nat × LBClass → EffSnapshot :=
  fun (i, c) =>
    let cReal :=
      if isCMZWJ c then
        match s.effPrev with
        | none    => LBClass.AL
        | some ep => if lb9BlocksAbsorb ep then LBClass.AL else c
      else c
    if isCMZWJ cReal then s
    else
      let cp := cps[i]!
      let isPi := isPiQuote cp cReal
      let effPrevPrev'   := s.effPrev
      let effPrevPrevCp' := s.effPrevCp
      let effPrev'       := some cReal
      let effPrevCp'     := some cp
      let effPrevNoSp'   :=
        if cReal == .SP then s.effPrevNoSp else some cReal
      let spSinceNoSp'   := cReal == .SP
      let riRun'         := if cReal == .RI then s.riRun + 1 else 0
      let piLeftCtxOK : Bool :=
        match s.effPrev with
        | none   => true
        | some pc =>
          pc == .BK || pc == .CR || pc == .LF || pc == .NL ||
          pc == .OP || pc == .QU || pc == .GL || pc == .SP ||
          pc == .ZW
      let inPiQuoteWindow' :=
        if isPi && piLeftCtxOK then true
        else if cReal == .SP then s.inPiQuoteWindow
        else false
      let inNuChain' :=
        if cReal == .NU then true
        else if s.inNuChain &&
                (cReal == .SY || cReal == .IS ||
                 cReal == .CL || cReal == .CP ||
                 cReal == .PR) then true
        else false
      { effPrev          := effPrev'
        effPrevCp        := effPrevCp'
        effPrevNoSp      := effPrevNoSp'
        spSinceNoSp      := spSinceNoSp'
        effPrevPrev      := effPrevPrev'
        effPrevPrevCp    := effPrevPrevCp'
        inPiQuoteWindow  := inPiQuoteWindow'
        riRun            := riRun'
        inNuChain        := inNuChain' }

/-- The push-carry step of `buildSnapshots`: push the current snapshot, then
    advance by `snapUpdate`. -/
def snapStep (cps : Array Nat)
    (acc : Array EffSnapshot × EffSnapshot) (ic : Nat × LBClass) :
    Array EffSnapshot × EffSnapshot :=
  (acc.1.push acc.2, snapUpdate cps acc.2 ic)

theorem snapStep_fst (cps : Array Nat) (acc : Array EffSnapshot × EffSnapshot)
    (ic : Nat × LBClass) : (snapStep cps acc ic).1 = acc.1.push acc.2 := rfl

theorem snapStep_snd (cps : Array Nat) (acc : Array EffSnapshot × EffSnapshot)
    (ic : Nat × LBClass) : (snapStep cps acc ic).2 = snapUpdate cps acc.2 ic := rfl

/-- `buildSnapshots` is the push-carry scan with step `snapStep`. The inline fold
    interleaves the push with its branches; factoring the push out is the only
    reshaping needed, discharged by cases on the absorb test. -/
theorem buildSnapshots_eq_foldl (cps : Array Nat) (lits : Array LBClass) :
    buildSnapshots cps lits =
      (((Array.range cps.size).zip lits).toList.foldl (snapStep cps)
        (#[], EffSnapshot.initial)).1 := by
  unfold buildSnapshots
  rw [Array.foldl_toList]
  apply congrArg Prod.fst
  rw [← Array.foldl_toList, ← Array.foldl_toList]
  apply PrefixScan.foldl_congr
  intro b a
  obtain ⟨out, s⟩ := b
  obtain ⟨i, c⟩ := a
  apply Prod.ext
  · rw [apply_ite Prod.fst]
    simp only [ite_self, snapStep]
  · rw [apply_ite Prod.snd]
    rfl

/-- **Snapshot array-index bridge.** The snapshot the decision reads at position
    `i` is the carry over the first `i` inputs — an instance of the push-carry
    scan bridge with update `snapUpdate`, over the indexed class sequence. -/
theorem buildSnapshots_getElem! (cps : Array Nat) (lits : Array LBClass)
    (i : Nat) (h : i < ((Array.range cps.size).zip lits).size) :
    (buildSnapshots cps lits)[i]! =
      (((Array.range cps.size).zip lits).toList.take i).foldl (snapUpdate cps)
        EffSnapshot.initial := by
  exact PrefixScan.build_getElem! (snapStep cps) (snapUpdate cps)
    (snapStep_fst cps) (snapStep_snd cps) EffSnapshot.initial
    ((Array.range cps.size).zip lits) (buildSnapshots cps lits)
    (buildSnapshots_eq_foldl cps lits) i h

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 EFFECTIVE-PREVIOUS FIELD — the LB9/LB10 resolved class, self-contained
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The `effPrev` field's self-contained update. The current class resolves to
    `cReal` — a CM/ZWJ becomes AL at start or after an LB9-blocking class, else
    keeps the previous effective class (absorbed, leaving `effPrev` unchanged). -/
def effPrevUpdate (ep : Option LBClass) (c : LBClass) : Option LBClass :=
  let cReal :=
    if isCMZWJ c then
      match ep with
      | none   => LBClass.AL
      | some e => if lb9BlocksAbsorb e then LBClass.AL else c
    else c
  if isCMZWJ cReal then ep else some cReal

/-- The `effPrev` component of the snapshot update depends only on `effPrev` —
    so it is a scan in its own right (`PrefixScan.foldl_proj` applies). -/
theorem snapUpdate_effPrev (cps : Array Nat) (s : EffSnapshot) (ic : Nat × LBClass) :
    (snapUpdate cps s ic).effPrev = effPrevUpdate s.effPrev ic.2 := by
  obtain ⟨i, c⟩ := ic
  unfold snapUpdate effPrevUpdate
  rw [apply_ite EffSnapshot.effPrev]

/-- **Effective-previous field bridge.** The `effPrev` the decision reads at
    position `i` is the fold of `effPrevUpdate` over the first `i` classes — the
    coupled snapshot fold isolated to its LB9/LB10 resolved-class component. -/
theorem buildSnapshots_effPrev (cps : Array Nat) (lits : Array LBClass) (i : Nat)
    (h : i < ((Array.range cps.size).zip lits).size) :
    ((buildSnapshots cps lits)[i]!).effPrev =
      (((Array.range cps.size).zip lits).toList.take i).foldl
        (fun ep ic => effPrevUpdate ep ic.2) none := by
  rw [buildSnapshots_getElem! cps lits i h]
  exact PrefixScan.foldl_proj EffSnapshot.effPrev (snapUpdate cps)
    (fun ep ic => effPrevUpdate ep ic.2) (fun s ic => snapUpdate_effPrev cps s ic)
    (((Array.range cps.size).zip lits).toList.take i) EffSnapshot.initial

/-- A non-CM/ZWJ class resolves to itself and sets `effPrev` (LB9 base case). -/
theorem effPrevUpdate_nonCMZWJ (ep : Option LBClass) (c : LBClass)
    (hc : isCMZWJ c = false) : effPrevUpdate ep c = some c := by
  unfold effPrevUpdate
  simp [hc]

/-- **Effective-previous on a combining-mark-free run.** Where no class is a
    CM/ZWJ, LB9/LB10 resolution is inert and `effPrev` is exactly the last class
    (the seed on the empty run). A declarative reading of the resolved-class field
    over the common case, independent of the fold. -/
theorem effPrevUpdate_foldl_noCMZWJ (l : List LBClass) (ep : Option LBClass)
    (hl : l.all (fun c => ! isCMZWJ c) = true) :
    l.foldl effPrevUpdate ep =
      (match l.getLast? with | some d => some d | none => ep) := by
  induction l using PrefixScan.list_snoc_induction with
  | hnil => rfl
  | hsnoc m c ih =>
    rw [List.all_append, List.all_cons, List.all_nil, Bool.and_true, Bool.and_eq_true] at hl
    obtain ⟨hm, hc⟩ := hl
    have hcf : isCMZWJ c = false := by simpa using hc
    rw [List.foldl_append, List.foldl_cons, List.foldl_nil,
        effPrevUpdate_nonCMZWJ (m.foldl effPrevUpdate ep) c hcf, List.getLast?_concat]

/-- A CM/ZWJ with no base resolves to AL (LB10 leading combining mark). -/
theorem isCMZWJ_AL : isCMZWJ .AL = false := by decide

theorem effPrevUpdate_CMZWJ_none (c : LBClass) (hc : isCMZWJ c = true) :
    effPrevUpdate none c = some .AL := by
  unfold effPrevUpdate
  simp [hc, isCMZWJ_AL]

/-- A CM/ZWJ after a base: absorbed (LB9) unless the base blocks, then AL. -/
theorem effPrevUpdate_CMZWJ_some (e c : LBClass) (hc : isCMZWJ c = true) :
    effPrevUpdate (some e) c = if lb9BlocksAbsorb e then some .AL else some e := by
  unfold effPrevUpdate
  by_cases hb : lb9BlocksAbsorb e <;> simp [hc, hb, isCMZWJ_AL]

/-- AL is not an LB9 anchor, so once `effPrev` is AL it absorbs further CM/ZWJ. -/
theorem lb9BlocksAbsorb_AL : lb9BlocksAbsorb .AL = false := by decide

/-- **Declarative effective-previous class.** Read the trailing run of CM/ZWJ and
    the base before it (the last non-CM/ZWJ class). With no trailing run, `effPrev`
    is the last class; with a trailing run it is the base, or `AL` when there is no
    base or the base is an LB9 anchor. A reverse-scan reading of LB9/LB10,
    structurally independent of the forward fold. -/
def effPrevSpec (l : List LBClass) : Option LBClass :=
  match (l.reverse.dropWhile isCMZWJ).head? with
  | none      => if (l.reverse.takeWhile isCMZWJ).isEmpty then none else some .AL
  | some base =>
    if (l.reverse.takeWhile isCMZWJ).isEmpty then some base
    else if lb9BlocksAbsorb base then some .AL
    else some base

/-- **State-machine step.** The reverse-scan spec's last-element recurrence
    matches the operational `effPrevUpdate`: appending `c` to the run is the same
    resolution the forward fold performs. The content of the effective-previous
    characterisation — every LB9/LB10 case (no base / base blocks / base absorbs,
    with or without a trailing run) reconciled here, not by `rfl`. -/
theorem effPrevSpec_snoc (m : List LBClass) (c : LBClass) :
    effPrevSpec (m ++ [c]) = effPrevUpdate (effPrevSpec m) c := by
  have hrev : (m ++ [c]).reverse = c :: m.reverse := by simp
  rw [effPrevSpec, effPrevSpec, hrev, List.takeWhile_cons, List.dropWhile_cons]
  by_cases hc : isCMZWJ c = true
  · cases hbase : (m.reverse.dropWhile isCMZWJ).head? with
    | none =>
      by_cases hre : (m.reverse.takeWhile isCMZWJ).isEmpty = true <;>
        simp_all [effPrevUpdate_CMZWJ_none, effPrevUpdate_CMZWJ_some, lb9BlocksAbsorb_AL]
    | some base =>
      by_cases hre : (m.reverse.takeWhile isCMZWJ).isEmpty = true <;>
        by_cases hbl : lb9BlocksAbsorb base = true <;>
        simp_all [effPrevUpdate_CMZWJ_some, lb9BlocksAbsorb_AL]
  · simp_all [effPrevUpdate_nonCMZWJ]

/-- **Effective-previous field characterisation.** The `effPrev` carry equals the
    declarative reverse-scan `effPrevSpec` — the resolved class of the last
    combining sequence per UAX #14 LB9/LB10, for all input, independent of the
    fold. -/
theorem effPrevUpdate_foldl_eq_spec (l : List LBClass) :
    l.foldl effPrevUpdate none = effPrevSpec l := by
  induction l using PrefixScan.list_snoc_induction with
  | hnil => rfl
  | hsnoc m c ih =>
    rw [List.foldl_append, List.foldl_cons, List.foldl_nil, ih, effPrevSpec_snoc]

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 REDUNDANT FIELDS — determined by effPrev via the resolved class
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The resolved class of `c` given the effective-previous class (LB9/LB10). -/
def cRealOf (ep : Option LBClass) (c : LBClass) : LBClass :=
  if isCMZWJ c then
    match ep with | none => .AL | some e => if lb9BlocksAbsorb e then .AL else c
  else c

/-- `effPrevUpdate` in terms of the resolved class: keep `ep` when the resolved
    class is a combining mark (absorbed), else advance to it. -/
theorem effPrevUpdate_cRealOf (ep : Option LBClass) (c : LBClass) :
    effPrevUpdate ep c =
      if isCMZWJ (cRealOf ep c) then ep else some (cRealOf ep c) := rfl

/-- The `spSinceNoSp` component of the snapshot update. -/
theorem snapUpdate_spSinceNoSp (cps : Array Nat) (s : EffSnapshot) (ic : Nat × LBClass) :
    (snapUpdate cps s ic).spSinceNoSp =
      if isCMZWJ (cRealOf s.effPrev ic.2) then s.spSinceNoSp
      else (cRealOf s.effPrev ic.2 == .SP) := by
  obtain ⟨i, c⟩ := ic
  unfold snapUpdate cRealOf
  rw [apply_ite EffSnapshot.spSinceNoSp]

/-- One `snapUpdate` preserves `spSinceNoSp = (effPrev == some SP)`. -/
theorem snapUpdate_spSinceNoSp_inv (cps : Array Nat) (s : EffSnapshot) (ic : Nat × LBClass)
    (hs : s.spSinceNoSp = (s.effPrev == some .SP)) :
    (snapUpdate cps s ic).spSinceNoSp = ((snapUpdate cps s ic).effPrev == some .SP) := by
  rw [snapUpdate_spSinceNoSp, snapUpdate_effPrev, effPrevUpdate_cRealOf]
  by_cases habs : isCMZWJ (cRealOf s.effPrev ic.2) = true
  · simp only [habs, if_true]; exact hs
  · simp [if_neg habs]

/-- **spSinceNoSp is redundant with effPrev.** The field is exactly whether the
    effective-previous class is `SP`; it carries no state the resolved-class
    characterisation does not already determine. -/
theorem buildSnapshots_spSinceNoSp (cps : Array Nat) (lits : Array LBClass) (i : Nat)
    (h : i < ((Array.range cps.size).zip lits).size) :
    ((buildSnapshots cps lits)[i]!).spSinceNoSp =
      (((buildSnapshots cps lits)[i]!).effPrev == some .SP) := by
  rw [buildSnapshots_getElem! cps lits i h]
  exact PrefixScan.foldl_inv
    (fun s => s.spSinceNoSp = (s.effPrev == some .SP))
    (snapUpdate cps) (fun s x hx => snapUpdate_spSinceNoSp_inv cps s x hx)
    (((Array.range cps.size).zip lits).toList.take i) EffSnapshot.initial rfl

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 PREV-PREV FIELD — the effPrev one effective step back (a shift register)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The `effPrevPrev` component of the snapshot update: on a non-absorbed step it
    takes the previous `effPrev` (shift), otherwise it is unchanged. -/
theorem snapUpdate_effPrevPrev (cps : Array Nat) (s : EffSnapshot) (ic : Nat × LBClass) :
    (snapUpdate cps s ic).effPrevPrev =
      if isCMZWJ (cRealOf s.effPrev ic.2) then s.effPrevPrev else s.effPrev := by
  obtain ⟨i, c⟩ := ic
  unfold snapUpdate cRealOf
  rw [apply_ite EffSnapshot.effPrevPrev]

/-- The joint `(effPrev, effPrevPrev)` update: advance `effPrev`, shifting the
    previous value into `effPrevPrev` on a non-absorbed step. Self-contained
    (reads only the pair), so the pair is a scan in its own right. -/
def effPrevPairUpdate (p : Option LBClass × Option LBClass) (c : LBClass) :
    Option LBClass × Option LBClass :=
  (effPrevUpdate p.1 c, if isCMZWJ (cRealOf p.1 c) then p.2 else p.1)

theorem snapUpdate_effPrevPair (cps : Array Nat) (s : EffSnapshot) (ic : Nat × LBClass) :
    ((snapUpdate cps s ic).effPrev, (snapUpdate cps s ic).effPrevPrev) =
      effPrevPairUpdate (s.effPrev, s.effPrevPrev) ic.2 := by
  rw [snapUpdate_effPrev, snapUpdate_effPrevPrev]
  rfl

/-- **Prev-pair field extraction.** The `(effPrev, effPrevPrev)` the decision reads
    is the pure joint fold from `(none, none)`; its first component is `effPrevSpec`
    (the LB9/LB10 resolved class), its second the resolved class one effective step
    back. -/
theorem buildSnapshots_effPrevPair (cps : Array Nat) (lits : Array LBClass) (i : Nat)
    (h : i < ((Array.range cps.size).zip lits).size) :
    (((buildSnapshots cps lits)[i]!).effPrev, ((buildSnapshots cps lits)[i]!).effPrevPrev) =
      (((Array.range cps.size).zip lits).toList.take i).foldl
        (fun p ic => effPrevPairUpdate p ic.2) (none, none) := by
  rw [buildSnapshots_getElem! cps lits i h]
  exact PrefixScan.foldl_proj (fun s => (s.effPrev, s.effPrevPrev)) (snapUpdate cps)
    (fun p ic => effPrevPairUpdate p ic.2) (fun s ic => snapUpdate_effPrevPair cps s ic)
    (((Array.range cps.size).zip lits).toList.take i) EffSnapshot.initial

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 EFFECTIVE-CLASS SEQUENCE — a clean reverse recursion, most-recent first
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The LB9/LB10-resolved effective classes of `l`, most-recent first, computed by
    a single recursion over the reversed class list: a non-combining class is a new
    effective class; a CM/ZWJ becomes `AL` at the start or after an LB9 anchor,
    else is absorbed into the current effective class. Appending to `l` is prepending
    to the recursion's input, so the fold's snoc step is this definition's `cons`. -/
def effClassesRev : List LBClass → List LBClass
  | []       => []
  | c :: rest =>
    let prior := effClassesRev rest
    if isCMZWJ c then
      (if (match prior.head? with | none => true | some b => lb9BlocksAbsorb b)
        then .AL :: prior else prior)
    else c :: prior

/-- The last two effective classes of `l` — `(effPrev, effPrevPrev)`. -/
def effPrevTwo (l : List LBClass) : Option LBClass × Option LBClass :=
  let e := effClassesRev l.reverse
  (e.head?, e.tail.head?)

/-- **The joint prev-pair fold equals the last two effective classes.** No
    `takeWhile`/`dropWhile`, no reconstruction: the snoc step is `effClassesRev`'s
    `cons`, matched against `effPrevPairUpdate` by cases on the resolution. -/
theorem effPrevPairUpdate_foldl (l : List LBClass) :
    l.foldl effPrevPairUpdate (none, none) = effPrevTwo l := by
  induction l using PrefixScan.list_snoc_induction with
  | hnil => rfl
  | hsnoc m c ih =>
    rw [List.foldl_append, List.foldl_cons, List.foldl_nil, ih]
    have hrev : (m ++ [c]).reverse = c :: m.reverse := by simp
    unfold effPrevTwo effPrevPairUpdate effPrevUpdate cRealOf
    rw [hrev, effClassesRev]
    by_cases hc : isCMZWJ c = true
    · cases hhd : (effClassesRev m.reverse).head? with
      | none => simp_all [isCMZWJ_AL]
      | some val => by_cases hbl : lb9BlocksAbsorb val = true <;> simp_all [isCMZWJ_AL]
    · cases hhd : (effClassesRev m.reverse).head? <;> simp_all [isCMZWJ_AL]

/-- **Prev-pair field characterisation.** The `(effPrev, effPrevPrev)` the decision
    reads at position `i` are the last two LB9/LB10-effective classes of the first
    `i` code points — head and second of `effClassesRev`, for all input, independent
    of the fold. -/
theorem buildSnapshots_effPrevTwo (cps : Array Nat) (lits : Array LBClass) (i : Nat)
    (h : i < ((Array.range cps.size).zip lits).size) :
    (((buildSnapshots cps lits)[i]!).effPrev, ((buildSnapshots cps lits)[i]!).effPrevPrev) =
      effPrevTwo ((((Array.range cps.size).zip lits).toList.take i).map (·.2)) := by
  rw [buildSnapshots_effPrevPair cps lits i h, ← effPrevPairUpdate_foldl, List.foldl_map]

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 RI-RUN FIELD — the trailing Regional_Indicator run (LB30a), off effClassesRev
-- ═══════════════════════════════════════════════════════════════════════════════

/-- A class is a Regional_Indicator. -/
def isRI (c : LBClass) : Bool := c == .RI

/-- The leading Regional_Indicator run length of an effective sequence. -/
def leadRI (p : List LBClass) : Nat := (p.takeWhile isRI).length

/-- The joint `(effPrev, riRun)` update: advance `effPrev`; the RI run grows on an
    effective RI, resets on any other effective class, holds when absorbed. -/
def riPairUpdate (p : Option LBClass × Nat) (c : LBClass) : Option LBClass × Nat :=
  (effPrevUpdate p.1 c,
    if isCMZWJ (cRealOf p.1 c) then p.2
    else (if cRealOf p.1 c == .RI then p.2 + 1 else 0))

/-- The `riRun` component of the snapshot update. -/
theorem snapUpdate_riRun (cps : Array Nat) (s : EffSnapshot) (ic : Nat × LBClass) :
    (snapUpdate cps s ic).riRun =
      if isCMZWJ (cRealOf s.effPrev ic.2) then s.riRun
      else (if cRealOf s.effPrev ic.2 == .RI then s.riRun + 1 else 0) := by
  obtain ⟨i, c⟩ := ic
  unfold snapUpdate cRealOf
  rw [apply_ite EffSnapshot.riRun]

theorem snapUpdate_riPair (cps : Array Nat) (s : EffSnapshot) (ic : Nat × LBClass) :
    ((snapUpdate cps s ic).effPrev, (snapUpdate cps s ic).riRun) =
      riPairUpdate (s.effPrev, s.riRun) ic.2 := by
  rw [snapUpdate_effPrev, snapUpdate_riRun]
  rfl

/-- **The RI-run fold equals the leading RI run of `effClassesRev`.** The RI run
    is exactly the trailing Regional_Indicator run of the effective classes — the
    count LB30a tests by parity. Proven against `effClassesRev`'s `cons`, not `rfl`. -/
theorem riPairUpdate_foldl (l : List LBClass) :
    l.foldl riPairUpdate (none, 0) =
      ((effClassesRev l.reverse).head?, leadRI (effClassesRev l.reverse)) := by
  induction l using PrefixScan.list_snoc_induction with
  | hnil => rfl
  | hsnoc m c ih =>
    rw [List.foldl_append, List.foldl_cons, List.foldl_nil, ih]
    have hrev : (m ++ [c]).reverse = c :: m.reverse := by simp
    unfold riPairUpdate effPrevUpdate cRealOf leadRI
    rw [hrev, effClassesRev]
    by_cases hc : isCMZWJ c = true
    · cases hhd : (effClassesRev m.reverse).head? with
      | none => simp_all [isCMZWJ_AL, isRI, List.takeWhile_cons]
      | some val =>
        by_cases hbl : lb9BlocksAbsorb val = true <;>
          simp_all [isCMZWJ_AL, isRI, List.takeWhile_cons]
    · by_cases hri : c == LBClass.RI <;>
        cases hhd : (effClassesRev m.reverse).head? <;>
        simp_all [isCMZWJ_AL, isRI, List.takeWhile_cons]

theorem buildSnapshots_riPair (cps : Array Nat) (lits : Array LBClass) (i : Nat)
    (h : i < ((Array.range cps.size).zip lits).size) :
    (((buildSnapshots cps lits)[i]!).effPrev, ((buildSnapshots cps lits)[i]!).riRun) =
      (((Array.range cps.size).zip lits).toList.take i).foldl
        (fun p ic => riPairUpdate p ic.2) (none, 0) := by
  rw [buildSnapshots_getElem! cps lits i h]
  exact PrefixScan.foldl_proj (fun s => (s.effPrev, s.riRun)) (snapUpdate cps)
    (fun p ic => riPairUpdate p ic.2) (fun s ic => snapUpdate_riPair cps s ic)
    (((Array.range cps.size).zip lits).toList.take i) EffSnapshot.initial

/-- **RI-run field characterisation.** The `riRun` the decision reads at position
    `i` is the leading RI run of the effective classes of the first `i` code points
    — the trailing Regional_Indicator count LB30a consumes, for all input. -/
theorem buildSnapshots_riRun (cps : Array Nat) (lits : Array LBClass) (i : Nat)
    (h : i < ((Array.range cps.size).zip lits).size) :
    ((buildSnapshots cps lits)[i]!).riRun =
      leadRI (effClassesRev ((((Array.range cps.size).zip lits).toList.take i).map (·.2)).reverse) := by
  have hp := buildSnapshots_riPair cps lits i h
  rw [← List.foldl_map, riPairUpdate_foldl] at hp
  exact congrArg Prod.snd hp

-- ═══════════════════════════════════════════════════════════════════════════════
-- §7 PREV-NO-SP FIELD — the last non-SP effective class, off effClassesRev
-- ═══════════════════════════════════════════════════════════════════════════════

/-- A class is not a space. -/
def isNotSP (c : LBClass) : Bool := c != .SP

/-- The most-recent non-SP effective class. -/
def lastNonSP (p : List LBClass) : Option LBClass := p.find? isNotSP

/-- The joint `(effPrev, effPrevNoSp)` update: advance `effPrev`; `effPrevNoSp`
    takes a non-SP effective class, holds on an SP or when absorbed. -/
def noSpPairUpdate (p : Option LBClass × Option LBClass) (c : LBClass) :
    Option LBClass × Option LBClass :=
  (effPrevUpdate p.1 c,
    if isCMZWJ (cRealOf p.1 c) then p.2
    else (if cRealOf p.1 c == .SP then p.2 else some (cRealOf p.1 c)))

/-- The `effPrevNoSp` component of the snapshot update. -/
theorem snapUpdate_effPrevNoSp (cps : Array Nat) (s : EffSnapshot) (ic : Nat × LBClass) :
    (snapUpdate cps s ic).effPrevNoSp =
      if isCMZWJ (cRealOf s.effPrev ic.2) then s.effPrevNoSp
      else (if cRealOf s.effPrev ic.2 == .SP then s.effPrevNoSp
            else some (cRealOf s.effPrev ic.2)) := by
  obtain ⟨i, c⟩ := ic
  unfold snapUpdate cRealOf
  rw [apply_ite EffSnapshot.effPrevNoSp]

theorem snapUpdate_noSpPair (cps : Array Nat) (s : EffSnapshot) (ic : Nat × LBClass) :
    ((snapUpdate cps s ic).effPrev, (snapUpdate cps s ic).effPrevNoSp) =
      noSpPairUpdate (s.effPrev, s.effPrevNoSp) ic.2 := by
  rw [snapUpdate_effPrev, snapUpdate_effPrevNoSp]
  rfl

/-- **The no-SP fold equals the most-recent non-SP effective class.** -/
theorem noSpPairUpdate_foldl (l : List LBClass) :
    l.foldl noSpPairUpdate (none, none) =
      ((effClassesRev l.reverse).head?, lastNonSP (effClassesRev l.reverse)) := by
  induction l using PrefixScan.list_snoc_induction with
  | hnil => rfl
  | hsnoc m c ih =>
    rw [List.foldl_append, List.foldl_cons, List.foldl_nil, ih]
    have hrev : (m ++ [c]).reverse = c :: m.reverse := by simp
    unfold noSpPairUpdate effPrevUpdate cRealOf lastNonSP
    rw [hrev, effClassesRev]
    by_cases hc : isCMZWJ c = true
    · cases hhd : (effClassesRev m.reverse).head? with
      | none => simp_all [isCMZWJ_AL, isNotSP, List.find?_cons]
      | some val =>
        by_cases hbl : lb9BlocksAbsorb val = true <;>
          simp_all [isCMZWJ_AL, isNotSP, List.find?_cons]
    · by_cases hsp : c == LBClass.SP <;>
        cases hhd : (effClassesRev m.reverse).head? <;>
        simp_all [isCMZWJ_AL, isNotSP, List.find?_cons]

theorem buildSnapshots_noSpPair (cps : Array Nat) (lits : Array LBClass) (i : Nat)
    (h : i < ((Array.range cps.size).zip lits).size) :
    (((buildSnapshots cps lits)[i]!).effPrev, ((buildSnapshots cps lits)[i]!).effPrevNoSp) =
      (((Array.range cps.size).zip lits).toList.take i).foldl
        (fun p ic => noSpPairUpdate p ic.2) (none, none) := by
  rw [buildSnapshots_getElem! cps lits i h]
  exact PrefixScan.foldl_proj (fun s => (s.effPrev, s.effPrevNoSp)) (snapUpdate cps)
    (fun p ic => noSpPairUpdate p ic.2) (fun s ic => snapUpdate_noSpPair cps s ic)
    (((Array.range cps.size).zip lits).toList.take i) EffSnapshot.initial

/-- **Prev-no-SP field characterisation.** The `effPrevNoSp` the decision reads at
    position `i` is the most-recent non-SP effective class of the first `i` code
    points, for all input. -/
theorem buildSnapshots_effPrevNoSp (cps : Array Nat) (lits : Array LBClass) (i : Nat)
    (h : i < ((Array.range cps.size).zip lits).size) :
    ((buildSnapshots cps lits)[i]!).effPrevNoSp =
      lastNonSP (effClassesRev ((((Array.range cps.size).zip lits).toList.take i).map (·.2)).reverse) := by
  have hp := buildSnapshots_noSpPair cps lits i h
  rw [← List.foldl_map, noSpPairUpdate_foldl] at hp
  exact congrArg Prod.snd hp

-- ═══════════════════════════════════════════════════════════════════════════════
-- §8 NU-CHAIN FIELD — the effective sequence ends in NU (SY|IS|CL|CP|PR)* (LB25)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- A class continues a numeric chain after `NU` (LB25). -/
def isNuTail (c : LBClass) : Bool :=
  c == .SY || c == .IS || c == .CL || c == .CP || c == .PR

/-- Whether the effective sequence (most-recent first) is in a numeric chain: a
    leading run of chain-tails then a `NU`. -/
def inNuChainSpec : List LBClass → Bool
  | []       => false
  | c :: rest => if c == .NU then true else if isNuTail c then inNuChainSpec rest else false

/-- The joint `(effPrev, inNuChain)` update. -/
def nuPairUpdate (p : Option LBClass × Bool) (c : LBClass) : Option LBClass × Bool :=
  (effPrevUpdate p.1 c,
    if isCMZWJ (cRealOf p.1 c) then p.2
    else (if cRealOf p.1 c == .NU then true
          else if p.2 && isNuTail (cRealOf p.1 c) then true else false))

/-- The `inNuChain` component of the snapshot update. -/
theorem snapUpdate_inNuChain (cps : Array Nat) (s : EffSnapshot) (ic : Nat × LBClass) :
    (snapUpdate cps s ic).inNuChain =
      if isCMZWJ (cRealOf s.effPrev ic.2) then s.inNuChain
      else (if cRealOf s.effPrev ic.2 == .NU then true
            else if s.inNuChain && isNuTail (cRealOf s.effPrev ic.2) then true else false) := by
  obtain ⟨i, c⟩ := ic
  unfold snapUpdate cRealOf isNuTail
  rw [apply_ite EffSnapshot.inNuChain]

theorem snapUpdate_nuPair (cps : Array Nat) (s : EffSnapshot) (ic : Nat × LBClass) :
    ((snapUpdate cps s ic).effPrev, (snapUpdate cps s ic).inNuChain) =
      nuPairUpdate (s.effPrev, s.inNuChain) ic.2 := by
  rw [snapUpdate_effPrev, snapUpdate_inNuChain]
  rfl

/-- **The NU-chain fold equals the NU-chain predicate on `effClassesRev`.** -/
theorem nuPairUpdate_foldl (l : List LBClass) :
    l.foldl nuPairUpdate (none, false) =
      ((effClassesRev l.reverse).head?, inNuChainSpec (effClassesRev l.reverse)) := by
  induction l using PrefixScan.list_snoc_induction with
  | hnil => rfl
  | hsnoc m c ih =>
    rw [List.foldl_append, List.foldl_cons, List.foldl_nil, ih]
    have hrev : (m ++ [c]).reverse = c :: m.reverse := by simp
    unfold nuPairUpdate effPrevUpdate cRealOf
    rw [hrev, effClassesRev]
    by_cases hc : isCMZWJ c = true
    · cases hhd : (effClassesRev m.reverse).head? with
      | none => simp_all [isCMZWJ_AL, isNuTail, inNuChainSpec]
      | some val =>
        by_cases hbl : lb9BlocksAbsorb val = true <;>
          simp_all [isCMZWJ_AL, isNuTail, inNuChainSpec]
    · cases hhd : (effClassesRev m.reverse).head? <;>
        simp_all [isCMZWJ_AL, isNuTail, inNuChainSpec, Bool.and_comm]

theorem buildSnapshots_nuPair (cps : Array Nat) (lits : Array LBClass) (i : Nat)
    (h : i < ((Array.range cps.size).zip lits).size) :
    (((buildSnapshots cps lits)[i]!).effPrev, ((buildSnapshots cps lits)[i]!).inNuChain) =
      (((Array.range cps.size).zip lits).toList.take i).foldl
        (fun p ic => nuPairUpdate p ic.2) (none, false) := by
  rw [buildSnapshots_getElem! cps lits i h]
  exact PrefixScan.foldl_proj (fun s => (s.effPrev, s.inNuChain)) (snapUpdate cps)
    (fun p ic => nuPairUpdate p ic.2) (fun s ic => snapUpdate_nuPair cps s ic)
    (((Array.range cps.size).zip lits).toList.take i) EffSnapshot.initial

/-- **NU-chain field characterisation.** The `inNuChain` the decision reads at
    position `i` holds iff the effective classes of the first `i` code points end
    in `NU (SY|IS|CL|CP|PR)*` (LB25), for all input. -/
theorem buildSnapshots_inNuChain (cps : Array Nat) (lits : Array LBClass) (i : Nat)
    (h : i < ((Array.range cps.size).zip lits).size) :
    ((buildSnapshots cps lits)[i]!).inNuChain =
      inNuChainSpec (effClassesRev ((((Array.range cps.size).zip lits).toList.take i).map (·.2)).reverse) := by
  have hp := buildSnapshots_nuPair cps lits i h
  rw [← List.foldl_map, nuPairUpdate_foldl] at hp
  exact congrArg Prod.snd hp

-- ═══════════════════════════════════════════════════════════════════════════════
-- §9 CODEPOINT FIELDS — effClassesRev carrying the code point of each segment
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Effective sequence carrying a code point alongside each resolved class:
    `effClassesRev` generalised so the `AL` of an absorbed run keeps the code point
    of the CM/ZWJ that produced it (the position the algorithm records). -/
def effClassesRevP : List (Nat × LBClass) → List (Nat × LBClass)
  | []       => []
  | gc :: rest =>
    let prior := effClassesRevP rest
    if isCMZWJ gc.2 then
      (if (match prior.head? with | none => true | some p => lb9BlocksAbsorb p.2)
        then (gc.1, .AL) :: prior else prior)
    else gc :: prior

/-- The joint `(effPrev, effPrevCp)` update over `(codepoint, class)` inputs. -/
def cpPairUpdate (p : Option LBClass × Option Nat) (gc : Nat × LBClass) :
    Option LBClass × Option Nat :=
  (effPrevUpdate p.1 gc.2, if isCMZWJ (cRealOf p.1 gc.2) then p.2 else some gc.1)

/-- The `effPrevCp` component of the snapshot update. -/
theorem snapUpdate_effPrevCp (cps : Array Nat) (s : EffSnapshot) (ic : Nat × LBClass) :
    (snapUpdate cps s ic).effPrevCp =
      if isCMZWJ (cRealOf s.effPrev ic.2) then s.effPrevCp else some cps[ic.1]! := by
  obtain ⟨i, c⟩ := ic
  unfold snapUpdate cRealOf
  rw [apply_ite EffSnapshot.effPrevCp]

theorem snapUpdate_cpPair (cps : Array Nat) (s : EffSnapshot) (ic : Nat × LBClass) :
    ((snapUpdate cps s ic).effPrev, (snapUpdate cps s ic).effPrevCp) =
      cpPairUpdate (s.effPrev, s.effPrevCp) (cps[ic.1]!, ic.2) := by
  rw [snapUpdate_effPrev, snapUpdate_effPrevCp]
  rfl

/-- **The codepoint fold reads the head of `effClassesRevP`.** -/
theorem cpPairUpdate_foldl (l : List (Nat × LBClass)) :
    l.foldl cpPairUpdate (none, none) =
      ((effClassesRevP l.reverse).head?.map (·.2), (effClassesRevP l.reverse).head?.map (·.1)) := by
  induction l using PrefixScan.list_snoc_induction with
  | hnil => rfl
  | hsnoc m c ih =>
    rw [List.foldl_append, List.foldl_cons, List.foldl_nil, ih]
    have hrev : (m ++ [c]).reverse = c :: m.reverse := by simp
    unfold cpPairUpdate effPrevUpdate cRealOf
    rw [hrev, effClassesRevP]
    by_cases hc : isCMZWJ c.2 = true
    · cases hhd : (effClassesRevP m.reverse).head? with
      | none => simp_all [isCMZWJ_AL]
      | some val =>
        by_cases hbl : lb9BlocksAbsorb val.2 = true <;> simp_all [isCMZWJ_AL]
    · cases hhd : (effClassesRevP m.reverse).head? <;> simp_all [isCMZWJ_AL]

theorem buildSnapshots_cpPair (cps : Array Nat) (lits : Array LBClass) (i : Nat)
    (h : i < ((Array.range cps.size).zip lits).size) :
    (((buildSnapshots cps lits)[i]!).effPrev, ((buildSnapshots cps lits)[i]!).effPrevCp) =
      (((Array.range cps.size).zip lits).toList.take i).foldl
        (fun p ic => cpPairUpdate p (cps[ic.1]!, ic.2)) (none, none) := by
  rw [buildSnapshots_getElem! cps lits i h]
  exact PrefixScan.foldl_proj (fun s => (s.effPrev, s.effPrevCp)) (snapUpdate cps)
    (fun p ic => cpPairUpdate p (cps[ic.1]!, ic.2)) (fun s ic => snapUpdate_cpPair cps s ic)
    (((Array.range cps.size).zip lits).toList.take i) EffSnapshot.initial

/-- **Prev-codepoint field characterisation.** The `effPrevCp` the decision reads at
    position `i` is the code point of the last effective segment — the head code
    point of `effClassesRevP`, for all input. -/
theorem buildSnapshots_effPrevCp (cps : Array Nat) (lits : Array LBClass) (i : Nat)
    (h : i < ((Array.range cps.size).zip lits).size) :
    ((buildSnapshots cps lits)[i]!).effPrevCp =
      (effClassesRevP ((((Array.range cps.size).zip lits).toList.take i).map
        (fun ic => (cps[ic.1]!, ic.2))).reverse).head?.map (·.1) := by
  have hp := buildSnapshots_cpPair cps lits i h
  rw [← List.foldl_map, cpPairUpdate_foldl] at hp
  exact congrArg Prod.snd hp

/-- The joint `(effPrev, effPrevCp, effPrevPrevCp)` update. -/
def cpTripleUpdate (p : Option LBClass × Option Nat × Option Nat) (gc : Nat × LBClass) :
    Option LBClass × Option Nat × Option Nat :=
  (effPrevUpdate p.1 gc.2,
    if isCMZWJ (cRealOf p.1 gc.2) then p.2.1 else some gc.1,
    if isCMZWJ (cRealOf p.1 gc.2) then p.2.2 else p.2.1)

/-- The `effPrevPrevCp` component of the snapshot update (shift of `effPrevCp`). -/
theorem snapUpdate_effPrevPrevCp (cps : Array Nat) (s : EffSnapshot) (ic : Nat × LBClass) :
    (snapUpdate cps s ic).effPrevPrevCp =
      if isCMZWJ (cRealOf s.effPrev ic.2) then s.effPrevPrevCp else s.effPrevCp := by
  obtain ⟨i, c⟩ := ic
  unfold snapUpdate cRealOf
  rw [apply_ite EffSnapshot.effPrevPrevCp]

theorem snapUpdate_cpTriple (cps : Array Nat) (s : EffSnapshot) (ic : Nat × LBClass) :
    ((snapUpdate cps s ic).effPrev, (snapUpdate cps s ic).effPrevCp,
        (snapUpdate cps s ic).effPrevPrevCp) =
      cpTripleUpdate (s.effPrev, s.effPrevCp, s.effPrevPrevCp) (cps[ic.1]!, ic.2) := by
  rw [snapUpdate_effPrev, snapUpdate_effPrevCp, snapUpdate_effPrevPrevCp]
  rfl

/-- **The codepoint triple reads the head and second of `effClassesRevP`.** -/
theorem cpTripleUpdate_foldl (l : List (Nat × LBClass)) :
    l.foldl cpTripleUpdate (none, none, none) =
      ((effClassesRevP l.reverse).head?.map (·.2),
        (effClassesRevP l.reverse).head?.map (·.1),
        (effClassesRevP l.reverse).tail.head?.map (·.1)) := by
  induction l using PrefixScan.list_snoc_induction with
  | hnil => rfl
  | hsnoc m c ih =>
    rw [List.foldl_append, List.foldl_cons, List.foldl_nil, ih]
    have hrev : (m ++ [c]).reverse = c :: m.reverse := by simp
    unfold cpTripleUpdate effPrevUpdate cRealOf
    rw [hrev, effClassesRevP]
    by_cases hc : isCMZWJ c.2 = true
    · cases hhd : (effClassesRevP m.reverse).head? with
      | none => simp_all [isCMZWJ_AL]
      | some val =>
        by_cases hbl : lb9BlocksAbsorb val.2 = true <;> simp_all [isCMZWJ_AL]
    · cases hhd : (effClassesRevP m.reverse).head? <;> simp_all [isCMZWJ_AL]

/-- **Prev-prev-codepoint field characterisation.** The `effPrevPrevCp` the decision
    reads at position `i` is the code point of the second-to-last effective segment
    — the second code point of `effClassesRevP`, for all input. -/
theorem buildSnapshots_effPrevPrevCp (cps : Array Nat) (lits : Array LBClass) (i : Nat)
    (h : i < ((Array.range cps.size).zip lits).size) :
    ((buildSnapshots cps lits)[i]!).effPrevPrevCp =
      (effClassesRevP ((((Array.range cps.size).zip lits).toList.take i).map
        (fun ic => (cps[ic.1]!, ic.2))).reverse).tail.head?.map (·.1) := by
  have hp : (((buildSnapshots cps lits)[i]!).effPrev, ((buildSnapshots cps lits)[i]!).effPrevCp,
      ((buildSnapshots cps lits)[i]!).effPrevPrevCp) =
      (((Array.range cps.size).zip lits).toList.take i).foldl
        (fun p ic => cpTripleUpdate p (cps[ic.1]!, ic.2)) (none, none, none) := by
    rw [buildSnapshots_getElem! cps lits i h]
    exact PrefixScan.foldl_proj (fun s => (s.effPrev, s.effPrevCp, s.effPrevPrevCp))
      (snapUpdate cps) (fun p ic => cpTripleUpdate p (cps[ic.1]!, ic.2))
      (fun s ic => snapUpdate_cpTriple cps s ic)
      (((Array.range cps.size).zip lits).toList.take i) EffSnapshot.initial
  rw [← List.foldl_map, cpTripleUpdate_foldl] at hp
  exact congrArg (fun t => t.2.2) hp

-- ═══════════════════════════════════════════════════════════════════════════════
-- §10 PI-QUOTE WINDOW — a Pi-quote with valid left context, then SP* (LB15a)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- LB15a left context: a Pi-quote opens the no-break window only after
    sot / BK / CR / LF / NL / OP / QU / GL / SP / ZW. -/
def piLeftCtxOK : Option LBClass → Bool
  | none    => true
  | some pc =>
    pc == .BK || pc == .CR || pc == .LF || pc == .NL ||
    pc == .OP || pc == .QU || pc == .GL || pc == .SP || pc == .ZW

/-- Whether the effective sequence (most-recent first) is in a Pi-quote window: a
    leading run of SP then a Pi-quote whose own predecessor is a valid left context. -/
def inPiWindowSpec : List (Nat × LBClass) → Bool
  | []       => false
  | gc :: rest =>
    if isPiQuote gc.1 gc.2 && piLeftCtxOK (rest.head?.map (·.2)) then true
    else if gc.2 == .SP then inPiWindowSpec rest else false

/-- The joint `(effPrev, inPiQuoteWindow)` update over `(codepoint, class)` inputs. -/
def piPairUpdate (p : Option LBClass × Bool) (gc : Nat × LBClass) : Option LBClass × Bool :=
  (effPrevUpdate p.1 gc.2,
    if isCMZWJ (cRealOf p.1 gc.2) then p.2
    else (if isPiQuote gc.1 (cRealOf p.1 gc.2) && piLeftCtxOK p.1 then true
          else if cRealOf p.1 gc.2 == .SP then p.2 else false))

/-- The `inPiQuoteWindow` component of the snapshot update. -/
theorem snapUpdate_inPiQuoteWindow (cps : Array Nat) (s : EffSnapshot) (ic : Nat × LBClass) :
    (snapUpdate cps s ic).inPiQuoteWindow =
      if isCMZWJ (cRealOf s.effPrev ic.2) then s.inPiQuoteWindow
      else (if isPiQuote cps[ic.1]! (cRealOf s.effPrev ic.2) && piLeftCtxOK s.effPrev then true
            else if cRealOf s.effPrev ic.2 == .SP then s.inPiQuoteWindow else false) := by
  obtain ⟨i, c⟩ := ic
  unfold snapUpdate cRealOf piLeftCtxOK
  rw [apply_ite EffSnapshot.inPiQuoteWindow]

theorem snapUpdate_piPair (cps : Array Nat) (s : EffSnapshot) (ic : Nat × LBClass) :
    ((snapUpdate cps s ic).effPrev, (snapUpdate cps s ic).inPiQuoteWindow) =
      piPairUpdate (s.effPrev, s.inPiQuoteWindow) (cps[ic.1]!, ic.2) := by
  rw [snapUpdate_effPrev, snapUpdate_inPiQuoteWindow]
  rfl

/-- **The Pi-window fold equals the Pi-window predicate on `effClassesRevP`.** -/
theorem piPairUpdate_foldl (l : List (Nat × LBClass)) :
    l.foldl piPairUpdate (none, false) =
      ((effClassesRevP l.reverse).head?.map (·.2), inPiWindowSpec (effClassesRevP l.reverse)) := by
  induction l using PrefixScan.list_snoc_induction with
  | hnil => rfl
  | hsnoc m c ih =>
    rw [List.foldl_append, List.foldl_cons, List.foldl_nil, ih]
    have hrev : (m ++ [c]).reverse = c :: m.reverse := by simp
    unfold piPairUpdate effPrevUpdate cRealOf
    rw [hrev, effClassesRevP]
    by_cases hc : isCMZWJ c.2 = true
    · cases hhd : (effClassesRevP m.reverse).head? with
      | none => simp_all [isCMZWJ_AL, inPiWindowSpec, isPiQuote]
      | some val =>
        by_cases hbl : lb9BlocksAbsorb val.2 = true <;>
          simp_all [isCMZWJ_AL, inPiWindowSpec, isPiQuote]
    · cases hhd : (effClassesRevP m.reverse).head? <;>
        simp_all [isCMZWJ_AL, inPiWindowSpec]

theorem buildSnapshots_piPair (cps : Array Nat) (lits : Array LBClass) (i : Nat)
    (h : i < ((Array.range cps.size).zip lits).size) :
    (((buildSnapshots cps lits)[i]!).effPrev, ((buildSnapshots cps lits)[i]!).inPiQuoteWindow) =
      (((Array.range cps.size).zip lits).toList.take i).foldl
        (fun p ic => piPairUpdate p (cps[ic.1]!, ic.2)) (none, false) := by
  rw [buildSnapshots_getElem! cps lits i h]
  exact PrefixScan.foldl_proj (fun s => (s.effPrev, s.inPiQuoteWindow)) (snapUpdate cps)
    (fun p ic => piPairUpdate p (cps[ic.1]!, ic.2)) (fun s ic => snapUpdate_piPair cps s ic)
    (((Array.range cps.size).zip lits).toList.take i) EffSnapshot.initial

/-- **Pi-window field characterisation.** The `inPiQuoteWindow` the decision reads at
    position `i` holds iff the effective segments of the first `i` code points end in
    a Pi-quote (valid left context) followed by `SP*` (LB15a), for all input. -/
theorem buildSnapshots_inPiQuoteWindow (cps : Array Nat) (lits : Array LBClass) (i : Nat)
    (h : i < ((Array.range cps.size).zip lits).size) :
    ((buildSnapshots cps lits)[i]!).inPiQuoteWindow =
      inPiWindowSpec (effClassesRevP ((((Array.range cps.size).zip lits).toList.take i).map
        (fun ic => (cps[ic.1]!, ic.2))).reverse) := by
  have hp := buildSnapshots_piPair cps lits i h
  rw [← List.foldl_map, piPairUpdate_foldl] at hp
  exact congrArg Prod.snd hp

/-- **Per-position structure.** `lineBreaks cps`, as a list, is
    `shouldBreakBefore` evaluated at each position `0 .. n-1`, followed by the
    LB3 end-of-text break. So the `lineBreaks` boundary at `i` is exactly the
    per-position decision over the (bridged) snapshot. -/
theorem lineBreaks_toList (cps : Array Nat) :
    (lineBreaks cps).toList =
      (List.range cps.size).map
        (fun i => shouldBreakBefore cps (cps.map lookupResolved)
          (buildSnapshots cps (cps.map lookupResolved)) i)
      ++ [true] := by
  unfold lineBreaks
  rw [Array.toList_push, PrefixScan.foldl_push_map_toList]
  simp

-- ═══════════════════════════════════════════════════════════════════════════════
-- §11 THE HEADLINE — lineBreaks equals its declarative UAX #14 specification
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The declarative snapshot at position `i`: every `EffSnapshot` field expressed as
    a function of the first `i` code points via `effClassesRev` / `effClassesRevP`,
    independent of the algorithm's fold. This is the state the UAX #14 rules read. -/
def lbSnapAt (cps : Array Nat) (i : Nat) : EffSnapshot :=
  let idx := ((Array.range cps.size).zip (cps.map lookupResolved)).toList.take i
  let e := effClassesRev (idx.map (·.2)).reverse
  let ep := effClassesRevP (idx.map (fun ic => (cps[ic.1]!, ic.2))).reverse
  { effPrev := e.head?
    effPrevCp := ep.head?.map (·.1)
    effPrevNoSp := lastNonSP e
    spSinceNoSp := (e.head? == some .SP)
    effPrevPrev := e.tail.head?
    effPrevPrevCp := ep.tail.head?.map (·.1)
    inPiQuoteWindow := inPiWindowSpec ep
    riRun := leadRI e
    inNuChain := inNuChainSpec e }

/-- **The fold's snapshot equals the declarative snapshot**, for all input — the
    nine field characterisations assembled into the whole `EffSnapshot`. -/
theorem buildSnapshots_snap_eq_spec (cps : Array Nat) (i : Nat)
    (h : i < ((Array.range cps.size).zip (cps.map lookupResolved)).size) :
    (buildSnapshots cps (cps.map lookupResolved))[i]! = lbSnapAt cps i := by
  have htwo := buildSnapshots_effPrevTwo cps (cps.map lookupResolved) i h
  have hnosp := buildSnapshots_effPrevNoSp cps (cps.map lookupResolved) i h
  have hsp := buildSnapshots_spSinceNoSp cps (cps.map lookupResolved) i h
  have hcp := buildSnapshots_effPrevCp cps (cps.map lookupResolved) i h
  have hppcp := buildSnapshots_effPrevPrevCp cps (cps.map lookupResolved) i h
  have hpi := buildSnapshots_inPiQuoteWindow cps (cps.map lookupResolved) i h
  have hri := buildSnapshots_riRun cps (cps.map lookupResolved) i h
  have hnu := buildSnapshots_inNuChain cps (cps.map lookupResolved) i h
  rcases hbs : (buildSnapshots cps (cps.map lookupResolved))[i]! with
    ⟨a, b, c, d, e2, f, g, ri, j⟩
  simp only [hbs] at htwo hnosp hsp hcp hppcp hpi hri hnu
  simp only [effPrevTwo, Prod.mk.injEq] at htwo
  obtain ⟨hep, hepp⟩ := htwo
  rw [hep] at hsp
  simp only [lbSnapAt]
  rw [hep, hepp, hnosp, hsp, hcp, hppcp, hpi, hri, hnu]

/-- `shouldBreakBefore` reads the snapshot array only at index `i`, so two arrays
    that agree there give the same decision. This lets the fold's snapshot array be
    replaced by the declarative one without a whole-array equality. -/
theorem shouldBreakBefore_snaps_congr (cps : Array Nat) (lits : Array LBClass)
    (s1 s2 : Array EffSnapshot) (i : Nat) (heq : s1[i]! = s2[i]!) :
    shouldBreakBefore cps lits s1 i = shouldBreakBefore cps lits s2 i := by
  unfold shouldBreakBefore
  rw [heq]

/-- The declarative UAX #14 break decision at position `i`: the algorithm's rule
    chain run over the declarative snapshot `lbSnapAt`. -/
def lbBreakSpecAt (cps : Array Nat) (i : Nat) : Bool :=
  shouldBreakBefore cps (cps.map lookupResolved)
    (((List.range cps.size).map (lbSnapAt cps)).toArray) i

theorem declSnaps_getElem! (cps : Array Nat) (i : Nat) (hi : i < cps.size) :
    (((List.range cps.size).map (lbSnapAt cps)).toArray)[i]! = lbSnapAt cps i := by
  have hsz : ((List.range cps.size).map (lbSnapAt cps)).toArray.size = cps.size := by simp
  rw [getElem!_pos ((List.range cps.size).map (lbSnapAt cps)).toArray i
        (by rw [hsz]; exact hi)]
  simp [List.getElem_toArray, List.getElem_map, List.getElem_range]

/-- **Line break equals its declarative UAX #14 specification.** `lineBreaks cps`
    is, position by position, the declarative LB1–LB31 decision over the raw code
    points — every snapshot field the rules read is a declarative function of the
    prefix (`effClassesRev` / `effClassesRevP`), not the fold — followed by the LB3
    end-of-text break. Correctness for all input, without brute force. -/
theorem lineBreaks_eq_spec (cps : Array Nat) :
    (lineBreaks cps).toList =
      (List.range cps.size).map (lbBreakSpecAt cps) ++ [true] := by
  rw [lineBreaks_toList]
  congr 1
  apply List.map_congr_left
  intro i hi
  rw [List.mem_range] at hi
  have hz : ((Array.range cps.size).zip (cps.map lookupResolved)).size = cps.size := by
    simp [Array.size_zip, Array.size_range, Array.size_map]
  have h : i < ((Array.range cps.size).zip (cps.map lookupResolved)).size := by
    rw [hz]; exact hi
  unfold lbBreakSpecAt
  apply shouldBreakBefore_snaps_congr
  rw [buildSnapshots_snap_eq_spec cps i h, declSnaps_getElem! cps i hi]

end Unicode.Segmentation.LineBreak
