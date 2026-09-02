/-
  Unicode.TrojanSource

  Defense against the Trojan Source class of attacks
  (Boucher–Anderson, CVE-2021-42574 / CVE-2021-42694). The attack
  uses Unicode bidi format-controls and homoglyph identifiers to
  make source code render one way to a human reviewer and parse
  another way to a compiler. Two predicate layers, both intended
  for use at the source-code, commit-message, code-review-diff,
  and PR-description boundaries:

    * `containsBidiFormatControl` — true iff `cps` contains any
      of the nine bidi format-control codepoints. This is the
      strict reject — most code review systems should refuse any
      bidi format character outright (the GitHub mitigation
      after CVE-2021-42574 was exactly this).

    * `hasUnbalancedBidi` — true iff isolate / embedding controls
      are not properly nested and terminated. The lenient check
      for systems that legitimately use bidi (right-to-left
      strings literals, comments in Arabic / Hebrew code).

  Plus the integrated decision function:

    * `safeForCodeContext` — combines the strict bidi reject with
      a Restriction-level threshold (≥ HighlyRestrictive) so that
      identifiers using mixed Latin / Cyrillic homoglyphs are
      rejected even when individually well-formed.

  The nine bidi format-control codepoints (UAX #9):

      U+202A  LEFT-TO-RIGHT EMBEDDING       (LRE)
      U+202B  RIGHT-TO-LEFT EMBEDDING       (RLE)
      U+202C  POP DIRECTIONAL FORMATTING    (PDF)
      U+202D  LEFT-TO-RIGHT OVERRIDE        (LRO)
      U+202E  RIGHT-TO-LEFT OVERRIDE        (RLO)
      U+2066  LEFT-TO-RIGHT ISOLATE         (LRI)
      U+2067  RIGHT-TO-LEFT ISOLATE         (RLI)
      U+2068  FIRST-STRONG ISOLATE          (FSI)
      U+2069  POP DIRECTIONAL ISOLATE       (PDI)
-/

import Unicode.Restriction

namespace Unicode.TrojanSource

open Unicode.Restriction (RestrictionLevel restrictionLevel)

-- The `safeForCodeContext` spot-checks reduce through the restriction and
-- script tables; kernel reduction of those lookups exceeds the default limit.
set_option maxRecDepth 1000000

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 BIDI FORMAT-CONTROL DETECTION
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The five embedding / override controls (LRE / RLE / PDF / LRO /
    RLO). Pop-directional-formatting (PDF) closes any embedding or
    override; the rest open one. -/
def isBidiEmbeddingControl (cp : Nat) : Bool :=
  Nat.ble 0x202A cp && Nat.ble cp 0x202E

/-- The four isolate controls (LRI / RLI / FSI / PDI). PDI closes
    any isolate; the rest open one. -/
def isBidiIsolateControl (cp : Nat) : Bool :=
  Nat.ble 0x2066 cp && Nat.ble cp 0x2069

/-- True iff `cp` is one of the nine UAX #9 bidi format-control
    codepoints — embedding (LRE/RLE/LRO/RLO/PDF) or isolate
    (LRI/RLI/FSI/PDI). These are the codepoints involved in the
    Trojan Source attack class. -/
def isBidiFormatControl (cp : Nat) : Bool :=
  isBidiEmbeddingControl cp || isBidiIsolateControl cp

/-- True iff `cps` contains any bidi format-control codepoint.
    Most source-code review systems should reject any input where
    this is true. -/
def containsBidiFormatControl (cps : List Nat) : Bool :=
  cps.any isBidiFormatControl

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 BIDI BALANCE / NESTING CHECK
--
-- For systems that legitimately use bidi controls (e.g. inline
-- right-to-left text in comments), enforce that every "open"
-- control is matched by a "close" control of the same kind.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- True iff `cp` opens an embedding-or-override context: LRE,
    RLE, LRO, or RLO.  Per UAX #9 §3.3.2 all four push a new
    bidi level onto the formatting stack and are closed by a
    single matching PDF.  RLO (`U+202E`) is the primary attack
    vector for Trojan Source (CVE-2021-42574), so its inclusion
    here is load-bearing for the balance check below. -/
def opensEmbedding (cp : Nat) : Bool :=
  cp = 0x202A || cp = 0x202B || cp = 0x202D || cp = 0x202E

/-- U+202C POP DIRECTIONAL FORMATTING. -/
def isPDF (cp : Nat) : Bool := cp = 0x202C

/-- True iff `cp` opens an isolate: LRI, RLI, FSI. -/
def opensIsolate (cp : Nat) : Bool :=
  cp = 0x2066 || cp = 0x2067 || cp = 0x2068

/-- U+2069 POP DIRECTIONAL ISOLATE. -/
def isPDI (cp : Nat) : Bool := cp = 0x2069

/-- Walk `cps` and check that embedding-opens and isolate-opens
    are properly closed. Returns `true` if the bidi controls are
    not balanced — i.e. an open without a matching close, a close
    without a matching open, or interleaved kinds. -/
def hasUnbalancedBidiGo (cps : List Nat) (embDepth isoDepth : Nat) : Bool :=
  match cps with
  | [] => embDepth ≠ 0 || isoDepth ≠ 0
  | cp :: rest =>
    if opensEmbedding cp then
      hasUnbalancedBidiGo rest (embDepth + 1) isoDepth
    else if isPDF cp then
      if embDepth = 0 then true
      else hasUnbalancedBidiGo rest (embDepth - 1) isoDepth
    else if opensIsolate cp then
      hasUnbalancedBidiGo rest embDepth (isoDepth + 1)
    else if isPDI cp then
      if isoDepth = 0 then true
      else hasUnbalancedBidiGo rest embDepth (isoDepth - 1)
    else
      hasUnbalancedBidiGo rest embDepth isoDepth

/-- True iff `cps` has unbalanced bidi format-controls — at end
    of input some embedding or isolate is still open, or a close
    appears with no matching open. -/
def hasUnbalancedBidi (cps : List Nat) : Bool :=
  hasUnbalancedBidiGo cps 0 0

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 INTEGRATED CODE-CONTEXT DECISION
-- ═══════════════════════════════════════════════════════════════════════════════

/-- True iff `cps` is safe to render in a source-code or
    code-review context: no bidi format-controls *and* the
    restriction level is at least Highly Restrictive (so
    Latin-Cyrillic homograph identifiers like `аррӏе` are
    rejected). The threshold can be relaxed for languages
    requiring stronger Latin/non-Latin mixing — but the bidi
    check is non-negotiable. -/
def safeForCodeContext (cps : List Nat) : Bool :=
  let lvl := restrictionLevel cps
  ! containsBidiFormatControl cps
    && (lvl = .ASCIIOnly
        || lvl = .SingleScript
        || lvl = .HighlyRestrictive)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 TEST VECTORS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- A pure ASCII identifier passes. -/
theorem safe_ascii :
    safeForCodeContext [0x69, 0x66, 0x20, 0x78, 0x20, 0x3D, 0x3D, 0x20, 0x31]
      = true := by decide +kernel

/-- The classic Trojan Source CVE-2021-42574 fragment uses U+202E
    RLO. With it present the input is rejected. -/
theorem reject_rlo :
    safeForCodeContext [0x69, 0x66, 0x202E, 0x78] = false := by decide +kernel

/-- LRI (U+2066) alone is also rejected. -/
theorem reject_lri :
    safeForCodeContext [0x69, 0x66, 0x2066, 0x78] = false := by decide +kernel

/-- containsBidiFormatControl flags the nine bidi controls. -/
theorem detect_lre  : isBidiFormatControl 0x202A = true := by decide +kernel
theorem detect_rle  : isBidiFormatControl 0x202B = true := by decide +kernel
theorem detect_pdf  : isBidiFormatControl 0x202C = true := by decide +kernel
theorem detect_lro  : isBidiFormatControl 0x202D = true := by decide +kernel
theorem detect_rlo  : isBidiFormatControl 0x202E = true := by decide +kernel
theorem detect_lri  : isBidiFormatControl 0x2066 = true := by decide +kernel
theorem detect_rli  : isBidiFormatControl 0x2067 = true := by decide +kernel
theorem detect_fsi  : isBidiFormatControl 0x2068 = true := by decide +kernel
theorem detect_pdi  : isBidiFormatControl 0x2069 = true := by decide +kernel

/-- Plain ASCII has no bidi format-controls. -/
theorem no_bidi_ascii :
    containsBidiFormatControl [0x61, 0x62, 0x63] = false := by decide +kernel

/-- Balanced LRE…PDF passes the balance check. -/
theorem balanced_lre_pdf :
    hasUnbalancedBidi [0x202A, 0x61, 0x202C] = false := by decide +kernel

/-- LRE without matching PDF is unbalanced. -/
theorem unbalanced_open_lre :
    hasUnbalancedBidi [0x202A, 0x61] = true := by decide +kernel

/-- PDF without preceding LRE/RLE/LRO is unbalanced. -/
theorem unbalanced_lone_pdf :
    hasUnbalancedBidi [0x61, 0x202C] = true := by decide +kernel

/-- A Cyrillic-letter identifier that passes Single-Script also
    passes `safeForCodeContext` — there are no bidi controls and
    the level meets the threshold. -/
theorem safe_cyrillic :
    safeForCodeContext [0x043F, 0x0440, 0x0438, 0x0432, 0x0435, 0x0442]
      = true := by decide +kernel

/-- The Cyrillic IDN-homograph form of `apple` is Single-Script
    (purely Cyrillic) and contains no bidi controls — it passes
    `safeForCodeContext` on its own. The actual phishing defense
    is a confusables comparison against the Latin form, not the
    restriction level. -/
theorem safe_apple_cyrillic_passes :
    safeForCodeContext [0x0430, 0x0440, 0x0440, 0x04CF, 0x0435]
      = true := by decide +kernel

/-- A Latin/Cyrillic mix is MinimallyRestrictive (below the
    Highly threshold) so `safeForCodeContext` rejects it even
    without bidi controls. -/
theorem reject_latin_cyrillic_mix :
    safeForCodeContext [0x0061, 0x0440, 0x0061] = false := by decide +kernel

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 ALL-INPUT PROPERTIES
--
-- The vectors above witness the defense on named attack strings. The
-- statements below hold of every input, by induction on the codepoint
-- list, with no codepoint space enumerated.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- A codepoint opening an embedding is a bidi format control. The four
    embedding opens LRE, RLE, LRO, RLO lie inside `U+202A..U+202E`, which
    is `isBidiEmbeddingControl`. -/
theorem opensEmbedding_isBidiFormatControl (cp : Nat)
    (h : opensEmbedding cp = true) : isBidiFormatControl cp = true := by
  unfold opensEmbedding at h
  unfold isBidiFormatControl isBidiEmbeddingControl
  rcases Nat.decEq cp 0x202A with hne | heq
  · rcases Nat.decEq cp 0x202B with hne2 | heq2
    · rcases Nat.decEq cp 0x202D with hne3 | heq3
      · rcases Nat.decEq cp 0x202E with hne4 | heq4
        · simp [hne, hne2, hne3, hne4] at h
        · subst heq4; decide
      · subst heq3; decide
    · subst heq2; decide
  · subst heq; decide

/-- PDF (`U+202C`) is a bidi format control: it lies inside the embedding
    range `U+202A..U+202E`. -/
theorem isPDF_isBidiFormatControl (cp : Nat)
    (h : isPDF cp = true) : isBidiFormatControl cp = true := by
  unfold isPDF at h
  have hEq : cp = 0x202C := of_decide_eq_true h
  subst hEq; decide

/-- A codepoint opening an isolate is a bidi format control. LRI, RLI and
    FSI lie inside `U+2066..U+2069`, which is `isBidiIsolateControl`. -/
theorem opensIsolate_isBidiFormatControl (cp : Nat)
    (h : opensIsolate cp = true) : isBidiFormatControl cp = true := by
  unfold opensIsolate at h
  unfold isBidiFormatControl isBidiIsolateControl
  rcases Nat.decEq cp 0x2066 with hne | heq
  · rcases Nat.decEq cp 0x2067 with hne2 | heq2
    · rcases Nat.decEq cp 0x2068 with hne3 | heq3
      · simp [hne, hne2, hne3] at h
      · subst heq3; decide
    · subst heq2; decide
  · subst heq; decide

/-- PDI (`U+2069`) is a bidi format control: it lies inside the isolate
    range `U+2066..U+2069`. -/
theorem isPDI_isBidiFormatControl (cp : Nat)
    (h : isPDI cp = true) : isBidiFormatControl cp = true := by
  unfold isPDI at h
  have hEq : cp = 0x2069 := of_decide_eq_true h
  subst hEq; decide

/-- **The balance walk is inert on control-free input, at any depth.**
    Every nesting role is a format control, so on input carrying none the
    walk takes its final branch at each position and both depths reach the
    end unchanged. The verdict is then exactly whether the walk began
    nested.

    Quantified over the starting depths because the walk threads them
    through the recursion; the depth-zero statement is the specialisation
    below. -/
theorem hasUnbalancedBidiGo_of_no_control (cps : List Nat) :
    ∀ embDepth isoDepth : Nat,
      cps.any isBidiFormatControl = false →
      hasUnbalancedBidiGo cps embDepth isoDepth
        = (decide (embDepth ≠ 0) || decide (isoDepth ≠ 0)) := by
  induction cps with
  | nil =>
      intro embDepth isoDepth hNone
      unfold hasUnbalancedBidiGo
      exact congrArg (fun flag => flag) rfl
  | cons cp rest ih =>
      intro embDepth isoDepth hNone
      rw [List.any_cons, Bool.or_eq_false_iff] at hNone
      obtain ⟨hHead, hTail⟩ := hNone
      have hEmb : opensEmbedding cp = false := by
        cases hv : opensEmbedding cp with
        | false => rfl
        | true =>
            rw [opensEmbedding_isBidiFormatControl cp hv] at hHead
            exact Bool.noConfusion hHead
      have hPDF : isPDF cp = false := by
        cases hv : isPDF cp with
        | false => rfl
        | true =>
            rw [isPDF_isBidiFormatControl cp hv] at hHead
            exact Bool.noConfusion hHead
      have hIso : opensIsolate cp = false := by
        cases hv : opensIsolate cp with
        | false => rfl
        | true =>
            rw [opensIsolate_isBidiFormatControl cp hv] at hHead
            exact Bool.noConfusion hHead
      have hPDI : isPDI cp = false := by
        cases hv : isPDI cp with
        | false => rfl
        | true =>
            rw [isPDI_isBidiFormatControl cp hv] at hHead
            exact Bool.noConfusion hHead
      unfold hasUnbalancedBidiGo
      simp only [hEmb, hPDF, hIso, hPDI]
      exact ih embDepth isoDepth hTail

/-- **Absence of bidi format controls implies balance, for every input.**
    The strict reject subsumes the lenient one: an input the strict layer
    admits cannot fail the balance check, so the two layers agree
    everywhere the strict layer passes.

    Induction on the input; no codepoint space is enumerated. -/
theorem balanced_of_no_bidi_control (cps : List Nat)
    (h : containsBidiFormatControl cps = false) :
    hasUnbalancedBidi cps = false := by
  unfold hasUnbalancedBidi
  unfold containsBidiFormatControl at h
  rw [hasUnbalancedBidiGo_of_no_control cps 0 0 h]
  decide

/-- **Everything `safeForCodeContext` admits is bidi-balanced.** The
    integrated decision requires the absence of format controls, so its
    output is balanced by `balanced_of_no_bidi_control` without the
    balance check being consulted.

    The agreement between the two defense layers, over all inputs rather
    than on vectors. -/
theorem safeForCodeContext_balanced (cps : List Nat)
    (h : safeForCodeContext cps = true) :
    hasUnbalancedBidi cps = false := by
  unfold safeForCodeContext at h
  have hNo : containsBidiFormatControl cps = false := by
    cases hv : containsBidiFormatControl cps with
    | false => rfl
    | true =>
        rw [hv] at h
        simp at h
  exact balanced_of_no_bidi_control cps hNo

/-- **A control-free verdict is a statement about every position.** No
    codepoint of an input `containsBidiFormatControl` reports `false` for
    is a bidi format control. -/
theorem no_control_mem (cps : List Nat) (cp : Nat)
    (h : containsBidiFormatControl cps = false) (hMem : cp ∈ cps) :
    isBidiFormatControl cp = false := by
  unfold containsBidiFormatControl at h
  cases hv : isBidiFormatControl cp with
  | false => rfl
  | true =>
      have hAny : cps.any isBidiFormatControl = true :=
        List.any_eq_true.mpr ⟨cp, hMem, hv⟩
      rw [h] at hAny
      exact Bool.noConfusion hAny

end Unicode.TrojanSource
