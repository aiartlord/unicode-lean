/-
  Unicode.Security.Display.SourceDisplayDivergence

  D1 — Detection of source-code-context attacks where the bytes a
  compiler executes diverge from what a human reviewer sees on
  screen.  Compound detector that composes the codepoint-level
  Layer-1 covert-channel detectors (C1 tag-block, C2 variation-
  selector, C3 zero-width, C5 bidi-balance) with the
  Layer-2 identity detector (I1 homoglyph).

  Threat model.  Tier A₂ (pipeline injector) / A₃ (supply-chain
  injector).  Adversary commits source code whose visible glyph
  stream looks innocuous (or matches an honest reference) but
  whose byte stream contains an embedded payload, a reordering
  control, an invisible operator, or a homoglyph identifier
  substitution.  Real-world adversaries combine: bidi-balanced +
  VS-payload + homoglyph-identifier in one file.

  Scope.

    * Language-agnostic by design (v0.12.0).  Earlier prereleases
      experimented with a `Language` parameter that filtered hits
      by source-region grammar (code vs. string-literal vs.
      comment).  That filtering surface has been retracted: it
      assumed a grammar's region partition makes some source
      bytes safer than others, an assumption the broader
      ecosystem evidence contradicts (tj-actions/changed-files
      March 2025 supply-chain attack; CVE-2025-29927 Next.js
      middleware bypass; LLM code-assistant prompt injection
      via JSDoc/docstring comments; npm-metadata-string supply-
      chain backdoors).  Source bytes are uniformly suspect
      regardless of which source-region a tokenizer would
      assign them to.  Every sub-detector hit therefore fires
      unconditionally.

    * C4 (byte-level surrogate-reassembly / UTF-8 anomaly) is NOT
      composed here — by the time the byte stream has been
      decoded to a codepoint sequence, the C4 check has already
      happened (or should have).  C4 must be run on the *byte*
      stream BEFORE this detector.

  Compound classification rule.

    * No sub-detector fires    → `.clear`.
    * Exactly one fires         → `.hazard` with the single-family
                                  sub-threat passed through.
    * Two or more fire         → `.compound` with the constituent
                                  family tags collected.
-/

import Unicode.Security.Calculus
import Unicode.Security.Covert.TagBlockPayload
import Unicode.Security.Covert.VariationSelectorPayload
import Unicode.Security.Covert.ZeroWidthPayload
import Unicode.Security.Covert.BidiControlBalance
import Unicode.TrojanSource
import Unicode.Security.Identity.HomoglyphConfusable

namespace Unicode.Security.Display.SourceDisplayDivergence

open Unicode.Security.Calculus
open Unicode.Security.Identity.HomoglyphConfusable (hasDecompositionSwap)
open Unicode.Normalization.LowCodepointNfc (toNFC_id_all_lt toNFC_id_of_starters)
open Unicode.Normalization.Compose (primaryComposite?_none_of_all_ne)

-- The spot checks run concrete inputs through the composed sub-detector
-- pipeline (tag / variation / zero-width / bidi / confusable-skeleton), so they
-- pin the wiring end to end rather than assuming it. The confusable skeleton is
-- a balanced decision tree whose nesting exceeds the default reducer recursion
-- budget.
set_option maxRecDepth 100000

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Types
-- ═══════════════════════════════════════════════════════════════════════════════

/-- D1 sub-threats — one per constituent family plus a `compound`
    variant for the multi-mechanism attack class. -/
inductive SubThreat where
  | tagBlock            (innerTag : String)
  | variationSelector   (innerTag : String)
  | zeroWidth           (innerTag : String)
  | bidiControl         (innerTag : String)
  | identifierHomoglyph (innerTag : String)
  | compound            (constituents : List String)
  deriving DecidableEq, Repr, Inhabited

/-- Top-level classification for D1. -/
inductive Classification where
  | clear
  | hazard (sub : SubThreat) (positions : List Nat) (decoded : List UInt8)
  deriving Inhabited

/-- D1 verdict — carries all five sub-detector verdicts so a
    reviewer can drill into any specific family if interested. -/
structure Verdict where
  input              : List Nat
  classify           : Classification
  c1Tag              : Option String        -- TagBlockPayload
  c2Tag              : Option String        -- VariationSelectorPayload
  c3Tag              : Option String        -- ZeroWidthPayload
  c5Tag              : Option String        -- BidiControlBalance
  i1Tag              : Option String        -- HomoglyphConfusable
  firedFamilies      : List String          -- non-clear family names
  safeForReview      : Bool
  deriving Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Sub-verdict aggregation
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Compose the five constituent verdicts into a single D1 verdict.
    The single-fire case threads the inner sub-threat tag through
    so a downstream reviewer can see *which* family fired without
    cross-referencing the per-family verdicts. -/
def buildClassification
    (c1Tag c2Tag c3Tag c5Tag i1Tag : Option String) : Classification :=
  let fires : List (String × String) :=
    [("C1", c1Tag.getD ""), ("C2", c2Tag.getD ""), ("C3", c3Tag.getD ""),
     ("C5", c5Tag.getD ""), ("I1", i1Tag.getD "")]
    |>.filter (fun pair => pair.2 ≠ "")
  match fires with
  | [] => .clear
  | [pair] =>
    let sub : SubThreat := match pair.1 with
      | "C1" => .tagBlock pair.2
      | "C2" => .variationSelector pair.2
      | "C3" => .zeroWidth pair.2
      | "C5" => .bidiControl pair.2
      | "I1" => .identifierHomoglyph pair.2
      | other => Function.const String (.compound [other]) other
    .hazard sub [] []
  | first :: second :: rest =>
    Function.const (List (String × String))
      (.hazard (.compound ((first :: second :: rest).map (fun pair => pair.1)))
        [] [])
      rest

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Top-level detection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The D1 detection function.  Runs all five constituent
    detectors on the same codepoint stream and aggregates the
    results into a compound verdict.

    Every sub-detector hit fires unconditionally, regardless of
    where in the source the offending codepoint sits.  Earlier
    prereleases tried to filter hits by source-region grammar
    (strings, comments) but that surface has been retracted —
    see module header for the threat-model rationale. -/
def detect (input : List Nat) : Verdict :=
  let c1 := Unicode.Security.Covert.TagBlockPayload.detect input
  let c2 := Unicode.Security.Covert.VariationSelectorPayload.detect input
  let c3 := Unicode.Security.Covert.ZeroWidthPayload.detect input
  -- Presence, not balance. A Trojan Source payload balances its controls,
  -- since an unbalanced run breaks the file it hides in, so the balance verdict
  -- is blind to the shape the attack takes. The BidiControlBalance family's own
  -- verdict is unchanged; only this constituent reads presence.
  let c5Present := input.any Unicode.TrojanSource.isBidiFormatControl
  let i1 := Unicode.Security.Identity.HomoglyphConfusable.detect input
  let c1Tag := c1.classify.tag
  let c2Tag := c2.classify.tag
  let c3Tag := c3.classify.tag
  let c5Tag := if c5Present then some "BidiControl" else none
  let i1Tag := i1.classify.tag
  let classify := buildClassification c1Tag c2Tag c3Tag c5Tag i1Tag
  let firedFamilies : List String :=
    [("C1", c1Tag), ("C2", c2Tag), ("C3", c3Tag),
     ("C5", c5Tag), ("I1", i1Tag)]
    |>.filterMap (fun pair => match pair.2 with
                              | some hit  => Function.const String (some pair.1) hit
                              | none      => none)
  { input := input,
    classify := classify,
    c1Tag := c1Tag, c2Tag := c2Tag, c3Tag := c3Tag,
    c5Tag := c5Tag, i1Tag := i1Tag,
    firedFamilies := firedFamilies,
    safeForReview := firedFamilies.isEmpty }

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Projection helpers
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Fixture-row tag string for each `SubThreat` constructor. -/
def SubThreat.tag : SubThreat → String
  | .tagBlock            innerTag      =>
      Function.const String "TagBlock" innerTag
  | .variationSelector   innerTag      =>
      Function.const String "VariationSelector" innerTag
  | .zeroWidth           innerTag      =>
      Function.const String "ZeroWidth" innerTag
  | .bidiControl         innerTag      =>
      Function.const String "BidiControl" innerTag
  | .identifierHomoglyph innerTag      =>
      Function.const String "IdentifierHomoglyph" innerTag
  | .compound            constituents  =>
      Function.const (List String) "Compound" constituents

/-- True iff the classification is `.clear`. -/
def Classification.isClear : Classification → Bool
  | .clear                     => true
  | .hazard sub positions decoded =>
      Function.const (SubThreat × List Nat × List UInt8) false
        (sub, positions, decoded)

/-- Tag string of a classification. -/
def Classification.tag : Classification → Option String
  | .clear                     => none
  | .hazard sub positions decoded =>
      Function.const (List Nat × List UInt8) (some sub.tag) (positions, decoded)

/-- Positions array of a classification. -/
def Classification.positions : Classification → List Nat
  | .clear                     => []
  | .hazard sub positions decoded =>
      Function.const (SubThreat × List UInt8) positions (sub, decoded)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 Spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

-- Each check settles the composed verdict without ever reducing the `toNFC`
-- pipeline. HomoglyphConfusable's `hasDecompositionSwap` is its only `toNFC`
-- call; it is rewritten to `false` structurally — by `toNFC_id_all_lt` for
-- all-ASCII inputs, and by `toNFC_id_of_starters` (indexed per-code-point
-- decomposition/CCC lookups plus an explicit non-composition tuple) for inputs
-- carrying tag, variation-selector, zero-width, or bidi code points. With that
-- branch pinned, HomoglyphConfusable's verdict reduces over the confusable
-- skeleton and script tables alone (bounded), and the four code-point-scan
-- sub-detectors plus the aggregation bookkeeping decide directly.

/-- Empty input is clear (every sub-detector clears). -/
theorem detect_empty_clear : (detect []).classify.isClear = true := by
  have hds : hasDecompositionSwap [] = false := by
    unfold hasDecompositionSwap; rw [toNFC_id_all_lt [] (by decide)]; simp
  have hi1 : (Unicode.Security.Identity.HomoglyphConfusable.detect []).classify.tag = none := by
    unfold Unicode.Security.Identity.HomoglyphConfusable.detect; rw [hds]; decide +kernel
  simp only [detect, hi1]
  decide

/-- Pure ASCII "Hello world" is clear. -/
theorem detect_ascii_clear :
    (detect [0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64]).classify.isClear
      = true := by
  have hds : hasDecompositionSwap [0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64]
      = false := by
    unfold hasDecompositionSwap
    rw [toNFC_id_all_lt [0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64] (by decide)]
    simp
  have hi1 : (Unicode.Security.Identity.HomoglyphConfusable.detect
      [0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64]).classify.tag = none := by
    unfold Unicode.Security.Identity.HomoglyphConfusable.detect; rw [hds]; decide +kernel
  simp only [detect, hi1]
  decide

/-- A pure-C1 attack — tag-encoded "AB" — fires `.tagBlock`. -/
theorem detect_tag_only :
    (detect [0xE0041, 0xE0042]).classify.tag = some "TagBlock" := by
  have hds : hasDecompositionSwap [0xE0041, 0xE0042] = false := by
    unfold hasDecompositionSwap
    rw [toNFC_id_of_starters [0xE0041, 0xE0042]
        (by intro x hx; simp at hx; rcases hx with h | h <;> subst h <;> exact ⟨by decide, by decide⟩)
        (by intro x hx; simp at hx; rcases hx with h | h <;> subst h <;> decide)
        ⟨primaryComposite?_none_of_all_ne 0xE0041 0xE0042 (by decide) (by decide +kernel), trivial⟩]
    simp
  have hi1 : (Unicode.Security.Identity.HomoglyphConfusable.detect
      [0xE0041, 0xE0042]).classify.tag = none := by
    unfold Unicode.Security.Identity.HomoglyphConfusable.detect; rw [hds]; decide +kernel
  simp only [detect, hi1]
  decide

/-- A pure-C2 attack — Latin A + VS16 — fires `.variationSelector`. -/
theorem detect_vs_only :
    (detect [0x0041, 0xFE0F]).classify.tag = some "VariationSelector" := by
  have hds : hasDecompositionSwap [0x0041, 0xFE0F] = false := by
    unfold hasDecompositionSwap
    rw [toNFC_id_of_starters [0x0041, 0xFE0F]
        (by intro x hx; simp at hx; rcases hx with h | h <;> subst h <;> exact ⟨by decide, by decide⟩)
        (by intro x hx; simp at hx; rcases hx with h | h <;> subst h <;> decide)
        ⟨primaryComposite?_none_of_all_ne 0x0041 0xFE0F (by decide) (by decide +kernel), trivial⟩]
    simp
  have hi1 : (Unicode.Security.Identity.HomoglyphConfusable.detect
      [0x0041, 0xFE0F]).classify.tag = none := by
    unfold Unicode.Security.Identity.HomoglyphConfusable.detect; rw [hds]; decide +kernel
  simp only [detect, hi1]
  decide

/-- A pure-C3 attack — Latin H + ZWSP + i — fires `.zeroWidth`. -/
theorem detect_zw_only :
    (detect [0x0048, 0x200B, 0x69]).classify.tag = some "ZeroWidth" := by
  have hds : hasDecompositionSwap [0x0048, 0x200B, 0x69] = false := by
    unfold hasDecompositionSwap
    rw [toNFC_id_of_starters [0x0048, 0x200B, 0x69]
        (by intro x hx; simp at hx; rcases hx with h | h | h <;> subst h <;> exact ⟨by decide, by decide⟩)
        (by intro x hx; simp at hx; rcases hx with h | h | h <;> subst h <;> decide)
        ⟨primaryComposite?_none_of_all_ne 0x0048 0x200B (by decide) (by decide +kernel),
         primaryComposite?_none_of_all_ne 0x200B 0x69 (by decide) (by decide +kernel), trivial⟩]
    simp
  have hi1 : (Unicode.Security.Identity.HomoglyphConfusable.detect
      [0x0048, 0x200B, 0x69]).classify.tag = none := by
    unfold Unicode.Security.Identity.HomoglyphConfusable.detect; rw [hds]; decide +kernel
  simp only [detect, hi1]
  decide

/-- A pure-C5 attack — lone RLO — fires `.bidiControl`. -/
theorem detect_bidi_only :
    (detect [0x202E, 0x41]).classify.tag = some "BidiControl" := by
  have hds : hasDecompositionSwap [0x202E, 0x41] = false := by
    unfold hasDecompositionSwap
    rw [toNFC_id_of_starters [0x202E, 0x41]
        (by intro x hx; simp at hx; rcases hx with h | h <;> subst h <;> exact ⟨by decide, by decide⟩)
        (by intro x hx; simp at hx; rcases hx with h | h <;> subst h <;> decide)
        ⟨primaryComposite?_none_of_all_ne 0x202E 0x41 (by decide) (by decide +kernel), trivial⟩]
    simp
  have hi1 : (Unicode.Security.Identity.HomoglyphConfusable.detect
      [0x202E, 0x41]).classify.tag = none := by
    unfold Unicode.Security.Identity.HomoglyphConfusable.detect; rw [hds]; decide +kernel
  simp only [detect, hi1]
  decide

/-- A *balanced* isolate pair still fires `.bidiControl`.  This is the case the
    constituent exists to catch: `BidiControlBalance` classifies U+2066 followed
    by U+2069 as clear, because the run opens and closes, while a Trojan Source
    payload balances its controls precisely so the file it hides in still
    parses.  Reading presence rather than the balance verdict is what keeps this
    input reportable. -/
theorem detect_balanced_bidi_fires :
    (detect [0x2066, 0x2069]).classify.tag = some "BidiControl" := by
  have hds : hasDecompositionSwap [0x2066, 0x2069] = false := by
    unfold hasDecompositionSwap
    rw [toNFC_id_of_starters [0x2066, 0x2069]
        (by intro x hx; simp at hx; rcases hx with h | h <;> subst h <;> exact ⟨by decide, by decide⟩)
        (by intro x hx; simp at hx; rcases hx with h | h <;> subst h <;> decide)
        ⟨primaryComposite?_none_of_all_ne 0x2066 0x2069 (by decide) (by decide +kernel), trivial⟩]
    simp
  have hi1 : (Unicode.Security.Identity.HomoglyphConfusable.detect
      [0x2066, 0x2069]).classify.tag = none := by
    unfold Unicode.Security.Identity.HomoglyphConfusable.detect; rw [hds]; decide +kernel
  simp only [detect, hi1]
  decide

/-- A pure-I1 attack — Nethereum typosquat — fires `.identifierHomoglyph`.
    Here the four codepoint-scan detectors are pinned clear and the skeleton
    reduces in place. -/
theorem detect_homoglyph_only :
    (detect [0x4E, 0x65, 0x74, 0x68, 0x65, 0x72, 0x0435, 0x75, 0x6D]).classify.tag
      = some "IdentifierHomoglyph" := by
  have hc1 : (Unicode.Security.Covert.TagBlockPayload.detect
      [0x4E, 0x65, 0x74, 0x68, 0x65, 0x72, 0x0435, 0x75, 0x6D]).classify.tag = none := by
    decide
  have hc2 : (Unicode.Security.Covert.VariationSelectorPayload.detect
      [0x4E, 0x65, 0x74, 0x68, 0x65, 0x72, 0x0435, 0x75, 0x6D]).classify.tag = none := by
    decide
  have hc3 : (Unicode.Security.Covert.ZeroWidthPayload.detect
      [0x4E, 0x65, 0x74, 0x68, 0x65, 0x72, 0x0435, 0x75, 0x6D]).classify.tag = none := by
    decide
  have hi1 : (Unicode.Security.Identity.HomoglyphConfusable.detect
      [0x4E, 0x65, 0x74, 0x68, 0x65, 0x72, 0x0435, 0x75, 0x6D]).classify.tag
      = some "TargetMatch" := by decide +kernel
  -- The bidi constituent reads presence directly, so `detect` no longer calls
  -- BidiControlBalance and a hypothesis about that detector's verdict has
  -- nothing left to rewrite; `decide` closes the presence test.
  simp only [detect, hc1, hc2, hc3, hi1]
  decide

/-- A compound attack — Latin A + VS16 + ZWSP — fires `.compound`. -/
theorem detect_compound_vs_plus_zw :
    (detect [0x0041, 0xFE0F, 0x200B]).classify.tag = some "Compound" := by
  have hds : hasDecompositionSwap [0x0041, 0xFE0F, 0x200B] = false := by
    unfold hasDecompositionSwap
    rw [toNFC_id_of_starters [0x0041, 0xFE0F, 0x200B]
        (by intro x hx; simp at hx; rcases hx with h | h | h <;> subst h <;> exact ⟨by decide, by decide⟩)
        (by intro x hx; simp at hx; rcases hx with h | h | h <;> subst h <;> decide)
        ⟨primaryComposite?_none_of_all_ne 0x0041 0xFE0F (by decide) (by decide +kernel),
         primaryComposite?_none_of_all_ne 0xFE0F 0x200B (by decide) (by decide +kernel), trivial⟩]
    simp
  have hi1 : (Unicode.Security.Identity.HomoglyphConfusable.detect
      [0x0041, 0xFE0F, 0x200B]).classify.tag = none := by
    unfold Unicode.Security.Identity.HomoglyphConfusable.detect; rw [hds]; decide +kernel
  simp only [detect, hi1]
  decide

/-- Tag + zero-width — also `.compound`. -/
theorem detect_compound_tag_plus_zw :
    (detect [0xE0041, 0xE0042, 0x200B]).classify.tag = some "Compound" := by
  have hds : hasDecompositionSwap [0xE0041, 0xE0042, 0x200B] = false := by
    unfold hasDecompositionSwap
    rw [toNFC_id_of_starters [0xE0041, 0xE0042, 0x200B]
        (by intro x hx; simp at hx; rcases hx with h | h | h <;> subst h <;> exact ⟨by decide, by decide⟩)
        (by intro x hx; simp at hx; rcases hx with h | h | h <;> subst h <;> decide)
        ⟨primaryComposite?_none_of_all_ne 0xE0041 0xE0042 (by decide) (by decide +kernel),
         primaryComposite?_none_of_all_ne 0xE0042 0x200B (by decide) (by decide +kernel), trivial⟩]
    simp
  have hi1 : (Unicode.Security.Identity.HomoglyphConfusable.detect
      [0xE0041, 0xE0042, 0x200B]).classify.tag = none := by
    unfold Unicode.Security.Identity.HomoglyphConfusable.detect; rw [hds]; decide +kernel
  simp only [detect, hi1]
  decide

/-- A clean code snippet "let x = 1;" is clear. -/
theorem detect_clean_code :
    (detect [0x6C, 0x65, 0x74, 0x20, 0x78, 0x20, 0x3D, 0x20, 0x31, 0x3B]).classify.isClear
      = true := by
  have hds : hasDecompositionSwap [0x6C, 0x65, 0x74, 0x20, 0x78, 0x20, 0x3D, 0x20, 0x31, 0x3B]
      = false := by
    unfold hasDecompositionSwap
    rw [toNFC_id_all_lt [0x6C, 0x65, 0x74, 0x20, 0x78, 0x20, 0x3D, 0x20, 0x31, 0x3B] (by decide)]
    simp
  have hi1 : (Unicode.Security.Identity.HomoglyphConfusable.detect
      [0x6C, 0x65, 0x74, 0x20, 0x78, 0x20, 0x3D, 0x20, 0x31, 0x3B]).classify.tag = none := by
    unfold Unicode.Security.Identity.HomoglyphConfusable.detect; rw [hds]; decide +kernel
  simp only [detect, hi1]
  decide

/-- `safeForReview` mirrors `isClear`. -/
theorem safeForReview_matches_clear_empty :
    (detect []).safeForReview = true := by
  have hds : hasDecompositionSwap [] = false := by
    unfold hasDecompositionSwap; rw [toNFC_id_all_lt [] (by decide)]; simp
  have hi1 : (Unicode.Security.Identity.HomoglyphConfusable.detect []).classify.tag = none := by
    unfold Unicode.Security.Identity.HomoglyphConfusable.detect; rw [hds]; decide +kernel
  simp only [detect, hi1]
  decide

theorem safeForReview_matches_hazard_VS :
    (detect [0x0041, 0xFE0F]).safeForReview = false := by
  have hds : hasDecompositionSwap [0x0041, 0xFE0F] = false := by
    unfold hasDecompositionSwap
    rw [toNFC_id_of_starters [0x0041, 0xFE0F]
        (by intro x hx; simp at hx; rcases hx with h | h <;> subst h <;> exact ⟨by decide, by decide⟩)
        (by intro x hx; simp at hx; rcases hx with h | h <;> subst h <;> decide)
        ⟨primaryComposite?_none_of_all_ne 0x0041 0xFE0F (by decide) (by decide +kernel), trivial⟩]
    simp
  have hi1 : (Unicode.Security.Identity.HomoglyphConfusable.detect
      [0x0041, 0xFE0F]).classify.tag = none := by
    unfold Unicode.Security.Identity.HomoglyphConfusable.detect; rw [hds]; decide +kernel
  simp only [detect, hi1]
  decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 Region-agnosticism spot checks
--
-- Pinning that detection fires on hazardous code points regardless of where they
-- sit in the source.  Some of these inputs previously cleared under a
-- `Language.rust` / `.python` / `.typescript` filter; that filter was retracted
-- in v0.12.0 because source-region grammar is not a security boundary — a
-- payload in a string literal or comment still deceives every consumer that
-- reads bytes (LLM code assistants, doc generators, IDE renderers, CI grep
-- matchers).
-- ═══════════════════════════════════════════════════════════════════════════════

/-- VS payload "inside a string literal" — fires because the source bytes are
    still attacker-visible regardless of what a tokenizer says about the
    region. -/
theorem detect_vs_inside_quote_pair_fires :
    (detect [0x22, 0x41, 0xFE00, 0x22]).classify.tag
      = some "VariationSelector" := by
  have hds : hasDecompositionSwap [0x22, 0x41, 0xFE00, 0x22] = false := by
    unfold hasDecompositionSwap
    rw [toNFC_id_of_starters [0x22, 0x41, 0xFE00, 0x22]
        (by intro x hx; simp at hx; rcases hx with h | h | h | h <;> subst h <;> exact ⟨by decide, by decide⟩)
        (by intro x hx; simp at hx; rcases hx with h | h | h | h <;> subst h <;> decide)
        ⟨primaryComposite?_none_of_all_ne 0x22 0x41 (by decide) (by decide +kernel),
         primaryComposite?_none_of_all_ne 0x41 0xFE00 (by decide) (by decide +kernel),
         primaryComposite?_none_of_all_ne 0xFE00 0x22 (by decide) (by decide +kernel), trivial⟩]
    simp
  have hi1 : (Unicode.Security.Identity.HomoglyphConfusable.detect
      [0x22, 0x41, 0xFE00, 0x22]).classify.tag = none := by
    unfold Unicode.Security.Identity.HomoglyphConfusable.detect; rw [hds]; decide +kernel
  simp only [detect, hi1]
  decide

/-- RLO "inside a line comment" — fires for the same reason.  Source-display
    divergence in a comment still deceives every consumer that reads bytes
    (LLM code assistants, doc generators, IDE renderers, CI grep matchers). -/
theorem detect_rlo_inside_line_comment_marker_fires :
    (detect [0x2F, 0x2F, 0x202E]).classify.tag
      = some "BidiControl" := by
  have hds : hasDecompositionSwap [0x2F, 0x2F, 0x202E] = false := by
    unfold hasDecompositionSwap
    rw [toNFC_id_of_starters [0x2F, 0x2F, 0x202E]
        (by intro x hx; simp at hx; rcases hx with h | h <;> subst h <;> exact ⟨by decide, by decide⟩)
        (by intro x hx; simp at hx; rcases hx with h | h <;> subst h <;> decide)
        ⟨primaryComposite?_none_of_all_ne 0x2F 0x2F (by decide) (by decide +kernel),
         primaryComposite?_none_of_all_ne 0x2F 0x202E (by decide) (by decide +kernel), trivial⟩]
    simp
  have hi1 : (Unicode.Security.Identity.HomoglyphConfusable.detect
      [0x2F, 0x2F, 0x202E]).classify.tag = none := by
    unfold Unicode.Security.Identity.HomoglyphConfusable.detect; rw [hds]; decide +kernel
  simp only [detect, hi1]
  decide

/-- RLO "inside a block comment" — fires. -/
theorem detect_rlo_inside_block_comment_fires :
    (detect [0x2F, 0x2A, 0x202E, 0x2A, 0x2F]).classify.tag
      = some "BidiControl" := by
  have hds : hasDecompositionSwap [0x2F, 0x2A, 0x202E, 0x2A, 0x2F] = false := by
    unfold hasDecompositionSwap
    rw [toNFC_id_of_starters [0x2F, 0x2A, 0x202E, 0x2A, 0x2F]
        (by intro x hx; simp at hx; rcases hx with h | h | h | h | h <;> subst h <;> exact ⟨by decide, by decide⟩)
        (by intro x hx; simp at hx; rcases hx with h | h | h | h | h <;> subst h <;> decide)
        ⟨primaryComposite?_none_of_all_ne 0x2F 0x2A (by decide) (by decide +kernel),
         primaryComposite?_none_of_all_ne 0x2A 0x202E (by decide) (by decide +kernel),
         primaryComposite?_none_of_all_ne 0x202E 0x2A (by decide) (by decide +kernel),
         primaryComposite?_none_of_all_ne 0x2A 0x2F (by decide) (by decide +kernel), trivial⟩]
    simp
  have hi1 : (Unicode.Security.Identity.HomoglyphConfusable.detect
      [0x2F, 0x2A, 0x202E, 0x2A, 0x2F]).classify.tag = none := by
    unfold Unicode.Security.Identity.HomoglyphConfusable.detect; rw [hds]; decide +kernel
  simp only [detect, hi1]
  decide

end Unicode.Security.Display.SourceDisplayDivergence
