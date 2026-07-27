/-
  Unicode.Security.Identity.HomoglyphConfusable

  Detection of homoglyph / confusable identifier substitution
  attacks (Nethereum Oct 2025, IDN homograph, Math-Alpha posing,
  Fullwidth disguise, decomposition swap, cross-script mixing).

  Threat model.  Tier A₁..A₃ (local injector → supply-chain
  injector).  Adversary registers a package / identifier / domain
  whose visible glyph stream is indistinguishable from a target's
  but whose byte stream differs at one or more positions.

  Detection strategy.  Reuse the project's existing UTS #39 §4
  skeleton machinery to project both the input and a curated list
  of canonical attack targets onto a confusable-equivalence
  representative, then test equality.  Layered with:

    * Math-Alphanumeric Symbols block detection (U+1D400..U+1D7FF
      mathematical italic / bold / fraktur / script / sans-serif).
    * Fullwidth / halfwidth form detection (U+FF01..U+FFEF).
    * Decomposition swap — `input ≠ NFC(input)`.
    * Cross-script mixing via the project's `Unicode.Restriction`
      machinery.

  Scope.

    * Six sub-threats covering the identity-spoofing class.
    * Canonical-target list sourced from
      `Unicode.Generated.KnownAttackTargets`, which embeds the
      SHA-pinned curated text file
      `Unicode/Ucd/Curated/KnownAttackTargets.txt`.  The text
      file is the maintenance surface for new attack targets;
      adding a target is a one-line edit followed by a SHA pin
      refresh.
-/

import Unicode.Security.Calculus
import Unicode.Confusables
import Unicode.ResolvedScripts
import Unicode.Restriction
import Unicode.Normalization.NFC
import Unicode.Normalization.LowCodepointNfc
import Unicode.Generated.KnownAttackTargets

namespace Unicode.Security.Identity.HomoglyphConfusable

open Unicode.Security.Calculus
open Unicode.Restriction (RestrictionLevel)

-- The skeleton/confusable spot checks reduce the mapping pipeline on concrete
-- inputs. The confusable lookup is a balanced decision tree (bounded per code
-- point, never a table scan), but the iterated skeleton, restriction, and
-- script-union stages descend it many times per check, nesting deeper than the
-- default reducer recursion and whnf heartbeat budgets.
set_option maxRecDepth 100000
set_option maxHeartbeats 8000000

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Types
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Sub-threat enumeration for HomoglyphConfusable.

    Priority order (highest first):
      1. `targetMatch`      input skeleton-equals a known canonical
                            target (the Nethereum / brand-impersonation
                            pattern).
      2. `mathAlpha`        input contains Mathematical Alphanumeric
                            Symbols posing as Latin identifier.
      3. `widthClass`       input contains fullwidth/halfwidth
                            ASCII variants.
      4. `decompositionSwap` input is not in NFC; the NFC form
                            differs at one or more positions.
      5. `crossScriptMix`   input mixes ≥2 non-Common, non-Inherited
                            scripts (Latin + Cyrillic, etc.).
      6. `restrictionLow`   input's UTS #39 restriction level is
                            below `.highlyRestrictive`.
-/
inductive SubThreat where
  | targetMatch        (target : String)
  | mathAlpha          (firstCp : Nat) (count : Nat)
  | widthClass         (firstCp : Nat) (count : Nat)
  | decompositionSwap  (firstDiffPos : Nat)
  | crossScriptMix     (scriptCount : Nat)
  | restrictionLow     (level : RestrictionLevel)
  deriving DecidableEq, Repr, Inhabited

/-- Top-level classification for HomoglyphConfusable. -/
inductive Classification where
  | clear
  | hazard (sub : SubThreat) (positions : List Nat) (decoded : List UInt8)
  deriving Inhabited

/-- Verdict — the structured output of `detect`. -/
structure Verdict where
  input              : List Nat
  classify           : Classification
  skeleton           : List Nat
  iteratedSkeleton   : List Nat
  restrictionLevel   : RestrictionLevel
  matchedTargets     : List String
  deriving Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Canonical attack-target dictionary
-- ═══════════════════════════════════════════════════════════════════════════════

/-- A canonical attack target — the legitimate name (e.g.
    "Nethereum") plus its byte-for-byte codepoint sequence as
    typed by a developer. -/
structure CanonicalTarget where
  name : String
  cps  : List Nat
  deriving Repr, Inhabited

/-- Construct a target from an ASCII name string. -/
def mkAscii (s : String) : CanonicalTarget :=
  { name := s, cps := s.toList.map Char.toNat }

/-- Canonical-target dictionary, derived from the SHA-pinned
    `Unicode/Ucd/Curated/KnownAttackTargets.txt` data file via
    `Unicode.Generated.KnownAttackTargets.targets`.  The data
    file is the single maintenance surface for the target set;
    this definition is its in-detector projection. -/
def canonicalTargets : List CanonicalTarget :=
  Unicode.Generated.KnownAttackTargets.targets.map mkAscii

/-- Letter skeletons of the canonical targets, materialized.

    `findTargetMatch` compares an input's letter skeleton against every target's,
    so computing the target side on demand would re-descend the confusable
    decision tree once per target on every single detection — the dominant cost
    of the whole detector. The values are pinned here instead and certified
    against the computed form by
    `HomoglyphConfusableSkeletonGate.canonicalTargetSkeletons_correct`, which is
    the single place that reduction is performed.

    Order matches `canonicalTargets` positionally; the two are consumed zipped. -/
def canonicalTargetSkeletons : List (List Nat) :=
  [ [110, 101, 116, 104, 101, 114, 101, 117, 114, 110],
     [101, 116, 104, 101, 114, 101, 117, 114, 110],
     [101, 116, 104, 101, 114, 115],
     [119, 101, 98, 51],
     [98, 105, 116, 99, 111, 105, 110],
     [117, 110, 105, 115, 119, 97, 112],
     [114, 110, 101, 116, 97, 114, 110, 97, 115, 107],
     [98, 105, 110, 97, 110, 99, 101],
     [99, 111, 105, 110, 98, 97, 115, 101],
     [115, 111, 108, 97, 110, 97],
     [114, 101, 97, 99, 116],
     [114, 101, 97, 99, 116, 45, 100, 111, 114, 110],
     [110, 101, 120, 116],
     [118, 117, 101],
     [97, 110, 103, 117, 108, 97, 114],
     [108, 111, 100, 97, 115, 104],
     [101, 120, 112, 114, 101, 115, 115],
     [101, 108, 101, 99, 116, 114, 111, 110],
     [116, 121, 112, 101, 115, 99, 114, 105, 112, 116],
     [119, 101, 98, 112, 97, 99, 107],
     [110, 111, 100, 101, 45, 102, 101, 116, 99, 104],
     [100, 105, 115, 99, 111, 114, 100, 46, 106, 115],
     [99, 114, 121, 112, 116, 111, 45, 106, 115],
     [100, 106, 97, 110, 103, 111],
     [114, 101, 113, 117, 101, 115, 116, 115],
     [102, 108, 97, 115, 107],
     [110, 117, 114, 110, 112, 121],
     [112, 97, 110, 100, 97, 115],
     [116, 101, 110, 115, 111, 114, 102, 108, 111, 119],
     [112, 121, 116, 111, 114, 99, 104],
     [114, 110, 97, 116, 112, 108, 111, 116, 108, 105, 98],
     [115, 99, 105, 112, 121],
     [98, 101, 97, 117, 116, 105, 102, 117, 108, 115, 111, 117, 112, 52],
     [112, 121, 121, 97, 114, 110, 108],
     [99, 114, 121, 112, 116, 111, 103, 114, 97, 112, 104, 121],
     [115, 101, 114, 100, 101],
     [116, 111, 107, 105, 111],
     [99, 108, 97, 112],
     [114, 101, 113, 119, 101, 115, 116],
     [114, 97, 110, 100],
     [97, 110, 121, 104, 111, 119],
     [114, 97, 105, 108, 115],
     [114, 115, 112, 101, 99],
     [100, 101, 118, 105, 115, 101],
     [110, 111, 107, 111, 103, 105, 114, 105],
     [103, 111, 111, 103, 108, 101],
     [97, 114, 110, 97, 122, 111, 110],
     [114, 110, 105, 99, 114, 111, 115, 111, 102, 116],
     [97, 112, 112, 108, 101],
     [103, 105, 116, 104, 117, 98],
     [103, 105, 116, 108, 97, 98],
     [98, 105, 116, 98, 117, 99, 107, 101, 116],
     [99, 108, 111, 117, 100, 102, 108, 97, 114, 101],
     [115, 116, 114, 105, 112, 101],
     [116, 119, 105, 108, 105, 111],
     [112, 97, 121, 112, 97, 108],
     [111, 112, 101, 110, 97, 105],
     [97, 110, 116, 104, 114, 111, 112, 105, 99],
     [99, 108, 97, 117, 100, 101],
     [99, 104, 97, 116, 103, 112, 116],
     [116, 101, 115, 108, 97],
     [116, 119, 105, 116, 116, 101, 114],
     [102, 97, 99, 101, 98, 111, 111, 107],
     [105, 110, 115, 116, 97, 103, 114, 97, 114, 110],
     [116, 105, 107, 116, 111, 107],
     [116, 101, 108, 101, 103, 114, 97, 114, 110],
     [100, 105, 115, 99, 111, 114, 100] ]

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Block predicates
-- ═══════════════════════════════════════════════════════════════════════════════

/-- True iff `cp` is in the Mathematical Alphanumeric Symbols block
    (U+1D400..U+1D7FF).  These codepoints render as italic/bold/
    fraktur/script/sans-serif/double-struck Latin and digit letters
    and are a common identifier-spoofing vector. -/
@[inline]
def isMathAlphanumeric (cp : Nat) : Bool :=
  0x1D400 ≤ cp ∧ cp ≤ 0x1D7FF

/-- True iff `cp` is in the Halfwidth and Fullwidth Forms block
    (U+FF01..U+FFEF) — fullwidth ASCII look-alikes plus halfwidth
    Katakana / Hangul jamo.  The fullwidth Latin variants
    (U+FF21..U+FF5A) are the typical identifier-spoofing
    sub-range. -/
@[inline]
def isFullwidthHalfwidth (cp : Nat) : Bool :=
  0xFF01 ≤ cp ∧ cp ≤ 0xFFEF

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Sub-threat detectors (each takes `input` + precomputed fields)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Find the first canonical target whose **letter** skeleton
    matches the input's letter skeleton, modulo the input being
    literally that target (no self-match).

    Uses `letterSkeleton` (which strips combining marks from the
    §4+§5.4 skeleton) rather than `iteratedSkeleton` so that
    base-letter+combining-mark confusables — e.g. U+0247 `ɇ` →
    `e + ◌̸`, U+0266 `ɦ` → `h + ◌̔`, U+0127 `ħ` → `h + ◌̵` —
    collapse to the bare-letter target.  Mutation testing against
    the rust-port surfaced that 21% of single-codepoint typosquat
    mutations against curated targets bypass `iteratedSkeleton`
    via this class of confusable; `letterSkeleton` closes the
    gap by treating "letter + accent" and the bare letter as
    typosquat-equivalent. -/
def findTargetMatch
    (input : List Nat) (iSkel : List Nat) : Option CanonicalTarget :=
  Function.const (List Nat)
    (let inputLetters := Unicode.Confusables.letterSkeleton input
     ((canonicalTargets.zip canonicalTargetSkeletons).find? (fun ts =>
        decide (ts.fst.cps ≠ input) ∧
        decide (ts.snd = inputLetters))).map (fun ts => ts.fst))
    iSkel

/-- Position of the first math-alphanumeric codepoint in `input`. -/
def firstMathAlphaPos (input : List Nat) : Option Nat :=
  (input.zipIdx.find? (fun cpWithIdx => isMathAlphanumeric cpWithIdx.1)).map
    (fun cpWithIdx => cpWithIdx.2)

/-- Count of math-alphanumeric codepoints in `input`. -/
def mathAlphaCount (input : List Nat) : Nat :=
  input.foldl (fun n cp => if isMathAlphanumeric cp then n + 1 else n) 0

/-- Position of the first fullwidth/halfwidth codepoint in `input`. -/
def firstFullwidthPos (input : List Nat) : Option Nat :=
  (input.zipIdx.find? (fun cpWithIdx => isFullwidthHalfwidth cpWithIdx.1)).map
    (fun cpWithIdx => cpWithIdx.2)

/-- Count of fullwidth/halfwidth codepoints in `input`. -/
def fullwidthCount (input : List Nat) : Nat :=
  input.foldl (fun n cp => if isFullwidthHalfwidth cp then n + 1 else n) 0

/-- True iff the input is not in NFC — i.e. `NFC(input) ≠ input`. -/
def hasDecompositionSwap (input : List Nat) : Bool :=
  decide (Unicode.Normalization.NFC.toNFC input ≠ input)

/-- First position at which `input` and its NFC form differ.
    Returns `none` if they match. -/
def firstDecompositionDiffPos (input : List Nat) : Option Nat :=
  let nfc := Unicode.Normalization.NFC.toNFC input
  ((input.zip nfc).zipIdx.find? (fun pairWithIdx =>
    decide (pairWithIdx.1.1 ≠ pairWithIdx.1.2))).map (fun pairWithIdx => pairWithIdx.2)

/-- Number of distinct non-Common, non-Inherited script families
    represented in `input`.  ≥ 2 indicates cross-script mixing.

    Uses `stringScriptUnion`, NOT `stringResolvedScripts`: the
    UTS #39 § 5.1.2 resolved-scripts intersection is empty
    whenever two codepoints' script-extension sets disagree
    (Latin ∩ Cyrillic = ∅), so it answers "could every codepoint
    share one script" rather than "how many scripts appear."
    For CrossScriptMix the union is the right primitive — we
    want to fire whenever the identifier mixes Latin with
    Cyrillic, Latin with Greek, etc., even when the
    intersection collapses to ∅. -/
def crossScriptCount (input : List Nat) : Nat :=
  let scripts := Unicode.Restriction.stringScriptUnion input
  scripts.length

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 Top-level detection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The HomoglyphConfusable detection function. -/
def detect (input : List Nat) : Verdict :=
  let skel := Unicode.Confusables.skeleton input
  let iSkel := Unicode.Confusables.iteratedSkeleton input
  let rl := Unicode.Restriction.restrictionLevel input
  let matched := findTargetMatch input iSkel
  let matchedNames : List String :=
    match matched with
    | some t => [t.name]
    | none   => []
  -- Priority order: targetMatch → mathAlpha → widthClass →
  -- decompositionSwap → crossScriptMix → restrictionLow → clear.
  let classification : Classification :=
    match matched with
    | some t => .hazard (.targetMatch t.name) [] []
    | none =>
      let mc := mathAlphaCount input
      if mc > 0 then
        match firstMathAlphaPos input with
        | some p =>
          .hazard (.mathAlpha (input.getD p 0) mc) [p] []
        | none   => .clear  -- unreachable when mc > 0
      else
        let fwc := fullwidthCount input
        if fwc > 0 then
          match firstFullwidthPos input with
          | some p =>
            .hazard (.widthClass (input.getD p 0) fwc) [p] []
          | none   => .clear
        else if hasDecompositionSwap input then
          let diffPos := (firstDecompositionDiffPos input).getD 0
          .hazard (.decompositionSwap diffPos) [diffPos] []
        else
          let sc := crossScriptCount input
          if sc ≥ 2 ∧ ¬ Unicode.Restriction.isHighlyRestrictive input then
            .hazard (.crossScriptMix sc) [] []
          else if rl = .MinimallyRestrictive ∨ rl = .Unrestricted then
            .hazard (.restrictionLow rl) [] []
          else
            .clear
  { input := input,
    classify := classification,
    skeleton := skel,
    iteratedSkeleton := iSkel,
    restrictionLevel := rl,
    matchedTargets := matchedNames }

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 Projection helpers (mirrors the covert-channel pattern)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Fixture-row tag string for each `SubThreat` constructor. -/
def SubThreat.tag : SubThreat → String
  | .targetMatch       target                =>
      Function.const String "TargetMatch" target
  | .mathAlpha         firstCp count         =>
      Function.const (Nat × Nat) "MathAlpha" (firstCp, count)
  | .widthClass        firstCp count         =>
      Function.const (Nat × Nat) "WidthClass" (firstCp, count)
  | .decompositionSwap firstDiffPos          =>
      Function.const Nat "DecompositionSwap" firstDiffPos
  | .crossScriptMix    scriptCount           =>
      Function.const Nat "CrossScriptMix" scriptCount
  | .restrictionLow    level                 =>
      Function.const RestrictionLevel "RestrictionLow" level

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

/-- Positions list of a classification. -/
def Classification.positions : Classification → List Nat
  | .clear                     => []
  | .hazard sub positions decoded =>
      Function.const (SubThreat × List UInt8) positions (sub, decoded)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §7 Spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Empty input is clear. -/
theorem detect_empty_clear : (detect []).classify.isClear = true := by
  decide +kernel

/-- NFC is the identity on the all-ASCII "Hello", so the decomposition-swap
    sub-check sees no divergence — established structurally, without reducing the
    composition table. -/
theorem hasDecompositionSwap_hello :
    hasDecompositionSwap [0x48, 0x65, 0x6C, 0x6C, 0x6F] = false := by
  unfold hasDecompositionSwap
  rw [Unicode.Normalization.LowCodepointNfc.toNFC_id_all_lt
        [0x48, 0x65, 0x6C, 0x6C, 0x6F] (by decide)]
  simp

/-- NFC is the identity on the all-ASCII "Nethereum". -/
theorem hasDecompositionSwap_nethereum :
    hasDecompositionSwap [0x4E, 0x65, 0x74, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6D] = false := by
  unfold hasDecompositionSwap
  rw [Unicode.Normalization.LowCodepointNfc.toNFC_id_all_lt
        [0x4E, 0x65, 0x74, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6D] (by decide)]
  simp

/-- Pure ASCII "Hello" is clear (no confusable structure). -/
theorem detect_ascii_clear :
    (detect [0x48, 0x65, 0x6C, 0x6C, 0x6F]).classify.isClear = true := by
  unfold detect
  rw [hasDecompositionSwap_hello]
  decide +kernel

/-- The legitimate "Nethereum" (pure Latin) is clear. -/
theorem detect_nethereum_legit_clear :
    (detect [0x4E, 0x65, 0x74, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6D]).classify.isClear = true := by
  unfold detect
  rw [hasDecompositionSwap_nethereum]
  decide +kernel

/-- The Nethereum Oct-2025 typosquat — final `е` (Cyrillic
    U+0435) replacing `e` (Latin U+0065) at position 6.  Iterated
    skeleton must match the canonical "Nethereum" target. -/
theorem detect_nethereum_attack :
    let cps : List Nat :=
      [0x4E, 0x65, 0x74, 0x68, 0x65, 0x72, 0x0435, 0x75, 0x6D]
    (detect cps).classify.tag = some "TargetMatch" := by decide +kernel

/-- Lower-case variant of the Nethereum typosquat — `nethereum`
    with Cyrillic SMALL LETTER IE (U+0435) at position 6.  NuGet
    package IDs are case-insensitive, so this is the same
    threat-class as the title-case variant.  Under UTS #39 §5.4
    case folding (added to `Unicode.Confusables.skeleton`), the
    title-case target `Nethereum` and this lower-case attack both
    fold to lower-case `nethereum`, their skeletons agree, and
    `TargetMatch` fires with target attribution preserved. -/
theorem detect_nethereum_lowercase_attack :
    let cps : List Nat :=
      [0x6E, 0x65, 0x74, 0x68, 0x65, 0x72, 0x0435, 0x75, 0x6D]
    (detect cps).classify.tag = some "TargetMatch" := by decide +kernel

/-- ALL-CAPS variant of the Nethereum typosquat — `NETHEREUM`
    with Cyrillic CAPITAL LETTER IE (U+0415) at position 6.  Same
    case-insensitivity argument as `detect_nethereum_lowercase_attack`;
    under §5.4 case folding the all-caps attack also folds to
    lower-case `nethereum` and fires `TargetMatch`. -/
theorem detect_nethereum_uppercase_attack :
    let cps : List Nat :=
      [0x4E, 0x45, 0x54, 0x48, 0x45, 0x52, 0x0415, 0x55, 0x4D]
    (detect cps).classify.tag = some "TargetMatch" := by decide +kernel

/-- Base-letter + combining-mark confusable — `nɇthereum`, where the
    second letter is U+0247 LATIN SMALL LETTER E WITH STROKE whose
    UTS #39 confusable maps to the SEQUENCE `e + combining long
    solidus overlay`.  The §4+§5.4 skeleton (without combining-mark
    stripping) does NOT match the bare-letter `nethereum` target
    because of the inserted combining mark.  `letterSkeleton`
    (which strips combining marks from the skeleton output) catches
    it.  Mutation testing surfaced this class — 21% of single-
    codepoint mutations across the curated target set bypassed
    `iteratedSkeleton` via similar "letter + accent" entries. -/
theorem detect_nethereum_stroked_e_attack :
    let cps : List Nat :=
      [0x6E, 0x0247, 0x74, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6D]
    (detect cps).classify.tag = some "TargetMatch" := by decide +kernel

/-- Base-letter + combining-mark confusable — `nehterħeum`, U+0127
    LATIN SMALL LETTER H WITH STROKE whose confusable maps to
    `h + combining short stroke overlay`.  Confirms `letterSkeleton`
    catches the H-variant of the same class. -/
theorem detect_nethereum_stroked_h_attack :
    let cps : List Nat :=
      [0x6E, 0x65, 0x74, 0x0127, 0x65, 0x72, 0x65, 0x75, 0x6D]
    (detect cps).classify.tag = some "TargetMatch" := by decide +kernel

/-- Zero-width insertion bypass — `net` + ZWSP (U+200B) + `hereum`.
    Without the `Default_Ignorable_Code_Point` filter in
    `letterSkeleton`, the inserted ZWSP survives into the
    comparison and breaks strict-equality match with the
    `nethereum` target.  Rust-port red-team confirmed: all six of
    {ZWSP, ZWNJ, ZWJ, WJ, BOM, NNBSP} inserted bypassed the prior
    detector (`Clear` verdict).  The default-ignorable filter
    closes the class. -/
theorem detect_nethereum_zwsp_insertion_attack :
    let cps : List Nat :=
      [0x6E, 0x65, 0x74, 0x200B, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6D]
    (detect cps).classify.tag = some "TargetMatch" := by decide +kernel

/-- Zero-width-joiner insertion variant — same class as
    `detect_nethereum_zwsp_insertion_attack` but with U+200D
    (ZWJ) which has CCC = 0 and is `Default_Ignorable`. -/
theorem detect_nethereum_zwj_insertion_attack :
    let cps : List Nat :=
      [0x6E, 0x65, 0x74, 0x200D, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6D]
    (detect cps).classify.tag = some "TargetMatch" := by decide +kernel

/-- Math-Alpha posing — `𝐀` (Mathematical Bold Capital A,
    U+1D400) by itself is flagged. -/
theorem detect_math_alpha :
    (detect [0x1D400]).classify.tag = some "MathAlpha" := by
  decide +kernel

/-- Fullwidth disguise — `Ｐａｙｐａｌ` (FF30 FF41 FF59 FF50 FF41 FF4C).
    With UTS #39 §5.4 case-folded skeleton the input case-folds and
    confusable-substitutes to lowercase ASCII `paypal`, which matches
    the curated `paypal` attack target; the higher-priority
    `TargetMatch` sub-threat fires before `WidthClass`, producing
    the strictly more informative classification (attacker is
    impersonating PayPal, not merely "input has fullwidth chars"). -/
theorem detect_fullwidth_paypal :
    let cps : List Nat :=
      [0xFF30, 0xFF41, 0xFF59, 0xFF50, 0xFF41, 0xFF4C]
    (detect cps).classify.tag = some "TargetMatch" := by decide +kernel

-- ═══════════════════════════════════════════════════════════════════════════════
-- §8 Predicate sanity checks
-- ═══════════════════════════════════════════════════════════════════════════════

theorem is_math_alpha_bold_A : isMathAlphanumeric 0x1D400 = true := by
  decide

theorem is_math_alpha_last : isMathAlphanumeric 0x1D7FF = true := by
  decide

theorem is_math_alpha_below : isMathAlphanumeric 0x1D3FF = false := by
  decide

theorem is_math_alpha_above : isMathAlphanumeric 0x1D800 = false := by
  decide

theorem is_fullwidth_A : isFullwidthHalfwidth 0xFF21 = true := by
  decide

theorem is_fullwidth_above : isFullwidthHalfwidth 0xFFF0 = false := by
  decide

theorem is_fullwidth_below : isFullwidthHalfwidth 0xFF00 = false := by
  decide

end Unicode.Security.Identity.HomoglyphConfusable
