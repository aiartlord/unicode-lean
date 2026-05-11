/-
  Unicode.Security.Identity.HomoglyphConfusable

  I1 — Detection of homoglyph / confusable identifier substitution
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

  v1 scope.

    * 8 sub-threats per L2-identity-spoofing.md §I1.1.
    * Canonical-target list seeded with ~30 commonly-targeted
      brand and crypto-package names.  Expansion to the
      ~1,000-entry top-N list is a v2 readiness item per
      `docs/specs/security/Phase0-readiness.md` §5.3.
-/

import Unicode.Security.Calculus
import Unicode.Confusables
import Unicode.ResolvedScripts
import Unicode.Restriction
import Unicode.Normalization.NFC

namespace Unicode.Security.Identity.HomoglyphConfusable

open Unicode.Security.Calculus
open Unicode.Restriction (RestrictionLevel)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Types
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Sub-threat enumeration for I1.

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
inductive I1SubThreat where
  | targetMatch        (target : String)
  | mathAlpha          (firstCp : Nat) (count : Nat)
  | widthClass         (firstCp : Nat) (count : Nat)
  | decompositionSwap  (firstDiffPos : Nat)
  | crossScriptMix     (scriptCount : Nat)
  | restrictionLow     (level : RestrictionLevel)
  deriving DecidableEq, Repr, Inhabited

/-- Top-level classification for I1. -/
inductive I1Classification where
  | clear
  | hazard (sub : I1SubThreat) (positions : Array Nat) (decoded : ByteArray)
  deriving Inhabited

/-- I1 verdict — the structured output of `detect`. -/
structure I1Verdict where
  input              : Array Nat
  classify           : I1Classification
  skeleton           : Array Nat
  iteratedSkeleton   : Array Nat
  restrictionLevel   : RestrictionLevel
  matchedTargets     : Array String
  deriving Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Canonical attack-target dictionary
-- ═══════════════════════════════════════════════════════════════════════════════

/-- A canonical attack target — the legitimate name (e.g.
    "Nethereum") plus its byte-for-byte codepoint sequence as
    typed by a developer.  v1 list seeded from the Oct 2025
    NuGet / npm / PyPI typosquatting reports plus the UTS #39
    confusable-detection illustrative example set. -/
structure CanonicalTarget where
  name : String
  cps  : Array Nat
  deriving Repr, Inhabited

/-- Construct a target from a literal ASCII string. -/
private def mkAscii (s : String) : CanonicalTarget :=
  { name := s, cps := (s.toList.map Char.toNat).toArray }

/-- v1 canonical-target dictionary. -/
def canonicalTargets : Array CanonicalTarget := #[
  -- Crypto / Web3 (Oct 2025 NuGet typosquat campaign + adjacent).
  mkAscii "Nethereum",
  mkAscii "ethereum",
  mkAscii "ethers",
  mkAscii "web3",
  mkAscii "bitcoin",
  mkAscii "uniswap",
  mkAscii "metamask",
  mkAscii "binance",
  mkAscii "coinbase",
  mkAscii "solana",
  -- Major package ecosystems / repos.
  mkAscii "react",
  mkAscii "express",
  mkAscii "lodash",
  mkAscii "django",
  mkAscii "flask",
  mkAscii "numpy",
  mkAscii "pandas",
  mkAscii "pytorch",
  mkAscii "tensorflow",
  -- IDN-targeted brand names (Secuarden KB Issue 10 plus general).
  mkAscii "apple",
  mkAscii "google",
  mkAscii "amazon",
  mkAscii "microsoft",
  mkAscii "github",
  mkAscii "paypal",
  mkAscii "stripe",
  mkAscii "openai",
  mkAscii "anthropic",
  mkAscii "claude",
  mkAscii "chatgpt",
  mkAscii "tesla",
  -- Social.
  mkAscii "twitter",
  mkAscii "facebook",
  mkAscii "instagram",
  mkAscii "tiktok",
  mkAscii "telegram",
  mkAscii "discord"
]

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

/-- Find the first canonical target whose iterated skeleton matches
    the input's iterated skeleton, modulo the input being literally
    that target (no self-match). -/
def findTargetMatch
    (input : Array Nat) (iSkel : Array Nat) : Option CanonicalTarget :=
  canonicalTargets.find? (fun t =>
    decide (t.cps ≠ input) ∧
    decide (Unicode.Confusables.iteratedSkeleton t.cps = iSkel))

/-- Position of the first math-alphanumeric codepoint in `input`. -/
def firstMathAlphaPos (input : Array Nat) : Option Nat :=
  (Array.range input.size).find? (fun i =>
    if h : i < input.size then isMathAlphanumeric input[i] else false)

/-- Count of math-alphanumeric codepoints in `input`. -/
def mathAlphaCount (input : Array Nat) : Nat :=
  input.foldl (fun n cp => if isMathAlphanumeric cp then n + 1 else n) 0

/-- Position of the first fullwidth/halfwidth codepoint in `input`. -/
def firstFullwidthPos (input : Array Nat) : Option Nat :=
  (Array.range input.size).find? (fun i =>
    if h : i < input.size then isFullwidthHalfwidth input[i] else false)

/-- Count of fullwidth/halfwidth codepoints in `input`. -/
def fullwidthCount (input : Array Nat) : Nat :=
  input.foldl (fun n cp => if isFullwidthHalfwidth cp then n + 1 else n) 0

/-- True iff the input is not in NFC — i.e. `NFC(input) ≠ input`. -/
def hasDecompositionSwap (input : Array Nat) : Bool :=
  decide (Unicode.Normalization.NFC.toNFC input ≠ input)

/-- First position at which `input` and its NFC form differ.
    Returns `none` if they match. -/
def firstDecompositionDiffPos (input : Array Nat) : Option Nat :=
  let nfc := Unicode.Normalization.NFC.toNFC input
  (Array.range (Nat.min input.size nfc.size)).find? (fun i =>
    if h : i < input.size ∧ i < nfc.size then
      decide (input[i]'h.1 ≠ nfc[i]'h.2)
    else
      false)

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
def crossScriptCount (input : Array Nat) : Nat :=
  let scripts := Unicode.Restriction.stringScriptUnion input
  scripts.size

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 Top-level detection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The I1 detection function. -/
def detect (input : Array Nat) : I1Verdict :=
  let skel := Unicode.Confusables.skeleton input
  let iSkel := Unicode.Confusables.iteratedSkeleton input
  let rl := Unicode.Restriction.restrictionLevel input
  let matched := findTargetMatch input iSkel
  let matchedNames : Array String :=
    match matched with
    | some t => #[t.name]
    | none   => #[]
  -- Priority order: targetMatch → mathAlpha → widthClass →
  -- decompositionSwap → crossScriptMix → restrictionLow → clear.
  let classification : I1Classification :=
    match matched with
    | some t => .hazard (.targetMatch t.name) #[] ByteArray.empty
    | none =>
      let mc := mathAlphaCount input
      if mc > 0 then
        match firstMathAlphaPos input with
        | some p =>
          .hazard (.mathAlpha (input[p]!) mc) #[p] ByteArray.empty
        | none   => .clear  -- unreachable when mc > 0
      else
        let fwc := fullwidthCount input
        if fwc > 0 then
          match firstFullwidthPos input with
          | some p =>
            .hazard (.widthClass (input[p]!) fwc) #[p] ByteArray.empty
          | none   => .clear
        else if hasDecompositionSwap input then
          let diffPos := (firstDecompositionDiffPos input).getD 0
          .hazard (.decompositionSwap diffPos) #[diffPos] ByteArray.empty
        else
          let sc := crossScriptCount input
          if sc ≥ 2 ∧ ¬ Unicode.Restriction.isHighlyRestrictive input then
            .hazard (.crossScriptMix sc) #[] ByteArray.empty
          else if rl = .MinimallyRestrictive ∨ rl = .Unrestricted then
            .hazard (.restrictionLow rl) #[] ByteArray.empty
          else
            .clear
  { input := input,
    classify := classification,
    skeleton := skel,
    iteratedSkeleton := iSkel,
    restrictionLevel := rl,
    matchedTargets := matchedNames }

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 Projection helpers (mirrors L1 pattern)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Fixture-row tag string for each `I1SubThreat` constructor. -/
def I1SubThreat.tag : I1SubThreat → String
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
def I1Classification.isClear : I1Classification → Bool
  | .clear                     => true
  | .hazard sub positions decoded =>
      Function.const (I1SubThreat × Array Nat × ByteArray) false
        (sub, positions, decoded)

/-- Tag string of a classification. -/
def I1Classification.tag : I1Classification → Option String
  | .clear                     => none
  | .hazard sub positions decoded =>
      Function.const (Array Nat × ByteArray) (some sub.tag) (positions, decoded)

/-- Positions array of a classification. -/
def I1Classification.positions : I1Classification → Array Nat
  | .clear                     => #[]
  | .hazard sub positions decoded =>
      Function.const (I1SubThreat × ByteArray) positions (sub, decoded)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §7 Spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Empty input is clear. -/
theorem detect_empty_clear : (detect #[]).classify.isClear = true := by
  native_decide

/-- Pure ASCII "Hello" is clear (no confusable structure). -/
theorem detect_ascii_clear :
    (detect #[0x48, 0x65, 0x6C, 0x6C, 0x6F]).classify.isClear = true := by
  native_decide

/-- The legitimate "Nethereum" (pure Latin) is clear. -/
theorem detect_nethereum_legit_clear :
    let cps : Array Nat :=
      #[0x4E, 0x65, 0x74, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6D]
    (detect cps).classify.isClear = true := by native_decide

/-- The Nethereum Oct-2025 typosquat — final `е` (Cyrillic
    U+0435) replacing `e` (Latin U+0065) at position 6.  Iterated
    skeleton must match the canonical "Nethereum" target. -/
theorem detect_nethereum_attack :
    let cps : Array Nat :=
      #[0x4E, 0x65, 0x74, 0x68, 0x65, 0x72, 0x0435, 0x75, 0x6D]
    (detect cps).classify.tag = some "TargetMatch" := by native_decide

/-- Math-Alpha posing — `𝐀` (Mathematical Bold Capital A,
    U+1D400) by itself is flagged. -/
theorem detect_math_alpha :
    (detect #[0x1D400]).classify.tag = some "MathAlpha" := by
  native_decide

/-- Fullwidth disguise — `Ｐａｙｐａｌ` (FF30 FF41 FF59 FF50 FF41 FF4C). -/
theorem detect_fullwidth_paypal :
    let cps : Array Nat :=
      #[0xFF30, 0xFF41, 0xFF59, 0xFF50, 0xFF41, 0xFF4C]
    (detect cps).classify.tag = some "WidthClass" := by native_decide

-- ═══════════════════════════════════════════════════════════════════════════════
-- §8 Predicate sanity checks
-- ═══════════════════════════════════════════════════════════════════════════════

theorem is_math_alpha_bold_A : isMathAlphanumeric 0x1D400 = true := by
  native_decide

theorem is_math_alpha_last : isMathAlphanumeric 0x1D7FF = true := by
  native_decide

theorem is_math_alpha_below : isMathAlphanumeric 0x1D3FF = false := by
  native_decide

theorem is_math_alpha_above : isMathAlphanumeric 0x1D800 = false := by
  native_decide

theorem is_fullwidth_A : isFullwidthHalfwidth 0xFF21 = true := by
  native_decide

theorem is_fullwidth_above : isFullwidthHalfwidth 0xFFF0 = false := by
  native_decide

theorem is_fullwidth_below : isFullwidthHalfwidth 0xFF00 = false := by
  native_decide

end Unicode.Security.Identity.HomoglyphConfusable
