/-
  Unicode.Security.Display.FilenameDisguise

  D2 — Detection of filename / extension disguise attacks where
  the visible extension differs from the byte extension.

  Threat model.  Tier A₁..A₂.  Adversary delivers a file whose
  rendered name looks like a benign type (`document.txt`,
  `photo.png`) but whose actual byte extension is executable or
  otherwise dangerous.  The canonical attack uses `U+202E`
  RIGHT-TO-LEFT OVERRIDE to flip the displayed glyph stream:

      document<RLO>txt.exe   bytes
      document   exe.txt     rendered

  Detection strategy.  v1 is presentation-agnostic and
  language-agnostic — it surfaces every codepoint that could
  cause display-vs-byte divergence in the filename context:

    1. Any bidi format-control codepoint
       (LRE/RLE/LRO/RLO/PDF/LRI/RLI/FSI/PDI).
    2. Any Halfwidth/Fullwidth Forms codepoint in the extension
       region (chars after the last `U+002E .`).
    3. Any Grapheme_Cluster_Break = Extend codepoint
       (combining marks etc.) in the extension region.

  Out of v1 scope: a full bidi-resolution → display-order
  extraction pass would pin "displayed extension ≠ byte
  extension" directly.  For v1 the structural detection above
  catches variants D2.a–D2.g except the native-RTL legitimate-
  use case (D2.e).  Native-RTL inputs that contain no bidi
  format-control codepoints clear.
-/

import Unicode.Security.Calculus
import Unicode.TrojanSource
import Unicode.Generated.GraphemeBreakProperty

namespace Unicode.Security.Display.FilenameDisguise

open Unicode.Security.Calculus

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Types
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Sub-threat enumeration for D2.

    Priority order (highest first):
      1. `rloFlip`              any bidi format-control in input
      2. `widthClassExt`        fullwidth/halfwidth codepoint
                                in the extension
      3. `combiningInExt`       combining mark in the extension
      4. `multipleExtensions`   ≥ 3 dots (advisory; could be
                                legitimate `.tar.gz.sig`)
-/
inductive D2SubThreat where
  | rloFlip            (position : Nat) (controlCp : Nat)
  | widthClassExt      (position : Nat) (cp : Nat)
  | combiningInExt     (position : Nat) (cp : Nat)
  | multipleExtensions (dotCount : Nat)
  deriving DecidableEq, Repr, Inhabited

/-- Top-level classification for D2. -/
inductive D2Classification where
  | clear
  | hazard (sub : D2SubThreat) (positions : Array Nat) (decoded : ByteArray)
  deriving Inhabited

/-- D2 verdict — the structured output of `detect`. -/
structure D2Verdict where
  input              : Array Nat
  classify           : D2Classification
  dotPositions       : Array Nat
  lastDotPos         : Option Nat
  bidiControlCount   : Nat
  fullwidthInExt     : Nat
  combiningInExt     : Nat
  deriving Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Core predicates
-- ═══════════════════════════════════════════════════════════════════════════════

/-- True iff `cp` is `U+002E FULL STOP` (the extension separator). -/
@[inline]
def isAsciiDot (cp : Nat) : Bool := cp = 0x002E

/-- True iff `cp` is in the Halfwidth and Fullwidth Forms block. -/
@[inline]
def isFullwidthHalfwidth (cp : Nat) : Bool :=
  0xFF01 ≤ cp ∧ cp ≤ 0xFFEF

/-- True iff `cp` has `Grapheme_Cluster_Break = Extend` — the
    Unicode-defined predicate for codepoints that combine with
    the preceding base.  Combining marks fall here. -/
def isGraphemeExtend (cp : Nat) : Bool :=
  match Unicode.Generated.GraphemeBreakProperty.lookupGCB cp with
  | .Extend => true
  | _other  => Function.const _ false _other

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Sub-detectors
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Positions of every `.` in `input`. -/
def dotPositions (input : Array Nat) : Array Nat :=
  (Array.range input.size).filterMap (fun i =>
    if h : i < input.size then
      if isAsciiDot input[i] then some i else none
    else none)

/-- Position and codepoint of the first bidi format-control in
    `input`. -/
def firstBidiControl (input : Array Nat) : Option (Nat × Nat) :=
  (Array.range input.size).findSome? (fun i =>
    if h : i < input.size then
      if Unicode.TrojanSource.isBidiFormatControl input[i] then
        some (i, input[i])
      else none
    else none)

/-- Position and codepoint of the first fullwidth/halfwidth char
    occurring at or after `start`. -/
def firstFullwidthFrom
    (input : Array Nat) (start : Nat) : Option (Nat × Nat) :=
  (Array.range input.size).findSome? (fun i =>
    if h : i < input.size ∧ i ≥ start then
      if isFullwidthHalfwidth input[i] then some (i, input[i])
      else none
    else none)

/-- Position and codepoint of the first Extend codepoint
    occurring at or after `start`. -/
def firstExtendFrom
    (input : Array Nat) (start : Nat) : Option (Nat × Nat) :=
  (Array.range input.size).findSome? (fun i =>
    if h : i < input.size ∧ i ≥ start then
      if isGraphemeExtend input[i] then some (i, input[i])
      else none
    else none)

/-- Count of fullwidth/halfwidth codepoints at or after `start`. -/
def countFullwidthFrom (input : Array Nat) (start : Nat) : Nat :=
  (Array.range input.size).foldl (init := 0) (fun n i =>
    if h : i < input.size ∧ i ≥ start then
      if isFullwidthHalfwidth input[i] then n + 1 else n
    else n)

/-- Count of Extend codepoints at or after `start`. -/
def countExtendFrom (input : Array Nat) (start : Nat) : Nat :=
  (Array.range input.size).foldl (init := 0) (fun n i =>
    if h : i < input.size ∧ i ≥ start then
      if isGraphemeExtend input[i] then n + 1 else n
    else n)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Top-level detection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The D2 detection function. -/
def detect (input : Array Nat) : D2Verdict :=
  let dots := dotPositions input
  let lastDot := dots[dots.size - 1]?
  let extStart : Nat :=
    match lastDot with
    | some p => p + 1
    | none   => input.size  -- no extension; range is empty
  let bidiCount :=
    input.foldl (fun n cp =>
      if Unicode.TrojanSource.isBidiFormatControl cp then n + 1 else n) 0
  let fwInExt := countFullwidthFrom input extStart
  let extInExt := countExtendFrom input extStart
  -- Priority: bidi control → fullwidth-in-ext → combining-in-ext
  --           → multi-ext.
  let classification : D2Classification :=
    match firstBidiControl input with
    | some (pos, ctlCp) =>
      .hazard (.rloFlip pos ctlCp) #[pos] ByteArray.empty
    | none =>
      match firstFullwidthFrom input extStart with
      | some (pos, cp) =>
        .hazard (.widthClassExt pos cp) #[pos] ByteArray.empty
      | none =>
        match firstExtendFrom input extStart with
        | some (pos, cp) =>
          .hazard (.combiningInExt pos cp) #[pos] ByteArray.empty
        | none =>
          if dots.size ≥ 3 then
            .hazard (.multipleExtensions dots.size) dots ByteArray.empty
          else
            .clear
  { input := input,
    classify := classification,
    dotPositions := dots,
    lastDotPos := lastDot,
    bidiControlCount := bidiCount,
    fullwidthInExt := fwInExt,
    combiningInExt := extInExt }

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 Projection helpers
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Fixture-row tag string for each `D2SubThreat` constructor. -/
def D2SubThreat.tag : D2SubThreat → String
  | .rloFlip            position controlCp =>
      Function.const (Nat × Nat) "RloFlip" (position, controlCp)
  | .widthClassExt      position cp        =>
      Function.const (Nat × Nat) "WidthClassExt" (position, cp)
  | .combiningInExt     position cp        =>
      Function.const (Nat × Nat) "CombiningInExt" (position, cp)
  | .multipleExtensions dotCount           =>
      Function.const Nat "MultipleExtensions" dotCount

/-- True iff the classification is `.clear`. -/
def D2Classification.isClear : D2Classification → Bool
  | .clear                     => true
  | .hazard sub positions decoded =>
      Function.const (D2SubThreat × Array Nat × ByteArray) false
        (sub, positions, decoded)

/-- Tag string of a classification. -/
def D2Classification.tag : D2Classification → Option String
  | .clear                     => none
  | .hazard sub positions decoded =>
      Function.const (Array Nat × ByteArray) (some sub.tag) (positions, decoded)

/-- Positions array of a classification. -/
def D2Classification.positions : D2Classification → Array Nat
  | .clear                     => #[]
  | .hazard sub positions decoded =>
      Function.const (D2SubThreat × ByteArray) positions (sub, decoded)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 Spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Empty filename is clear. -/
theorem detect_empty_clear : (detect #[]).classify.isClear = true := by
  native_decide

/-- Plain ASCII filename `document.txt` is clear. -/
theorem detect_plain_txt_clear :
    let cps := #[0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74,
                 0x2E, 0x74, 0x78, 0x74]  -- "document.txt"
    (detect cps).classify.isClear = true := by native_decide

/-- ASCII filename with no extension is clear. -/
theorem detect_no_extension_clear :
    (detect #[0x66, 0x6F, 0x6F]).classify.isClear = true := by native_decide

/-- Two-segment filename `archive.tar.gz` is clear. -/
theorem detect_tar_gz_clear :
    let cps := #[0x61, 0x72, 0x63, 0x68, 0x69, 0x76, 0x65,
                 0x2E, 0x74, 0x61, 0x72, 0x2E, 0x67, 0x7A]
    (detect cps).classify.isClear = true := by native_decide

/-- The classic Trojan filename `document<RLO>txt.exe` fires
    `.rloFlip` at the RLO position. -/
theorem detect_rlo_flip :
    let cps := #[0x64, 0x6F, 0x63, 0x75, 0x6D, 0x65, 0x6E, 0x74,
                 0x202E, 0x74, 0x78, 0x74, 0x2E, 0x65, 0x78, 0x65]
    (detect cps).classify.tag = some "RloFlip" := by native_decide

/-- Fullwidth `.ＥＸＥ` extension fires `.widthClassExt`. -/
theorem detect_fullwidth_exe :
    let cps := #[0x66, 0x69, 0x6C, 0x65,
                 0x2E, 0xFF25, 0xFF38, 0xFF25]  -- "file.ＥＸＥ"
    (detect cps).classify.tag = some "WidthClassExt" := by native_decide

/-- A combining mark in the extension fires `.combiningInExt`.
    `.e<combining acute>xe` — the combining acute (U+0301) is
    `Grapheme_Cluster_Break = Extend`. -/
theorem detect_combining_in_ext :
    let cps := #[0x66, 0x69, 0x6C, 0x65,
                 0x2E, 0x65, 0x0301, 0x78, 0x65]  -- "file.éxe"
    (detect cps).classify.tag = some "CombiningInExt" := by native_decide

/-- Triple-extension `setup.tar.gz.sig` fires `.multipleExtensions`
    (advisory).  Could be a legitimate detached-signature file. -/
theorem detect_triple_extension :
    let cps := #[0x73, 0x65, 0x74, 0x75, 0x70,
                 0x2E, 0x74, 0x61, 0x72,
                 0x2E, 0x67, 0x7A,
                 0x2E, 0x73, 0x69, 0x67]
    (detect cps).classify.tag = some "MultipleExtensions" := by native_decide

/-- Native Hebrew filename (no bidi controls) is clear — the
    D2.e legitimate-RTL-language case. -/
theorem detect_hebrew_clear :
    let cps := #[0x05D0, 0x05D1, 0x05D2, 0x2E, 0x74, 0x78, 0x74]
                -- אבג.txt
    (detect cps).classify.isClear = true := by native_decide

/-- RLI/PDI isolate variant of the flip — also `.rloFlip`
    (any bidi control triggers it). -/
theorem detect_isolate_flip :
    let cps := #[0x64, 0x6F, 0x63, 0x2067,  -- doc + RLI
                 0x74, 0x78, 0x74, 0x2E, 0x65, 0x78, 0x65, 0x2069]
    (detect cps).classify.tag = some "RloFlip" := by native_decide

end Unicode.Security.Display.FilenameDisguise
