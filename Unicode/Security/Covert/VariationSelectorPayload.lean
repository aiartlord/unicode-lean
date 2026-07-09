/-
  Unicode.Security.Covert.VariationSelectorPayload

  Detection of GlassWorm-class invisible payloads encoded in
  Unicode variation selectors.

  Threat model.  Tier A₁ (local injector).  Adversary crafts an input
  consisting of one visible base codepoint followed by a sequence of
  variation-selector codepoints (`U+FE00..U+FE0F` ∪ `U+E0100..U+E01EF`)
  that the receiving renderer treats as a no-op glyph variant but
  that a downstream string-processing layer (e.g. an LLM tokenizer
  or a clipboard pipeline) preserves byte-for-byte.  Decoding pairs
  of VS codepoints back into bytes recovers an arbitrary payload.

  Sanctioning model.  Three classes of variation sequence are
  sanctioned by the Standard:

    1. Standardized (`StandardizedVariants.txt`, UCD 17.0.0) —
       math symbols, Mongolian, Egyptian hieroglyphs, CJK Compat.
    2. Emoji presentation — `Basic_Emoji` codepoint + `U+FE0F`
       (registered in `emoji-sequences.txt`).
    3. Emoji text presentation — Emoji-property codepoint + `U+FE0E`
       (forces text rather than emoji rendering).

  Any VS occurrence not matching one of the three classes is, by
  definition, not sanctioned — and is treated as `.suspicious`.

  Algorithm shape (one pass over `input`):

    Phase 1 — per-position classification into
              `.nonVS`, `.registeredStandardized`,
              `.registeredEmojiPresentation`, or `.suspicious`.
    Phase 2 — partition into `registered` / `suspicious` index lists.
    Phase 3 — short-circuit clear verdict if `suspicious.isEmpty`.
    Phase 4 — decode the suspicious-VS run to a byte stream
              (two nibbles per byte).
    Phase 5 — classify the sub-threat by priority order.
-/

import Unicode.Security.Calculus
import Unicode.Emoji
import Unicode.Generated.StandardizedVariants
import Unicode.Generated.EmojiData

namespace Unicode.Security.Covert.VariationSelectorPayload

set_option maxRecDepth 1000000

open Unicode.Security.Calculus

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 Types
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The use-class of a single position in `input`. -/
inductive VSUseClass where
  | nonVS                          -- not a variation selector
  | registeredStandardized         -- in StandardizedVariants.txt
  | registeredEmojiPresentation    -- VS16 after an emoji-presentation base
  | registeredTextPresentation     -- VS15 after an emoji codepoint
  | suspicious                     -- VS use not matching any registered class
  deriving DecidableEq, Repr, Inhabited

/-- Coarse classifier for the recovered byte stream.  Used to drive
    the `DirectPayload` sub-threat verdict; deliberately
    conservative (prefix-only), with no recursive base64/hex
    re-decoding. -/
inductive ExecutableHint where
  | empty                          -- no recovered payload
  | ascii                          -- entirely printable ASCII, no exec marker
  | javascript                     -- starts with `eval(`, `Function(`, etc.
  | shell                          -- starts with shell-spawn primitive
  | binary                         -- contains non-printable bytes
  deriving DecidableEq, Repr, Inhabited

/-- Sub-threat enumeration for VariationSelectorPayload.  Each
    variant carries the attribution payload needed to populate
    the fixture-row `attribution` column. -/
inductive SubThreat where
  /-- A pair-aligned VS run on a single base whose decoded bytes
      look like an actual payload (typical GlassWorm shape). -/
  | directPayload      (decoded : String) (hint : ExecutableHint)
  /-- A single suspicious VS attached to a base that has no
      registered variation sequence at all (e.g. VS16 on Latin A). -/
  | illegalTarget      (targetCp : Nat) (vsCp : Nat)
  /-- A suspicious VS run that follows a registered VS sequence on
      the same base — payload hiding behind a legit glyph variant. -/
  | embeddedAfterReg   (registeredEndPos : Nat) (payloadStartPos : Nat)
  /-- A long suspicious VS run with only one distinct VS value —
      structurally anomalous rather than payload-shaped. -/
  | repeatedBase       (baseCp : Nat) (vsCount : Nat) (uniqueVS : Nat)
  deriving DecidableEq, Repr, Inhabited

/-- Top-level classification for VariationSelectorPayload.

    The `decoded` field carries the recovered byte stream when the
    classifier fired; for the clear case it is implicitly empty. -/
inductive Classification where
  | clear
  | hazard (sub : SubThreat) (positions : Array Nat) (decoded : ByteArray)
  deriving Inhabited

/-- Verdict — the structured output of `detect`. -/
structure Verdict where
  input                  : Array Nat
  classify               : Classification
  registeredPositions    : Array Nat               -- indices of registered VS
  suspiciousPositions    : Array Nat               -- indices of suspicious VS
  perPositionClass       : Array VSUseClass        -- one entry per input position
  recoveredPayloadBytes  : ByteArray
  deriving Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 Core primitives
-- ═══════════════════════════════════════════════════════════════════════════════

/-- True iff `cp` is a variation selector.

    Two contiguous ranges are sanctioned by the Standard:
      * `U+FE00..U+FE0F`     — the original 16 VS (VS1..VS16)
      * `U+E0100..U+E01EF`   — the supplementary VS (VS17..VS256)
      * `U+180B..U+180D`     — the Mongolian Free Variation Selectors

    All three count for the purpose of payload detection. -/
@[inline]
def isVariationSelector (cp : Nat) : Bool :=
  (0xFE00 ≤ cp ∧ cp ≤ 0xFE0F) ∨
  (0xE0100 ≤ cp ∧ cp ≤ 0xE01EF) ∨
  (0x180B ≤ cp ∧ cp ≤ 0x180D)

/-- Decode a single VS codepoint to its nibble value in [0, 255].

    Uses GlassWorm's bit layout: VS1..VS16 = nibbles 0..15, VS17..VS256
    = nibbles 16..255.  Mongolian FVS codepoints (180B..180D) are not
    part of the GlassWorm-style payload alphabet and decode to `none`
    so they do not contribute bytes to the recovered payload. -/
@[inline]
def vsToNibble (cp : Nat) : Option Nat :=
  if 0xFE00 ≤ cp ∧ cp ≤ 0xFE0F then some (cp - 0xFE00)
  else if 0xE0100 ≤ cp ∧ cp ≤ 0xE01EF then some (cp - 0xE0100 + 16)
  else none

/-- Decode a sequence of VS codepoints to the recovered byte stream.
    Two nibbles → one byte (high nibble first).  An odd trailing
    nibble is discarded. -/
def decodeVSRun (vs : Array Nat) : ByteArray := Id.run do
  let mut bytes : ByteArray := ByteArray.empty
  let mut highNibble : Option Nat := none
  for cp in vs do
    match vsToNibble cp with
    | none => pure ()
    | some n =>
      match highNibble with
      | none   => highNibble := some n
      | some h =>
        bytes := bytes.push (UInt8.ofNat ((h <<< 4) ||| n))
        highNibble := none
  pure bytes

/-- True iff the byte represents a printable ASCII character (0x20..0x7E)
    or an ASCII whitespace (tab / newline / carriage return). -/
@[inline]
def isPrintableAsciiByte (b : UInt8) : Bool :=
  let n := b.toNat
  (n ≥ 0x20 ∧ n ≤ 0x7E) ∨ n = 0x09 ∨ n = 0x0A ∨ n = 0x0D

/-- True iff every byte in `bytes` is printable ASCII. -/
def allPrintableAscii (bytes : ByteArray) : Bool := Id.run do
  let mut ok := true
  for b in bytes do
    if ¬ isPrintableAsciiByte b then ok := false
  pure ok

/-- Lossy ASCII-only decode of a byte stream.  Non-ASCII bytes are
    replaced with `?`.  Used as the `decoded` field of `directPayload`. -/
def decodeAsciiLossy (bytes : ByteArray) : String := Id.run do
  let mut s : String := ""
  for b in bytes do
    if isPrintableAsciiByte b then
      s := s.push (Char.ofNat b.toNat)
    else
      s := s.push '?'
  pure s

/-- True iff the decoded string starts with one of the named JS-shaped
    payload prefixes seen in published GlassWorm samples. -/
def looksLikeJavaScript (s : String) : Bool :=
  s.startsWith "eval(" ∨
  s.startsWith "Function(" ∨
  s.startsWith "(function" ∨
  s.startsWith "javascript:" ∨
  s.startsWith "atob("

/-- True iff the decoded string starts with a shell-spawn primitive. -/
def looksLikeShell (s : String) : Bool :=
  s.startsWith "sh -c " ∨
  s.startsWith "bash -c " ∨
  s.startsWith "curl " ∨
  s.startsWith "wget " ∨
  s.startsWith "/bin/sh"

/-- Classify the recovered bytes by surface-level pattern.
    Matches a literal byte prefix (`bash `, `curl `, `wget `,
    `/bin/sh`) — recursive base64/hex re-decoding is a
    downstream sanitiser's responsibility, not this layer's. -/
def classifyExecutableHint (bytes : ByteArray) : ExecutableHint :=
  if bytes.size = 0 then .empty
  else if ¬ allPrintableAscii bytes then .binary
  else
    let s := decodeAsciiLossy bytes
    if looksLikeJavaScript s then .javascript
    else if looksLikeShell s then .shell
    else .ascii

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 Per-position classification
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Classify the use of the codepoint at position `p` in `input`.

    A VS is `.registeredStandardized` iff `StandardizedVariants.txt`
    sanctions the (base, VS) pair.  A VS16 (`FE0F`) is
    `.registeredEmojiPresentation` iff the base has the `Emoji`
    property — equivalently, iff base ∈ emoji-data.txt's
    Emoji-property set, which is the union of:

      * `Emoji_Presentation = Yes` codepoints (default-emoji,
        FE0F is a no-op flip), and
      * `emoji-variation-sequences.txt` member codepoints
        (default-text, FE0F flips to emoji style).

    A VS15 (`FE0E`) is `.registeredTextPresentation` under the
    symmetric condition.  Everything else that is a VS is
    `.suspicious`.

    `Unicode.Emoji.isEmoji` is the structural (file-derived)
    predicate for "this codepoint can legitimately carry a
    presentation VS", so it is the correct check here.  Detectors
    that need to distinguish "FE0F changes the rendering style"
    from "FE0F is a no-op" should consult
    `Unicode.Generated.EmojiVariationSequences.hasRegisteredEmojiPresentation`
    directly. -/
def classifyVSPosition (input : Array Nat) (p : Nat) : VSUseClass :=
  match input[p]? with
  | none      => .nonVS
  | some cp   =>
    if ¬ isVariationSelector cp then .nonVS
    else if p = 0 then .suspicious  -- a VS with no preceding base
    else
      let baseCp := input[p - 1]!
      if Unicode.Generated.StandardizedVariants.isStandardizedVariation baseCp cp
        then .registeredStandardized
      else if cp = 0xFE0F ∧ Unicode.Emoji.isEmoji baseCp
        then .registeredEmojiPresentation
      else if cp = 0xFE0E ∧ Unicode.Emoji.isEmoji baseCp
        then .registeredTextPresentation
      else .suspicious

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 Sub-threat selection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Number of distinct VS codepoints occurring at the given positions. -/
private def countUniqueVS (input : Array Nat) (positions : Array Nat) : Nat :=
  let cps := positions.map (fun p => input[p]!)
  cps.foldl (init := (#[] : Array Nat)) (fun acc cp =>
    if acc.contains cp then acc else acc.push cp) |>.size

/-- True iff the input contains at least one registered VS position
    that precedes at least one suspicious VS position.  Returns the
    `(lastRegisteredPos, firstSuspiciousPos)` pair when fired.

    The check is "any registered VS comes before any suspicious VS",
    not "adjacent": the typical pattern is `EMOJI VS16 BASE SUS+`,
    where the registered VS at position 1 precedes the suspicious
    run that begins after an intervening base codepoint. -/
private def embeddedAfterRegistered
    (registered suspicious : Array Nat) : Option (Nat × Nat) :=
  match suspicious[0]? with
  | none => none
  | some firstSus =>
    -- Filter registered to those that come before firstSus.
    let priorReg := registered.filter (fun p => p < firstSus)
    match priorReg[priorReg.size - 1]? with
    | some lastReg => some (lastReg, firstSus)
    | none         => none

/-- True iff every codepoint at the given positions is the same VS. -/
private def allSameVS (input : Array Nat) (positions : Array Nat) : Bool :=
  match positions[0]? with
  | none => true
  | some p0 =>
    let cp0 := input[p0]!
    positions.all (fun p => input[p]! = cp0)

/-- Pick the sub-threat for a non-empty suspicious-VS run.

    Priority order (highest first):
      1. `embeddedAfterReg`  — input mixes registered + suspicious VS
                              (payload hiding behind a legit glyph)
      2. `repeatedBase`      — long run, single unique VS value
                              (structurally anomalous, not payload-shaped)
      3. `directPayload`     — pair-aligned run, decoded bytes recovered
      4. `illegalTarget`     — fallback, single suspicious VS on a
                              base that has no registered variation
-/
def pickSubThreat
    (input : Array Nat)
    (registered suspicious : Array Nat)
    (payload : ByteArray) : SubThreat :=
  -- Phase 1: embedded-after-registered takes priority.
  match embeddedAfterRegistered registered suspicious with
  | some (regEnd, payloadStart) =>
    .embeddedAfterReg regEnd payloadStart
  | none =>
    -- Phase 2: long single-VS run is more specific than directPayload.
    if suspicious.size ≥ 4 ∧ allSameVS input suspicious then
      let p0 := suspicious[0]!
      let baseCp := if p0 = 0 then 0 else input[p0 - 1]!
      .repeatedBase baseCp suspicious.size 1
    -- Phase 3: direct payload if we recovered at least one full byte.
    else if payload.size ≥ 1 then
      .directPayload (decodeAsciiLossy payload) (classifyExecutableHint payload)
    -- Phase 4: single suspicious VS on an unregistered base.
    else
      let p := suspicious[0]!
      let targetCp := if p = 0 then 0 else input[p - 1]!
      .illegalTarget targetCp input[p]!

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 Top-level detection
-- ═══════════════════════════════════════════════════════════════════════════════

/-- True iff the class denotes a registered (sanctioned) VS use. -/
@[inline]
def VSUseClass.isRegistered : VSUseClass → Bool
  | .registeredStandardized
  | .registeredEmojiPresentation
  | .registeredTextPresentation => true
  | .nonVS                       => false
  | .suspicious                  => false

/-- True iff the class denotes a suspicious VS use. -/
@[inline]
def VSUseClass.isSuspicious : VSUseClass → Bool
  | .suspicious                   => true
  | .nonVS                        => false
  | .registeredStandardized       => false
  | .registeredEmojiPresentation  => false
  | .registeredTextPresentation   => false

/-- The VariationSelectorPayload detection function.  Returns
    a structured verdict over the codepoint sequence `input`. -/
def detect (input : Array Nat) : Verdict :=
  -- Phase 1: per-position classification.
  let perPos : Array VSUseClass :=
    (Array.range input.size).map (classifyVSPosition input)
  -- Phase 2: partition VS positions into registered + suspicious.
  let regSet : Array Nat :=
    (Array.range input.size).filterMap (fun i =>
      if h : i < perPos.size then
        if perPos[i].isRegistered then some i else none
      else none)
  let susSet : Array Nat :=
    (Array.range input.size).filterMap (fun i =>
      if h : i < perPos.size then
        if perPos[i].isSuspicious then some i else none
      else none)
  -- Phase 3: short-circuit clear verdict.
  if susSet.isEmpty then
    { input := input,
      classify := .clear,
      registeredPositions := regSet,
      suspiciousPositions := #[],
      perPositionClass := perPos,
      recoveredPayloadBytes := ByteArray.empty }
  else
    -- Phase 4: decode payload bytes from the suspicious-VS run.
    let payload : ByteArray := decodeVSRun (susSet.map (fun p => input[p]!))
    -- Phase 5: pick sub-threat.
    let sub : SubThreat := pickSubThreat input regSet susSet payload
    { input := input,
      classify := .hazard sub susSet payload,
      registeredPositions := regSet,
      suspiciousPositions := susSet,
      perPositionClass := perPos,
      recoveredPayloadBytes := payload }

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 Projection helpers — used by both spot-check theorems and the
-- per-family conformance harness.  Every constructor binder is absorbed
-- via `Function.const` so the totals are checkable without anonymous
-- wildcards or leading-underscore "hint" names.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Fixture-row tag string for each `SubThreat` constructor.
    Matches the `Hazard:<Tag>` atom used in column 2 of
    `VariationSelectorPayloadTest.txt`. -/
def SubThreat.tag : SubThreat → String
  | .directPayload    decodedStr   hint              =>
      Function.const (String × ExecutableHint) "DirectPayload"
        (decodedStr, hint)
  | .illegalTarget    targetCp     vsCp              =>
      Function.const (Nat × Nat) "IllegalTarget"
        (targetCp, vsCp)
  | .embeddedAfterReg regEnd       payloadStart      =>
      Function.const (Nat × Nat) "EmbeddedAfterRegistered"
        (regEnd, payloadStart)
  | .repeatedBase     baseCp       vsCount   uniqueVS =>
      Function.const (Nat × Nat × Nat) "RepeatedBase"
        (baseCp, vsCount, uniqueVS)

/-- True iff the classification is `.clear`. -/
def Classification.isClear : Classification → Bool
  | .clear                     => true
  | .hazard sub positions decoded =>
      Function.const (SubThreat × Array Nat × ByteArray) false
        (sub, positions, decoded)

/-- Tag string of a classification (`none` for `.clear`). -/
def Classification.tag : Classification → Option String
  | .clear                     => none
  | .hazard sub positions decoded =>
      Function.const (Array Nat × ByteArray) (some sub.tag) (positions, decoded)

/-- Positions array of a classification (empty for `.clear`). -/
def Classification.positions : Classification → Array Nat
  | .clear                     => #[]
  | .hazard sub positions decoded =>
      Function.const (SubThreat × ByteArray) positions (sub, decoded)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §7 Spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Empty input is clear. -/
theorem detect_empty_clear : (detect #[]).classify.isClear = true := by
  decide +kernel

/-- Pure ASCII text is clear. -/
theorem detect_ascii_clear :
    (detect #[0x48, 0x65, 0x6C, 0x6C, 0x6F]).classify.isClear = true := by
  decide +kernel

/-- Emoji + VS16 — registered emoji-presentation, clear verdict. -/
theorem detect_emoji_presentation_clear :
    (detect #[0x1F600, 0xFE0F]).classify.isClear = true := by
  decide +kernel

/-- Mongolian Letter A + FVS1 (180B) — registered standardized variation,
    clear verdict.  (Mongolian uses 180B..180D, not the FE-range.) -/
theorem detect_mongolian_variation_clear :
    (detect #[0x1820, 0x180B]).classify.isClear = true := by
  decide +kernel

/-- VS16 (FE0F) on Latin A — Latin codepoints have no registered
    variation sequences, so this is `.illegalTarget`. -/
theorem detect_illegal_target_latin :
    (detect #[0x0041, 0xFE0F]).classify.tag = some "IllegalTarget" := by
  decide +kernel

/-- One-byte direct payload: `'a' + FE04 + FE01` decodes to the
    single byte `0x41 = 'A'`.  Must classify as `.directPayload`. -/
theorem detect_direct_payload_byte :
    (detect #[0x0061, 0xFE04, 0xFE01]).classify.tag = some "DirectPayload" := by
  decide +kernel

/-- The same input recovers the decoded byte stream `#['A']`. -/
theorem detect_direct_payload_decodes_A :
    (detect #[0x0061, 0xFE04, 0xFE01]).recoveredPayloadBytes.toList = [0x41] := by
  decide +kernel

/-- A repeated-VS run on a Latin base produces `.repeatedBase`. -/
theorem detect_repeated_base :
    (detect #[0x0061, 0xFE04, 0xFE04, 0xFE04, 0xFE04,
              0xFE04, 0xFE04, 0xFE04, 0xFE04]).classify.tag
      = some "RepeatedBase" := by decide +kernel

/-- A registered emoji presentation followed by a suspicious-VS run
    produces `.embeddedAfterReg` (payload hiding behind a legit glyph). -/
theorem detect_embedded_after_registered :
    (detect #[0x1F600, 0xFE0F, 0x0061,
              0xFE06, 0xFE05]).classify.tag = some "EmbeddedAfterRegistered" := by
  decide +kernel

/-- VS15 (FE0E) on a Latin codepoint is `.illegalTarget` — Latin has
    no Emoji property, so VS15 is not a sanctioned text-presentation. -/
theorem detect_vs15_on_latin_illegal :
    (detect #[0x0041, 0xFE0E]).classify.tag = some "IllegalTarget" := by
  decide +kernel

/-- Supplementary-VS range (E0100) on Latin A is `.illegalTarget`. -/
theorem detect_supplementary_vs_on_latin :
    (detect #[0x0041, 0xE0100]).classify.tag = some "IllegalTarget" := by
  decide +kernel

-- ═══════════════════════════════════════════════════════════════════════════════
-- §8 Boundary-case spot checks
-- ═══════════════════════════════════════════════════════════════════════════════

/-- A leading VS (no preceding base) is hazardous (not clear). -/
theorem detect_leading_vs_suspicious :
    (detect #[0xFE04]).classify.isClear = false := by
  decide +kernel

/-- `vsToNibble` is exhaustive on the FE-range: every codepoint in
    `0xFE00..0xFE0F` returns a `some` in `[0, 15]`. -/
theorem vsToNibble_fe00 : vsToNibble 0xFE00 = some 0   := by decide +kernel
theorem vsToNibble_fe0f : vsToNibble 0xFE0F = some 15  := by decide +kernel
theorem vsToNibble_e0100 : vsToNibble 0xE0100 = some 16 := by decide +kernel
theorem vsToNibble_e01ef : vsToNibble 0xE01EF = some 255 := by decide +kernel

/-- `vsToNibble` returns `none` outside its two sanctioned ranges. -/
theorem vsToNibble_outside : vsToNibble 0x0041 = none := by decide +kernel

end Unicode.Security.Covert.VariationSelectorPayload
