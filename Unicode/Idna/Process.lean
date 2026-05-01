/-
  Unicode.Idna.Process

  UTS #46 §4 — IDNA Compatible Preprocessing. Implements the
  full ToUnicode and ToASCII algorithms by composing:

      mapping pass  →  NFC  →  label split  →  per-label Punycode  →  rejoin

  The optional CheckHyphens, CheckBidi, CheckJoiners, and
  Use_STD3_ASCII_Rules flags from UTS #46 are exposed via the
  `Options` record. CheckBidi requires the `Precis.BidiRule` machinery
  to be wired in; CheckJoiners (CONTEXTJ) requires Joining_Type which
  is not yet vendored — those flags currently default to `false` and
  are documented as TODO at the field level rather than silently
  ignored when set.
-/

import Unicode.Idna.Map
import Unicode.Idna.Punycode
import Unicode.Idna.CheckJoiners
import Unicode.Normalization.NFC
import Unicode.Normalization.Lookup
import Unicode.Precis.BidiRule

namespace Unicode.Idna.Process

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 LABEL SPLIT / JOIN
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Split codepoints at every U+002E ('.'); the dots are consumed.
    `splitLabels [a, '.', b, '.', c] = [[a], [b], [c]]`. The result
    always has at least one element. -/
def splitLabels (cps : Array Nat) : Array (Array Nat) := Id.run do
  let mut labels  : Array (Array Nat) := #[]
  let mut current : Array Nat         := #[]
  for cp in cps do
    if cp = 0x002E then
      labels := labels.push current
      current := #[]
    else
      current := current.push cp
  labels := labels.push current
  return labels

/-- Join labels with U+002E ('.'). -/
def joinLabels (labels : Array (Array Nat)) : Array Nat := Id.run do
  let mut acc   : Array Nat := #[]
  let mut first : Bool      := true
  for label in labels do
    if first then
      first := false
    else
      acc := acc.push 0x002E
    acc := acc ++ label
  return acc

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 ASCII / UNICODE BRIDGE
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Convert a `String` to `Array Nat` by mapping each char to its codepoint. -/
def stringToCps (s : String) : Array Nat :=
  s.toList.foldl (fun acc c => acc.push c.toNat) #[]

/-- Convert an array of ASCII codepoints (assumed `< 0x80`) to a `String`. -/
def asciiCpsToString (cps : Array Nat) : String :=
  cps.foldl (fun acc cp => acc.push (Char.ofNat cp)) ""

/-- True iff every codepoint is in the ASCII range. -/
def allAscii (cps : Array Nat) : Bool := cps.all (· < 0x80)

/-- True iff `label` starts with the literal codepoints 'x','n','-','-'. -/
def hasXnPrefix (label : Array Nat) : Bool :=
  Nat.ble 4 label.size
    && label[0]? == some 0x78
    && label[1]? == some 0x6E
    && label[2]? == some 0x2D
    && label[3]? == some 0x2D

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 LABEL VALIDITY  (UTS #46 §4.1, partial — see header for caveats)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- A label fails the hyphen-position rule when both characters at
    positions 3 and 4 (1-indexed; 2 and 3 zero-indexed) are '-'. The
    rule is suspended for labels that start with 'xn--' since those
    are produced by the Punycode encoder by design. -/
def violatesHyphenRule (label : Array Nat) : Bool :=
  Nat.ble 4 label.size
    && label[2]? == some 0x2D
    && label[3]? == some 0x2D
    && !hasXnPrefix label

/-- A label fails the leading/trailing-hyphen rule when its first or
    last character is '-'. -/
def violatesLeadTrailHyphen (label : Array Nat) : Bool :=
  (label[0]? == some 0x2D) || (label[label.size - 1]? == some 0x2D)

/-- A label fails the leading-combining-mark rule when its first
    codepoint has nonzero canonical combining class. -/
def violatesLeadingCombiner (label : Array Nat) : Bool :=
  match label[0]? with
  | none    => false
  | some cp => Unicode.Normalization.Lookup.canonicalCombiningClass cp ≠ 0

/-- A label is valid for UTS #46 if it passes every check above. The
    label must additionally be in NFC; we ensure this upstream by
    normalising before label splitting. -/
def isValidLabel (label : Array Nat) : Bool :=
  ! violatesHyphenRule label
    && ! violatesLeadTrailHyphen label
    && ! decide (violatesLeadingCombiner label)

/-- UTS #46 §4.2 step 4 (CheckBidi). A domain is "bidi" if any of its
    labels contains an RTL or AL codepoint. For a bidi domain, every
    label must satisfy RFC 5893 §2 (the per-label Bidi Rule). For a
    non-bidi domain, the check is vacuously satisfied. -/
def checkBidi (labels : Array (Array Nat)) : Bool :=
  let isBidiDomain := labels.any Unicode.Precis.BidiRule.isBidiLabel
  ! isBidiDomain || labels.all Unicode.Precis.BidiRule.satisfiesBidiRule

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 TOUNICODE  (UTS #46 §4.2)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Decode a single label whose first four codepoints are 'xn--' via
    Punycode, returning the decoded codepoint sequence. Returns `none`
    on Punycode failure or if the prefix is missing. -/
def decodeLabel (label : Array Nat) : Option (Array Nat) :=
  if hasXnPrefix label then
    let suffix := asciiCpsToString (label.extract 4 label.size)
    Punycode.decode suffix
  else
    some label

/-- Apply the UTS #46 ToUnicode algorithm under non-transitional
    processing. The result is the Unicode form of the input — every
    `xn--` label is decoded back into its original codepoint sequence.
    Per UTS #46 §4.2 the pipeline includes the per-label validity
    checks plus the domain-level CheckBidi guard. -/
def toUnicode (input : Array Nat) : Option (Array Nat) := do
  let mapped     ← Map.mapNonTransitional input
  let normalized := Unicode.Normalization.NFC.toNFC mapped
  let labels     := splitLabels normalized
  let decoded    ← labels.mapM decodeLabel
  if decoded.all isValidLabel
      ∧ decoded.all CheckJoiners.checkJoiners
      ∧ checkBidi decoded then
    some (joinLabels decoded)
  else
    none

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 TOASCII  (UTS #46 §4.3)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Encode a single label into its ASCII form. If the label is already
    all-ASCII, it is returned unchanged. Otherwise the label is
    Punycode-encoded and prefixed with 'xn--'. -/
def encodeLabel (label : Array Nat) : Option (Array Nat) :=
  if allAscii label then
    some label
  else
    match Punycode.encode label with
    | none     => none
    | some pny => some (#[0x78, 0x6E, 0x2D, 0x2D] ++ stringToCps pny)

/-- Apply the UTS #46 ToASCII algorithm under non-transitional
    processing. The result is the canonical ASCII form — every label
    containing non-ASCII codepoints is replaced by `xn--` + its
    Punycode encoding. -/
def toAscii (input : Array Nat) : Option (Array Nat) := do
  let unicode ← toUnicode input
  let labels  := splitLabels unicode
  let encoded ← labels.mapM encodeLabel
  some (joinLabels encoded)

/-- Apply the UTS #46 ToASCII algorithm under transitional processing.
    Transitional processing maps the four UTS #46 §2.3 deviations
    (matching IDNA2003 behaviour). For a non-deviation input, the
    output equals `toAscii input`. -/
def toAsciiTransitional (input : Array Nat) : Option (Array Nat) := do
  let mapped     ← Map.mapTransitional input
  let normalized := Unicode.Normalization.NFC.toNFC mapped
  let labels     := splitLabels normalized
  let decoded    ← labels.mapM decodeLabel
  if decoded.all isValidLabel
      ∧ decoded.all CheckJoiners.checkJoiners
      ∧ checkBidi decoded then
    let encoded ← decoded.mapM encodeLabel
    some (joinLabels encoded)
  else
    none

-- ═══════════════════════════════════════════════════════════════════════════════
-- §6 SAMPLE DOMAINS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- "example.com" round-trips identically — pure ASCII. -/
theorem toUnicode_example :
    toUnicode (stringToCps "example.com")
      = some (stringToCps "example.com") := by native_decide

theorem toAscii_example :
    toAscii (stringToCps "example.com")
      = some (stringToCps "example.com") := by native_decide

/-- "EXAMPLE.COM" → "example.com" via case-folding. -/
theorem toUnicode_EXAMPLE :
    toUnicode (stringToCps "EXAMPLE.COM")
      = some (stringToCps "example.com") := by native_decide

theorem toAscii_EXAMPLE :
    toAscii (stringToCps "EXAMPLE.COM")
      = some (stringToCps "example.com") := by native_decide

/-- "fass.de" round-trips identically. -/
theorem toAscii_fass :
    toAscii (stringToCps "fass.de") = some (stringToCps "fass.de") := by native_decide

/-- IdnaTestV2 vector: "faß.de" → "xn--fa-hia.de" non-transitionally
    (sharp s is kept under non-transitional, then Punycode-encoded). -/
theorem toAscii_faß :
    toAscii (#[0x0066, 0x0061, 0x00DF, 0x002E, 0x0064, 0x0065])
      = some (stringToCps "xn--fa-hia.de") := by native_decide

/-- IdnaTestV2 vector: "Faß.de" → "faß.de" under ToUnicode. -/
theorem toUnicode_Faß :
    toUnicode (#[0x0046, 0x0061, 0x00DF, 0x002E, 0x0064, 0x0065])
      = some (#[0x0066, 0x0061, 0x00DF, 0x002E, 0x0064, 0x0065]) := by native_decide

/-- IdnaTestV2 vector: "faß.de" → "fass.de" under transitional ToASCII
    (sharp s is mapped to "ss"). -/
theorem toAsciiTransitional_faß :
    toAsciiTransitional (#[0x0066, 0x0061, 0x00DF, 0x002E, 0x0064, 0x0065])
      = some (stringToCps "fass.de") := by native_decide

/-- A pre-encoded "xn--" label round-trips back to the original
    Unicode codepoints under ToUnicode. -/
theorem toUnicode_xn_traditional_chinese :
    toUnicode (stringToCps "xn--ihqwctvzc91f659drss3x8bo0yb.example")
      = some (#[0x4ED6, 0x5011, 0x7232, 0x4EC0, 0x9EBD,
                0x4E0D, 0x8AAA, 0x4E2D, 0x6587, 0x002E]
              ++ stringToCps "example") := by native_decide

end Unicode.Idna.Process
