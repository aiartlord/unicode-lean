/-
  Unicode.Restriction

  UTS #39 § 5 Restriction Levels and Mixed-Number Detection.

  Six restriction levels, ordered from strictest to laxest:

    1. ASCII-Only             — every codepoint < U+0080.
    2. Single-Script          — non-ASCII; the resolved-scripts
                                intersection across all
                                non-Common/non-Inherited codepoints
                                is non-empty.
    3. Highly Restrictive     — Single-Script, OR every codepoint's
                                resolved scripts intersect one of
                                three CJK "covered" sets:
                                  · Latin + Han + Hiragana + Katakana
                                    ("Japanese")
                                  · Latin + Han + Bopomofo
                                    ("Chinese")
                                  · Latin + Han + Hangul ("Korean").
    4. Moderately Restrictive — Highly Restrictive, OR every codepoint
                                resolves to {Latn} or to one fixed
                                "other" Recommended script, with the
                                "other" not being Cyrillic or Greek.
    5. Minimally Restrictive  — every codepoint has
                                Identifier_Status = Allowed (UTS #39
                                General security profile).
    6. Unrestricted           — anything (including Restricted-status
                                codepoints).

  Plus the Mixed-Number detection (§ 5.3): a string contains digits
  drawn from more than one decimal-digit set if more than one
  "first-of-set" codepoint divides into the input. The first
  codepoint of each Numeric_Type=Decimal block is at fixed offsets
  in the UCD; we enumerate the canonical set inline.
-/

import Unicode.Identifier
import Unicode.ResolvedScripts

namespace Unicode.Restriction

open Unicode.Generated.ScriptExtensions (ScriptAbbrev)
open Unicode.ResolvedScripts (resolveScripts isCommonScript isInheritedScript)

/-- The six UTS #39 restriction levels, strictest first. -/
inductive RestrictionLevel where
  | ASCIIOnly
  | SingleScript
  | HighlyRestrictive
  | ModeratelyRestrictive
  | MinimallyRestrictive
  | Unrestricted
  deriving DecidableEq, Repr, Inhabited

-- ═══════════════════════════════════════════════════════════════════════════════
-- §1 SCRIPT-SET HELPERS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- True iff `cp` is a Common- or Inherited-script codepoint. Such
    codepoints are ignored when computing the resolved-scripts
    intersection per UTS #39 § 5.1. -/
def isIgnoredForIntersection (cp : Nat) : Bool :=
  isCommonScript cp || isInheritedScript cp

/-- True iff `a` and `b` intersect — share at least one
    `ScriptAbbrev` value. -/
def intersects (a b : Array ScriptAbbrev) : Bool :=
  a.any (fun s => b.contains s)

/-- Intersect a list of script-sets pairwise. Returns the common
    scripts across all of them; returns `#[]` if any input set is
    `#[]` (the result is empty by definition). -/
def intersectMany (sets : Array (Array ScriptAbbrev)) : Array ScriptAbbrev :=
  match sets[0]? with
  | none      => #[]
  | some head => Id.run do
    let mut acc := head
    for h : i in [1:sets.size] do
      acc := acc.filter (fun s => sets[i].contains s)
    return acc

/-- True iff every codepoint in `set` is contained in `super`. -/
def isSubset (set super : Array ScriptAbbrev) : Bool :=
  set.all (fun s => super.contains s)

-- ═══════════════════════════════════════════════════════════════════════════════
-- §2 INDIVIDUAL LEVEL PREDICATES
-- ═══════════════════════════════════════════════════════════════════════════════

/-- True iff every codepoint of `cps` is < U+0080 (ASCII). -/
def isAsciiOnly (cps : Array Nat) : Bool :=
  cps.all (fun cp => cp < 0x80)

/-- The resolved-scripts intersection across all non-Common,
    non-Inherited codepoints of `cps`. UTS #39 calls this the
    "resolved-scripts set" of the string. -/
def stringResolvedScripts (cps : Array Nat) : Array ScriptAbbrev :=
  let nonIgnored := cps.filter (fun cp => ! isIgnoredForIntersection cp)
  if nonIgnored.isEmpty then #[]
  else
    let sets := nonIgnored.map resolveScripts
    intersectMany sets

/-- True iff `cps` is Single-Script per UTS #39 § 5.1.2: not
    ASCII-Only and `stringResolvedScripts` is non-empty. -/
def isSingleScript (cps : Array Nat) : Bool :=
  ! isAsciiOnly cps && ! (stringResolvedScripts cps).isEmpty

/-- The "Japanese" covered set: Latin + Han + Hiragana + Katakana. -/
def coveredJapanese : Array ScriptAbbrev := #[.Latn, .Hani, .Hira, .Kana]

/-- The "Chinese" covered set: Latin + Han + Bopomofo. -/
def coveredChinese : Array ScriptAbbrev := #[.Latn, .Hani, .Bopo]

/-- The "Korean" covered set: Latin + Han + Hangul. -/
def coveredKorean : Array ScriptAbbrev := #[.Latn, .Hani, .Hang]

/-- True iff every non-ignored codepoint's resolved scripts is
    a subset of `covered`. Used to test the three CJK covered
    sets for Highly Restrictive. -/
def allWithinCoveredSet (cps : Array Nat) (covered : Array ScriptAbbrev) : Bool :=
  cps.all (fun cp =>
    if isIgnoredForIntersection cp then true
    else
      let r := resolveScripts cp
      r.size > 0 && intersects r covered)

/-- True iff `cps` matches one of the three CJK covered sets:
    Japanese / Chinese / Korean (each a fixed combination of Latin
    plus CJK ideographic and syllabic scripts). -/
def isCoveredCJK (cps : Array Nat) : Bool :=
  allWithinCoveredSet cps coveredJapanese
    || allWithinCoveredSet cps coveredChinese
    || allWithinCoveredSet cps coveredKorean

/-- True iff `cps` is Highly Restrictive: Single-Script or one of
    the three CJK covered combinations. -/
def isHighlyRestrictive (cps : Array Nat) : Bool :=
  isSingleScript cps || isCoveredCJK cps

/-- True iff `cps` matches the Moderately Restrictive shape:
    every codepoint resolves to {Latn} or to one fixed "other"
    Recommended script, with the "other" ∉ {Cyrl, Grek}. The
    "other" is determined by scanning for the first
    not-Latin-not-Common-not-Inherited script encountered. -/
def isModeratelyRestrictiveShape (cps : Array Nat) : Bool := Id.run do
  let mut other : Option ScriptAbbrev := none
  for cp in cps do
    if isIgnoredForIntersection cp then continue
    let r := resolveScripts cp
    -- A codepoint must resolve to {Latn} or to exactly one script.
    if r.size = 0 then return false
    if intersects r #[.Latn] then continue
    -- Determine the "other" script; pick the first non-Latin entry.
    match r[0]? with
    | none => return false
    | some s =>
      if s = .Cyrl ∨ s = .Grek then return false
      match other with
      | none => other := some s
      | some o =>
        if s ≠ o then return false
  return other.isSome

/-- True iff `cps` is Moderately Restrictive: Highly Restrictive
    or Latin + one non-Cyrl/non-Grek other Recommended script. -/
def isModeratelyRestrictive (cps : Array Nat) : Bool :=
  isHighlyRestrictive cps || isModeratelyRestrictiveShape cps

/-- True iff every codepoint of `cps` has Identifier_Status = Allowed
    (UTS #39 General security profile). -/
def isMinimallyRestrictive (cps : Array Nat) : Bool :=
  cps.all Unicode.Identifier.isAllowedStatus

-- ═══════════════════════════════════════════════════════════════════════════════
-- §3 INTEGRATED LEVEL DECISION
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The strictest UTS #39 § 5.1 restriction level satisfied by
    `cps`. Returns `Unrestricted` for inputs that fail every
    stricter level. -/
def restrictionLevel (cps : Array Nat) : RestrictionLevel :=
  if isAsciiOnly cps then .ASCIIOnly
  else if isSingleScript cps then .SingleScript
  else if isHighlyRestrictive cps then .HighlyRestrictive
  else if isModeratelyRestrictiveShape cps then .ModeratelyRestrictive
  else if isMinimallyRestrictive cps then .MinimallyRestrictive
  else .Unrestricted

-- ═══════════════════════════════════════════════════════════════════════════════
-- §4 MIXED-NUMBER DETECTION  (UTS #39 § 5.3)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- The set of "first-of-set" decimal-digit codepoints — each is
    the digit-zero of a 10-codepoint Numeric_Type=Decimal block.
    A string mixing digits from two distinct sets fails
    Mixed-Number. The list comes from UCD `UnicodeData.txt`
    Numeric_Type=Decimal entries with `Numeric_Value=0`. -/
def decimalZeroOffsets : Array Nat := #[
  0x0030,  -- DIGIT ZERO (ASCII)
  0x0660,  -- ARABIC-INDIC DIGIT ZERO
  0x06F0,  -- EXTENDED ARABIC-INDIC DIGIT ZERO
  0x07C0,  -- NKO DIGIT ZERO
  0x0966,  -- DEVANAGARI DIGIT ZERO
  0x09E6,  -- BENGALI DIGIT ZERO
  0x0A66,  -- GURMUKHI DIGIT ZERO
  0x0AE6,  -- GUJARATI DIGIT ZERO
  0x0B66,  -- ORIYA DIGIT ZERO
  0x0BE6,  -- TAMIL DIGIT ZERO
  0x0C66,  -- TELUGU DIGIT ZERO
  0x0CE6,  -- KANNADA DIGIT ZERO
  0x0D66,  -- MALAYALAM DIGIT ZERO
  0x0DE6,  -- SINHALA LITH DIGIT ZERO
  0x0E50,  -- THAI DIGIT ZERO
  0x0ED0,  -- LAO DIGIT ZERO
  0x0F20,  -- TIBETAN DIGIT ZERO
  0x1040,  -- MYANMAR DIGIT ZERO
  0x1090,  -- MYANMAR SHAN DIGIT ZERO
  0x17E0,  -- KHMER DIGIT ZERO
  0x1810,  -- MONGOLIAN DIGIT ZERO
  0x1946,  -- LIMBU DIGIT ZERO
  0x19D0,  -- NEW TAI LUE DIGIT ZERO
  0x1A80,  -- TAI THAM HORA DIGIT ZERO
  0x1A90,  -- TAI THAM THAM DIGIT ZERO
  0x1B50,  -- BALINESE DIGIT ZERO
  0x1BB0,  -- SUNDANESE DIGIT ZERO
  0x1C40,  -- LEPCHA DIGIT ZERO
  0x1C50,  -- OL CHIKI DIGIT ZERO
  0xA620,  -- VAI DIGIT ZERO
  0xA8D0,  -- SAURASHTRA DIGIT ZERO
  0xA900,  -- KAYAH LI DIGIT ZERO
  0xA9D0,  -- JAVANESE DIGIT ZERO
  0xA9F0,  -- MYANMAR TAI LAING DIGIT ZERO
  0xAA50,  -- CHAM DIGIT ZERO
  0xABF0,  -- MEETEI MAYEK DIGIT ZERO
  0xFF10   -- FULLWIDTH DIGIT ZERO
]

/-- True iff `cp` is a decimal digit — its codepoint lies in the
    10-codepoint range `[zero, zero+9]` for some entry in
    `decimalZeroOffsets`. -/
def isDecimalDigit (cp : Nat) : Bool :=
  decimalZeroOffsets.any (fun digitZero => digitZero ≤ cp ∧ cp ≤ digitZero + 9)

/-- The "first-of-set" zero codepoint for a decimal digit `cp`,
    or `none` if `cp` is not a decimal digit. -/
def digitSetOf? (cp : Nat) : Option Nat :=
  decimalZeroOffsets.findSome? (fun digitZero =>
    if digitZero ≤ cp ∧ cp ≤ digitZero + 9 then some digitZero else none)

/-- True iff `cps` contains digits from more than one decimal
    digit set — UTS #39 § 5.3 Mixed-Number Detection. -/
def hasMixedNumbers (cps : Array Nat) : Bool := Id.run do
  let mut seen : Option Nat := none
  for cp in cps do
    match digitSetOf? cp with
    | none => continue
    | some set =>
      match seen with
      | none => seen := some set
      | some prev =>
        if prev ≠ set then return true
  return false

-- ═══════════════════════════════════════════════════════════════════════════════
-- §5 SAMPLE STRINGS
-- ═══════════════════════════════════════════════════════════════════════════════

/-- "abc" is ASCII-Only. -/
theorem rl_abc :
    restrictionLevel #[0x61, 0x62, 0x63] = .ASCIIOnly := by native_decide

/-- The empty string is ASCII-Only (vacuously). -/
theorem rl_empty :
    restrictionLevel #[] = .ASCIIOnly := by native_decide

/-- Pure Greek "λόγος" is Single-Script. -/
theorem rl_logos :
    restrictionLevel #[0x03BB, 0x03CC, 0x03B3, 0x03BF, 0x03C2]
      = .SingleScript := by native_decide

/-- Pure Cyrillic "привет" is Single-Script. -/
theorem rl_privet :
    restrictionLevel #[0x043F, 0x0440, 0x0438, 0x0432, 0x0435, 0x0442]
      = .SingleScript := by native_decide

/-- The IDN homograph attack `аррӏе` (Cyrillic а р р ӏ е) is
    Single-Script (purely Cyrillic) — the deeper anti-spoofing
    check requires a confusables comparison against the registered
    Latin form `apple`, not just restriction-level. -/
theorem rl_apple_cyrillic :
    restrictionLevel #[0x0430, 0x0440, 0x0440, 0x04CF, 0x0435]
      = .SingleScript := by native_decide

/-- A Latin/Cyrillic mix is Minimally Restrictive — fails
    Single-Script (intersection empty) and the Moderately
    Restrictive shape (Cyrillic is in the excluded set), but
    every codepoint is Identifier_Status=Allowed. Callers
    rejecting IDN homograph attacks should require
    `.HighlyRestrictive` or stricter. -/
theorem rl_latin_cyrillic_mix :
    restrictionLevel #[0x0061, 0x0440, 0x0061]
      = .MinimallyRestrictive := by native_decide

/-- A Latin/Greek mix is also Minimally Restrictive. -/
theorem rl_latin_greek_mix :
    restrictionLevel #[0x0061, 0x03B1, 0x0061]
      = .MinimallyRestrictive := by native_decide

/-- The restriction level reflects script-shape regardless of
    Identifier_Status. `a + U+0080` is SingleScript because
    U+0080 has Script=Common (ignored) and only Latin remains
    in the intersection — even though U+0080 has
    Identifier_Status=Restricted. To reach `Unrestricted` the
    string must additionally fail every script-shape check. -/
theorem rl_ascii_with_c1_is_singlescript :
    restrictionLevel #[0x0061, 0x0080] = .SingleScript := by native_decide

/-- Latin + Cyrillic + a Restricted-status codepoint is
    Unrestricted — fails Single-Script (Latn ∩ Cyrl = ∅), fails
    Moderately (Cyrl excluded), fails Minimally (Restricted). -/
theorem rl_unrestricted_real :
    restrictionLevel #[0x0061, 0x0440, 0x0080]
      = .Unrestricted := by native_decide

/-- Mixed numbers: ASCII digit and Arabic-Indic digit. -/
theorem mixed_numbers_ascii_arabic :
    hasMixedNumbers #[0x0030, 0x0660] = true := by native_decide

/-- Pure ASCII digits are not mixed. -/
theorem mixed_numbers_ascii_only :
    hasMixedNumbers #[0x0030, 0x0031, 0x0039] = false := by native_decide

/-- An empty string has no mixed numbers. -/
theorem mixed_numbers_empty :
    hasMixedNumbers #[] = false := by native_decide

/-- Plain text with no digits has no mixed numbers. -/
theorem mixed_numbers_plain :
    hasMixedNumbers #[0x0061, 0x0062, 0x0063] = false := by native_decide

end Unicode.Restriction
