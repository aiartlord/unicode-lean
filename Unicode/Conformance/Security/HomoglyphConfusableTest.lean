/-
  Unicode.Conformance.Security.HomoglyphConfusableTest

  Conformance certificate for the HomoglyphConfusable detector (identity layer:
  confusable-skeleton spoofing of identifiers, package names, and domains).

  What this harness certifies.  The detector implements the UTS #39
  (Unicode Security Mechanisms) §4 confusable-detection machinery together with
  the §5.1 mixed-script and §5.2 restriction-level analysis: it projects an
  input onto its confusable skeleton and tests that skeleton against a curated
  dictionary of attack targets and against the Mathematical Alphanumeric Symbols
  block.  This certificate pins the verdict the detector must draw on the
  representative inputs listed below.

  Threat model.  An adversary registers an identifier — a package on a public
  registry, a wallet name, a domain — whose rendered glyph stream is visually
  indistinguishable from a legitimate target's while its underlying codepoint
  stream differs at one or more positions.  The Mathematical Bold Capital A
  (U+1D400), for instance, renders as a heavy "A" yet is a wholly distinct
  codepoint from ASCII 'A' (U+0041); a victim reading the name cannot tell them
  apart, and a tokenizer that trusts the bytes accepts the impostor.

  The discrimination the detector draws.  A sanctioned identifier is one written
  in a single, coherent script whose codepoints carry no confusable structure —
  it passes as clear.  A hazardous identifier is one whose skeleton collides with
  a known target or whose codepoints are drawn from a look-alike block such as
  the Mathematical Alphanumeric Symbols; the detector tags such an input with the
  specific sub-threat (here, `MathAlpha`) so the caller learns not merely that the
  name is suspect but why.

  How to read the certificate.  Each `Row` pairs an `input` codepoint sequence
  with the classification `tag` its verdict must carry — `none` denoting a clear
  verdict, since `isClear` holds exactly when `tag` is `none`.  `verifyRow`
  recomputes `detect` and compares the projected tag; `all_rows_pass` discharges
  the whole table in the kernel.  Appending a vector grows the proof obligation,
  so the certified coverage can only ever widen and never silently regress.
-/

import Unicode.Security.Identity.HomoglyphConfusable
import Unicode.Conformance.Security.VectorFile

namespace Unicode.Conformance.Security.HomoglyphConfusableTest

open Unicode.Security.Identity.HomoglyphConfusable

set_option maxRecDepth 100000
set_option maxHeartbeats 8000000

-- ── §1  The certificate table ───────────────────────────────────────────────

/-- One conformance row: an `input` sequence and the classification `tag` its
    verdict must carry (`none` for a clear verdict — `isClear` holds precisely
    when the tag is absent). -/
structure Row where
  input : List Nat
  tag : Option String

/-- The representative hazard — and clear — vectors this harness certifies. -/
def rows : List Row :=
  [ -- Mathematical Bold Capital A (U+1D400): a lone Math-Alphanumeric look-alike
    -- of ASCII 'A'. It is the discriminating case for the `MathAlpha` sub-threat
    -- because no target-skeleton match applies, so the block predicate alone must
    -- carry the verdict.
    { input := [0x1D400], tag := some "MathAlpha" },
    -- Plain ASCII "Hello": a single-script Latin identifier with no confusable
    -- structure — the clear baseline that proves the detector does not fire on
    -- ordinary text.
    { input := [0x48, 0x65, 0x6C, 0x6C, 0x6F], tag := none } ]

/-- A row passes when `detect` reproduces the classification tag the row
    prescribes. -/
def verifyRow (r : Row) : Bool :=
  (detect r.input).classify.tag == r.tag

-- ── §2  The closed certificate ──────────────────────────────────────────────

/-- Every certified vector draws exactly the verdict the UTS #39 confusable
    machinery and the Math-Alphanumeric block predicate demand. -/
theorem all_rows_pass : rows.all verifyRow = true := by decide +kernel

-- ═══════════════════════════════════════════════════════════════════════════════
-- The pinned vector file, executed
--
-- `Unicode/Ucd/Security/HomoglyphConfusableTest.txt` is hash-pinned by
-- `scripts/check-security-hashes.sh`, which fixes its bytes.  Running the
-- detector over those bytes is a separate claim, and this section makes it:
-- `rowsList` is mirrored against a fresh parse of the file at build time, and
-- `all_vectors_pass` reduces the detector over every row in the kernel.  A row
-- added to, removed from, or edited in the file fails the build until the
-- harness agrees with it again.
-- ═══════════════════════════════════════════════════════════════════════════════

open Unicode.Conformance.Security.VectorFile (VectorRow parseFile)

/-- Raw text of the pinned vector file, embedded at compile time. -/
def vectorsRaw : String := include_str "../../Ucd/Security/HomoglyphConfusableTest.txt"

/-- Every row of the pinned vector file, freshly parsed. -/
def parsedRows : List VectorRow := parseFile vectorsRaw

/-- The pinned rows, materialized so the kernel can reduce over them. -/
def rowsList : List VectorRow := [
  ⟨[0x0048, 0x0065, 0x006C, 0x006C, 0x006F], "Clear", []⟩,
  ⟨[0x004E, 0x0065, 0x0074, 0x0068, 0x0065, 0x0072, 0x0065, 0x0075, 0x006D], "Clear", []⟩,
  ⟨[0x0061, 0x0070, 0x0070, 0x006C, 0x0065], "Clear", []⟩,
  ⟨[0x006F, 0x0070, 0x0065, 0x006E, 0x0061, 0x0069], "Clear", []⟩,
  ⟨[0x4E2D, 0x6587], "Clear", []⟩,
  ⟨[0x004E, 0x0065, 0x0074, 0x0068, 0x0065, 0x0072, 0x0435, 0x0075, 0x006D], "Hazard:TargetMatch", []⟩,
  ⟨[0x0430, 0x0070, 0x0070, 0x006C, 0x0065], "Hazard:TargetMatch", []⟩,
  ⟨[0x0070, 0x0430, 0x0079, 0x0070, 0x0430, 0x006C], "Hazard:TargetMatch", []⟩,
  ⟨[0x1D400], "Hazard:MathAlpha", [0]⟩,
  ⟨[0x1D400, 0x1D429, 0x1D429, 0x1D425, 0x1D41E], "Hazard:TargetMatch", []⟩,
  ⟨[0x1D434], "Hazard:MathAlpha", [0]⟩,
  ⟨[0x1D49C], "Hazard:MathAlpha", [0]⟩,
  ⟨[0x1D504], "Hazard:MathAlpha", [0]⟩,
  ⟨[0xFF21], "Hazard:WidthClass", [0]⟩,
  ⟨[0xFF30, 0xFF41, 0xFF59, 0xFF50, 0xFF41, 0xFF4C], "Hazard:TargetMatch", []⟩,
  ⟨[0xFF15], "Hazard:WidthClass", [0]⟩,
  ⟨[0x0435, 0x0074, 0x0068, 0x0065, 0x0072, 0x0065, 0x0075, 0x006D], "Hazard:TargetMatch", []⟩,
  ⟨[0x043E, 0x0070, 0x0065, 0x006E, 0x0061, 0x0069], "Hazard:TargetMatch", []⟩,
  ⟨[0x0067, 0x006F, 0x043E, 0x0067, 0x006C, 0x0065], "Hazard:TargetMatch", []⟩,
  ⟨[0x0063, 0x006C, 0x0430, 0x0075, 0x0064, 0x0065], "Hazard:TargetMatch", []⟩,
  ⟨[0x0067, 0x0456, 0x0074, 0x0068, 0x0075, 0x0062], "Hazard:TargetMatch", []⟩,
  ⟨[0x0072, 0x0435, 0x0061, 0x0063, 0x0074], "Hazard:TargetMatch", []⟩,
  ⟨[0x1D5A0], "Hazard:MathAlpha", [0]⟩,
  ⟨[0x1D538], "Hazard:MathAlpha", [0]⟩,
  ⟨[0x1D670], "Hazard:MathAlpha", [0]⟩,
  ⟨[0xFF71], "Hazard:WidthClass", [0]⟩,
  ⟨[0xFF27, 0xFF49, 0xFF54, 0xFF48, 0xFF55, 0xFF42], "Hazard:WidthClass", [0]⟩,
  ⟨[0x0065, 0x0301], "Hazard:DecompositionSwap", [0]⟩,
  ⟨[0x006F, 0x0308], "Hazard:DecompositionSwap", [0]⟩,
  ⟨[0x0061, 0x0300], "Hazard:DecompositionSwap", [0]⟩,
  ⟨[0x0065, 0x0301, 0x0061, 0x0300], "Hazard:DecompositionSwap", [0]⟩,
  ⟨[0x006D, 0x043E, 0x0063, 0x0072, 0x006F, 0x0073, 0x006F, 0x0066, 0x0074], "Hazard:CrossScriptMix", []⟩,
  ⟨[0x0073, 0x006F, 0x043E, 0x0061, 0x006E, 0x0061], "Hazard:CrossScriptMix", []⟩,
  ⟨[0x006D, 0x0065, 0x0430, 0x0061, 0x006D, 0x0061, 0x0073, 0x006B], "Hazard:CrossScriptMix", []⟩,
  ⟨[0x0062, 0x0069, 0x0430, 0x006E, 0x0061, 0x006E, 0x0063, 0x0065], "Hazard:CrossScriptMix", []⟩,
  ⟨[0x0061, 0x0062, 0x03B1, 0x03B2], "Hazard:CrossScriptMix", []⟩,
  ⟨[0x0078, 0x0079, 0x0444, 0x0444], "Hazard:CrossScriptMix", []⟩,
  ⟨[0x03B1, 0x03B2, 0x0444, 0x0445], "Hazard:CrossScriptMix", []⟩,
  ⟨[0x11700], "Hazard:RestrictionLow", []⟩,
  ⟨[0x12000], "Hazard:RestrictionLow", []⟩,
  ⟨[0x13000], "Hazard:RestrictionLow", []⟩
]

-- `rowsList` mirrors a fresh parse of the vector file, checked at build time.
#eval do
  unless rowsList == parsedRows do
    throw (IO.userError "HomoglyphConfusableTest drift: rowsList ≠ parsed vector file")

/-- Run the detector over one row and compare with the verdict the file states. -/
def verifyVectorRow (r : VectorRow) : Bool :=
  let v := detect r.codepoints
  if r.expectsClear then v.classify.isClear
  else v.classify.tag == r.expectedTag

/-- Every vector the pinned file states holds of the detector. -/
theorem all_vectors_pass : rowsList.all verifyVectorRow = true := by decide +kernel

end Unicode.Conformance.Security.HomoglyphConfusableTest
