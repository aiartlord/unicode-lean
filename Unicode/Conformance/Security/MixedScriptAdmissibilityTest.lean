/-
  Unicode.Conformance.Security.MixedScriptAdmissibilityTest

  Conformance certificate for the MixedScriptAdmissibility detector (identity
  layer, UTS #39 §5.1 Mixed-Script Detection and §5.2 Restriction-Level
  Detection, resting on the Script property of UAX #24).

  What this harness certifies.  The detector partitions an identifier's
  codepoints by their Unicode Script property and reports whether the label is
  confined to a single script (admissible) or draws characters from scripts that
  collectively read as one — the mixed-script confusable classes UTS #39 singles
  out — or contains a codepoint whose Identifier_Status is Restricted.  Each
  verdict carries not only a sub-threat tag but the per-script presence booleans
  that justify it.

  Threat model.  A label such as "аpple" that mixes Cyrillic and Latin letters
  renders identically to its all-Latin twin, so an attacker registers the
  look-alike to impersonate a trusted name in a domain, package registry, or
  account handle.  Restricted-status codepoints — formatters and archaic
  characters that no legitimate modern identifier needs — extend the same
  deception, smuggling invisible or exotic scaffolding into a name that appears
  ordinary.

  The discrimination the detector draws.  A single-script run (plain ASCII Latin,
  for instance) is sanctioned and returns clear; a run that combines Latin with
  Cyrillic or with Greek is flagged with the specific mixed-script class, and its
  per-script flags record exactly which scripts co-occurred; a lone
  Restricted-status codepoint is flagged on its own even absent any mixing.

  How to read the certificate.  Each theorem below pins the complete verdict for
  one discriminating vector — a Latin/Cyrillic mix, a Latin/Greek mix, a solitary
  Restricted-status codepoint, and a benign single-script label — and
  `all_rows_pass` conjoins them into the single closed obligation this harness
  exports.  Appending a further vector extends that conjunction, so the guarantee
  grows with the threat catalogue and cannot silently regress.
-/

import Unicode.Security.Identity.MixedScriptAdmissibility
import Unicode.Conformance.Security.VectorFile

namespace Unicode.Conformance.Security.MixedScriptAdmissibilityTest

open Unicode.Security.Identity.MixedScriptAdmissibility

set_option maxRecDepth 1000000

/-- Latin 'a' (U+0061) flanking Cyrillic 'а' (U+0440) is the archetypal
    homoglyph attack: the two letters are visually identical, so the label reads
    as pure Latin while carrying a Cyrillic character, and the detector must both
    tag it `LatinCyrillic` and record that Latin and Cyrillic actually co-occur. -/
theorem latin_cyrillic_verdict :
    let v := detect [0x0061, 0x0440, 0x0061]
    v.classify.tag = some "LatinCyrillic"
      ∧ v.hasLatin = true ∧ v.hasCyrillic = true := by decide +kernel

/-- Latin 'a' (U+0061) flanking Greek 'α' (U+03B1) exercises the second
    confusable class the detector must separate from Latin/Cyrillic: the verdict
    has to name `LatinGreek` specifically and mark Latin and Greek present, so a
    Greek intruder is never mistaken for the Cyrillic case or waved through. -/
theorem latin_greek_verdict :
    let v := detect [0x0061, 0x03B1, 0x0061]
    v.classify.tag = some "LatinGreek"
      ∧ v.hasLatin = true ∧ v.hasGreek = true := by decide +kernel

/-- U+115F HANGUL CHOSEONG FILLER carries Identifier_Status Restricted and has
    no place in a legitimate modern identifier, so the detector must flag it
    `RestrictedStatusCp` from a single codepoint, proving the restricted-status
    check is independent of any script-mixing evidence. -/
theorem restricted_status_verdict :
    let v := detect [0x115F]
    v.classify.tag = some "RestrictedStatusCp" := by decide +kernel

/-- Plain ASCII "Hello" is confined to a single script, the sanctioned case the
    detector must pass untouched: it returns clear and reports no Cyrillic, so a
    benign Latin label never trips a mixed-script or restricted-status alarm. -/
theorem ascii_clear_verdict :
    let v := detect [0x48, 0x65, 0x6C, 0x6C, 0x6F]
    v.classify.isClear = true ∧ v.hasCyrillic = false := by decide +kernel

/-- The complete certificate: every conformance vector above holds
    simultaneously. Appending a vector extends this conjunction, so the
    guarantee this harness makes grows with the threat catalogue and cannot
    silently regress. -/
theorem all_rows_pass :
    (let v := detect [0x0061, 0x0440, 0x0061]
     v.classify.tag = some "LatinCyrillic"
       ∧ v.hasLatin = true ∧ v.hasCyrillic = true) ∧
    (let v := detect [0x0061, 0x03B1, 0x0061]
     v.classify.tag = some "LatinGreek"
       ∧ v.hasLatin = true ∧ v.hasGreek = true) ∧
    (let v := detect [0x115F]
     v.classify.tag = some "RestrictedStatusCp") ∧
    (let v := detect [0x48, 0x65, 0x6C, 0x6C, 0x6F]
     v.classify.isClear = true ∧ v.hasCyrillic = false) :=
  ⟨latin_cyrillic_verdict, latin_greek_verdict,
   restricted_status_verdict, ascii_clear_verdict⟩

-- ═══════════════════════════════════════════════════════════════════════════════
-- The pinned vector file, executed
--
-- `Unicode/Ucd/Security/MixedScriptAdmissibilityTest.txt` is hash-pinned by
-- `scripts/check-security-hashes.sh`, which fixes its bytes.  Running the
-- detector over those bytes is a separate claim, and this section makes it:
-- `rowsList` is mirrored against a fresh parse of the file at build time, and
-- `all_vectors_pass` reduces the detector over every row in the kernel.  A row
-- added to, removed from, or edited in the file fails the build until the
-- harness agrees with it again.
-- ═══════════════════════════════════════════════════════════════════════════════

open Unicode.Conformance.Security.VectorFile (VectorRow parseFile)

/-- Raw text of the pinned vector file, embedded at compile time. -/
def vectorsRaw : String := include_str "../../Ucd/Security/MixedScriptAdmissibilityTest.txt"

/-- Every row of the pinned vector file, freshly parsed. -/
def parsedRows : List VectorRow := parseFile vectorsRaw

/-- The pinned rows, materialized so the kernel can reduce over them. -/
def rowsList : List VectorRow := [
  ⟨[0x0048, 0x0065, 0x006C, 0x006C, 0x006F], "Clear", []⟩,
  ⟨[0x043F, 0x0440, 0x0438, 0x0432, 0x0435, 0x0442], "Clear", []⟩,
  ⟨[0x03B1, 0x03BB, 0x03C6, 0x03B1], "Clear", []⟩,
  ⟨[0x4E2D, 0x6587], "Clear", []⟩,
  ⟨[0xD55C, 0xAE00], "Clear", []⟩,
  ⟨[0x3042, 0x3044, 0x3046], "Clear", []⟩,
  ⟨[0x0627, 0x0628, 0x0629], "Clear", []⟩,
  ⟨[0x05D0, 0x05D1, 0x05D2], "Clear", []⟩,
  ⟨[0x0061, 0x0440, 0x0061], "Hazard:LatinCyrillic", [1]⟩,
  ⟨[0x0070, 0x0430, 0x0079], "Hazard:LatinCyrillic", [1]⟩,
  ⟨[0x0070, 0x0430, 0x0070, 0x0430, 0x006C], "Hazard:LatinCyrillic", [1, 3]⟩,
  ⟨[0x006F, 0x043E, 0x0070], "Hazard:LatinCyrillic", [1]⟩,
  ⟨[0x006F, 0x043E, 0x0065, 0x006E, 0x0430, 0x0069], "Hazard:LatinCyrillic", [1, 4]⟩,
  ⟨[0x0410, 0x0044, 0x004D, 0x0049, 0x004E], "Hazard:LatinCyrillic", [0]⟩,
  ⟨[0x0061, 0x03B1, 0x0061], "Hazard:LatinGreek", [1]⟩,
  ⟨[0x006F, 0x03BF, 0x0070], "Hazard:LatinGreek", [1]⟩,
  ⟨[0x115F], "Hazard:RestrictedStatusCp", [0]⟩,
  ⟨[0x1160], "Hazard:RestrictedStatusCp", [0]⟩,
  ⟨[0x0048, 0x03F5, 0x006C], "Hazard:RestrictedStatusCp", [1]⟩,
  ⟨[0x0048, 0x05D0, 0x0069], "Hazard:ScriptMixOther", []⟩,
  ⟨[0x03B1, 0x0430], "Hazard:ScriptMixOther", []⟩,
  ⟨[0x0061, 0x0627, 0x0062], "Hazard:ScriptMixOther", []⟩,
  ⟨[0x0061, 0x0F40, 0x0062], "Hazard:ScriptMixOther", []⟩,
  ⟨[0x0430, 0x05D0, 0x0431], "Hazard:ScriptMixOther", []⟩
]

-- `rowsList` mirrors a fresh parse of the vector file, checked at build time.
#eval do
  unless rowsList == parsedRows do
    throw (IO.userError "MixedScriptAdmissibilityTest drift: rowsList ≠ parsed vector file")

/-- Run the detector over one row and compare with the verdict the file states. -/
def verifyVectorRow (r : VectorRow) : Bool :=
  let v := detect r.codepoints
  if r.expectsClear then v.classify.isClear
  else v.classify.tag == r.expectedTag

/-- Every vector the pinned file states holds of the detector. -/
theorem all_vectors_pass : rowsList.all verifyVectorRow = true := by decide +kernel

end Unicode.Conformance.Security.MixedScriptAdmissibilityTest
