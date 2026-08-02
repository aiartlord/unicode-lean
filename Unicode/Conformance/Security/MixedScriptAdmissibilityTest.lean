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

end Unicode.Conformance.Security.MixedScriptAdmissibilityTest
