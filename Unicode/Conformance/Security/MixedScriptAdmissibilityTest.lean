/-
  Unicode.Conformance.Security.MixedScriptAdmissibilityTest

  Conformance for the MixedScriptAdmissibility detector (UTS-39 mixed-script and
  restricted-status confusables — Latin/Cyrillic, Latin/Greek, and Restricted-status
  codepoint hazards).

  Each theorem checks the full verdict — sub-threat tag together with the per-script
  presence booleans — on a representative vector: a Latin/Cyrillic mix, a Latin/Greek
  mix, a lone Restricted-status codepoint, and a single-script clear.
-/

import Unicode.Security.Identity.MixedScriptAdmissibility

namespace Unicode.Conformance.Security.MixedScriptAdmissibilityTest

open Unicode.Security.Identity.MixedScriptAdmissibility

set_option maxRecDepth 1000000

/-- Latin 'a' + Cyrillic 'а' + Latin 'a' — the canonical Latin/Cyrillic homoglyph mix. -/
theorem latin_cyrillic_verdict :
    let v := detect [0x0061, 0x0440, 0x0061]
    v.classify.tag = some "LatinCyrillic"
      ∧ v.hasLatin = true ∧ v.hasCyrillic = true := by decide +kernel

/-- Latin 'a' + Greek 'α' + Latin 'a' — Latin/Greek mix. -/
theorem latin_greek_verdict :
    let v := detect [0x0061, 0x03B1, 0x0061]
    v.classify.tag = some "LatinGreek"
      ∧ v.hasLatin = true ∧ v.hasGreek = true := by decide +kernel

/-- A Restricted-status codepoint (U+115F Hangul filler) fires on its own. -/
theorem restricted_status_verdict :
    let v := detect [0x115F]
    v.classify.tag = some "RestrictedStatusCp" := by decide +kernel

/-- Plain ASCII is single-script Latin — clear. -/
theorem ascii_clear_verdict :
    let v := detect [0x48, 0x65, 0x6C, 0x6C, 0x6F]
    v.classify.isClear = true ∧ v.hasCyrillic = false := by decide +kernel

end Unicode.Conformance.Security.MixedScriptAdmissibilityTest
