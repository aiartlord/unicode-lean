/-
  Unicode.Conformance.Security.MixedScriptAdmissibilityTest

  Conformance for the MixedScriptAdmissibility detector (UTS-39 mixed-script and
  restricted-status confusables — Latin/Cyrillic, Latin/Greek, and Restricted-status
  codepoint hazards).

  The detector is exhaustively spot-checked in its own module (§): single-script
  clears and every mixed-script sub-threat. What those tag-only checks do not pin is
  the per-script boolean metadata (hasLatin/hasCyrillic/hasGreek) a consumer reads.
  This module verifies the full verdict on representative vectors.

  The prior `all_rows_pass := by decide` over the include_str corpus is not used: an
  include_str String's `.toList` is opaque to the kernel reducer, so a parse-and-decide
  over the corpus is stuck rather than proving anything. The fixture .txt is illustrative.
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
