/-
  Unicode.Conformance.Security.AdmissibilityFormDriftTest

  Conformance for the AdmissibilityFormDrift detector: it flags a hazard exactly when
  a string's UTS-39 identifier admissibility changes under NFKC, composing
  `isAllowedIdentifier` with `NFKC.toNFKC`.

  Each theorem checks the verdict on a documented case: ASCII stays admissible, the
  ﬁ ligature and a decomposed Hangul-jamo sequence both flip admissibility under NFKC.
  Each NFKC form is rewritten away with a proven normalization witness, leaving the
  admissibility scan for `decide`.
-/

import Unicode.Security.Boundary.AdmissibilityFormDrift

namespace Unicode.Conformance.Security.AdmissibilityFormDriftTest

open Unicode.Security.Boundary.AdmissibilityFormDrift

set_option maxRecDepth 100000

/-- ASCII "admin" is admissible both before and after NFKC — clear. -/
theorem admin_clear :
    (detect [0x61, 0x64, 0x6D, 0x69, 0x6E]).classify.isClear = true := by
  unfold detect
  rw [Unicode.Normalization.LowCodepointNfkc.toNFKC_id_of_starters
        [0x61, 0x64, 0x6D, 0x69, 0x6E] (by decide) (by decide)]
  decide

/-- The ﬁ ligature (U+FB01) is not an admissible identifier, but its NFKC form "fi"
    is — admissibility flips, so the detector fires. -/
theorem fi_ligature_drift :
    (detect [0xFB01]).classify.tag = some "AdmissibilityFormDrift" := by
  unfold detect
  rw [Unicode.Normalization.DetectorFormVectors.toNFKC_ligature_fi]
  decide

/-- Decomposed Hangul jamos each pass the per-codepoint scan, but NFKC composes them
    into an admissible precomposed syllable — flipping the whole-string verdict. -/
theorem jamo_sequence_drift :
    (detect [0x1112, 0x1161, 0x11AB]).classify.tag
      = some "AdmissibilityFormDrift" := by
  unfold detect
  rw [Unicode.Normalization.DetectorFormVectors.toNFKC_jamo_han]
  decide

end Unicode.Conformance.Security.AdmissibilityFormDriftTest
