/-
  Unicode.Conformance.Security.AdmissibilityFormDriftTest

  Conformance for the AdmissibilityFormDrift detector: it flags a hazard exactly when
  a string's UTS-39 identifier admissibility changes under NFKC, composing
  `isAllowedIdentifier` with `NFKC.toNFKC`.

    * `detect_isClear_characterization` — the verdict is clear iff the input and its
      NFKC form agree on admissibility: soundness and completeness of the detector as
      a decision procedure for the drift predicate.
    * `detect_records_input_admissibility` / `detect_records_nfkc_admissibility` —
      the booleans the verdict carries are exactly the two admissibility evaluations.
-/

import Unicode.Security.Boundary.AdmissibilityFormDrift

namespace Unicode.Conformance.Security.AdmissibilityFormDriftTest

open Unicode.Identifier (isAllowedIdentifier)
open Unicode.Security.Boundary.AdmissibilityFormDrift

/-- **Decision-correctness (all inputs).** `detect` reports a clear verdict exactly
    when the input and its NFKC form agree on UTS-39 identifier admissibility — it
    flags the admissibility-form-drift hazard precisely when that predicate flips.
    This is the soundness and completeness of the detector as a decision procedure;
    together with correctness of the two primitives it fully characterises the
    detector, with no per-row corpus reduction. -/
theorem detect_isClear_characterization (input : List Nat) :
    (detect input).classify.isClear
      = (isAllowedIdentifier input
          == isAllowedIdentifier (Unicode.Normalization.NFKC.toNFKC input)) := by
  simp only [detect, Classification.isClear]
  generalize isAllowedIdentifier input = a
  generalize isAllowedIdentifier (Unicode.Normalization.NFKC.toNFKC input) = b
  cases a <;> cases b <;> rfl

/-- The verdict carries the input's own admissibility verdict verbatim, so a
    downstream consumer inspecting a hazard reads the true value. -/
theorem detect_records_input_admissibility (input : List Nat) :
    (detect input).inputAdmissible = isAllowedIdentifier input := rfl

/-- The verdict carries the NFKC form's admissibility verdict verbatim. -/
theorem detect_records_nfkc_admissibility (input : List Nat) :
    (detect input).nfkcAdmissible
      = isAllowedIdentifier (Unicode.Normalization.NFKC.toNFKC input) := rfl

end Unicode.Conformance.Security.AdmissibilityFormDriftTest
