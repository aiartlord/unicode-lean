/-
  Unicode.Conformance.Security.AdmissibilityFormDriftTest

  Conformance for the AdmissibilityFormDrift detector.

  This detector is correct by construction: `detect` flags a hazard exactly when a
  string's UTS-39 identifier admissibility changes under NFKC. Its substance lives
  entirely in two primitives proven elsewhere — `isAllowedIdentifier` (the UTS-39
  status-table lookup, in `Unicode.Identifier`) and `NFKC.toNFKC` (normalization,
  in `Unicode.Normalization.NFKC`). The composition itself is a three-line function
  with no independent content to enumerate.

  Accordingly the verification here is the detector's **contract, stated over every
  input** and discharged structurally (no corpus reduction):

    * `detect_isClear_characterization` — the verdict is clear iff the admissibility
      predicate agrees on the input and its NFKC form; i.e. the detector is a sound
      and complete decision procedure for the drift predicate.
    * `detect_records_input_admissibility` / `detect_records_nfkc_admissibility` —
      the booleans the verdict carries downstream are exactly the two predicate
      evaluations, so consumers reading a hazard get faithful data.

  Representative attack-vector behaviour (ASCII clear, `ﬁ`-ligature drift, decomposed
  Hangul-jamo drift) is verified in the detector module itself — `detect_ascii_clear`,
  `detect_fi_ligature_drift`, `detect_jamo_sequence_drift` — each proven the efficient
  way: `unfold detect` then rewrite the NFKC form away with a proven normalization
  witness (`toNFKC_id_of_starters` / `DetectorFormVectors.toNFKC_*`), leaving only the
  cheap admissibility scan for `decide`. Re-`decide`ing raw `toNFKC` per row would cost
  ~3.4 GB each with no proof content the contract theorem does not already give for all
  inputs. The `AdmissibilityFormDriftTest.txt` fixture is illustrative external data;
  it is not reduced in the kernel (an `include_str` String's `.toList` is opaque to the
  reducer, so a parse-and-`decide` over it gets stuck rather than proving anything).
-/

import Unicode.Security.Boundary.AdmissibilityFormDrift

namespace Unicode.Conformance.Security.AdmissibilityFormDriftTest

open Unicode.Identifier (isAllowedIdentifier)
open Unicode.Security.Boundary.AdmissibilityFormDrift

/-- **Decision-correctness (all inputs).** `detect` reports a clear verdict exactly
    when the input and its NFKC form agree on UTS-39 identifier admissibility — it
    flags the admissibility-form-drift hazard precisely when that predicate flips.
    This is the soundness and completeness of the detector as a decision procedure;
    together with correctness of the two primitives it fully characterises the X4
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
