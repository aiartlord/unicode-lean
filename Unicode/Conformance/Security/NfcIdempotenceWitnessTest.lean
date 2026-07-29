/-
  Unicode.Conformance.Security.NfcIdempotenceWitnessTest

  Conformance for the NfcIdempotenceWitness detector: it reports a hazard exactly when
  the input diverges from its own NFC form, or (failing that) from its NFKC form — a
  normalization-idempotence hazard, arising when a validator and a consumer disagree
  on whether normalization has already happened.

  The theorems state the detector's contract over every input: the clear/hazard
  decision, and the NFC/NFKC lengths the verdict carries, are each exactly the
  underlying value.
-/

import Unicode.Security.Form.NfcIdempotenceWitness

namespace Unicode.Conformance.Security.NfcIdempotenceWitnessTest

open Unicode.Security.Form.NfcIdempotenceWitness

/-- **Decision-correctness (all inputs).** `detect` is clear exactly when the input
    equals both its NFC and its NFKC form (no divergence position) — soundness and
    completeness of the clear/hazard decision (NFC checked first). -/
theorem detect_isClear_characterization (input : List Nat) :
    (detect input).classify.isClear
      = ((firstDivergence input (Unicode.Normalization.NFC.toNFC input)).isNone
          && (firstDivergence input (Unicode.Normalization.NFKC.toNFKC input)).isNone) := by
  simp only [detect, Classification.isClear]
  cases firstDivergence input (Unicode.Normalization.NFC.toNFC input) <;>
    cases firstDivergence input (Unicode.Normalization.NFKC.toNFKC input) <;> rfl

/-- The verdict's NFC length is exactly the length of the input's NFC form. -/
theorem detect_nfcLen (input : List Nat) :
    (detect input).nfcLen = (Unicode.Normalization.NFC.toNFC input).length := rfl

/-- The verdict's NFKC length is exact. -/
theorem detect_nfkcLen (input : List Nat) :
    (detect input).nfkcLen = (Unicode.Normalization.NFKC.toNFKC input).length := rfl

end Unicode.Conformance.Security.NfcIdempotenceWitnessTest
