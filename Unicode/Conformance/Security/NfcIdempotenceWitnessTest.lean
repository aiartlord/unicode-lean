/-
  Unicode.Conformance.Security.NfcIdempotenceWitnessTest

  Conformance for the NfcIdempotenceWitness detector (input that is not already in
  NFC / NFKC form — a normalization-idempotence hazard exploited when a validator
  and a consumer disagree on whether normalization already happened).

  The detector is a predicate composition: `detect` reports a hazard exactly when the
  input diverges from its own NFC form, or (failing that) from its NFKC form. We
  verify its contract over EVERY input, structurally, with no corpus reduction — the
  divergence predicates and the normal forms stay opaque, so nothing is reduced.
  Representative vectors are proven in the detector module.

  The prior `all_rows_pass := by decide` over the include_str corpus is not used: an
  include_str String's `.toList` is opaque to the kernel reducer, so a parse-and-decide
  over the corpus is stuck rather than proving anything. The fixture .txt is illustrative.
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
