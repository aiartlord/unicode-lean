/-
  Unicode.Conformance.Security.NfcIdempotenceWitnessTest

  Conformance for the NfcIdempotenceWitness detector: it reports a hazard when the
  input diverges from its own NFC form, or (failing that) from its NFKC form — a
  normalization-idempotence hazard, arising when a validator and a consumer disagree
  on whether normalization has already happened.

  Each theorem checks the verdict on a documented case: precomposed é is already NFC
  (clear), decomposed é diverges from its NFC form, and the ﬁ ligature diverges from
  its NFKC form (its NFC form is rewritten away with a proven witness).
-/

import Unicode.Security.Form.NfcIdempotenceWitness

namespace Unicode.Conformance.Security.NfcIdempotenceWitnessTest

open Unicode.Security.Form.NfcIdempotenceWitness

set_option maxRecDepth 100000

/-- Precomposed é (U+00E9) already equals its NFC and NFKC forms — clear. -/
theorem precomposed_e_clear :
    (detect [0x00E9]).classify.isClear = true := by decide

/-- Decomposed é (U+0065 U+0301) differs from its NFC form (which composes to
    U+00E9) at position 0 — a non-NFC form. -/
theorem decomposed_e_nfc :
    (detect [0x0065, 0x0301]).classify.tag = some "NonNfcForm" := by decide

/-- The ﬁ ligature (U+FB01) equals its own NFC form but not its NFKC form ("fi") —
    a non-NFKC compatibility form. -/
theorem fi_ligature_nfkc :
    (detect [0xFB01]).classify.tag = some "NonNfkcCompatForm" := by
  unfold detect
  rw [Unicode.Normalization.DetectorFormVectors.toNFC_ligature_fi,
      Unicode.Normalization.DetectorFormVectors.toNFKC_ligature_fi]
  decide

end Unicode.Conformance.Security.NfcIdempotenceWitnessTest
