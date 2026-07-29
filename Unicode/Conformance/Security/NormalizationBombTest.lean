/-
  Unicode.Conformance.Security.NormalizationBombTest

  Conformance for the NormalizationBomb detector: it reports a hazard when the input
  expands explosively under normalization — a decompression-bomb / DoS hazard — by a
  fixed priority: a per-codepoint blow-up, else an NFKD expansion ratio over
  `nfkdRatioPct`, else an NFD ratio over `nfdRatioPct`, else clear.

  The theorems state the detector's contract over every input: the clear/hazard
  decision honours that priority, and the NFD/NFKD/input lengths and per-codepoint
  expansion the verdict carries are each exact.
-/

import Unicode.Security.Form.NormalizationBomb

namespace Unicode.Conformance.Security.NormalizationBombTest

open Unicode.Security.Form.NormalizationBomb

/-- **Decision-correctness (all inputs).** `detect` is clear exactly when there is no
    per-codepoint blow-up and both the NFKD and NFD expansion ratios are within
    threshold — soundness and completeness of the clear/hazard decision, honouring
    the blow-up → NFKD-ratio → NFD-ratio priority. -/
theorem detect_isClear_characterization (input : List Nat) :
    (detect input).classify.isClear
      = ((firstBlowupCp input).isNone
          && !decide (nfkdRatioPctOf input > nfkdRatioPct)
          && !decide (nfdRatioPctOf input > nfdRatioPct)) := by
  simp only [detect, Classification.isClear]
  cases firstBlowupCp input with
  | some v => rfl
  | none =>
    by_cases h1 : nfkdRatioPctOf input > nfkdRatioPct <;>
      by_cases h2 : nfdRatioPctOf input > nfdRatioPct <;>
      simp [h1, h2, Function.const]

/-- The verdict's NFD length is exactly the length of the input's NFD form. -/
theorem detect_nfdLen (input : List Nat) :
    (detect input).nfdLen = (Unicode.Normalization.NFC.toNFD input).length := rfl

/-- The verdict's NFKD length is exact. -/
theorem detect_nfkdLen (input : List Nat) :
    (detect input).nfkdLen = (Unicode.Normalization.NFKD.toNFKD input).length := rfl

/-- The verdict's input length is exact. -/
theorem detect_inputLen (input : List Nat) :
    (detect input).inputLen = input.length := rfl

/-- The verdict's maximum per-codepoint expansion is exact. -/
theorem detect_maxPerCpExpansion (input : List Nat) :
    (detect input).maxPerCpExpansion = maxPerCpExpansion input := rfl

end Unicode.Conformance.Security.NormalizationBombTest
