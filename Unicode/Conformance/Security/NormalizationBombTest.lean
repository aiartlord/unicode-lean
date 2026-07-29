/-
  Unicode.Conformance.Security.NormalizationBombTest

  Conformance for the NormalizationBomb detector (input that expands explosively under
  normalization — a decompression-bomb / DoS hazard, either a single codepoint that
  blows up or a whole-string NFKD/NFD expansion ratio past threshold).

  The detector is a predicate composition with a fixed priority: a per-codepoint
  blow-up, else an NFKD ratio over `nfkdRatioPct`, else an NFD ratio over
  `nfdRatioPct`, else clear. We verify its contract over EVERY input, structurally,
  with no corpus reduction — the blow-up predicate and the ratio functions stay
  opaque, so no normalization is reduced. Representative vectors are in the detector
  module.

  The prior `all_rows_pass := by decide` over the include_str corpus is not used: an
  include_str String's `.toList` is opaque to the kernel reducer, so a parse-and-decide
  over the corpus is stuck rather than proving anything. The fixture .txt is illustrative.
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
