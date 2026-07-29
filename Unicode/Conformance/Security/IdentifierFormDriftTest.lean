/-
  Unicode.Conformance.Security.IdentifierFormDriftTest

  Conformance for the IdentifierFormDrift detector (per-codepoint UTS-39 identifier
  status shift between a codepoint and its NFKD head — the sibling of
  AdmissibilityFormDrift at the codepoint rather than whole-string level).

  The detector is a predicate composition: `detect` reports a hazard exactly when
  `firstStatusShift` locates a codepoint whose Identifier_Status differs from that of
  its NFKD head. Its substance lives in the primitives proven elsewhere
  (`isAllowedIdentifier` / the status table, `toNFKD`). We therefore verify its
  contract over EVERY input, structurally, with no corpus reduction — the reference-
  monitor guarantee that the clear/hazard decision and the reported position and
  count are exactly the underlying predicate. Representative attack vectors (Math-
  Italic, fullwidth) are proven in the detector module (§5).

  The prior `all_rows_pass := by decide` over the include_str corpus is not used: an
  include_str String's `.toList` is opaque to the kernel reducer, so a parse-and-decide
  over the corpus is stuck rather than proving anything. The fixture .txt is illustrative.
-/

import Unicode.Security.Boundary.IdentifierFormDrift

namespace Unicode.Conformance.Security.IdentifierFormDriftTest

open Unicode.Security.Boundary.IdentifierFormDrift

/-- **Decision-correctness (all inputs).** `detect` is clear exactly when no
    codepoint's UTS-39 identifier status shifts under NFKD — soundness and
    completeness of the detector as a decision procedure for identifier form drift. -/
theorem detect_isClear_characterization (input : List Nat) :
    (detect input).classify.isClear = (firstStatusShift input).isNone := by
  simp only [detect, Classification.isClear]
  cases firstStatusShift input <;> rfl

/-- **Position-correctness (all inputs).** When a hazard fires, the reported position
    is exactly the first status-shift position; when clear, no position is reported. -/
theorem detect_positions_characterization (input : List Nat) :
    (detect input).classify.positions
      = (firstStatusShift input).elim [] (fun pc => [pc.1]) := by
  simp only [detect, Classification.positions]
  cases firstStatusShift input <;> rfl

/-- **Count-correctness (all inputs).** The verdict's shift count is exactly the
    number of status-shifting codepoints a consumer would compute. -/
theorem detect_shiftCount_characterization (input : List Nat) :
    (detect input).shiftCount = statusShiftCount input := rfl

end Unicode.Conformance.Security.IdentifierFormDriftTest
