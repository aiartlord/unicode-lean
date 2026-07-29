/-
  Unicode.Conformance.Security.IdentifierFormDriftTest

  Conformance for the IdentifierFormDrift detector: it reports a hazard exactly when a
  codepoint's UTS-39 Identifier_Status differs from that of its NFKD head — the
  per-codepoint sibling of AdmissibilityFormDrift.

  Each theorem checks the verdict on a documented case: a Greek letter with identity
  NFKD stays clear, while Mathematical-Italic 'a' and fullwidth 'A' are Restricted
  codepoints whose NFKD heads are Allowed — a status shift the detector flags.
-/

import Unicode.Security.Boundary.IdentifierFormDrift

namespace Unicode.Conformance.Security.IdentifierFormDriftTest

open Unicode.Security.Boundary.IdentifierFormDrift

set_option maxRecDepth 100000

/-- Greek lowercase α (U+03B1) is Allowed with identity NFKD — clear. -/
theorem greek_alpha_clear :
    (detect [0x03B1]).classify.isClear = true := by decide

/-- Mathematical Italic Small A (U+1D44E) is Restricted; its NFKD head U+0061 is
    Allowed — a status shift. -/
theorem math_italic_a_shift :
    (detect [0x1D44E]).classify.tag = some "IdentifierStatusShift" := by decide

/-- Fullwidth A (U+FF21) is Restricted; its NFKD head U+0041 is Allowed. -/
theorem fullwidth_A_shift :
    (detect [0xFF21]).classify.tag = some "IdentifierStatusShift" := by decide

end Unicode.Conformance.Security.IdentifierFormDriftTest
