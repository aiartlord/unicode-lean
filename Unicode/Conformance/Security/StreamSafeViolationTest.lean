/-
  Unicode.Conformance.Security.StreamSafeViolationTest

  Conformance for the StreamSafeViolation detector: it reports a hazard when a
  non-starter run exceeds the UAX #15 Stream-Safe cap of 30 — a normalization-buffer
  DoS hazard.

  The two theorems witness the cap boundary exactly: a run of 30 combining marks stays
  clear, and a run of 31 fires the overrun. (Discharged by the detector module's own
  proofs, which characterise the non-starter run without reducing the CCC table.)
-/

import Unicode.Security.Form.StreamSafeViolation

namespace Unicode.Conformance.Security.StreamSafeViolationTest

open Unicode.Security.Form.StreamSafeViolation

/-- Exactly 30 non-starters is within the UAX #15 cap of 30 — clear. -/
theorem thirty_marks_clear : (detect vThirty).classify.isClear = true :=
  detect_thirty_marks_clear

/-- Thirty-one non-starters exceeds the cap — a stream-safe overrun. -/
theorem thirtyone_marks_overrun :
    (detect vThirtyOne).classify.tag = some "StreamSafeOverrun" :=
  detect_thirtyone_marks_hazard

end Unicode.Conformance.Security.StreamSafeViolationTest
