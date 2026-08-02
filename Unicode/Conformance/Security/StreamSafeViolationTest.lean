/-
  Unicode.Conformance.Security.StreamSafeViolationTest

  Conformance certificate for the StreamSafeViolation detector (form layer,
  UAX #15 §13 Stream-Safe Text Format).

  Threat model.  Canonical ordering imposes no bound on how many combining marks
  may follow a base character, so an adversary can append an unbounded
  non-starter run ("Zalgo" text).  A normalizer that buffers a whole combining
  sequence before reordering then faces unbounded intermediate state — a memory
  amplification that turns a short input into a denial-of-service against any
  downstream normalization pass.

  What the detector draws.  UAX #15 caps a sanctioned non-starter run at 30 (the
  Stream-Safe limit, remediated by inserting U+034F COMBINING GRAPHEME JOINER);
  the detector reports a `StreamSafeOverrun` hazard for the first run that
  exceeds it and stays clear at or below it.

  The certificate.  This detector reasons over the canonical combining class
  table, which does not reduce under `decide`; its verdicts are therefore
  established by the detector module's own proofs
  (`detect_thirty_marks_clear`, `detect_thirtyone_marks_hazard`), which
  characterise the non-starter run without materialising the CCC table.  The two
  vector theorems below witness the cap boundary exactly, and `all_rows_pass`
  bundles them into the single closed certificate this harness exports.
-/

import Unicode.Security.Form.StreamSafeViolation

namespace Unicode.Conformance.Security.StreamSafeViolationTest

open Unicode.Security.Form.StreamSafeViolation

-- ── §1  Cap-boundary vectors ────────────────────────────────────────────────

/-- Exactly thirty non-starters sits on the UAX #15 cap — clear.  This is the
    high-water mark a legitimate stacked diacritic sequence may reach. -/
theorem thirty_marks_clear : (detect vThirty).classify.isClear = true :=
  detect_thirty_marks_clear

/-- Thirty-one non-starters is the first length past the cap — the smallest run
    that surfaces the buffer-amplification hazard as `StreamSafeOverrun`. -/
theorem thirtyone_marks_overrun :
    (detect vThirtyOne).classify.tag = some "StreamSafeOverrun" :=
  detect_thirtyone_marks_hazard

-- ── §2  The closed certificate ──────────────────────────────────────────────

/-- The complete certificate: the cap holds clear and one past it overruns.
    Extending the harness with a further vector extends this conjunction, so the
    guarantee grows with the threat catalogue and cannot silently regress. -/
theorem all_rows_pass :
    (detect vThirty).classify.isClear = true ∧
    (detect vThirtyOne).classify.tag = some "StreamSafeOverrun" :=
  ⟨thirty_marks_clear, thirtyone_marks_overrun⟩

end Unicode.Conformance.Security.StreamSafeViolationTest
