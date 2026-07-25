/-
  Unicode.Precis.PreparationVectorsPreserved

  UsernameCasePreserved (RFC 8265 §3.4) conformance vectors: representative
  admissible inputs paired with their prepared forms. This profile applies
  width mapping and NFC but preserves case.
-/

import Unicode.Precis.Preparation

namespace Unicode.Precis.Preparation

set_option maxRecDepth 100000

-- ═══════════════════════════════════════════════════════════════════════════════
-- ADMISSIBLE (PASS)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Empty input passes preparation. -/
theorem prepPreserved_empty : precisPreparationPreserved #[] = some #[] := by
  unfold precisPreparationPreserved
  rw [precisMapPreserved_ascii_output #[] (by decide)]
  decide +kernel

/-- Pure-lowercase ASCII is unchanged — case preserved, no mapping. -/
theorem prepPreserved_alice :
    precisPreparationPreserved #[0x61, 0x6C, 0x69, 0x63, 0x65]
      = some #[0x61, 0x6C, 0x69, 0x63, 0x65] := by
  unfold precisPreparationPreserved
  rw [precisMapPreserved_ascii_output #[0x61, 0x6C, 0x69, 0x63, 0x65] (by decide)]
  decide +kernel

/-- Pure-uppercase ASCII is preserved (unlike UsernameCaseMapped which
    folds to lowercase). -/
theorem prepPreserved_uppercase_ALICE :
    precisPreparationPreserved #[0x41, 0x4C, 0x49, 0x43, 0x45]
      = some #[0x41, 0x4C, 0x49, 0x43, 0x45] := by
  unfold precisPreparationPreserved
  rw [precisMapPreserved_ascii_output #[0x41, 0x4C, 0x49, 0x43, 0x45] (by decide)]
  decide +kernel

/-- Mixed-case identifier is preserved. -/
theorem prepPreserved_mixed_Alice :
    precisPreparationPreserved #[0x41, 0x6C, 0x69, 0x63, 0x65]
      = some #[0x41, 0x6C, 0x69, 0x63, 0x65] := by
  unfold precisPreparationPreserved
  rw [precisMapPreserved_ascii_output #[0x41, 0x6C, 0x69, 0x63, 0x65] (by decide)]
  decide +kernel

/-- Fullwidth ASCII is width-mapped but not case-folded. `Ａｌｉｃｅ`
    prepares to `Alice`, preserving case. -/
theorem prepPreserved_fullwidth_Alice :
    precisPreparationPreserved #[0xFF21, 0xFF4C, 0xFF49, 0xFF43, 0xFF45]
      = some #[0x41, 0x6C, 0x69, 0x63, 0x65] := by
  unfold precisPreparationPreserved
  rw [precisMapPreserved_ascii_output #[0xFF21, 0xFF4C, 0xFF49, 0xFF43, 0xFF45] (by decide)]
  decide +kernel

end Unicode.Precis.Preparation
