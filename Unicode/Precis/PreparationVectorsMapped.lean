/-
  Unicode.Precis.PreparationVectorsMapped

  UsernameCaseMapped (RFC 8265 §3.3) conformance vectors: representative
  admissible inputs paired with their prepared forms, and the concrete
  idempotence of preparation on each. The closed-form universal
  `precis_idempotent` lives in `Unicode.Precis.Preparation`.
-/

import Unicode.Precis.Preparation

namespace Unicode.Precis.Preparation

set_option maxRecDepth 100000

-- ═══════════════════════════════════════════════════════════════════════════════
-- ADMISSIBLE (PASS)
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Empty input passes preparation (no codepoints to classify). -/
theorem prep_empty : precisPreparation #[] = some #[] := by
  unfold precisPreparation
  rw [precisMap_ascii_output #[] (by decide)]
  decide +kernel

/-- Pure-lowercase ASCII identifier is unchanged. -/
theorem prep_alice :
    precisPreparation #[0x61, 0x6C, 0x69, 0x63, 0x65]
      = some #[0x61, 0x6C, 0x69, 0x63, 0x65] := by
  unfold precisPreparation
  rw [precisMap_ascii_output #[0x61, 0x6C, 0x69, 0x63, 0x65] (by decide)]
  decide +kernel

/-- Pure-uppercase ASCII identifier folds to lowercase. -/
theorem prep_uppercase_ALICE :
    precisPreparation #[0x41, 0x4C, 0x49, 0x43, 0x45]
      = some #[0x61, 0x6C, 0x69, 0x63, 0x65] := by
  unfold precisPreparation
  rw [precisMap_ascii_output #[0x41, 0x4C, 0x49, 0x43, 0x45] (by decide)]
  decide +kernel

/-- Fullwidth ASCII identifier is width-mapped to ASCII then
    case-folded. `Ａｌｉｃｅ` (U+FF21 U+FF4C U+FF49 U+FF43 U+FF45)
    prepares to `alice`. -/
theorem prep_fullwidth_Alice :
    precisPreparation #[0xFF21, 0xFF4C, 0xFF49, 0xFF43, 0xFF45]
      = some #[0x61, 0x6C, 0x69, 0x63, 0x65] := by
  unfold precisPreparation
  rw [precisMap_ascii_output #[0xFF21, 0xFF4C, 0xFF49, 0xFF43, 0xFF45] (by decide)]
  decide +kernel

/-- SHARP S prepares to `ss` via the case-folding step. -/
theorem prep_sharp_s :
    precisPreparation #[0x00DF] = some #[0x0073, 0x0073] := by
  unfold precisPreparation
  rw [precisMap_ascii_output #[0x00DF] (by decide)]
  decide +kernel

/-- Underscore and digits are accepted. -/
theorem prep_underscore_digits :
    precisPreparation #[0x005F, 0x0030, 0x0031]
      = some #[0x005F, 0x0030, 0x0031] := by
  unfold precisPreparation
  rw [precisMap_ascii_output #[0x005F, 0x0030, 0x0031] (by decide)]
  decide +kernel

-- ═══════════════════════════════════════════════════════════════════════════════
-- IDEMPOTENCE — CONCRETE VECTORS
-- Double-application returns the same result. The closed-form universal
-- `precis_idempotent` is proven structurally in `Unicode.Precis.Preparation`.
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Empty input is idempotent under preparation. -/
theorem prep_idempotent_empty :
    precisPreparation #[] >>= precisPreparation = some #[] := by
  rw [prep_empty]
  exact prep_empty

/-- Already-lowercase ASCII is idempotent under preparation. -/
theorem prep_idempotent_alice :
    (precisPreparation #[0x61, 0x6C, 0x69, 0x63, 0x65]).bind precisPreparation
      = some #[0x61, 0x6C, 0x69, 0x63, 0x65] := by
  rw [prep_alice, Option.bind_some]
  exact prep_alice

/-- Applying preparation to the already-folded `alice` output
    equals `some alice`. -/
theorem prep_idempotent_alice_from_fullwidth :
    (precisPreparation #[0xFF21, 0xFF4C, 0xFF49, 0xFF43, 0xFF45]).bind precisPreparation
      = some #[0x61, 0x6C, 0x69, 0x63, 0x65] := by
  rw [prep_fullwidth_Alice, Option.bind_some]
  exact prep_alice

/-- Sharp-s's output `ss` is a fixed point of preparation. -/
theorem prep_idempotent_sharp_s :
    (precisPreparation #[0x00DF]).bind precisPreparation
      = some #[0x0073, 0x0073] := by
  rw [prep_sharp_s, Option.bind_some]
  unfold precisPreparation
  rw [precisMap_ascii_output #[0x0073, 0x0073] (by decide)]
  decide +kernel

/-- Capital ALICE folds to alice; re-applying preparation leaves it
    unchanged. -/
theorem prep_idempotent_uppercase_ALICE :
    (precisPreparation #[0x41, 0x4C, 0x49, 0x43, 0x45]).bind precisPreparation
      = some #[0x61, 0x6C, 0x69, 0x63, 0x65] := by
  rw [prep_uppercase_ALICE, Option.bind_some]
  exact prep_alice

end Unicode.Precis.Preparation
