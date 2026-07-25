/-
  Unicode.Precis.PreparationVectorsRejected

  Rejection conformance vectors for the UsernameCaseMapped (RFC 8265 §3.3) and
  UsernameCasePreserved (§3.4) profiles: inputs the admissibility gate refuses —
  ASCII space, U+202E right-to-left override, U+200B zero-width space, and a
  mixed identifier concealing a disallowed codepoint.
-/

import Unicode.Precis.Preparation

namespace Unicode.Precis.Preparation

open Unicode.Normalization
open Unicode.Normalization.LowCodepointNfc (toNFC_id_of_starters)
open Unicode.Precis.WidthMapping (widthMap_id_of_all_non_source)
open Unicode.Precis.CaseMapping (caseFold_id_of_all_non_source)

set_option maxRecDepth 100000

-- ═══════════════════════════════════════════════════════════════════════════════
-- USERNAMECASEMAPPED — REJECTED
-- ═══════════════════════════════════════════════════════════════════════════════

/-- ASCII SPACE is rejected (not admissible in IdentifierClass). -/
theorem prep_rejects_space :
    precisPreparation #[0x0020] = none := by
  unfold precisPreparation
  rw [precisMap_ascii_output #[0x0020] (by decide)]
  decide +kernel

/-- RIGHT-TO-LEFT OVERRIDE is rejected (Trojan Source vector). The mapping is
    the identity on U+202E — it is a non-source, non-decomposing starter — so
    only the admissibility gate is evaluated, over no normalization table. -/
theorem prep_rejects_bidi_override :
    precisPreparation #[0x202E] = none := by
  unfold precisPreparation
  rw [precisMap_id_singleton 0x202E (by decide) (by decide) (by decide) (by decide) (by decide)]
  decide +kernel

/-- ZERO WIDTH SPACE is rejected (invisible content). -/
theorem prep_rejects_zwsp :
    precisPreparation #[0x200B] = none := by
  unfold precisPreparation
  rw [precisMap_id_singleton 0x200B (by decide) (by decide) (by decide) (by decide) (by decide)]
  decide +kernel

/-- An otherwise-valid identifier containing a disallowed codepoint is rejected —
    the category check fails on the disallowed byte even though the surrounding
    ASCII would be accepted. The three code points are non-source starters and no
    adjacent pair primary-composes, so the mapping is the identity structurally. -/
theorem prep_rejects_mixed :
    precisPreparation #[0x61, 0x202E, 0x62] = none := by
  have hmap : precisMap #[0x61, 0x202E, 0x62] = #[0x61, 0x202E, 0x62] := by
    unfold precisMap
    rw [widthMap_id_of_all_non_source #[0x61, 0x202E, 0x62] (by decide),
        caseFold_id_of_all_non_source #[0x61, 0x202E, 0x62] (by decide)]
    exact toNFC_id_of_starters #[0x61, 0x202E, 0x62]
      (by intro x hx; simp at hx; rcases hx with h | h | h <;> subst h <;> exact ⟨by decide, by decide⟩)
      (by intro x hx; simp at hx; rcases hx with h | h | h <;> subst h <;> decide)
      ⟨Compose.primaryComposite?_none_of_all_ne 0x61 0x202E (by decide) (by decide +kernel),
       Compose.primaryComposite?_none_of_all_ne 0x202E 0x62 (by decide) (by decide +kernel),
       trivial⟩
  unfold precisPreparation
  rw [hmap]
  decide +kernel

-- ═══════════════════════════════════════════════════════════════════════════════
-- USERNAMECASEPRESERVED — REJECTED
-- ═══════════════════════════════════════════════════════════════════════════════

/-- Space is still disallowed under IdentifierClass. -/
theorem prepPreserved_rejects_space :
    precisPreparationPreserved #[0x0020] = none := by
  unfold precisPreparationPreserved
  rw [precisMapPreserved_ascii_output #[0x0020] (by decide)]
  decide +kernel

/-- Bidi override is still disallowed (Trojan Source protection). -/
theorem prepPreserved_rejects_bidi_override :
    precisPreparationPreserved #[0x202E] = none := by
  unfold precisPreparationPreserved
  rw [precisMapPreserved_id_singleton 0x202E (by decide) (by decide) (by decide) (by decide)]
  decide +kernel

end Unicode.Precis.Preparation
