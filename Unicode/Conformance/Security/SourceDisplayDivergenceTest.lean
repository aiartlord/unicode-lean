/-
  Unicode.Conformance.Security.SourceDisplayDivergenceTest

  Conformance for the SourceDisplayDivergence detector — the compound detector that
  composes TagBlockPayload, VariationSelectorPayload, ZeroWidthPayload,
  BidiControlBalance, and HomoglyphConfusable on one codepoint stream and reports when
  the source bytes and the displayed glyphs diverge.

  Each theorem exercises a vector that fires exactly one constituent detector, so the
  set also checks the priority ordering among them. The homoglyph sub-detector's NFC
  form is rewritten away with `toNFC_id_of_starters` and per-pair
  `primaryComposite?_none_of_all_ne` witnesses, leaving a cheap `decide`.
-/

import Unicode.Security.Display.SourceDisplayDivergence

namespace Unicode.Conformance.Security.SourceDisplayDivergenceTest

open Unicode.Security.Display.SourceDisplayDivergence
open Unicode.Security.Identity.HomoglyphConfusable (hasDecompositionSwap)
open Unicode.Normalization.LowCodepointNfc (toNFC_id_of_starters)
open Unicode.Normalization.Compose (primaryComposite?_none_of_all_ne)

set_option maxRecDepth 100000

/-- A pure tag-block payload (U+E0041 U+E0042) fires the C1 family only. -/
theorem tag_block_family_verdict :
    (detect [0xE0041, 0xE0042]).classify.tag = some "TagBlock" := by
  have hds : hasDecompositionSwap [0xE0041, 0xE0042] = false := by
    unfold hasDecompositionSwap
    rw [toNFC_id_of_starters [0xE0041, 0xE0042]
        (by intro x hx; simp at hx; rcases hx with h | h <;> subst h <;> exact ⟨by decide, by decide⟩)
        (by intro x hx; simp at hx; rcases hx with h | h <;> subst h <;> decide)
        ⟨primaryComposite?_none_of_all_ne 0xE0041 0xE0042 (by decide) (by decide +kernel), trivial⟩]
    simp
  have hi1 : (Unicode.Security.Identity.HomoglyphConfusable.detect
      [0xE0041, 0xE0042]).classify.tag = none := by
    unfold Unicode.Security.Identity.HomoglyphConfusable.detect; rw [hds]; decide +kernel
  simp only [detect, hi1]
  decide

/-- A pure variation-selector payload (Latin A + VS16) fires the VariationSelectorPayload
    family only. -/
theorem variation_selector_family_verdict :
    (detect [0x0041, 0xFE0F]).classify.tag = some "VariationSelector" := by
  have hds : hasDecompositionSwap [0x0041, 0xFE0F] = false := by
    unfold hasDecompositionSwap
    rw [toNFC_id_of_starters [0x0041, 0xFE0F]
        (by intro x hx; simp at hx; rcases hx with h | h <;> subst h <;> exact ⟨by decide, by decide⟩)
        (by intro x hx; simp at hx; rcases hx with h | h <;> subst h <;> decide)
        ⟨primaryComposite?_none_of_all_ne 0x0041 0xFE0F (by decide) (by decide +kernel), trivial⟩]
    simp
  have hi1 : (Unicode.Security.Identity.HomoglyphConfusable.detect
      [0x0041, 0xFE0F]).classify.tag = none := by
    unfold Unicode.Security.Identity.HomoglyphConfusable.detect; rw [hds]; decide +kernel
  simp only [detect, hi1]
  decide

/-- A pure zero-width payload (Latin H + ZWSP + i) fires the ZeroWidthPayload family
    only. -/
theorem zero_width_family_verdict :
    (detect [0x0048, 0x200B, 0x69]).classify.tag = some "ZeroWidth" := by
  have hds : hasDecompositionSwap [0x0048, 0x200B, 0x69] = false := by
    unfold hasDecompositionSwap
    rw [toNFC_id_of_starters [0x0048, 0x200B, 0x69]
        (by intro x hx; simp at hx; rcases hx with h | h | h <;> subst h <;> exact ⟨by decide, by decide⟩)
        (by intro x hx; simp at hx; rcases hx with h | h | h <;> subst h <;> decide)
        ⟨primaryComposite?_none_of_all_ne 0x0048 0x200B (by decide) (by decide +kernel),
         primaryComposite?_none_of_all_ne 0x200B 0x69 (by decide) (by decide +kernel), trivial⟩]
    simp
  have hi1 : (Unicode.Security.Identity.HomoglyphConfusable.detect
      [0x0048, 0x200B, 0x69]).classify.tag = none := by
    unfold Unicode.Security.Identity.HomoglyphConfusable.detect; rw [hds]; decide +kernel
  simp only [detect, hi1]
  decide

end Unicode.Conformance.Security.SourceDisplayDivergenceTest
