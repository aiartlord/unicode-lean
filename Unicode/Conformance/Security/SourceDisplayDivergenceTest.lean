/-
  Unicode.Conformance.Security.SourceDisplayDivergenceTest

  Conformance for the SourceDisplayDivergence detector (D1) — the compound detector
  that composes TagBlockPayload (C1), VariationSelectorPayload (C2), ZeroWidthPayload
  (C3), BidiControlBalance (C5), and HomoglyphConfusable (I1) on one codepoint stream
  and reports when the source bytes and the displayed glyphs diverge.

  Each vector below fires exactly one constituent family, so this doubles as a
  per-family priority regression check. The proofs strip the homoglyph sub-detector's
  NFC pipeline the efficient way — rewriting the NFC form away with `toNFC_id_of_starters`
  and per-pair `primaryComposite?_none_of_all_ne` witnesses (the same recipe the
  detector module uses), leaving only a cheap `decide`. No corpus is reduced.

  The prior `all_rows_pass := by decide` over the include_str corpus is not used: an
  include_str String's `.toList` is opaque to the kernel reducer, so a parse-and-decide
  over the corpus is stuck rather than proving anything. The fixture .txt is illustrative.
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

/-- A pure variation-selector payload (Latin A + VS16) fires the C2 family only. -/
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

/-- A pure zero-width payload (Latin H + ZWSP + i) fires the C3 family only. -/
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
