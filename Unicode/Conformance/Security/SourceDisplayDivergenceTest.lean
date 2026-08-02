/-
  Unicode.Conformance.Security.SourceDisplayDivergenceTest

  What this harness certifies.  It pins the verdicts of the
  SourceDisplayDivergence detector, the compound reference monitor for
  source-code-context attacks described in UTS #55 (Unicode Source Code
  Handling) and UTS #39 (Unicode Security Mechanisms).  The detector runs one
  codepoint stream through five constituent checks at once — a tag-block payload
  scan, a variation-selector payload scan, a zero-width payload scan, a
  bidi-control balance check, and the UTS #39 confusable-skeleton (homoglyph)
  comparison — and reports whenever the bytes a compiler would execute diverge
  from the glyphs a human reviewer sees on screen.

  Threat model.  An adversary commits source whose visible glyph stream looks
  innocuous while its byte stream smuggles an ignorable-character payload, an
  invisible operator, a reordering control, or a homoglyph identifier
  substitution; the Trojan Source class of attacks combines several of these in
  a single file.  A reviewer approves what the terminal renders, and the
  compiler runs something else.

  The discrimination the detector draws.  A stream carrying no such mechanism is
  sanctioned and left clear; a stream carrying exactly one is routed to that
  single family's hazard tag, and a stream carrying several is escalated to a
  compound verdict.  Each vector below is deliberately constructed to activate
  exactly one constituent mechanism, so it witnesses both that the composed
  pipeline recognises that family and that it does not spuriously implicate the
  other four — the single-family tag is the discriminating observation.  The
  confusable sub-check reasons over the canonical composition table, which does
  not reduce under `decide`; each vector's NFC form is therefore rewritten to
  the identity with `toNFC_id_of_starters` and discharged with per-pair
  `primaryComposite?_none_of_all_ne` witnesses, after which the remaining
  routing is a cheap kernel decision.

  How to read the certificate.  Each theorem names the vector and the single
  family tag it must draw; `all_rows_pass` conjoins them into the one certificate
  this harness exports.  Appending a further vector extends that conjunction, so
  the guarantee grows with the threat catalogue and cannot silently regress.
-/

import Unicode.Security.Display.SourceDisplayDivergence

namespace Unicode.Conformance.Security.SourceDisplayDivergenceTest

open Unicode.Security.Display.SourceDisplayDivergence
open Unicode.Security.Identity.HomoglyphConfusable (hasDecompositionSwap)
open Unicode.Normalization.LowCodepointNfc (toNFC_id_of_starters)
open Unicode.Normalization.Compose (primaryComposite?_none_of_all_ne)

set_option maxRecDepth 100000

/-- Two Unicode tag characters (U+E0041 U+E0042) render as nothing yet carry an
    ASCII-shadow payload; the stream must be routed to the `TagBlock` family
    alone, confirming the tag-block scan fires while the variation-selector,
    zero-width, bidi, and confusable checks stay silent. -/
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

/-- A Latin A followed by VS16 (U+0041 U+FE0F) attaches an invisible
    variation-selector to an otherwise ordinary letter; the stream must draw the
    `VariationSelector` family alone, confirming the variation-selector scan
    fires while none of the other four constituent checks do. -/
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

/-- A zero-width space spliced between two visible letters (U+0048 U+200B U+0069)
    splits one rendered identifier into two distinct byte-level tokens; the
    stream must draw the `ZeroWidth` family alone, confirming the zero-width scan
    fires while the tag-block, variation-selector, bidi, and confusable checks
    stay clear. -/
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

/-- The complete certificate: every conformance vector above holds
    simultaneously. Appending a vector extends this conjunction, so the
    guarantee this harness makes grows with the threat catalogue and cannot
    silently regress. -/
theorem all_rows_pass :
    (detect [0xE0041, 0xE0042]).classify.tag = some "TagBlock" ∧
    (detect [0x0041, 0xFE0F]).classify.tag = some "VariationSelector" ∧
    (detect [0x0048, 0x200B, 0x69]).classify.tag = some "ZeroWidth" :=
  ⟨tag_block_family_verdict, variation_selector_family_verdict,
   zero_width_family_verdict⟩

end Unicode.Conformance.Security.SourceDisplayDivergenceTest
