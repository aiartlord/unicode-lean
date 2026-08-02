/-
  Unicode.Conformance.Security.AiWatermarkDetectabilityTest

  What this harness certifies.  It pins down the verdicts of the
  AiWatermarkDetectability detector, which scans an input for codepoint patterns
  consistent with a statistical AI-provenance watermark.  The markers it hunts
  are drawn from the invisible corners of the Unicode repertoire: format and
  default-ignorable characters in the sense of UAX #44 (the General_Category and
  Default_Ignorable_Code_Point properties), and the variation selectors whose
  legitimate presentation role is fixed by UTS #51 §2.3.  A watermarking protocol
  can borrow U+202F NARROW NO-BREAK SPACE as a boundary token, or a variation
  selector (U+FE00..U+FE0F, U+E0100..U+E01EF) as a data carrier, precisely because
  these codepoints render to nothing and survive copy-paste through plain-text
  channels.

  Threat model.  A provenance-attribution attacker either emits a provider's
  genuine watermark or injects markers that impersonate one, aiming to have benign
  human text mislabelled as machine-generated (or the reverse).  Character-level
  inspection cannot authenticate a provider, so the detector's job is narrower and
  honest: identify which scheme's markers are present, count them, and locate them,
  leaving cryptographic attribution to downstream code.

  The discrimination the detector draws.  It separates plain text that carries no
  invisible markers (a `clear` verdict) from text bearing a recognisable marker
  scheme, and among the latter it names the sub-threat — an NNBSP boundary token,
  a variation-selector carrier not adjacent to an emoji (emoji-adjacent variation
  selectors being the sanctioned UTS #51 presentation use), and so on — reporting
  the marker count and the exact marker positions rather than a bare Boolean.

  How to read the certificate.  Each theorem below fixes the whole verdict — the
  sub-threat tag together with the marker count and, where it discriminates, the
  marker positions — on one representative vector: an NNBSP spliced between letters,
  a bare variation selector in non-emoji text, and a plain-ASCII string that must
  stay clear.  The final theorem `all_rows_pass` conjoins every vector verdict into
  a single obligation; appending a new vector extends that conjunction, so the
  guarantee this harness makes grows with the threat catalogue and cannot silently
  regress.
-/

import Unicode.Security.Crypto.AiWatermarkDetectability

namespace Unicode.Conformance.Security.AiWatermarkDetectabilityTest

open Unicode.Security.Crypto.AiWatermarkDetectability

set_option maxRecDepth 1000000

/-- A single U+202F NARROW NO-BREAK SPACE spliced between two Latin letters is the
    minimal NNBSP boundary token: it renders as an ordinary thin gap yet marks a
    word boundary that a watermark protocol can read back.  The detector must name
    the `NnbspBoundary` sub-threat, count exactly one marker, and report its
    position as index 1, distinguishing the injected marker from the surrounding
    plain text. -/
theorem nnbsp_boundary_verdict :
    let v := detect [0x61, 0x202F, 0x62]
    v.classify.tag = some "NnbspBoundary"
      ∧ v.classify.positions = [1] ∧ v.markerCount = 1 := by decide +kernel

/-- A variation selector (U+FE0F) sitting in ordinary, non-emoji text has no
    presentation role to play, so its only plausible purpose is to carry watermark
    data — the case UTS #51 §2.3 sanctions only when the selector is emoji-adjacent.
    The detector must draw the `VariationSelectorCarrier` verdict and count the lone
    selector as one marker. -/
theorem vs_carrier_verdict :
    let v := detect [0x61, 0xFE0F, 0x62]
    v.classify.tag = some "VariationSelectorCarrier"
      ∧ v.markerCount = 1 := by decide +kernel

/-- Plain ASCII contains no invisible or default-ignorable characters at all, so it
    carries no watermark markers; this is the negative control that guards against a
    detector that flags benign text, and its verdict must be exactly `clear`. -/
theorem ascii_clear_verdict :
    (detect [0x61, 0x62, 0x63]).classify = .clear := by decide +kernel

/-- The complete certificate: every conformance vector above holds simultaneously.
    Appending a vector extends this conjunction, so the guarantee this harness makes
    grows with the threat catalogue and cannot silently regress. -/
theorem all_rows_pass :
    (let v := detect [0x61, 0x202F, 0x62]
     v.classify.tag = some "NnbspBoundary"
       ∧ v.classify.positions = [1] ∧ v.markerCount = 1) ∧
    (let v := detect [0x61, 0xFE0F, 0x62]
     v.classify.tag = some "VariationSelectorCarrier"
       ∧ v.markerCount = 1) ∧
    (detect [0x61, 0x62, 0x63]).classify = .clear :=
  ⟨nnbsp_boundary_verdict, vs_carrier_verdict, ascii_clear_verdict⟩

end Unicode.Conformance.Security.AiWatermarkDetectabilityTest
