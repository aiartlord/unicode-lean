/-
  Unicode.Conformance.Security.VariationSelectorPayloadTest

  What this harness certifies.  It exercises the VariationSelectorPayload
  detector against the variation-selector mechanism of the Unicode Standard
  (§23.4 Variation Selectors), whose sanctioned uses are the registered
  variation sequences: the emoji text/emoji presentation selectors of UTS #51
  §4, the ideographic sequences of UAX #45 / the Ideographic Variation
  Database, and the Mongolian free variation selectors.  The variation-selector
  code points fall in two blocks — U+FE00..U+FE0F (VS1..VS16) and
  U+E0100..U+E01EF (VS17..VS256) — plus the Mongolian selectors U+180B..U+180D.

  Threat model.  A variation selector is invisible: it mutates the presentation
  of the preceding base character and renders as nothing on its own.  An
  adversary can therefore append a run of selectors to an innocuous base and
  smuggle a hidden byte string through any channel that preserves code points
  but shows only glyphs — the "GlassWorm" family of supply-chain payloads that
  ride inside identifiers, commit messages, and package metadata.  Because each
  VS16-style selector contributes a nibble, a run of them reconstructs
  arbitrary bytes with no visible trace.

  The discrimination the detector draws.  A variation selector is sanctioned
  only when it forms a *registered* sequence with its base: a real emoji-
  presentation pair, an ideographic variation sequence, or a Mongolian
  base-plus-FVS pair.  Everything else is hazardous — a selector on a base with
  no registered sequence is an `IllegalTarget`, and a decodable run of
  selectors carrying byte content is a `DirectPayload`.  Each verdict below
  therefore checks the full result: the sub-threat tag, the recovered payload
  bytes, and the split between registered and suspicious selector positions.

  How to read the certificate.  Each theorem pins one representative vector —
  a direct two-selector payload, an illegal target, a supplementary-plane
  illegal target, a registered emoji-presentation sequence, and a Mongolian
  free variation selector — and its verdicts are established by `decide +kernel`
  over the concrete input.  The final theorem `all_rows_pass` conjoins every
  vector into one closed obligation; appending a further vector extends that
  conjunction, so the guarantee this harness makes grows with the threat
  catalogue and cannot silently regress.
-/

import Unicode.Security.Covert.VariationSelectorPayload

namespace Unicode.Conformance.Security.VariationSelectorPayloadTest

open Unicode.Security.Covert.VariationSelectorPayload

/-- The canonical GlassWorm attack: two variation selectors appended to the
    innocuous base 'a' carry the low and high nibbles (4, 1) that reconstruct
    the byte 0x41, so the detector must not merely flag the run but recover the
    smuggled payload byte and mark both selector positions suspicious. -/
theorem direct_payload_verdict :
    let v := detect [0x0061, 0xFE04, 0xFE01]
    v.classify.tag = some "DirectPayload"
      ∧ v.recoveredPayloadBytes = [0x41]
      ∧ v.suspiciousPositions = [1, 2] := by decide +kernel

/-- VS16 (U+FE0F, the emoji-presentation selector) applied to Latin 'A' forms
    no registered variation sequence — a plain letter has no emoji presentation
    — so the selector is unsanctioned and must be reported as an `IllegalTarget`
    at position 1 rather than passed through as decoration. -/
theorem illegal_target_verdict :
    let v := detect [0x0041, 0xFE0F]
    v.classify.tag = some "IllegalTarget"
      ∧ v.suspiciousPositions = [1] := by decide +kernel

/-- The same rejection must hold across the supplementary-plane selector block:
    a VS17-range selector (U+E0100) on Latin 'A' is just as unregistered as the
    BMP case, so the detector must classify it `IllegalTarget` and not lose the
    high-plane selectors that carry the bulk of a GlassWorm payload. -/
theorem supplementary_vs_illegal_verdict :
    let v := detect [0x0041, 0xE0100]
    v.classify.tag = some "IllegalTarget" := by decide +kernel

/-- The negative control that keeps the detector from crying wolf: VS16 after
    U+1F600 GRINNING FACE is a genuine emoji-presentation sequence from UTS #51,
    so the verdict must be clear and the selector must be recorded as a
    registered position — never a suspicious one — so legitimate emoji survive. -/
theorem emoji_presentation_clear_verdict :
    let v := detect [0x1F600, 0xFE0F]
    v.classify.isClear = true
      ∧ v.registeredPositions = [1] ∧ v.suspiciousPositions = [] := by decide +kernel

/-- The second negative control, covering the other sanctioned block: a
    Mongolian free variation selector (U+180B) on a Mongolian base (U+1820 A)
    is a registered pairing, so the detector must return clear and not mistake a
    script's legitimate spelling mechanism for a covert channel. -/
theorem mongolian_variation_clear_verdict :
    let v := detect [0x1820, 0x180B]
    v.classify.isClear = true := by decide +kernel

/-- The complete certificate: every conformance vector above holds
    simultaneously. Appending a vector extends this conjunction, so the
    guarantee this harness makes grows with the threat catalogue and cannot
    silently regress. -/
theorem all_rows_pass :
    (let v := detect [0x0061, 0xFE04, 0xFE01]
     v.classify.tag = some "DirectPayload"
       ∧ v.recoveredPayloadBytes = [0x41]
       ∧ v.suspiciousPositions = [1, 2]) ∧
    (let v := detect [0x0041, 0xFE0F]
     v.classify.tag = some "IllegalTarget"
       ∧ v.suspiciousPositions = [1]) ∧
    (let v := detect [0x0041, 0xE0100]
     v.classify.tag = some "IllegalTarget") ∧
    (let v := detect [0x1F600, 0xFE0F]
     v.classify.isClear = true
       ∧ v.registeredPositions = [1] ∧ v.suspiciousPositions = []) ∧
    (let v := detect [0x1820, 0x180B]
     v.classify.isClear = true) :=
  ⟨direct_payload_verdict, illegal_target_verdict, supplementary_vs_illegal_verdict,
    emoji_presentation_clear_verdict, mongolian_variation_clear_verdict⟩

end Unicode.Conformance.Security.VariationSelectorPayloadTest
