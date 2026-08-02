/-
  Unicode.Conformance.Security.HashInputStabilityTest

  Conformance certificate for the HashInputStability detector (cryptographic
  input-stability layer, UTS #39 §6.1 canonical-form guidance together with the
  hash-input canonicalisation contracts of RFC 8785 §3 and RFC 4880 / 9580).

  What this certifies.  A signer and a verifier must hash byte-identical inputs.
  The detector fixes a single canonical hash-input form — NFC followed by
  stripping of trailing ASCII framing whitespace `{U+0020, U+0009, U+000A,
  U+000D}` — and flags any input that is not already in that form, because such
  an input hashes to a different digest once a downstream stage re-canonicalises
  it.

  Threat model.  A pipeline injector submits text whose canonical form differs
  across stages of a signing pipeline — PGP body canonicalisation, RFC 8785 JSON
  serialisation, audit logs whose line endings an editor rewrites on read-back,
  or webhook HMACs recomputed over re-encoded bytes.  Wherever the signing end
  and the verifying end disagree on trim policy, line-ending convention, or
  normalisation form, two inputs that a human reads as "the same content" produce
  divergent hashes while both parties believe they signed identical bytes — a
  silent signature-bypass and hash-collision hazard.

  The discrimination the detector draws.  Text already equal to its trimmed-NFC
  form is sanctioned and reported `clear`.  Text carrying trailing ASCII
  whitespace draws a `TrailingWhitespace` verdict that pinpoints the offending
  positions and the byte-length of the stable (trimmed) form, so a caller can
  see exactly what canonicalisation would change.  Unicode-category spaces
  (NBSP, `U+2000..U+200A`, ideographic space) are deliberately treated as
  content, not framing, and are left intact.

  How to read the certificate.  Each theorem below pins the detector's full
  verdict — sub-threat tag together with the stable size and, where it
  discriminates, the reported positions — on one representative vector: a
  trailing space, a trailing CRLF, and a stable lowercase-ASCII clear.  Because
  every vector is low-ASCII, NFC is the identity and is rewritten away with
  `toNFC_id_lowAscii`, leaving a cheap `decide`.  The final `all_rows_pass`
  theorem conjoins all three verdicts into the single certificate this harness
  exports; appending a further vector extends that conjunction, so the guarantee
  grows with the threat catalogue and cannot silently regress.
-/

import Unicode.Security.Crypto.HashInputStability

namespace Unicode.Conformance.Security.HashInputStabilityTest

open Unicode.Security.Crypto.HashInputStability

/-- A single trailing space is the minimal instability: `"a "` and `"a"` are one
    trim step apart, so a signer that trims and a verifier that does not compute
    different digests over what looks like the same word.  The detector must draw
    `TrailingWhitespace`, locate the space at position 1, and report that the
    stable (trimmed) form has size 1. -/
theorem trailing_space_verdict :
    let v := detect [0x61, 0x20]
    v.classify.tag = some "TrailingWhitespace"
      ∧ v.classify.positions = [1] ∧ v.stableSize = 1 := by
  unfold detect detectWithContext hashStable
  rw [toNFC_id_lowAscii [0x61, 0x20] (by decide)]
  decide

/-- A trailing CRLF is the line-ending variant of the same hazard: an editor or
    transport that rewrites `\r\n` on read-back changes the bytes a verifier
    hashes.  The detector must still draw `TrailingWhitespace` and reduce the two
    framing bytes away to a stable form of size 1. -/
theorem trailing_crlf_verdict :
    let v := detect [0x61, 0x0D, 0x0A]
    v.classify.tag = some "TrailingWhitespace" ∧ v.stableSize = 1 := by
  unfold detect detectWithContext hashStable
  rw [toNFC_id_lowAscii [0x61, 0x0D, 0x0A] (by decide)]
  decide

/-- Plain lowercase ASCII with no trailing framing is already its own trimmed-NFC
    form, so signer and verifier hash identical bytes.  This is the sanctioned
    baseline that proves the detector does not over-report content as a hazard. -/
theorem ascii_clear_verdict :
    (detect [0x61, 0x62, 0x63]).classify = .clear := by
  unfold detect detectWithContext hashStable
  rw [toNFC_id_lowAscii [0x61, 0x62, 0x63] (by decide)]
  decide

/-- The complete certificate: every conformance vector above holds
    simultaneously. Appending a vector extends this conjunction, so the
    guarantee this harness makes grows with the threat catalogue and cannot
    silently regress. -/
theorem all_rows_pass :
    (let v := detect [0x61, 0x20]
     v.classify.tag = some "TrailingWhitespace"
       ∧ v.classify.positions = [1] ∧ v.stableSize = 1) ∧
    (let v := detect [0x61, 0x0D, 0x0A]
     v.classify.tag = some "TrailingWhitespace" ∧ v.stableSize = 1) ∧
    (detect [0x61, 0x62, 0x63]).classify = .clear :=
  ⟨trailing_space_verdict, trailing_crlf_verdict, ascii_clear_verdict⟩

end Unicode.Conformance.Security.HashInputStabilityTest
